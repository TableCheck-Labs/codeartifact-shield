"""Package trust verification — npm attestation + provenance audit.

npm publishes sigstore-based attestations for packages built via GitHub
Actions or GitLab CI. Two predicate types exist:

* **Provenance** (``https://slsa.dev/provenance/v1``): links the tarball
  to a specific source commit + CI build.
* **Publish** (``https://github.com/npm/attestation/tree/main/specs/publish/v0.1``):
  confirms the publish event was authorised.

A package with both attestations has the highest trust level. Losing
either between versions is a trust downgrade — the most likely cause is
a compromised maintainer account publishing outside CI.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeartifact_shield._allowlist import PackageAllowlist
from codeartifact_shield._http import DEFAULT_RETRIES, with_retry
from codeartifact_shield._lockfile import (
    extract_package_name,
    is_installable_entry,
    load_lockfile,
)

PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
PUBLISH_PREDICATE = (
    "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
)

DEFAULT_REGISTRY = "https://registry.npmjs.org"
DEFAULT_TIMEOUT = 30
DEFAULT_WORKERS = 32


class TrustLevel(enum.IntEnum):
    """Ordered from lowest to highest trust."""

    NONE = 0
    PROVENANCE_ONLY = 1
    PUBLISH_ONLY = 2
    PROVENANCE_AND_PUBLISH = 3

    @property
    def label(self) -> str:
        return _TRUST_LABELS[self]


_TRUST_LABELS = {
    TrustLevel.NONE: "none",
    TrustLevel.PROVENANCE_ONLY: "provenance-only",
    TrustLevel.PUBLISH_ONLY: "publish-only",
    TrustLevel.PROVENANCE_AND_PUBLISH: "provenance+publish",
}


def classify_attestations(predicate_types: set[str]) -> TrustLevel:
    has_provenance = PROVENANCE_PREDICATE in predicate_types
    has_publish = PUBLISH_PREDICATE in predicate_types
    if has_provenance and has_publish:
        return TrustLevel.PROVENANCE_AND_PUBLISH
    if has_publish:
        return TrustLevel.PUBLISH_ONLY
    if has_provenance:
        return TrustLevel.PROVENANCE_ONLY
    return TrustLevel.NONE


@dataclass
class SignerPin:
    """Expected signer identity for a package, loaded from a manifest file."""

    identity: str
    issuer: str


# Manifest: package_name → SignerPin
SignerManifest = dict[str, SignerPin]


def load_signer_manifest(path: Path) -> SignerManifest:
    import json

    if not path.exists():
        return {}
    raw: dict[str, Any] = json.loads(path.read_text())
    manifest: SignerManifest = {}
    for name, entry in raw.items():
        if isinstance(entry, dict) and "identity" in entry and "issuer" in entry:
            manifest[name] = SignerPin(
                identity=entry["identity"], issuer=entry["issuer"]
            )
    return manifest


def save_signer_manifest(path: Path, manifest: SignerManifest) -> None:
    import json

    data = {
        name: {"identity": pin.identity, "issuer": pin.issuer}
        for name, pin in sorted(manifest.items())
    }
    path.write_text(json.dumps(data, indent=2) + "\n")


@dataclass
class SignatureResult:
    """Outcome of sigstore signature verification for one attestation."""

    verified: bool
    signer_identity: str | None = None
    signer_issuer: str | None = None
    error: str | None = None


@dataclass
class TrustFinding:
    package_name: str
    version: str
    trust_level: TrustLevel
    previous_version: str | None = None
    previous_trust_level: TrustLevel | None = None
    signature: SignatureResult | None = None
    pinned_identity: str | None = None
    signer_changed: bool = False

    @property
    def downgrade(self) -> bool:
        if self.previous_trust_level is None:
            return False
        return self.trust_level < self.previous_trust_level


@dataclass
class TrustReport:
    total_checked: int = 0
    findings: list[TrustFinding] = field(default_factory=list)
    network_errors: list[str] = field(default_factory=list)

    @property
    def downgrades(self) -> list[TrustFinding]:
        return [f for f in self.findings if f.downgrade]

    @property
    def no_attestation(self) -> list[TrustFinding]:
        return [
            f for f in self.findings if f.trust_level == TrustLevel.NONE
        ]

    @property
    def clean(self) -> bool:
        return not self.downgrades


def _attestation_url(registry: str, name: str, version: str) -> str:
    return f"{registry.rstrip('/')}/-/npm/v1/attestations/{name}@{version}"


def _sigstore_available() -> bool:
    try:
        import sigstore.models  # noqa: F401
        import sigstore.verify  # noqa: F401

        return True
    except ImportError:
        return False


def _extract_signer(bundle: object) -> tuple[str | None, str | None]:
    """Extract (identity, issuer) from a parsed sigstore Bundle's certificate."""
    import cryptography.x509

    try:
        cert = bundle.signing_certificate  # type: ignore[attr-defined]
        san = cert.extensions.get_extension_for_class(
            cryptography.x509.SubjectAlternativeName
        )
        uris = san.value.get_values_for_type(
            cryptography.x509.UniformResourceIdentifier
        )
        identity = uris[0] if uris else None
        oidc_oid = cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
        issuer_ext = cert.extensions.get_extension_for_oid(oidc_oid)
        issuer: str | None = issuer_ext.value.value.decode("utf-8")
    except Exception:
        return None, None
    return identity, issuer


def _verify_provenance_bundle(
    bundle_json: str,
    expected_identity: str | None = None,
    expected_issuer: str | None = None,
) -> SignatureResult:
    """Verify a sigstore provenance bundle against the production trust root.

    When ``expected_identity`` and ``expected_issuer`` are provided, the
    sigstore ``Identity`` policy is used — the bundle must have been signed
    by exactly that workflow from that OIDC issuer. Without them, chain
    validity and tlog inclusion are still verified, but the signer is only
    reported (not enforced).
    """
    from sigstore.models import Bundle
    from sigstore.verify import Verifier
    from sigstore.verify.policy import Identity, UnsafeNoOp, VerificationPolicy

    try:
        bundle = Bundle.from_json(bundle_json)
    except Exception as exc:
        return SignatureResult(verified=False, error=f"bundle parse: {exc}")

    verification_policy: VerificationPolicy
    if expected_identity and expected_issuer:
        verification_policy = Identity(identity=expected_identity, issuer=expected_issuer)
    else:
        verification_policy = UnsafeNoOp()

    try:
        verifier = Verifier.production()
        verifier.verify_dsse(bundle, verification_policy)
    except Exception as exc:
        return SignatureResult(verified=False, error=f"verification: {exc}")

    identity, issuer = _extract_signer(bundle)

    return SignatureResult(
        verified=True,
        signer_identity=identity,
        signer_issuer=issuer,
    )


def verify_attestation_signatures(
    registry: str,
    name: str,
    version: str,
    pin: SignerPin | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> SignatureResult:
    """Fetch and verify the provenance attestation's sigstore signature.

    When ``pin`` is provided, the bundle is verified against the pinned
    identity — a mismatch (different workflow, different issuer) fails
    verification even if the bundle is otherwise cryptographically valid.
    """
    import json

    url = _attestation_url(registry, name, version)
    data = _http_get_json(url, timeout=timeout, retries=retries)
    if data is None:
        return SignatureResult(verified=False, error="no attestations (404)")

    for att in data.get("attestations", []):
        pt = att.get("predicateType", "")
        if pt == PROVENANCE_PREDICATE:
            bundle_json = json.dumps(att.get("bundle", {}))
            return _verify_provenance_bundle(
                bundle_json,
                expected_identity=pin.identity if pin else None,
                expected_issuer=pin.issuer if pin else None,
            )

    return SignatureResult(
        verified=False, error="no provenance attestation to verify"
    )


def _http_get_json(
    url: str, timeout: int, retries: int = DEFAULT_RETRIES
) -> dict[str, Any] | None:
    """Fetch JSON; return None on 404 (no attestations for this package)."""
    import json
    import urllib.error
    import urllib.request

    def attempt() -> dict[str, Any] | None:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data: dict[str, Any] = json.loads(resp.read())
                return data
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    result: dict[str, Any] | None = with_retry(attempt, retries=retries)
    return result


def fetch_trust_level(
    registry: str,
    name: str,
    version: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> TrustLevel:
    url = _attestation_url(registry, name, version)
    data = _http_get_json(url, timeout=timeout, retries=retries)
    if data is None:
        return TrustLevel.NONE
    predicates: set[str] = set()
    for att in data.get("attestations", []):
        pt = att.get("predicateType")
        if isinstance(pt, str):
            predicates.add(pt)
    return classify_attestations(predicates)


def _fetch_previous_version(
    registry: str,
    name: str,
    current_version: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> str | None:
    """Find the semver-predecessor of ``current_version`` on the registry."""
    import functools

    import nodesemver

    url = f"{registry.rstrip('/')}/{name}"
    data = _http_get_json(url, timeout=timeout, retries=retries)
    if data is None:
        return None
    versions_obj = data.get("versions", {})
    if not isinstance(versions_obj, dict):
        return None
    all_versions: list[str] = sorted(
        versions_obj,
        key=functools.cmp_to_key(lambda a, b: nodesemver.compare(a, b, loose=True)),
    )
    try:
        idx = all_versions.index(current_version)
    except ValueError:
        return None
    if idx == 0:
        return None
    return all_versions[idx - 1]


def check_trust(
    lockfile_path: Path,
    *,
    policy: str = "audit",
    registry: str = DEFAULT_REGISTRY,
    allow: Iterable[str] = (),
    allow_private: Iterable[str] = (),
    verify_signatures: bool = False,
    signer_manifest: SignerManifest | None = None,
    max_workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> TrustReport:
    """Audit trust levels for every installable package in the lockfile.

    Args:
        lockfile_path: ``package-lock.json`` to audit.
        policy: ``"audit"`` (report only), ``"no-downgrade"`` (fail on
            downgrade), or ``"require-provenance"`` (fail if any package
            lacks provenance).
        registry: npm registry URL for fetching attestations.
        allow: Package names/specs exempt from trust checks.
        allow_private: Package names/specs for private packages (will 404
            on public registry — exempt from attestation requirements).
        max_workers: Thread-pool size for parallel attestation fetches.
        timeout: Per-request HTTP timeout in seconds.
        retries: Number of retries per request.
    """
    lock = load_lockfile(lockfile_path)
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})
    allowlist = PackageAllowlist.from_entries(allow)
    private_allowlist = PackageAllowlist.from_entries(allow_private)

    seen: dict[tuple[str, str], None] = {}
    for key, entry in pkgs.items():
        if not is_installable_entry(key, entry):
            continue
        name = extract_package_name(key, entry)
        version = entry.get("version")
        if not name or not isinstance(version, str):
            continue
        if allowlist.allows(name, version):
            continue
        if private_allowlist.allows(name, version):
            continue
        seen[(name, version)] = None

    pkg_list = list(seen)
    report = TrustReport(total_checked=len(pkg_list))
    if not pkg_list:
        return report

    # Phase 1: fetch trust levels in parallel.
    trust_levels: dict[tuple[str, str], TrustLevel] = {}
    workers = max(1, min(max_workers, len(pkg_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        tl_futures: dict[Future[TrustLevel], tuple[str, str]] = {
            pool.submit(
                fetch_trust_level, registry, name, version,
                timeout=timeout, retries=retries,
            ): (name, version)
            for (name, version) in pkg_list
        }
        for fut in as_completed(tl_futures):
            name, version = tl_futures[fut]
            try:
                trust_levels[(name, version)] = fut.result()
            except Exception as exc:
                report.network_errors.append(f"{name}@{version}: {exc}")
                trust_levels[(name, version)] = TrustLevel.NONE

    need_downgrade_check = policy == "no-downgrade"

    # Phase 2: if no-downgrade policy, fetch previous versions in parallel.
    prev_trust: dict[tuple[str, str], tuple[str, TrustLevel]] = {}
    if need_downgrade_check:
        prev_versions: dict[tuple[str, str], str | None] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pv_futures: dict[Future[str | None], tuple[str, str]] = {
                pool.submit(
                    _fetch_previous_version, registry, name, version,
                    timeout=timeout, retries=retries,
                ): (name, version)
                for (name, version) in pkg_list
            }
            for pv_fut in as_completed(pv_futures):
                name, version = pv_futures[pv_fut]
                try:
                    prev_versions[(name, version)] = pv_fut.result()
                except Exception as exc:
                    report.network_errors.append(
                        f"{name}@{version} (prev lookup): {exc}"
                    )

        prev_to_fetch = [
            (name, version, pv)
            for (name, version), pv in prev_versions.items()
            if pv is not None
        ]
        if prev_to_fetch:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                pt_futures: dict[Future[TrustLevel], tuple[str, str, str]] = {
                    pool.submit(
                        fetch_trust_level, registry, name, pv,
                        timeout=timeout, retries=retries,
                    ): (name, version, pv)
                    for (name, version, pv) in prev_to_fetch
                }
                for pt_fut in as_completed(pt_futures):
                    name, version, pv = pt_futures[pt_fut]
                    try:
                        prev_trust[(name, version)] = (pv, pt_fut.result())
                    except Exception as exc:
                        report.network_errors.append(
                            f"{name}@{pv} (prev trust): {exc}"
                        )

    # Phase 3 (optional): verify provenance signatures via sigstore.
    pins = signer_manifest or {}
    sig_results: dict[tuple[str, str], SignatureResult] = {}
    if verify_signatures:
        provenance_pkgs = [
            (n, v)
            for (n, v) in pkg_list
            if trust_levels.get((n, v), TrustLevel.NONE)
            in (TrustLevel.PROVENANCE_ONLY, TrustLevel.PROVENANCE_AND_PUBLISH)
        ]
        if provenance_pkgs:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                sig_futures: dict[Future[SignatureResult], tuple[str, str]] = {
                    pool.submit(
                        verify_attestation_signatures,
                        registry,
                        name,
                        version,
                        pin=pins.get(name),
                        timeout=timeout,
                        retries=retries,
                    ): (name, version)
                    for (name, version) in provenance_pkgs
                }
                for sig_fut in as_completed(sig_futures):
                    name, version = sig_futures[sig_fut]
                    try:
                        sig_results[(name, version)] = sig_fut.result()
                    except Exception as exc:
                        sig_results[(name, version)] = SignatureResult(
                            verified=False, error=str(exc)
                        )

    # Build findings.
    for name, version in pkg_list:
        tl = trust_levels.get((name, version), TrustLevel.NONE)
        finding = TrustFinding(
            package_name=name,
            version=version,
            trust_level=tl,
        )
        if (name, version) in prev_trust:
            pv, ptl = prev_trust[(name, version)]
            finding.previous_version = pv
            finding.previous_trust_level = ptl
        if (name, version) in sig_results:
            sig = sig_results[(name, version)]
            finding.signature = sig
            pin = pins.get(name)
            if pin:
                finding.pinned_identity = pin.identity
                if sig.verified and sig.signer_identity != pin.identity:
                    finding.signer_changed = True
            elif pins and sig.verified and tl in (
                TrustLevel.PROVENANCE_ONLY,
                TrustLevel.PROVENANCE_AND_PUBLISH,
            ):
                # Manifest exists but no pin for this package — new signer,
                # not a change. Will be picked up by --update-signers.
                pass
        elif pins.get(name) and verify_signatures:
            # Pinned but no provenance on this version — signer lost.
            finding.pinned_identity = pins[name].identity
            finding.signer_changed = True
            finding.signature = SignatureResult(
                verified=False,
                error="pinned signer exists but package has no provenance",
            )
        report.findings.append(finding)

    return report
