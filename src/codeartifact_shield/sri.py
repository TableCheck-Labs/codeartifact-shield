"""SRI integrity hash backfill for npm package-lock.json against AWS CodeArtifact.

Why this exists
---------------

AWS CodeArtifact's npm proxy does **not** include the `dist.integrity` field
in npm-registry-style metadata responses (the response served at
``GET /<package>`` or ``GET /<package>/<version>``). When the npm client
resolves dependencies through CodeArtifact and writes ``package-lock.json``,
every entry comes out with no ``integrity`` value. The lockfile then pins
versions but cannot detect a tampered tarball — ``npm ci`` becomes
"trust whatever bytes the registry currently returns at the resolved URL".

CodeArtifact *does* store and expose SHA-256 + SHA-512 hashes for every
package asset; it just doesn't surface them in the npm-format response.
The :func:`patch_lockfile` function in this module pulls the hash via the
``ListPackageVersionAssets`` API for each lockfile entry, computes the SRI
``sha512-<base64>`` string, and patches the lockfile in place.

After patching, ``npm ci`` will validate every tarball it installs against
the SRI hash and fail fast on any mismatch.

Limits
------

* Only npm lockfiles (lockfileVersion 2 or 3) — older v1 files use a
  different structure and aren't supported.
* If a package is not present in the CodeArtifact repository
  (e.g. a transitive that was never resolved through it), the patcher
  skips that entry. ``verify_lockfile`` reports such gaps so CI can
  decide whether to fail or just warn.
* Scoped packages: lockfile keys look like ``node_modules/@scope/name``;
  CodeArtifact wants ``namespace=scope`` (no leading @) and ``package=name``.
* CodeArtifact stores tarball assets as ``package.tgz``; the asset hash
  is the same as ``dist.integrity`` would have been (verified by
  cross-referencing the public registry's published SHA-512 for several
  popular packages).
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PackageRef:
    """Identifier for a single lockfile entry, in CodeArtifact's vocabulary."""

    namespace: str | None  # e.g. "tanstack" for @tanstack/react-query, else None
    name: str  # e.g. "react-query"
    version: str

    @property
    def lockfile_key(self) -> str:
        if self.namespace:
            return f"node_modules/@{self.namespace}/{self.name}"
        return f"node_modules/{self.name}"


@dataclass
class PatchReport:
    """Summary of a patch run."""

    patched: int = 0  # entries that now have an integrity hash they didn't before
    already_present: int = 0  # entries that already had integrity
    not_in_codeartifact: list[str] = None  # type: ignore[assignment]
    api_errors: list[tuple[str, str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.not_in_codeartifact is None:
            self.not_in_codeartifact = []
        if self.api_errors is None:
            self.api_errors = []

    @property
    def total_with_integrity(self) -> int:
        return self.patched + self.already_present


def _ref_from_lockfile_key(key: str) -> PackageRef | None:
    """Parse a lockfile path like ``node_modules/@scope/name`` into a ref.

    Returns None for keys we can't translate (the root entry, workspaces, etc.).
    """
    if not key.startswith("node_modules/"):
        return None
    tail = key[len("node_modules/") :]
    # Nested deps: ``node_modules/<pkg>/node_modules/<inner>`` — only the
    # outermost matters because CodeArtifact stores by package, not by
    # path. We take the *last* node_modules segment to find the actual
    # installed package id.
    if "/node_modules/" in tail:
        tail = tail.rsplit("/node_modules/", 1)[1]
    if tail.startswith("@"):
        # scoped: @scope/name
        if "/" not in tail:
            return None
        scope, name = tail[1:].split("/", 1)
        return PackageRef(namespace=scope, name=name, version="")
    return PackageRef(namespace=None, name=tail, version="")


def _iter_lockfile_packages(lock: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield ``(lockfile_key, entry)`` pairs for installable packages.

    Skips the root entry (the empty key) which represents the project itself.
    """
    pkgs = lock.get("packages", {})
    for key, entry in pkgs.items():
        if not key:
            continue
        if entry.get("link"):
            # Workspace symlinks aren't fetched from a registry.
            continue
        if not entry.get("version"):
            # Some entries are bundled-only or workspace-only.
            continue
        yield key, entry


def sri_from_sha512_hex(hex_digest: str) -> str:
    """Convert a hex SHA-512 digest into an SRI ``sha512-<base64>`` string.

    Cross-checked against multiple packages: the value matches what the
    public npm registry publishes as ``dist.integrity`` for the same
    tarball. This is the format ``npm ci`` validates against.
    """
    binary = bytes.fromhex(hex_digest)
    if len(binary) != 64:
        raise ValueError(f"expected 64-byte SHA-512, got {len(binary)} bytes")
    return "sha512-" + base64.b64encode(binary).decode("ascii")


def _query_sha512(client: Any, domain: str, repository: str, ref: PackageRef) -> str | None:
    """Pull the SHA-512 of ``package.tgz`` for one ref from CodeArtifact.

    Returns the hex digest, or None when the package isn't in the repo
    (404 / ResourceNotFoundException). Re-raises any other error so the
    caller can record it.
    """
    kwargs: dict[str, Any] = {
        "domain": domain,
        "repository": repository,
        "format": "npm",
        "package": ref.name,
        "packageVersion": ref.version,
    }
    if ref.namespace:
        kwargs["namespace"] = ref.namespace
    try:
        resp = client.list_package_version_assets(**kwargs)
    except client.exceptions.ResourceNotFoundException:
        return None
    # The tarball asset is consistently named "package.tgz" across all
    # npm packages CodeArtifact ingests.
    for asset in resp.get("assets", []):
        if asset.get("name") == "package.tgz":
            hashes = asset.get("hashes", {})
            sha512 = hashes.get("SHA-512")
            if sha512:
                return str(sha512)
            logger.warning(
                "asset for %s@%s has no SHA-512 hash (only %s)",
                ref.name,
                ref.version,
                list(hashes),
            )
    return None


def patch_lockfile(
    lockfile_path: Path,
    *,
    domain: str,
    repository: str,
    boto3_session: Any | None = None,
    dry_run: bool = False,
) -> PatchReport:
    """Walk a package-lock.json and inject SRI integrity hashes from CodeArtifact.

    ``dry_run=True`` does the API calls and reports what *would* change but
    leaves the lockfile untouched — useful for a CI verify step that
    asserts no patching is needed before allowing a PR to merge.
    """
    if boto3_session is None:
        import boto3

        boto3_session = boto3.Session()
    client = boto3_session.client("codeartifact")

    lock = json.loads(lockfile_path.read_text())
    lf_version = lock.get("lockfileVersion")
    if lf_version not in (2, 3):
        raise ValueError(
            f"unsupported lockfileVersion {lf_version}; only v2 and v3 are supported"
        )

    report = PatchReport()
    for key, entry in _iter_lockfile_packages(lock):
        if entry.get("integrity"):
            report.already_present += 1
            continue
        ref = _ref_from_lockfile_key(key)
        if ref is None:
            continue
        ref = PackageRef(namespace=ref.namespace, name=ref.name, version=entry["version"])
        try:
            hex_sha512 = _query_sha512(client, domain, repository, ref)
        except Exception as exc:  # noqa: BLE001 - report and continue
            logger.warning("API error for %s@%s: %s", ref.name, ref.version, exc)
            report.api_errors.append((key, str(exc)[:200]))
            continue
        if hex_sha512 is None:
            report.not_in_codeartifact.append(key)
            continue
        entry["integrity"] = sri_from_sha512_hex(hex_sha512)
        report.patched += 1

    if not dry_run and report.patched:
        # Preserve trailing newline and 2-space indent — match npm's
        # native lockfile formatting so a subsequent `npm ci` doesn't
        # rewrite the file.
        lockfile_path.write_text(json.dumps(lock, indent=2) + "\n")

    return report


def verify_lockfile(lockfile_path: Path) -> tuple[int, int]:
    """Return ``(with_integrity, total)`` for installable lockfile entries.

    Doesn't talk to CodeArtifact — pure lockfile read. The CLI uses this
    as the basis for a fail-on-missing-SRI gate.
    """
    lock = json.loads(lockfile_path.read_text())
    total = 0
    with_integrity = 0
    for _key, entry in _iter_lockfile_packages(lock):
        total += 1
        if entry.get("integrity"):
            with_integrity += 1
    return with_integrity, total
