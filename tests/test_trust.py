"""Tests for package trust verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.trust import (
    PROVENANCE_PREDICATE,
    PUBLISH_PREDICATE,
    SignatureResult,
    SignerManifest,
    SignerPin,
    TrustLevel,
    _verify_provenance_bundle,
    check_trust,
    classify_attestations,
    fetch_trust_level,
    load_signer_manifest,
    save_signer_manifest,
    verify_attestation_signatures,
)


def _write_lock(tmp_path: Path, packages: dict[str, Any]) -> Path:
    lf = tmp_path / "package-lock.json"
    lf.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return lf


# ---------------------------------------------------------------------------
# Unit: classify_attestations
# ---------------------------------------------------------------------------


def test_classify_both() -> None:
    assert (
        classify_attestations({PROVENANCE_PREDICATE, PUBLISH_PREDICATE})
        == TrustLevel.PROVENANCE_AND_PUBLISH
    )


def test_classify_provenance_only() -> None:
    assert (
        classify_attestations({PROVENANCE_PREDICATE})
        == TrustLevel.PROVENANCE_ONLY
    )


def test_classify_publish_only() -> None:
    assert (
        classify_attestations({PUBLISH_PREDICATE})
        == TrustLevel.PUBLISH_ONLY
    )


def test_classify_none() -> None:
    assert classify_attestations(set()) == TrustLevel.NONE


def test_classify_unknown_predicate_ignored() -> None:
    assert (
        classify_attestations({"https://example.com/unknown"})
        == TrustLevel.NONE
    )


# ---------------------------------------------------------------------------
# Unit: TrustLevel ordering
# ---------------------------------------------------------------------------


def test_trust_level_ordering() -> None:
    assert TrustLevel.NONE < TrustLevel.PROVENANCE_ONLY
    assert TrustLevel.PROVENANCE_ONLY < TrustLevel.PUBLISH_ONLY
    assert TrustLevel.PUBLISH_ONLY < TrustLevel.PROVENANCE_AND_PUBLISH


def test_trust_level_labels() -> None:
    assert TrustLevel.NONE.label == "none"
    assert TrustLevel.PROVENANCE_AND_PUBLISH.label == "provenance+publish"


# ---------------------------------------------------------------------------
# Unit: fetch_trust_level (mocked HTTP)
# ---------------------------------------------------------------------------


def _mock_attestation(predicates: list[str]) -> dict[str, Any]:
    return {
        "attestations": [
            {"predicateType": p, "bundle": {}} for p in predicates
        ]
    }


def test_fetch_trust_level_both(tmp_path: Path) -> None:
    response = _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return response

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        level = fetch_trust_level(
            "https://registry.npmjs.org", "sigstore", "2.3.1"
        )
    assert level == TrustLevel.PROVENANCE_AND_PUBLISH


def test_fetch_trust_level_404_is_none() -> None:
    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        level = fetch_trust_level(
            "https://registry.npmjs.org", "private-pkg", "1.0.0"
        )
    assert level == TrustLevel.NONE


def test_fetch_trust_level_empty_attestations() -> None:
    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return {"attestations": []}

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        level = fetch_trust_level(
            "https://registry.npmjs.org", "old-pkg", "0.1.0"
        )
    assert level == TrustLevel.NONE


# ---------------------------------------------------------------------------
# Integration: check_trust audit mode
# ---------------------------------------------------------------------------


def test_audit_mode_classifies_all_packages(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/attested": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/attested/-/attested-1.0.0.tgz",
            },
            "node_modules/unattested": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/unattested/-/unattested-2.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attested@1.0.0" in url:
            return _mock_attestation(
                [PROVENANCE_PREDICATE, PUBLISH_PREDICATE]
            )
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="audit")

    assert report.total_checked == 2
    assert report.clean
    by_name = {f.package_name: f for f in report.findings}
    assert by_name["attested"].trust_level == TrustLevel.PROVENANCE_AND_PUBLISH
    assert by_name["unattested"].trust_level == TrustLevel.NONE
    assert len(report.no_attestation) == 1


def test_allowlist_skips_package(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/skipped": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/skipped/-/skipped-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        raise AssertionError(f"should not be called: {url}")

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="audit", allow=("skipped",))

    assert report.total_checked == 0


def test_private_allowlist_skips_package(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/@corp/internal": {
                "version": "1.0.0",
                "resolved": "https://ca.example.com/@corp/internal/-/internal-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        raise AssertionError(f"should not be called: {url}")

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(
            lf, policy="audit", allow_private=("@corp/internal",)
        )

    assert report.total_checked == 0


# ---------------------------------------------------------------------------
# Integration: no-downgrade mode
# ---------------------------------------------------------------------------


def test_no_downgrade_detects_trust_regression(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/regressed": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/regressed/-/regressed-2.0.0.tgz",
            },
        },
    )
    packument = {
        "versions": {
            "1.0.0": {},
            "2.0.0": {},
        }
    }

    call_log: list[str] = []

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        call_log.append(url)
        if "attestations/regressed@2.0.0" in url:
            return _mock_attestation([PUBLISH_PREDICATE])
        if "attestations/regressed@1.0.0" in url:
            return _mock_attestation(
                [PROVENANCE_PREDICATE, PUBLISH_PREDICATE]
            )
        if url.endswith("/regressed"):
            return packument
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="no-downgrade")

    assert not report.clean
    assert len(report.downgrades) == 1
    dg = report.downgrades[0]
    assert dg.package_name == "regressed"
    assert dg.version == "2.0.0"
    assert dg.trust_level == TrustLevel.PUBLISH_ONLY
    assert dg.previous_version == "1.0.0"
    assert dg.previous_trust_level == TrustLevel.PROVENANCE_AND_PUBLISH


def test_no_downgrade_clean_when_trust_maintained(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/stable": {
                "version": "3.0.0",
                "resolved": "https://registry.npmjs.org/stable/-/stable-3.0.0.tgz",
            },
        },
    )
    packument = {
        "versions": {"2.0.0": {}, "3.0.0": {}},
    }

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation(
                [PROVENANCE_PREDICATE, PUBLISH_PREDICATE]
            )
        if url.endswith("/stable"):
            return packument
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="no-downgrade")

    assert report.clean
    assert len(report.downgrades) == 0


def test_no_downgrade_first_version_has_no_previous(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/brand-new": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/brand-new/-/brand-new-1.0.0.tgz",
            },
        },
    )
    packument = {"versions": {"1.0.0": {}}}

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PUBLISH_PREDICATE])
        if url.endswith("/brand-new"):
            return packument
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="no-downgrade")

    assert report.clean
    finding = report.findings[0]
    assert finding.previous_version is None
    assert not finding.downgrade


def test_workspace_entries_skipped(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "system/i18n": {"name": "@example/i18n", "version": "1.0.0"},
            "node_modules/@example/i18n": {"link": True},
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        raise AssertionError(f"should not be called: {url}")

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="audit")

    assert report.total_checked == 0


def test_network_error_recorded(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/flaky": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/flaky/-/flaky-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        raise TimeoutError("connection timed out")

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(lf, policy="audit")

    assert len(report.network_errors) == 1
    assert "flaky@1.0.0" in report.network_errors[0]
    assert report.findings[0].trust_level == TrustLevel.NONE


# ---------------------------------------------------------------------------
# Phase 3: sigstore signature verification (mocked)
# ---------------------------------------------------------------------------


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_verify_real_provenance_bundle() -> None:
    """End-to-end: verify a real sigstore provenance bundle from npm."""
    bundle_path = FIXTURE_DIR / "undici-7.10.0-provenance-bundle.json"
    bundle_json = bundle_path.read_text()
    result = _verify_provenance_bundle(bundle_json)
    assert result.verified, f"real bundle should verify: {result.error}"
    assert result.signer_identity is not None
    assert "github.com" in result.signer_identity
    assert result.signer_issuer == "https://token.actions.githubusercontent.com"


def test_verify_provenance_bundle_success() -> None:
    """Mocked sigstore verification returning a successful result."""

    class FakeBundle:
        signing_certificate = None

    with (
        patch("sigstore.models.Bundle.from_json", return_value=FakeBundle()),
        patch("sigstore.verify.Verifier.production") as mock_prod,
    ):
        mock_verifier = mock_prod.return_value
        mock_verifier.verify_dsse.return_value = (
            "application/vnd.in-toto+json",
            b'{"subject": []}',
        )
        result = _verify_provenance_bundle("{}")

    assert result.verified


def test_verify_provenance_bundle_parse_failure() -> None:
    with patch(
        "sigstore.models.Bundle.from_json",
        side_effect=ValueError("invalid bundle"),
    ):
        result = _verify_provenance_bundle("{}")

    assert not result.verified
    assert "bundle parse" in (result.error or "")


def test_verify_provenance_bundle_verification_failure() -> None:
    class FakeBundle:
        signing_certificate = None

    with (
        patch("sigstore.models.Bundle.from_json", return_value=FakeBundle()),
        patch("sigstore.verify.Verifier.production") as mock_prod,
    ):
        mock_verifier = mock_prod.return_value
        mock_verifier.verify_dsse.side_effect = Exception("signature mismatch")
        result = _verify_provenance_bundle("{}")

    assert not result.verified
    assert "verification" in (result.error or "")


def test_verify_attestation_signatures_no_provenance() -> None:
    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return _mock_attestation([PUBLISH_PREDICATE])

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        result = verify_attestation_signatures(
            "https://registry.npmjs.org", "pkg", "1.0.0"
        )

    assert not result.verified
    assert "no provenance" in (result.error or "")


def test_verify_attestation_signatures_404() -> None:
    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        result = verify_attestation_signatures(
            "https://registry.npmjs.org", "pkg", "1.0.0"
        )

    assert not result.verified
    assert "404" in (result.error or "")


def test_check_trust_with_verify_signatures(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/attested": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/attested/-/attested-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])
        return None

    mock_sig = SignatureResult(
        verified=True,
        signer_identity="https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main",
        signer_issuer="https://token.actions.githubusercontent.com",
    )

    with (
        patch("codeartifact_shield.trust._http_get_json", mock_get),
        patch(
            "codeartifact_shield.trust.verify_attestation_signatures",
            return_value=mock_sig,
        ),
    ):
        report = check_trust(lf, policy="audit", verify_signatures=True)

    assert report.total_checked == 1
    finding = report.findings[0]
    assert finding.signature is not None
    assert finding.signature.verified
    assert "github.com" in (finding.signature.signer_identity or "")


def test_check_trust_sig_failure_makes_report_not_clean(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/tampered": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/tampered/-/tampered-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PROVENANCE_PREDICATE])
        return None

    mock_sig = SignatureResult(verified=False, error="signature mismatch")

    with (
        patch("codeartifact_shield.trust._http_get_json", mock_get),
        patch(
            "codeartifact_shield.trust.verify_attestation_signatures",
            return_value=mock_sig,
        ),
    ):
        report = check_trust(lf, policy="audit", verify_signatures=True)

    finding = report.findings[0]
    assert finding.signature is not None
    assert not finding.signature.verified


# ---------------------------------------------------------------------------
# Signer manifest: load / save / round-trip
# ---------------------------------------------------------------------------


def test_signer_manifest_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "signers.json"
    manifest: SignerManifest = {
        "undici": SignerPin(
            identity="https://github.com/nodejs/undici/.github/workflows/release.yml@refs/heads/main",
            issuer="https://token.actions.githubusercontent.com",
        ),
    }
    save_signer_manifest(path, manifest)
    loaded = load_signer_manifest(path)
    assert loaded["undici"].identity == manifest["undici"].identity
    assert loaded["undici"].issuer == manifest["undici"].issuer


def test_load_signer_manifest_missing_file(tmp_path: Path) -> None:
    assert load_signer_manifest(tmp_path / "nonexistent.json") == {}


# ---------------------------------------------------------------------------
# Signer pinning: identity enforcement
# ---------------------------------------------------------------------------


def test_signer_pin_match_passes(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/pinned-pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/pinned-pkg/-/pinned-pkg-1.0.0.tgz",
            },
        },
    )
    expected_identity = "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
    expected_issuer = "https://token.actions.githubusercontent.com"

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])
        return None

    mock_sig = SignatureResult(
        verified=True,
        signer_identity=expected_identity,
        signer_issuer=expected_issuer,
    )
    manifest: SignerManifest = {
        "pinned-pkg": SignerPin(identity=expected_identity, issuer=expected_issuer),
    }

    with (
        patch("codeartifact_shield.trust._http_get_json", mock_get),
        patch(
            "codeartifact_shield.trust.verify_attestation_signatures",
            return_value=mock_sig,
        ),
    ):
        report = check_trust(
            lf, policy="audit", verify_signatures=True, signer_manifest=manifest
        )

    finding = report.findings[0]
    assert not finding.signer_changed
    assert finding.pinned_identity == expected_identity


def test_signer_pin_mismatch_flags_change(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/hijacked": {
                "version": "2.0.0",
                "resolved": "https://registry.npmjs.org/hijacked/-/hijacked-2.0.0.tgz",
            },
        },
    )
    pinned_identity = "https://github.com/legit/repo/.github/workflows/release.yml@refs/heads/main"
    actual_identity = "https://github.com/attacker/fork/.github/workflows/publish.yml@refs/heads/main"

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])
        return None

    mock_sig = SignatureResult(
        verified=True,
        signer_identity=actual_identity,
        signer_issuer="https://token.actions.githubusercontent.com",
    )
    manifest: SignerManifest = {
        "hijacked": SignerPin(
            identity=pinned_identity,
            issuer="https://token.actions.githubusercontent.com",
        ),
    }

    with (
        patch("codeartifact_shield.trust._http_get_json", mock_get),
        patch(
            "codeartifact_shield.trust.verify_attestation_signatures",
            return_value=mock_sig,
        ),
    ):
        report = check_trust(
            lf, policy="audit", verify_signatures=True, signer_manifest=manifest
        )

    finding = report.findings[0]
    assert finding.signer_changed
    assert finding.pinned_identity == pinned_identity


def test_signer_pin_lost_provenance_flags_change(tmp_path: Path) -> None:
    """Package had a pinned signer but new version has no provenance at all."""
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/lost-provenance": {
                "version": "3.0.0",
                "resolved": "https://registry.npmjs.org/lost-provenance/-/lost-provenance-3.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return None  # no attestations
        return None

    manifest: SignerManifest = {
        "lost-provenance": SignerPin(
            identity="https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main",
            issuer="https://token.actions.githubusercontent.com",
        ),
    }

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        report = check_trust(
            lf, policy="audit", verify_signatures=True, signer_manifest=manifest
        )

    finding = report.findings[0]
    assert finding.signer_changed
    assert finding.signature is not None
    assert not finding.signature.verified
    assert "no provenance" in (finding.signature.error or "")
