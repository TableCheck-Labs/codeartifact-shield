"""Tests for the OSV.dev vulnerability audit module.

Mock fixtures in ``tests/fixtures/osv/`` are real responses captured from
``api.osv.dev`` so the tests reflect actual API shape (range type ``SEMVER``
rather than ``ECOSYSTEM``, ``database_specific.severity`` casing, the
``modified`` timestamps on batch results, the empty-object form ``{}``
returned for a package with no vulns, etc.).

To refresh the fixtures, run:
    curl -fsSL https://api.osv.dev/v1/vulns/<GHSA-id> > tests/fixtures/osv/vuln-<GHSA-id>.json
    curl -fsSL -X POST https://api.osv.dev/v1/querybatch -H 'Content-Type: application/json' \\
         -d '{"queries":[...]}' > tests/fixtures/osv/batch-<label>.json
"""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.audit import (
    _extract_fixed_version,
    _extract_severity,
    _meets_floor,
    audit_lockfile,
    load_whitelist_file,
)

FIXTURES = Path(__file__).parent / "fixtures" / "osv"


def _load_fixture(name: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return payload


def _write_lock(tmp_path: Path, packages: dict[str, dict]) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return p


# Real fixtures from api.osv.dev.
_BATCH_3PKG = _load_fixture("batch-lodash-axios-react.json")
# GHSA-35jh-r3h4-6jhm (Command Injection) IS returned for lodash@4.17.15 in
# the real batch above. GHSA-jf85-cpcp-j695 (Prototype Pollution) is fixed
# at 4.17.12 so 4.17.15 isn't affected — kept as a fixture for the
# fixed_version / severity-extraction unit tests but not used in the
# multi-id batch integration test.
_VULN_LODASH_CMDINJ = _load_fixture("vuln-GHSA-35jh-r3h4-6jhm.json")
_VULN_LODASH_PROTO = _load_fixture("vuln-GHSA-jf85-cpcp-j695.json")
_VULN_AXIOS = _load_fixture("vuln-GHSA-cph5-m8f7-6c5x.json")


def _mock_from_fixtures(
    batch_response: dict[str, Any], vuln_db: dict[str, dict[str, Any]]
):
    """Return (mock_post, mock_get) that replay the given OSV responses."""

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return batch_response

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        vuln_id = url.rsplit("/", 1)[-1]
        return vuln_db[vuln_id]

    return mock_post, mock_get


# ---------------------------------------------------------------------------
# helpers — validated against real fixture shapes
# ---------------------------------------------------------------------------


def test_extract_severity_real_lodash_fixture_is_critical() -> None:
    # Real OSV record classifies CVE-2019-10744 as CRITICAL — confirms
    # cas uses the database_specific severity directly.
    assert _extract_severity(_VULN_LODASH_PROTO) == "CRITICAL"


def test_extract_severity_real_axios_fixture_is_high() -> None:
    assert _extract_severity(_VULN_AXIOS) == "HIGH"


def test_extract_severity_real_lodash_cmdinj_is_high() -> None:
    assert _extract_severity(_VULN_LODASH_CMDINJ) == "HIGH"


def test_extract_severity_normalizes_moderate_to_medium() -> None:
    assert _extract_severity({"database_specific": {"severity": "MODERATE"}}) == "MEDIUM"


def test_extract_severity_unknown_when_missing() -> None:
    assert _extract_severity({}) == "UNKNOWN"
    assert _extract_severity({"database_specific": {}}) == "UNKNOWN"


def test_extract_fixed_version_lodash_real_fixture() -> None:
    # Real fixture: prototype-pollution advisory is fixed at 4.17.12.
    assert _extract_fixed_version(_VULN_LODASH_PROTO, "lodash") == "4.17.12"


def test_extract_fixed_version_lodash_cmdinj_fixed_at_4_17_21() -> None:
    # The well-known 4.17.21 fix corresponds to the command-injection
    # advisory, not the prototype-pollution one.
    assert _extract_fixed_version(_VULN_LODASH_CMDINJ, "lodash") == "4.17.21"


def test_extract_fixed_version_axios_real_fixture() -> None:
    assert _extract_fixed_version(_VULN_AXIOS, "axios") == "0.21.2"


def test_extract_fixed_version_returns_none_when_pkg_not_in_affected() -> None:
    assert _extract_fixed_version(_VULN_LODASH_PROTO, "not-lodash") is None


def test_meets_floor_strict_at_threshold() -> None:
    assert _meets_floor("HIGH", "HIGH") is True
    assert _meets_floor("CRITICAL", "HIGH") is True
    assert _meets_floor("MEDIUM", "HIGH") is False
    assert _meets_floor("LOW", "MEDIUM") is False
    assert _meets_floor("HIGH", "low") is True


# ---------------------------------------------------------------------------
# audit_lockfile — integration against captured fixtures
# ---------------------------------------------------------------------------


def test_audit_clean_lockfile_no_vulns(tmp_path: Path) -> None:
    # The real batch response for react@18.3.1 returns an empty object {} —
    # not {"vulns": []}. Verify cas handles that shape.
    lf = _write_lock(tmp_path, {"node_modules/react": {"version": "18.3.1"}})
    mock_post, mock_get = _mock_from_fixtures(
        batch_response={"results": [{}]}, vuln_db={}
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)
    assert report.clean
    assert report.total_checked == 1
    assert report.findings == []


def test_audit_reports_real_lodash_vuln(tmp_path: Path) -> None:
    # lodash@4.17.15 IS affected by the command-injection advisory
    # (GHSA-35jh-r3h4-6jhm, fixed in 4.17.21). Mirror the real batch
    # response shape, then assert against the real fixture details.
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.15"}})
    batch = {"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm", "modified": "x"}]}]}
    mock_post, mock_get = _mock_from_fixtures(
        batch_response=batch,
        vuln_db={"GHSA-35jh-r3h4-6jhm": _VULN_LODASH_CMDINJ},
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)
    assert not report.clean
    assert len(report.findings) == 1
    f = report.findings[0]
    assert f.package_name == "lodash"
    assert f.version == "4.17.15"
    assert f.vuln_id == "GHSA-35jh-r3h4-6jhm"
    assert f.severity == "HIGH"
    assert f.summary == "Command Injection in lodash"
    assert f.fixed_in == "4.17.21"
    assert f.aliases == ["CVE-2021-23337"]


def test_audit_handles_real_multi_id_batch(tmp_path: Path) -> None:
    # Replay the real 3-package batch response shape: 6 IDs for lodash,
    # 17 IDs for axios, empty {} for react. cas must process all three
    # entries in the order they appear in the lockfile.
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/axios": {"version": "0.21.0"},
            "node_modules/react": {"version": "18.3.1"},
        },
    )
    # Build a vuln_db that returns minimal valid details for every ID the
    # real batch references (so the detail-fetch loop succeeds for all).
    vuln_db: dict[str, dict[str, Any]] = {}
    for result in _BATCH_3PKG["results"]:
        for v in result.get("vulns", []):
            vuln_db[v["id"]] = {
                "id": v["id"],
                "summary": "stub",
                "database_specific": {"severity": "LOW"},
                "affected": [],
                "aliases": [],
            }
    vuln_db["GHSA-35jh-r3h4-6jhm"] = _VULN_LODASH_CMDINJ
    vuln_db["GHSA-cph5-m8f7-6c5x"] = _VULN_AXIOS

    mock_post, mock_get = _mock_from_fixtures(
        batch_response=_BATCH_3PKG, vuln_db=vuln_db
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)
    by_pkg = {(f.package_name, f.vuln_id) for f in report.findings}
    # Real IDs from the captured batch:
    assert ("lodash", "GHSA-35jh-r3h4-6jhm") in by_pkg
    assert ("axios", "GHSA-cph5-m8f7-6c5x") in by_pkg
    # react has no entries in the real batch (third result is the empty {}).
    assert not any(f.package_name == "react" for f in report.findings)


def test_audit_allowlist_excludes_by_primary_id(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.15"}})
    batch = {"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]}
    mock_post, mock_get = _mock_from_fixtures(
        batch_response=batch, vuln_db={"GHSA-35jh-r3h4-6jhm": _VULN_LODASH_CMDINJ}
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf, allow_ids=["GHSA-35JH-R3H4-6JHM"])
    assert report.clean


def test_audit_allowlist_excludes_by_cve_alias(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.15"}})
    batch = {"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]}
    mock_post, mock_get = _mock_from_fixtures(
        batch_response=batch, vuln_db={"GHSA-35jh-r3h4-6jhm": _VULN_LODASH_CMDINJ}
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf, allow_ids=["cve-2021-23337"])
    assert report.clean


def test_audit_severity_floor_drops_below_threshold(tmp_path: Path) -> None:
    # Use real CRITICAL lodash fixture (prototype pollution) + a synthetic
    # MODERATE record for axios to validate the floor cleanly.
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.10"},
            "node_modules/axios": {"version": "0.21.0"},
        },
    )
    batch = {
        "results": [
            {"vulns": [{"id": "GHSA-jf85-cpcp-j695"}]},  # CRITICAL (real)
            {"vulns": [{"id": "moderate-only"}]},  # MODERATE (stub)
        ]
    }
    vuln_db = {
        "GHSA-jf85-cpcp-j695": _VULN_LODASH_PROTO,
        "moderate-only": {
            "id": "moderate-only",
            "summary": "moderate stub",
            "database_specific": {"severity": "MODERATE"},
            "affected": [],
            "aliases": [],
        },
    }
    mock_post, mock_get = _mock_from_fixtures(batch_response=batch, vuln_db=vuln_db)
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf, severity_floor="HIGH")
    assert len(report.findings) == 1
    assert report.findings[0].package_name == "lodash"


def test_audit_dedupes_unique_vuln_detail_fetches(tmp_path: Path) -> None:
    # Same vuln ID flagged for two packages — should only fetch detail once.
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/b": {"version": "1.0.0"},
        },
    )
    fetched: list[str] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {
            "results": [
                {"vulns": [{"id": "GHSA-x"}]},
                {"vulns": [{"id": "GHSA-x"}]},
            ]
        }

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        fetched.append(url)
        return {
            "id": "GHSA-x",
            "summary": "shared",
            "database_specific": {"severity": "HIGH"},
            "affected": [],
            "aliases": [],
        }

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)
    assert len(fetched) == 1
    assert len(report.findings) == 2


def test_audit_network_error_surfaces_cleanly(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/x": {"version": "1.0.0"}})

    def boom(url: str, body: dict[str, Any], timeout: int, retries: int = 2) -> dict[str, Any]:
        raise urllib.error.URLError("network unreachable")

    with patch("codeartifact_shield.audit._http_post_json", boom):
        report = audit_lockfile(lf)
    assert not report.clean
    assert report.network_error is not None
    assert "network unreachable" in report.network_error
    assert report.findings == []


def test_audit_skips_workspace_link_entries(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/some-lib": {"version": "1.0.0"},
            "node_modules/@my/workspace-pkg": {"link": True, "resolved": "apps/foo"},
        },
    )
    posted_queries: list[dict[str, Any]] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        posted_queries.extend(body["queries"])
        return {"results": [{}]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        audit_lockfile(lf)
    assert len(posted_queries) == 1
    assert posted_queries[0]["package"]["name"] == "some-lib"


def test_audit_dedupes_same_name_version_across_lockfile(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/parent/node_modules/foo": {"version": "1.0.0"},
        },
    )
    posted_queries: list[dict[str, Any]] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        posted_queries.extend(body["queries"])
        return {"results": [{}]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        audit_lockfile(lf)
    assert len(posted_queries) == 1


def test_audit_empty_lockfile_clean(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {})
    report = audit_lockfile(lf)
    assert report.clean
    assert report.total_checked == 0


# ---------------------------------------------------------------------------
# load_whitelist_file — auditjs / plain-array support
# ---------------------------------------------------------------------------


def test_load_whitelist_file_auditjs_format(tmp_path: Path) -> None:
    f = tmp_path / "auditjs.json"
    f.write_text(
        json.dumps(
            {
                "affected": [{"coordinates": "pkg:npm/ip@2.0.0", "vulnerabilities": []}],
                "ignore": [
                    {"id": "CVE-2023-42282"},
                    {"id": "CVE-2024-21540"},
                ],
            }
        )
    )
    ids = load_whitelist_file(f)
    assert ids == ["CVE-2023-42282", "CVE-2024-21540"]


def test_load_whitelist_file_plain_array(tmp_path: Path) -> None:
    f = tmp_path / "whitelist.json"
    f.write_text(json.dumps(["GHSA-aaaa-bbbb-cccc", "CVE-2024-99999"]))
    ids = load_whitelist_file(f)
    assert ids == ["GHSA-aaaa-bbbb-cccc", "CVE-2024-99999"]


def test_load_whitelist_file_rejects_unknown_shape(tmp_path: Path) -> None:
    import pytest

    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"random_top_level": "nothing useful"}))
    with pytest.raises(ValueError, match="unrecognised whitelist format"):
        load_whitelist_file(f)


def test_load_whitelist_file_rejects_malformed_ignore_entries(tmp_path: Path) -> None:
    import pytest

    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"ignore": [{"not_id": "x"}]}))
    with pytest.raises(ValueError, match="must be an object with a string `id`"):
        load_whitelist_file(f)


def test_audit_whitelist_file_suppresses_finding(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.15"}})
    wl = tmp_path / "auditjs.json"
    wl.write_text(json.dumps({"ignore": [{"id": "CVE-2021-23337"}]}))
    batch = {"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]}
    mock_post, mock_get = _mock_from_fixtures(
        batch_response=batch,
        vuln_db={"GHSA-35jh-r3h4-6jhm": _VULN_LODASH_CMDINJ},
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf, whitelist_file=wl)
    assert report.clean  # suppressed by CVE alias from whitelist file


def test_audit_whitelist_file_and_allow_ids_merge(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/axios": {"version": "0.21.0"},
        },
    )
    wl = tmp_path / "auditjs.json"
    wl.write_text(json.dumps({"ignore": [{"id": "GHSA-35jh-r3h4-6jhm"}]}))
    batch = {
        "results": [
            {"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]},
            {"vulns": [{"id": "GHSA-cph5-m8f7-6c5x"}]},
        ]
    }
    mock_post, mock_get = _mock_from_fixtures(
        batch_response=batch,
        vuln_db={
            "GHSA-35jh-r3h4-6jhm": _VULN_LODASH_CMDINJ,
            "GHSA-cph5-m8f7-6c5x": _VULN_AXIOS,
        },
    )
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        # Whitelist suppresses lodash; --allow suppresses axios.
        report = audit_lockfile(
            lf, allow_ids=["GHSA-cph5-m8f7-6c5x"], whitelist_file=wl
        )
    assert report.clean


# ---------------------------------------------------------------------------
# audit --probe-private — close the silent gap for CodeArtifact-only deps
# ---------------------------------------------------------------------------


def test_audit_probe_private_flags_packages_missing_from_public_npm(
    tmp_path: Path,
) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@my/internal-only": {"version": "1.0.0"},
        },
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        # Neither package has OSV findings (lodash@4.17.21 is the latest
        # patched version; @my/internal-only is private).
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        # Public npm registry: lodash exists, internal-only is 404.
        if url.endswith("/lodash"):
            return 200
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf, probe_registry="https://registry.npmjs.org"
        )
    # Secure-by-default: package not in OSV AND not on public npm → HIGH.
    assert any(n == "@my/internal-only" for n, _ in report.unaudited_blocked)
    assert all(n != "@my/internal-only" for n, _ in report.unaudited_allowed)
    assert all(n != "lodash" for n, _ in report.unaudited_blocked)
    assert not report.clean


def test_audit_probe_private_default_off_no_extra_requests(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    get_calls: list[str] = []

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        get_calls.append(url)
        return {}

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)  # probe_registry=None
    assert get_calls == []  # no probes by default
    assert report.unaudited_blocked == []
    assert report.unaudited_allowed == []


def test_audit_uses_name_field_for_npm_aliases(tmp_path: Path) -> None:
    # Aliased entry: key is `node_modules/string-width-cjs` but the
    # canonical npm name (in `name`) is `string-width`. cas must query
    # OSV with the canonical name, not the alias, or it silently misses
    # vulns (OSV doesn't index alias names).
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/string-width-cjs": {
                "name": "string-width",
                "version": "4.2.3",
            },
        },
    )
    queried_names: list[str] = []

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        queried_names.extend([q["package"]["name"] for q in body["queries"]])
        return {"results": [{}]}

    with patch("codeartifact_shield.audit._http_post_json", mock_batch):
        audit_lockfile(lf)
    assert queried_names == ["string-width"]  # NOT "string-width-cjs"


def test_audit_ca_endpoint_demotes_unaudited_to_info(tmp_path: Path) -> None:
    # v0.7.1: when a package is 404 on the public probe registry but
    # FOUND on a configured CA endpoint, treat as trusted-private (INFO),
    # not HIGH. Mirrors cooldown's CA-fallback model.
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {"node_modules/@my/internal": {"version": "1.0.0"}},
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}  # no OSV findings

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if "registry.npmjs.org" in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
        if "codeartifact" in url:
            assert auth_header == "Bearer fake-ca-token"
            return 200
        raise AssertionError(f"unexpected URL: {url}")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca-12345.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo",
            auth_header="Bearer fake-ca-token",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert any(n == "@my/internal" for n, _ in report.unaudited_allowed)
    assert all(n != "@my/internal" for n, _ in report.unaudited_blocked)
    assert report.clean  # build does not fail


def test_audit_404_on_all_endpoints_stays_blocked(tmp_path: Path) -> None:
    # Package 404s on both public probe AND CA endpoint → HIGH, fails build.
    # This is the typo / lockfile-tampering signal.
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path, {"node_modules/lodahs": {"version": "1.0.0"}}
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert any(n == "lodahs" for n, _ in report.unaudited_blocked)
    assert all(n != "lodahs" for n, _ in report.unaudited_allowed)
    assert not report.clean


def test_audit_only_ca_no_public_probe(tmp_path: Path) -> None:
    # CA-only project: no public probe. Trusted-on-CA → INFO; 404 → HIGH.
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {
            "node_modules/@my/legit": {"version": "1.0.0"},
            "node_modules/@my/typo": {"version": "1.0.0"},
        },
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if url.endswith("@my%2Flegit"):
            return 200
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            # No probe_registry — CA endpoint is the only trust source.
            trusted_endpoints=trusted,
        )
    assert any(n == "@my/legit" for n, _ in report.unaudited_allowed)
    assert any(n == "@my/typo" for n, _ in report.unaudited_blocked)
    assert not report.clean


def test_audit_backward_compat_no_ca_endpoints(tmp_path: Path) -> None:
    # When trusted_endpoints is empty/None (v0.7.0 caller pattern), audit
    # must behave identically: 404 on probe-private → HIGH unaudited_blocked.
    lf = _write_lock(
        tmp_path, {"node_modules/@my/internal-only": {"version": "1.0.0"}}
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf, probe_registry="https://registry.npmjs.org"
        )
    assert any(n == "@my/internal-only" for n, _ in report.unaudited_blocked)
    assert not report.clean


def test_audit_allow_private_demotes_unaudited_to_info(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/@org/typo": {"version": "1.0.0"},
            "node_modules/@org/legit-internal": {"version": "1.0.0"},
        },
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            allow_unaudited=["@org/legit-internal"],
        )
    assert any(n == "@org/legit-internal" for n, _ in report.unaudited_allowed)
    assert any(n == "@org/typo" for n, _ in report.unaudited_blocked)
    assert not report.clean


def test_audit_probe_parallel_dispatches_concurrently(tmp_path: Path) -> None:
    """Performance: with N packages and 50ms simulated per-probe latency,
    serial budget is N*50ms. Parallel with 20 workers must finish in
    well under a quarter of that. Verifies the executor is actually
    parallelising the probe phase.
    """
    import time

    n_packages = 40
    pkgs = {
        f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(n_packages)
    }
    lf = _write_lock(tmp_path, pkgs)

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{} for _ in body["queries"]]}

    def slow_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        time.sleep(0.05)
        return 200

    start = time.monotonic()
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", slow_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            max_workers=20,
        )
    elapsed = time.monotonic() - start

    serial_budget_seconds = n_packages * 0.05
    assert elapsed < serial_budget_seconds / 3, (
        f"probe parallelism broken: {elapsed:.2f}s elapsed, "
        f"serial budget {serial_budget_seconds:.2f}s"
    )
    # All packages found on probe-registry → no findings.
    assert report.clean


def test_audit_probe_serial_when_max_workers_one(tmp_path: Path) -> None:
    import time

    pkgs = {
        f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(5)
    }
    lf = _write_lock(tmp_path, pkgs)

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{} for _ in body["queries"]]}

    def slow_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        time.sleep(0.05)
        return 200

    start = time.monotonic()
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", slow_head
    ):
        audit_lockfile(
            lf, probe_registry="https://registry.npmjs.org", max_workers=1
        )
    elapsed = time.monotonic() - start
    # 5 * 50ms = 250ms expected serial. Allow some scheduling slack.
    assert elapsed >= 0.20, f"serial mode unexpectedly fast: {elapsed:.2f}s"


def test_audit_probe_cache_hit_avoids_http(tmp_path: Path) -> None:
    """When the probe cache has both packages cached, no HTTP HEAD is issued."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@my/internal": {"version": "1.0.0"},
        },
    )
    cache_file = tmp_path / "probe-cache.json"
    cache_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": {
                    "probe-registry": {
                        "lodash": "found",
                        "@my/internal": "404",
                    }
                },
            }
        )
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        raise AssertionError("HEAD must not be called on full cache hit")

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            probe_cache_path=cache_file,
        )
    # lodash found → no finding; @my/internal 404 → blocked.
    assert any(n == "@my/internal" for n, _ in report.unaudited_blocked)


def test_audit_probe_cache_miss_persists(tmp_path: Path) -> None:
    """A first run with no cache writes results for both 200s and 404s."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@my/internal": {"version": "1.0.0"},
        },
    )
    cache_file = tmp_path / "probe-cache.json"

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if url.endswith("/lodash"):
            return 200
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            probe_cache_path=cache_file,
        )
    persisted = json.loads(cache_file.read_text())
    assert persisted["schema_version"] == 1
    assert persisted["entries"]["probe-registry"]["lodash"] == "found"
    assert persisted["entries"]["probe-registry"]["@my/internal"] == "404"


def test_audit_corrupt_probe_cache_falls_back(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    cache_file = tmp_path / "probe-cache.json"
    cache_file.write_text("{not valid json")

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        return 200

    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            probe_cache_path=cache_file,
        )
    assert report.clean
    # Cache re-written cleanly.
    persisted = json.loads(cache_file.read_text())
    assert persisted["schema_version"] == 1


def test_audit_real_auditjs_fixture_loads(tmp_path: Path) -> None:
    # Sanity check that load_whitelist_file accepts the actual production
    # auditjs.json shape (captured as a fixture).
    real = _load_fixture("auditjs-sample.json")
    f = tmp_path / "auditjs.json"
    f.write_text(json.dumps(real))
    ids = load_whitelist_file(f)
    # Every entry must be a non-empty CVE/GHSA-shaped string.
    assert ids
    assert all(isinstance(i, str) and i for i in ids)
    assert "CVE-2023-42282" in ids


# ---------------------------------------------------------------------------
# Resilient fallthrough — a probe-registry error must not short-circuit
# the trusted-endpoint fallback. Regression guard for the v0.7.1 CI failure
# where a single probe-registry URLError aborted the whole audit.
# ---------------------------------------------------------------------------


def test_audit_probe_error_but_ca_resolves_is_clean(tmp_path: Path) -> None:
    """probe-registry errors (URLError), CA endpoint returns 200 for the
    same private package → result is clean (INFO-level unaudited_allowed),
    NOT a build failure."""
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {"node_modules/@example/private-pkg": {"version": "1.0.0"}},
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}  # no OSV findings

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if "registry.npmjs.org" in url:
            raise urllib.error.URLError("network unreachable")
        if "codeartifact" in url:
            return 200
        raise AssertionError(f"unexpected URL: {url}")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert any(n == "@example/private-pkg" for n, _ in report.unaudited_allowed)
    assert report.network_error is None
    assert report.unaudited_blocked == []
    assert report.clean


def test_audit_probe_error_and_ca_error_surfaces_network_error(
    tmp_path: Path,
) -> None:
    """If BOTH endpoints error and the package is never resolved, surface
    the first probe error — don't silently treat as known-blocked."""
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {"node_modules/@my/pkg": {"version": "1.0.0"}},
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        raise urllib.error.URLError("network unreachable")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert report.network_error is not None
    assert "@my/pkg" in report.network_error
    assert "probe-registry" in report.network_error
    assert not report.clean


def test_audit_probe_error_and_ca_404_surfaces_network_error(
    tmp_path: Path,
) -> None:
    """probe-registry errors, CA returns 404 → we still didn't definitively
    resolve the name (the probe error means we can't say whether it's a
    real 404 across the board). Surface the first error."""
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {"node_modules/maybe-typo": {"version": "1.0.0"}},
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if "registry.npmjs.org" in url:
            raise urllib.error.URLError("network unreachable")
        if "codeartifact" in url:
            raise urllib.error.HTTPError(
                url, 404, "Not Found", {}, None  # type: ignore[arg-type]
            )
        raise AssertionError(f"unexpected URL: {url}")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert report.network_error is not None
    assert "maybe-typo" in report.network_error
    assert not report.clean


def test_audit_probe_404_and_ca_error_surfaces_network_error(
    tmp_path: Path,
) -> None:
    """Symmetric to the above: probe-registry clean-404, CA errors. The CA
    error means we can't trust the 404 as authoritative. Surface the error."""
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {"node_modules/@my/pkg": {"version": "1.0.0"}},
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        if "registry.npmjs.org" in url:
            raise urllib.error.HTTPError(
                url, 404, "Not Found", {}, None  # type: ignore[arg-type]
            )
        if "codeartifact" in url:
            raise urllib.error.URLError("transient")
        raise AssertionError(f"unexpected URL: {url}")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    assert report.network_error is not None
    assert "@my/pkg" in report.network_error
    assert "my-ca" in report.network_error
    assert not report.clean


def test_audit_probe_error_one_pkg_other_pkg_resolves_correctly(
    tmp_path: Path,
) -> None:
    """Two packages: one errors+resolves on CA (should be INFO), the other
    errors+404s on CA (should surface network_error). Validates the per-name
    outcome tracking actually distinguishes between them."""
    from codeartifact_shield.cooldown import RegistryEndpoint

    lf = _write_lock(
        tmp_path,
        {
            "node_modules/@my/legit": {"version": "1.0.0"},
            "node_modules/@my/sketchy": {"version": "1.0.0"},
        },
    )

    def mock_batch(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{}, {}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        # Both packages error on probe-registry.
        if "registry.npmjs.org" in url:
            raise urllib.error.URLError("transient")
        # On CA: @my/legit resolves, @my/sketchy errors too.
        if "codeartifact" in url:
            if "legit" in url:
                return 200
            raise urllib.error.URLError("transient")
        raise AssertionError(f"unexpected URL: {url}")

    trusted = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.audit._http_post_json", mock_batch), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(
            lf,
            probe_registry="https://registry.npmjs.org",
            trusted_endpoints=trusted,
        )
    # @my/sketchy never resolved AND errored — should surface as network_error
    # (early return prevents @my/legit from showing up in unaudited_allowed,
    # but that's OK: the build is failing on the more serious finding).
    assert report.network_error is not None
    assert "@my/sketchy" in report.network_error
    assert not report.clean


# ---------------------------------------------------------------------------
# Multi-endpoint OSV — v0.8.0
# ---------------------------------------------------------------------------


def test_audit_default_endpoint_is_osv_dev(tmp_path: Path) -> None:
    """Backward compat — default `osv_endpoints` points at OSV.dev only,
    and the URL passed to `_http_post_json` reflects that."""
    lf = _write_lock(tmp_path, {"node_modules/react": {"version": "18.3.1"}})
    captured_urls: list[str] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        captured_urls.append(url)
        return {"results": [{}]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise AssertionError("no vuln details expected")

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf)
    assert report.clean
    assert captured_urls == ["https://api.osv.dev/v1/querybatch"]


def test_audit_dispatches_batch_to_every_configured_endpoint(tmp_path: Path) -> None:
    """With two endpoints configured, the batch URL on each must be POSTed."""
    lf = _write_lock(tmp_path, {"node_modules/react": {"version": "18.3.1"}})
    captured_urls: list[str] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        captured_urls.append(url)
        return {"results": [{}]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise AssertionError("no vuln details expected")

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        audit_lockfile(
            lf,
            osv_endpoints=(
                "https://api.osv.dev",
                "https://cas-server.example.internal",
            ),
        )
    assert sorted(captured_urls) == sorted(
        [
            "https://api.osv.dev/v1/querybatch",
            "https://cas-server.example.internal/v1/querybatch",
        ]
    )


def test_audit_unions_findings_from_two_endpoints(tmp_path: Path) -> None:
    """One endpoint sees GHSA-X for axios, the other sees EX-Y. Both surface,
    deduped only if they share aliases (this test: they don't)."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        if "osv.dev" in url:
            return {"results": [{"vulns": [{"id": "GHSA-public-x"}]}]}
        if "internal" in url:
            return {"results": [{"vulns": [{"id": "EX-2026-0009"}]}]}
        raise AssertionError(f"unexpected URL: {url}")

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        vid = url.rsplit("/", 1)[-1]
        if vid == "GHSA-public-x":
            return {
                "id": "GHSA-public-x",
                "summary": "public ssrf",
                "database_specific": {"severity": "HIGH"},
            }
        if vid == "EX-2026-0009":
            return {
                "id": "EX-2026-0009",
                "summary": "internal SOC finding",
                "database_specific": {"severity": "CRITICAL"},
            }
        raise AssertionError(f"unexpected vuln URL: {url}")

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://api.osv.dev",
                "https://cas-server.internal",
            ),
        )
    assert len(report.findings) == 2
    vids = sorted(f.vuln_id for f in report.findings)
    assert vids == ["EX-2026-0009", "GHSA-public-x"]


def test_audit_dedupes_cross_endpoint_same_vuln_via_aliases(tmp_path: Path) -> None:
    """The mini-Shai-Hulud-style case: cas-server publishes the TC-namespaced
    advisory listing GHSA-X as an alias; OSV.dev later returns GHSA-X
    directly. Both reach cas, but cas must emit ONE finding with merged
    aliases."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        if "osv.dev" in url:
            return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]}]}
        if "internal" in url:
            return {"results": [{"vulns": [{"id": "EX-2026-0099"}]}]}
        raise AssertionError(url)

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        vid = url.rsplit("/", 1)[-1]
        if vid == "GHSA-aaaa-bbbb-cccc":
            return {
                "id": "GHSA-aaaa-bbbb-cccc",
                "summary": "axios SSRF (public GHSA wording)",
                "database_specific": {"severity": "HIGH"},
            }
        if vid == "EX-2026-0099":
            return {
                "id": "EX-2026-0099",
                "aliases": ["GHSA-aaaa-bbbb-cccc"],
                "summary": "axios SSRF (internal SOC wording)",
                "database_specific": {"severity": "CRITICAL"},
            }
        raise AssertionError(url)

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://api.osv.dev",
                "https://cas-server.internal",
            ),
        )
    assert len(report.findings) == 1, "alias-overlap must collapse to one finding"
    f = report.findings[0]
    # Canonical id is the lex-smallest member of the group.
    assert f.vuln_id == "EX-2026-0099"
    # Merged aliases include the partner id.
    assert "GHSA-aaaa-bbbb-cccc" in f.aliases
    # Severity merge takes the maximum across the group.
    assert f.severity == "CRITICAL"


def test_audit_one_endpoint_down_others_keep_serving(tmp_path: Path) -> None:
    """If one configured endpoint errors but at least one answered, the
    build must NOT fail — matches v0.7.2 resilient-fallthrough semantics."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        if "broken" in url:
            raise urllib.error.URLError("network unreachable")
        return {"results": [{"vulns": [{"id": "EX-2026-0001"}]}]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {
            "id": "EX-2026-0001",
            "summary": "internal SOC finding",
            "database_specific": {"severity": "HIGH"},
        }

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://broken.example",
                "https://working.example",
            ),
        )
    assert report.network_error is None
    assert len(report.findings) == 1


def test_audit_all_endpoints_down_surfaces_network_error(tmp_path: Path) -> None:
    """All endpoints failing → hard network_error like the v0.7.x model."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.URLError("everything down")

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://broken-1.example",
                "https://broken-2.example",
            ),
        )
    assert report.network_error is not None
    assert "all endpoints" in report.network_error.lower()


def test_audit_finding_source_attribution(tmp_path: Path) -> None:
    """Each finding records which endpoint surfaced it (the canonical's
    origin). When two endpoints both return the canonical, the
    earlier-listed endpoint wins."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        if "primary" in url:
            return {"results": [{"vulns": [{"id": "EX-2026-0001"}]}]}
        if "secondary" in url:
            return {"results": [{"vulns": [{"id": "EX-2026-0001"}]}]}
        raise AssertionError(url)

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {"id": "EX-2026-0001", "database_specific": {"severity": "HIGH"}}

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://primary.example",
                "https://secondary.example",
            ),
        )
    assert len(report.findings) == 1
    assert report.findings[0].source == "https://primary.example"


def test_audit_detail_fetch_falls_back_when_primary_endpoint_fails_after_batch(
    tmp_path: Path,
) -> None:
    """An endpoint can succeed at the batch step but fail at the detail
    step (transient). cas must try other endpoints that returned the same
    id before giving up."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})
    detail_attempts: list[str] = []

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{"vulns": [{"id": "EX-2026-0001"}]}]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        detail_attempts.append(url)
        if "flaky" in url:
            raise urllib.error.URLError("detail flake")
        return {"id": "EX-2026-0001", "database_specific": {"severity": "HIGH"}}

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=(
                "https://flaky.example",
                "https://stable.example",
            ),
        )
    assert report.network_error is None
    assert len(report.findings) == 1
    # Detail-fetch tried both endpoints, in order.
    assert any("flaky" in u for u in detail_attempts)
    assert any("stable" in u for u in detail_attempts)


def test_audit_canonical_id_is_lex_smallest_in_alias_group(tmp_path: Path) -> None:
    """If a group has GHSA-x, EX-y, and CVE-z all linked by aliases, the
    canonical id is the lex-smallest — CVE-z. Forms a deterministic
    contract for downstream allowlist matching."""
    lf = _write_lock(tmp_path, {"node_modules/axios": {"version": "1.6.7"}})

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        if "a.example" in url:
            return {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}]}
        if "b.example" in url:
            return {"results": [{"vulns": [{"id": "EX-2026-9999"}]}]}
        raise AssertionError(url)

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        vid = url.rsplit("/", 1)[-1]
        if vid == "GHSA-xxxx":
            return {"id": "GHSA-xxxx", "aliases": ["CVE-2026-0001"]}
        if vid == "EX-2026-9999":
            return {"id": "EX-2026-9999", "aliases": ["CVE-2026-0001"]}
        raise AssertionError(url)

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(
            lf,
            osv_endpoints=("https://a.example", "https://b.example"),
        )
    assert len(report.findings) == 1
    f = report.findings[0]
    # Both records carry the same CVE alias → grouped. The lex-smallest of
    # the two PRIMARY ids ("EX-2026-9999" < "GHSA-xxxx") is canonical.
    assert f.vuln_id == "EX-2026-9999"
    assert "GHSA-xxxx" in f.aliases
    assert "CVE-2026-0001" in f.aliases


def test_audit_dispatches_endpoint_chunk_cross_product_in_parallel(
    tmp_path: Path,
) -> None:
    """Performance contract: with E endpoints × C chunks, wall time must be
    bounded by max(per-call latency), not E·C·latency. Sleep-injected mock
    proves the parallelism."""
    import threading
    import time

    # 3 endpoints × 3 chunks (3000 packages / OSV_BATCH_SIZE=1000) = 9 calls.
    pkg_count = 3000
    pkgs = {
        f"node_modules/pkg-{i:04d}": {"version": "1.0.0"} for i in range(pkg_count)
    }
    lf = _write_lock(tmp_path, pkgs)

    in_flight = 0
    peak = 0
    lock = threading.Lock()

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        nonlocal in_flight, peak
        with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        time.sleep(0.1)  # simulate network latency
        with lock:
            in_flight -= 1
        chunk_size = len(body["queries"])
        return {"results": [{} for _ in range(chunk_size)]}

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise AssertionError("no vuln details expected")

    endpoints = (
        "https://ep1.example",
        "https://ep2.example",
        "https://ep3.example",
    )
    start = time.perf_counter()
    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_get_json", mock_get
    ):
        report = audit_lockfile(lf, osv_endpoints=endpoints)
    elapsed = time.perf_counter() - start
    assert report.clean
    # 9 calls × 100ms each = 900ms if serial. Parallelised, should be <300ms.
    assert elapsed < 0.5, f"expected <500ms wall time, got {elapsed*1000:.0f}ms"
    # At least 6 of the 9 calls should overlap (max workers allowing).
    assert peak >= 6, f"expected peak ≥6 in-flight calls, got {peak}"
