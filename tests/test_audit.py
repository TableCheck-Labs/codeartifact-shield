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

    def mock_post(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
        return batch_response

    def mock_get(url: str, timeout: int) -> dict[str, Any]:
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

    def mock_post(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
        return {
            "results": [
                {"vulns": [{"id": "GHSA-x"}]},
                {"vulns": [{"id": "GHSA-x"}]},
            ]
        }

    def mock_get(url: str, timeout: int) -> dict[str, Any]:
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

    def boom(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
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

    def mock_post(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
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

    def mock_post(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
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
