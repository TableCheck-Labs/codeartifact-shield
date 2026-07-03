"""Bun gate behaviour — drift, sri, registry, scripts, audit, cooldown, trust."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.audit import audit_lockfile
from codeartifact_shield.cooldown import check_cooldown
from codeartifact_shield.drift import check_bun_drift
from codeartifact_shield.lockfiles import LockFormat
from codeartifact_shield.registry import check_registry
from codeartifact_shield.scripts import check_install_scripts
from codeartifact_shield.sri import verify_lockfile

FIXTURES = Path(__file__).parent / "fixtures" / "bun"


def _stage(tmp_path: Path, lock: str) -> Path:
    dst = tmp_path / "bun.lock"
    shutil.copy(FIXTURES / lock, dst)
    return dst


# ---------------------------------------------------------------------------
# sri verify — tuple integrity; workspace/file excluded from the denominator
# ---------------------------------------------------------------------------


def test_sri_verify_full_coverage() -> None:
    # 6 sha512 entries count; linkdep (workspace) + filedep (file) are excluded.
    covered, total = verify_lockfile(FIXTURES / "bun-basic.lock", LockFormat.BUN)
    assert covered == total == 6


def test_sri_verify_missing_integrity_lowers(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,"packages":{'
        '"has":["has@1.0.0","",{},"sha512-' + "a" * 86 + '=="],'
        '"missing":["missing@1.0.0","",{}]'
        "}}"
    )
    assert verify_lockfile(p, LockFormat.BUN) == (1, 2)


# ---------------------------------------------------------------------------
# registry — explicit URLs host-gated, default registry → registry_implied
# ---------------------------------------------------------------------------


def test_registry_partial_buckets() -> None:
    report = check_registry(FIXTURES / "bun-basic.lock", allowed_hosts=None)
    implied = set(report.registry_implied)
    assert {"is-number", "is-odd", "left-pad"} <= implied
    assert report.by_host == {"npm.example.com": 1}
    assert len(report.git_sourced) == 1
    assert report.git_sourced[0][0] == "gitdep"
    assert len(report.tarball_sourced) == 1
    assert {"linkdep", "filedep"} <= set(report.file_sourced)


def test_registry_leak_when_host_not_allowed() -> None:
    report = check_registry(
        FIXTURES / "bun-basic.lock", allowed_hosts=["registry.npmjs.org"]
    )
    # scoped-registry-pkg resolves from npm.example.com → a leak.
    assert ("scoped-registry-pkg", "npm.example.com") in report.leaked


# ---------------------------------------------------------------------------
# scripts — trustedDependencies audit
# ---------------------------------------------------------------------------


def test_scripts_trusted_dependency_flagged() -> None:
    report = check_install_scripts(FIXTURES / "bun-basic.lock", allowed=["esbuild"])
    assert report.trusted_mode
    flagged = {f.package_name for f in report.flagged}
    assert flagged == {"is-odd"}
    allowed = {f.package_name for f in report.allowed}
    assert allowed == {"esbuild"}
    assert not report.clean


def test_scripts_all_trusted_allowlisted_is_clean() -> None:
    report = check_install_scripts(
        FIXTURES / "bun-basic.lock", allowed=["is-odd", "esbuild"]
    )
    assert report.clean
    assert {f.package_name for f in report.allowed} == {"is-odd", "esbuild"}


def test_scripts_flagged_version_resolved_from_lockfile() -> None:
    report = check_install_scripts(FIXTURES / "bun-basic.lock", allowed=[])
    versions = {f.package_name: f.version for f in report.flagged}
    assert versions["is-odd"] == "3.0.1"
    assert versions["esbuild"] == ""  # trusted but not resolved in this lockfile


# ---------------------------------------------------------------------------
# drift — direct + transitive + orphan
# ---------------------------------------------------------------------------


def test_drift_clean_workspace(tmp_path: Path) -> None:
    _stage(tmp_path, "bun-workspace.lock")
    report = check_bun_drift(tmp_path)
    assert report.clean


def test_drift_direct_mismatch(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,'
        '"workspaces":{"":{"name":"r","dependencies":{"left-pad":"1.3.0"}}},'
        '"packages":{"left-pad":["left-pad@1.2.0","",{},"sha512-' + "a" * 86 + '=="]}}'
    )
    report = check_bun_drift(tmp_path)
    assert ("dependencies", "left-pad", "1.3.0", "1.2.0") in report.mismatches


def test_drift_missing_direct_dep(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,'
        '"workspaces":{"":{"name":"r","dependencies":{"left-pad":"1.3.0"}}},'
        '"packages":{}}'
    )
    report = check_bun_drift(tmp_path)
    assert ("dependencies", "left-pad", "1.3.0", "MISSING") in report.mismatches


def test_drift_transitive_dangling_edge(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,'
        '"workspaces":{"":{"name":"r","dependencies":{"is-odd":"3.0.1"}}},'
        '"packages":{'
        '"is-odd":["is-odd@3.0.1","",{"dependencies":{"is-number":"^6.0.0"}},"sha512-'
        + "a" * 86
        + '=="]}}'  # is-number is never resolved → dangling
    )
    report = check_bun_drift(tmp_path)
    assert ("is-odd@3.0.1", "is-number", "^6.0.0", "MISSING") in report.transitive_mismatches


def test_drift_orphan_entry(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,'
        '"workspaces":{"":{"name":"r","dependencies":{"left-pad":"1.3.0"}}},'
        '"packages":{'
        '"left-pad":["left-pad@1.3.0","",{},"sha512-' + "a" * 86 + '=="],'
        '"sneaky":["sneaky@9.9.9","",{},"sha512-' + "b" * 86 + '=="]}}'
    )
    report = check_bun_drift(tmp_path)
    assert report.orphan_entries == ["sneaky"]


def test_drift_ranges_mode_satisfies(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text(
        '{"lockfileVersion":1,'
        '"workspaces":{"":{"name":"r","dependencies":{"lodash":"^4.17.21"}}},'
        '"packages":{"lodash":["lodash@4.18.1","",{},"sha512-' + "a" * 86 + '=="]}}'
    )
    assert check_bun_drift(tmp_path, ranges=True).clean
    # default (exact) mode flags the range as drift.
    assert not check_bun_drift(tmp_path).clean


# ---------------------------------------------------------------------------
# audit / cooldown — all bun entries are the npm ecosystem
# ---------------------------------------------------------------------------


def test_audit_queries_all_as_npm() -> None:
    asked: set[tuple[str, str]] = set()

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        for q in body.get("queries", []):
            asked.add((q["package"]["name"], q["package"]["ecosystem"]))
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        report = audit_lockfile(FIXTURES / "bun-basic.lock")
    ecosystems = {eco for _name, eco in asked}
    assert ecosystems == {"npm"}
    assert ("is-odd", "npm") in asked
    assert report.clean


def test_cooldown_uses_npm_registry(tmp_path: Path) -> None:
    _stage(tmp_path, "bun-workspace.lock")

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {
            "time": {
                "6.0.0": "2020-01-01T00:00:00.000Z",
                "3.0.1": "2020-01-01T00:00:00.000Z",
                "1.3.0": "2020-01-01T00:00:00.000Z",
            }
        }

    with patch("codeartifact_shield.cooldown._http_get_json", mock_get):
        report = check_cooldown(tmp_path / "bun.lock", min_age_days=14)
    assert report.clean
    # workspace: link entries carry no registry version → not counted.
    assert report.total_checked == 3
