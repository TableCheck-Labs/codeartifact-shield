"""pnpm gate behaviour — drift, sri verify, registry, scripts, audit, cooldown."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.audit import audit_lockfile
from codeartifact_shield.cooldown import check_cooldown
from codeartifact_shield.drift import check_pnpm_drift
from codeartifact_shield.lockfiles import LockFormat
from codeartifact_shield.registry import check_registry
from codeartifact_shield.scripts import check_install_scripts
from codeartifact_shield.sri import verify_lockfile

FIXTURES = Path(__file__).parent / "fixtures" / "pnpm"


def _stage(tmp_path: Path, fixture: str, extra: dict[str, str] | None = None) -> Path:
    shutil.copy(FIXTURES / fixture, tmp_path / "pnpm-lock.yaml")
    for name, content in (extra or {}).items():
        (tmp_path / name).write_text(content)
    return tmp_path / "pnpm-lock.yaml"


def _write_lock(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# drift
# ---------------------------------------------------------------------------


def test_drift_clean(tmp_path: Path) -> None:
    _stage(tmp_path, "lock-v9-workspace.yaml")
    report = check_pnpm_drift(tmp_path)
    assert report.clean


def test_drift_direct_mismatch(tmp_path: Path) -> None:
    _write_lock(
        tmp_path,
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      is-odd:\n"
        "        specifier: 3.0.1\n"
        "        version: 3.0.2\n"
        "packages:\n"
        "  is-odd@3.0.2:\n"
        "    resolution: {integrity: sha512-" + "a" * 86 + "==}\n"
        "snapshots:\n"
        "  is-odd@3.0.2: {}\n",
    )
    report = check_pnpm_drift(tmp_path)
    assert not report.clean
    assert report.mismatches == [("dependencies", "is-odd", "3.0.1", "3.0.2")]


def test_drift_direct_range_ok(tmp_path: Path) -> None:
    _write_lock(
        tmp_path,
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      is-odd:\n"
        "        specifier: ^3.0.0\n"
        "        version: 3.0.1\n"
        "packages:\n"
        "  is-odd@3.0.1:\n"
        "    resolution: {integrity: sha512-" + "a" * 86 + "==}\n"
        "snapshots:\n"
        "  is-odd@3.0.1: {}\n",
    )
    report = check_pnpm_drift(tmp_path, ranges=True)
    assert report.clean


def test_drift_transitive_missing_edge(tmp_path: Path) -> None:
    _write_lock(
        tmp_path,
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      is-odd:\n"
        "        specifier: 3.0.1\n"
        "        version: 3.0.1\n"
        "packages:\n"
        "  is-odd@3.0.1:\n"
        "    resolution: {integrity: sha512-" + "a" * 86 + "==}\n"
        "snapshots:\n"
        "  is-odd@3.0.1:\n"
        "    dependencies:\n"
        "      is-number: 6.0.0\n",  # is-number@6.0.0 never declared as a package
    )
    report = check_pnpm_drift(tmp_path)
    assert ("is-odd@3.0.1", "is-number", "6.0.0", "MISSING") in report.transitive_mismatches


def test_drift_orphan_entry(tmp_path: Path) -> None:
    _write_lock(
        tmp_path,
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  .:\n"
        "    dependencies:\n"
        "      is-odd:\n"
        "        specifier: 3.0.1\n"
        "        version: 3.0.1\n"
        "packages:\n"
        "  is-odd@3.0.1:\n"
        "    resolution: {integrity: sha512-" + "a" * 86 + "==}\n"
        "  orphan-pkg@9.9.9:\n"
        "    resolution: {integrity: sha512-" + "b" * 86 + "==}\n"
        "snapshots:\n"
        "  is-odd@3.0.1: {}\n"
        "  orphan-pkg@9.9.9: {}\n",
    )
    report = check_pnpm_drift(tmp_path)
    assert report.orphan_entries == ["orphan-pkg@9.9.9"]


# ---------------------------------------------------------------------------
# sri verify
# ---------------------------------------------------------------------------


def test_sri_verify_full_coverage(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v9-basic.yaml")
    covered, total = verify_lockfile(lf, LockFormat.PNPM)
    assert covered == total == 5


def test_sri_verify_missing_integrity_lowers_coverage(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  has-it@1.0.0:\n"
        "    resolution: {integrity: sha512-" + "a" * 86 + "==}\n"
        "  missing-it@1.0.0:\n"
        "    resolution: {tarball: 'https://example.com/x.tgz'}\n"
        "snapshots:\n"
        "  has-it@1.0.0: {}\n"
        "  missing-it@1.0.0: {}\n",
    )
    covered, total = verify_lockfile(lf)
    assert (covered, total) == (1, 2)


# ---------------------------------------------------------------------------
# registry
# ---------------------------------------------------------------------------


def test_registry_partial_buckets(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v6-basic.yaml")
    report = check_registry(lf, allowed_hosts=None)
    implied = set(report.registry_implied)
    assert "/is-odd@3.0.1" in implied
    assert "/native-mod@1.0.0" in implied
    assert len(report.git_sourced) == 1
    assert report.git_sourced[0][0].startswith("github.com/example/forked-dep/")
    assert report.tarball_sourced == [
        ("/@example/tarball-dep@1.0.0", "https://example.com/tarball-dep-1.0.0.tgz")
    ]
    # No explicit-registry URL entries, so nothing is host-gated / leaked.
    assert report.leaked == []


# ---------------------------------------------------------------------------
# scripts
# ---------------------------------------------------------------------------


def test_scripts_v6_flags_requires_build(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v6-basic.yaml")
    report = check_install_scripts(lf)
    assert {f.package_name for f in report.flagged} == {"native-mod"}


def test_scripts_v6_allow_demotes(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v6-basic.yaml")
    report = check_install_scripts(lf, allowed=["native-mod"])
    assert report.flagged == []
    assert {f.package_name for f in report.allowed} == {"native-mod"}


def test_scripts_v9_no_policy_fails_closed(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v9-basic.yaml")
    report = check_install_scripts(lf)
    assert report.policy_unknown is True
    assert report.script_info_available is False
    assert not report.clean


def test_scripts_v9_with_only_built_dependencies(tmp_path: Path) -> None:
    lf = _stage(
        tmp_path,
        "lock-v9-basic.yaml",
        extra={"pnpm-workspace.yaml": "onlyBuiltDependencies:\n  - react-dom\n"},
    )
    report = check_install_scripts(lf)
    assert report.policy_unknown is False
    assert {f.package_name for f in report.flagged} == {"react-dom"}
    # Allowlisting the built dep clears the finding.
    report2 = check_install_scripts(lf, allowed=["react-dom"])
    assert report2.clean


def test_scripts_v9_policy_from_package_json(tmp_path: Path) -> None:
    lf = _stage(
        tmp_path,
        "lock-v9-basic.yaml",
        extra={"package.json": '{"pnpm": {"onlyBuiltDependencies": []}}'},
    )
    report = check_install_scripts(lf)
    # An explicit empty policy is "discovered" — nothing may build → clean.
    assert report.policy_unknown is False
    assert report.clean


# ---------------------------------------------------------------------------
# audit / cooldown — (name, version) extraction against mocked HTTP
# ---------------------------------------------------------------------------


def test_cooldown_extracts_name_version(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v9-workspace.yaml")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        # Every installed pnpm package resolves cleanly (old enough).
        return {
            "time": dict.fromkeys(
                ("6.0.0", "3.0.1", "0.0.1"), "2020-01-01T00:00:00.000Z"
            )
        }

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, min_age_days=14)
    assert report.total_checked == 3
    assert report.clean


def test_audit_queries_pnpm_names(tmp_path: Path) -> None:
    lf = _stage(tmp_path, "lock-v9-workspace.yaml")
    asked: set[str] = set()

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        for q in body.get("queries", []):
            asked.add(q["package"]["name"])
            assert q["package"]["ecosystem"] == "npm"
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        report = audit_lockfile(lf)
    assert asked == {"is-number", "is-odd", "leftpad"}
    assert report.clean
