"""Deno gate behaviour — drift, sri, registry, scripts, audit, cooldown, trust, pin."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.audit import audit_lockfile
from codeartifact_shield.cooldown import check_cooldown
from codeartifact_shield.drift import check_deno_drift
from codeartifact_shield.lockfiles import LockFormat
from codeartifact_shield.pins import check_deno_pinning
from codeartifact_shield.registry import check_registry
from codeartifact_shield.scripts import check_install_scripts
from codeartifact_shield.sri import verify_lockfile

FIXTURES = Path(__file__).parent / "fixtures" / "deno"


def _stage(tmp_path: Path, lock: str = "lock-v4.json", manifest: bool = True) -> Path:
    shutil.copy(FIXTURES / lock, tmp_path / "deno.lock")
    if manifest:
        shutil.copy(FIXTURES / "deno.json", tmp_path / "deno.json")
    return tmp_path / "deno.lock"


# ---------------------------------------------------------------------------
# sri verify — npm sha512 + jsr sha256 + remote sha256 all count
# ---------------------------------------------------------------------------


def test_sri_verify_full_coverage() -> None:
    covered, total = verify_lockfile(FIXTURES / "lock-v4.json", LockFormat.DENO)
    assert covered == total == 5


def test_sri_verify_missing_integrity_lowers(tmp_path: Path) -> None:
    p = tmp_path / "deno.lock"
    p.write_text(
        json.dumps(
            {
                "version": "4",
                "npm": {
                    "a@1.0.0": {"integrity": "sha512-" + "a" * 86 + "=="},
                    "b@1.0.0": {},
                },
            }
        )
    )
    assert verify_lockfile(p, LockFormat.DENO) == (1, 2)


# ---------------------------------------------------------------------------
# registry — remote host gating + cross-host redirects
# ---------------------------------------------------------------------------


def test_registry_remote_host_gated_and_implied() -> None:
    report = check_registry(FIXTURES / "lock-v4.json", allowed_hosts=None)
    # npm + jsr → registry_implied INFO; the remote URL is host-gated.
    assert len(report.registry_implied) == 4
    assert report.by_host == {"deno.land": 1}
    assert report.leaked == []


def test_registry_remote_leak_when_host_not_allowed() -> None:
    report = check_registry(
        FIXTURES / "lock-v4.json", allowed_hosts=["example.com"]
    )
    assert report.leaked == [
        ("https://deno.land/std@0.220.1/assert/assert.ts", "deno.land")
    ]


def test_registry_cross_host_redirect_flagged() -> None:
    report = check_registry(FIXTURES / "lock-v5.json", allowed_hosts=None)
    assert report.redirect_cross_host == [
        ("https://deno.land/x/foo/mod.ts", "https://cdn.other-host.example/foo/mod.ts")
    ]


def test_registry_same_host_redirect_not_flagged() -> None:
    report = check_registry(FIXTURES / "lock-v4.json", allowed_hosts=None)
    assert report.redirect_cross_host == []


# ---------------------------------------------------------------------------
# scripts — clean by design, never fails
# ---------------------------------------------------------------------------


def test_scripts_deno_never_fails() -> None:
    report = check_install_scripts(FIXTURES / "lock-v4.json")
    assert report.clean
    assert report.flagged == []
    assert report.script_info_available is False


# ---------------------------------------------------------------------------
# drift — direct-only + orphan
# ---------------------------------------------------------------------------


def test_drift_clean_with_ranges(tmp_path: Path) -> None:
    _stage(tmp_path)
    report = check_deno_drift(tmp_path, ranges=True)
    assert report.clean


def test_drift_missing_specifier(tmp_path: Path) -> None:
    _stage(tmp_path, manifest=False)
    (tmp_path / "deno.json").write_text(
        json.dumps({"imports": {"missing": "npm:missing@^9"}})
    )
    report = check_deno_drift(tmp_path, ranges=True)
    assert ("imports", "npm:missing@^9", "npm:missing@^9", "MISSING") in report.mismatches


def test_drift_orphan_detection(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "deno.json", tmp_path / "deno.json")
    lock = json.loads((FIXTURES / "lock-v4.json").read_text())
    lock["npm"]["orphan@9.9.9"] = {"integrity": "sha512-" + "z" * 86 + "=="}
    (tmp_path / "deno.lock").write_text(json.dumps(lock))
    report = check_deno_drift(tmp_path, ranges=True)
    assert report.orphan_entries == ["orphan@9.9.9"]


# ---------------------------------------------------------------------------
# pin — deno imports mode
# ---------------------------------------------------------------------------


def test_pin_flags_ranges_and_unversioned(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "deno.json", tmp_path / "deno.json")
    report = check_deno_pinning(tmp_path)
    flagged = {f.package_name: f.kind for f in report.flagged}
    # npm/jsr ranges flagged; versioned https import (foo@1.2.3) is OK.
    assert flagged == {"chalk": "range", "@std/assert": "range"}


def test_pin_unversioned_https_flagged(tmp_path: Path) -> None:
    (tmp_path / "deno.json").write_text(
        json.dumps(
            {
                "imports": {
                    "pinned": "https://deno.land/x/foo@1.2.3/mod.ts",
                    "floating": "https://example.com/mod.ts",
                }
            }
        )
    )
    report = check_deno_pinning(tmp_path)
    assert {f.package_name: f.kind for f in report.flagged} == {
        "floating": "remote_unversioned"
    }


def test_pin_allowlist(tmp_path: Path) -> None:
    shutil.copy(FIXTURES / "deno.json", tmp_path / "deno.json")
    report = check_deno_pinning(tmp_path, allowed=["chalk", "@std/assert"])
    assert report.flagged == []
    assert {f.package_name for f in report.allowed} == {"chalk", "@std/assert"}


# ---------------------------------------------------------------------------
# audit — npm → OSV, jsr → INFO unaudited_jsr, remote → skipped
# ---------------------------------------------------------------------------


def test_audit_npm_only_queried_jsr_reported() -> None:
    asked: set[tuple[str, str]] = set()

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        for q in body.get("queries", []):
            asked.add((q["package"]["name"], q["package"]["ecosystem"]))
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        report = audit_lockfile(FIXTURES / "lock-v4.json")
    assert asked == {("chalk", "npm"), ("ansi-styles", "npm")}
    assert set(report.unaudited_jsr) == {("@std/assert", "1.0.0"), ("@std/internal", "1.0.0")}
    assert report.remote_skipped == 1
    assert report.clean  # jsr is INFO by default


def test_audit_fail_on_unaudited_jsr() -> None:
    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        report = audit_lockfile(
            FIXTURES / "lock-v4.json", fail_on_unaudited_jsr=True
        )
    assert not report.clean


# ---------------------------------------------------------------------------
# cooldown — npm via npm registry, jsr via api.jsr.io, remote skipped
# ---------------------------------------------------------------------------


def test_cooldown_npm_and_jsr_resolved() -> None:
    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "jsr.io" in url:
            return {
                "items": [
                    {"version": "1.0.0", "createdAt": "2020-01-01T00:00:00Z"}
                ]
            }
        return {
            "time": dict.fromkeys(
                ("5.3.0", "6.2.1"), "2020-01-01T00:00:00.000Z"
            )
        }

    with patch("codeartifact_shield.cooldown._http_get_json", mock_get):
        report = check_cooldown(FIXTURES / "lock-v4.json", min_age_days=14)
    assert report.total_checked == 4  # 2 npm + 2 jsr
    assert report.remote_skipped == 1
    assert report.clean
    assert report.jsr_unresolved == []


def test_cooldown_jsr_unresolvable_is_info(tmp_path: Path) -> None:
    p = tmp_path / "deno.lock"
    p.write_text(
        json.dumps(
            {"version": "4", "jsr": {"@std/x@1.0.0": {"integrity": "a" * 64}}}
        )
    )

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {"items": []}  # no versions → unresolvable

    with patch("codeartifact_shield.cooldown._http_get_json", mock_get):
        report = check_cooldown(p, min_age_days=14)
    assert report.jsr_unresolved == ["@std/x@1.0.0"]
    assert report.clean  # jsr unresolved is INFO, not a failure
