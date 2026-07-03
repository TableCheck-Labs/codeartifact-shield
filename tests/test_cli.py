"""CLI-surface tests — severity badges (G11) and structured output (G10).

These exercise the user-facing output: severity prefixes that let reviewers
prioritize, and machine-readable JSON for downstream tools (SARIF /
GitHub Code Scanning).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from codeartifact_shield.cli import main
from codeartifact_shield.trust import PROVENANCE_PREDICATE, PUBLISH_PREDICATE


def _write_lock(tmp_path: Path, packages: dict[str, dict]) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return p


def _write_pair(tmp_path: Path, pkg: dict, lock_packages: dict) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": lock_packages})
    )
    return tmp_path


# ---------------------------------------------------------------------------
# G11 — severity badges in human-readable output
# ---------------------------------------------------------------------------


def test_registry_leak_tagged_critical(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/sneaky/-/sneaky-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        [
            "registry",
            str(lf),
            "--allowed-host",
            ".d.codeartifact.us-east-1.amazonaws.com",
        ],
    )
    assert result.exit_code == 1
    assert "[CRITICAL]" in result.stderr, (
        "registry leak must be tagged CRITICAL — it's the highest-blast-radius "
        "finding (active route to untrusted bytes at install time)"
    )


def test_registry_insecure_scheme_tagged_critical(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "http://acme.d.codeartifact.us-east-1.amazonaws.com/-/sneaky-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        [
            "registry",
            str(lf),
            "--allowed-host",
            ".d.codeartifact.us-east-1.amazonaws.com",
        ],
    )
    assert result.exit_code == 1
    assert "[CRITICAL]" in result.stderr


def test_drift_orphan_tagged_high(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"lodash": "4.17.21"}},
        {
            "": {"dependencies": {"lodash": "4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://acme.d.codeartifact.us-east-1.amazonaws.com/-/sneaky.tgz",
                "integrity": "sha512-" + "a" * 86 + "==",
            },
        },
    )
    result = CliRunner().invoke(main, ["drift", str(root)])
    assert result.exit_code == 1
    assert "[HIGH]" in result.stderr, (
        "orphan lockfile entry should be tagged HIGH — strong tampering signature"
    )


def test_scripts_finding_tagged_high(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "hasInstallScript": True,
            },
        },
    )
    result = CliRunner().invoke(main, ["scripts", str(lf)])
    assert result.exit_code == 1
    assert "[HIGH]" in result.stderr


def test_sri_below_threshold_tagged_high(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/no-integrity": {
                "version": "1.0.0",
                "resolved": "https://r/no-integrity.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main, ["sri", "verify", str(lf), "--min-coverage", "100"]
    )
    assert result.exit_code == 1
    assert "[HIGH]" in result.stderr


# ---------------------------------------------------------------------------
# G10 — structured JSON output for CI consumption
# ---------------------------------------------------------------------------


def test_registry_json_output_structure(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/sneaky/-/sneaky-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        [
            "registry",
            str(lf),
            "--allowed-host",
            ".d.codeartifact.us-east-1.amazonaws.com",
            "--json",
        ],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["command"] == "registry"
    assert payload["clean"] is False
    assert "findings" in payload
    assert any(f["severity"] == "CRITICAL" for f in payload["findings"])
    assert payload["severity_counts"]["CRITICAL"] >= 1


def test_drift_json_output_orphan(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"lodash": "4.17.21"}},
        {
            "": {"dependencies": {"lodash": "4.17.21"}},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://acme.d.codeartifact.us-east-1.amazonaws.com/-/sneaky.tgz",
                "integrity": "sha512-" + "a" * 86 + "==",
            },
        },
    )
    result = CliRunner().invoke(main, ["drift", str(root), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["command"] == "drift"
    assert payload["clean"] is False
    assert any(
        f["type"] == "orphan_entry" and f["severity"] == "HIGH"
        for f in payload["findings"]
    )


def test_scripts_json_output_includes_package_name(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "2.0.0",
                "hasInstallScript": True,
            },
        },
    )
    result = CliRunner().invoke(main, ["scripts", str(lf), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["command"] == "scripts"
    finding = next(f for f in payload["findings"] if f["type"] == "install_script")
    assert finding["package"] == "sneaky"
    assert finding["version"] == "2.0.0"
    assert finding["severity"] == "HIGH"


def test_sri_json_clean_lockfile(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://r/a.tgz",
                "integrity": "sha512-" + "a" * 86 + "==",
            },
        },
    )
    result = CliRunner().invoke(main, ["sri", "verify", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["clean"] is True
    assert payload["coverage_percent"] == 100.0
    assert payload["covered"] == 1
    assert payload["total"] == 1


# ---------------------------------------------------------------------------
# v1 lockfile / structural error handling: cas drift/registry/scripts must
# emit a clean [HIGH] FAIL line, not a Python traceback. Found during an
# org-wide sweep that crashed on every npm-6-era archive repo.
# ---------------------------------------------------------------------------


def _write_v1_lockfile(tmp_path: Path) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    return p


def test_drift_emits_clean_error_on_v1_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    _write_v1_lockfile(tmp_path)
    result = CliRunner().invoke(main, ["drift", str(tmp_path)])
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "unsupported lockfileVersion" in result.stderr
    assert "[HIGH]" in result.stderr


def test_drift_v1_lockfile_json(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    _write_v1_lockfile(tmp_path)
    result = CliRunner().invoke(main, ["drift", str(tmp_path), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["clean"] is False
    assert payload["findings"][0]["type"] == "lockfile_load_error"


def test_registry_emits_clean_error_on_v1_lockfile(tmp_path: Path) -> None:
    lf = _write_v1_lockfile(tmp_path)
    result = CliRunner().invoke(main, ["registry", str(lf)])
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "unsupported lockfileVersion" in result.stderr


def test_scripts_emits_clean_error_on_v1_lockfile(tmp_path: Path) -> None:
    lf = _write_v1_lockfile(tmp_path)
    result = CliRunner().invoke(main, ["scripts", str(lf)])
    assert result.exit_code == 1
    assert "Traceback" not in result.stderr
    assert "unsupported lockfileVersion" in result.stderr


# ---------------------------------------------------------------------------
# Auto-detect at the CLI level.
# ---------------------------------------------------------------------------


def test_registry_no_allowed_host_triggers_auto_detect(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(main, ["registry", str(lf), "--json"])
    # Single host, no leaks expected — auto-detect picks npmjs.org.
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["clean"] is True


def test_registry_auto_detect_surfaces_detected_hosts_in_json(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            f"node_modules/p{i}": {
                "version": "1.0.0",
                "resolved": f"https://acme-1.d.codeartifact.us-east-1.amazonaws.com/-/p{i}.tgz",
            }
            for i in range(20)
        },
    )
    result = CliRunner().invoke(main, ["registry", str(lf), "--json"])
    payload = json.loads(result.stdout)
    # We don't expose detected_primary_hosts on top-level JSON yet; the
    # human/json output should at minimum mark it clean.
    assert payload["clean"] is True


def test_json_output_is_parseable(tmp_path: Path) -> None:
    """--json mode must produce parseable JSON on stdout."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/sneaky/-/sneaky-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        [
            "registry",
            str(lf),
            "--allowed-host",
            ".d.codeartifact.us-east-1.amazonaws.com",
            "--json",
        ],
    )
    json.loads(result.stdout)  # must not raise


# ---------------------------------------------------------------------------
# --fail-on-exotic: unified exotic-source failure mode
# ---------------------------------------------------------------------------


def test_fail_on_exotic_exits_nonzero_on_tarball(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/custom": {
                "version": "1.0.0",
                "resolved": "https://builds.internal/custom-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        ["registry", str(lf), "--fail-on-exotic", "--json"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    types = [f["type"] for f in payload["findings"]]
    assert "tarball_sourced" in types


def test_fail_on_exotic_implies_fail_on_git(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/forked": {
                "version": "1.0.0",
                "resolved": "git+ssh://git@github.com/x/y.git#abc",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        ["registry", str(lf), "--fail-on-exotic", "--json"],
    )
    assert result.exit_code == 1


def test_fail_on_exotic_clean_when_all_registry(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        ["registry", str(lf), "--fail-on-exotic", "--json"],
    )
    assert result.exit_code == 0


def test_tarball_sourced_in_json_output(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/custom": {
                "version": "1.0.0",
                "resolved": "https://example.com/custom-1.0.0.tgz",
            },
        },
    )
    result = CliRunner().invoke(
        main,
        ["registry", str(lf), "--json"],
    )
    payload = json.loads(result.stdout)
    tarball_findings = [
        f for f in payload["findings"] if f["type"] == "tarball_sourced"
    ]
    assert len(tarball_findings) == 1
    assert tarball_findings[0]["severity"] == "MEDIUM"
    assert "url" in tarball_findings[0]


# ---------------------------------------------------------------------------
# pin — direct-dep pinning policy audit
# ---------------------------------------------------------------------------


def _write_pkg_only(tmp_path: Path, content: dict[str, object]) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(content))
    return tmp_path


def test_pin_clean_exits_zero(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path,
        {"dependencies": {"a": "1.2.3"}, "devDependencies": {"b": "2.0.0"}},
    )
    result = CliRunner().invoke(main, ["pin", str(project)])
    assert result.exit_code == 0
    assert "OK" in result.stdout


def test_pin_flagged_exits_one_and_tagged_high(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path, {"dependencies": {"a": "^1.0.0"}}
    )
    result = CliRunner().invoke(main, ["pin", str(project)])
    assert result.exit_code == 1
    assert "[HIGH]" in result.stderr
    assert "a = ^1.0.0" in result.stderr


def test_pin_json_output_structure(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path,
        {
            "dependencies": {"a": "^1.0.0", "b": "1.0.0"},
            "devDependencies": {"c": "latest"},
        },
    )
    result = CliRunner().invoke(main, ["pin", str(project), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["command"] == "pin"
    assert payload["total_checked"] == 3
    assert payload["clean"] is False
    unpinned = [f for f in payload["findings"] if f["type"] == "unpinned"]
    assert {f["package"] for f in unpinned} == {"a", "c"}
    kinds = {f["package"]: f["kind"] for f in unpinned}
    assert kinds["a"] == "range"
    assert kinds["c"] == "dist_tag"
    assert payload["severity_counts"]["HIGH"] == 2


def test_pin_allowlist_via_flag(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path, {"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}}
    )
    result = CliRunner().invoke(
        main, ["pin", str(project), "--allow", "a", "--json"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    # `a` should be INFO (allowed), `b` should be HIGH (flagged).
    by_pkg = {f["package"]: f for f in payload["findings"]}
    assert by_pkg["a"]["type"] == "unpinned_allowed"
    assert by_pkg["a"]["severity"] == "INFO"
    assert by_pkg["b"]["type"] == "unpinned"
    assert by_pkg["b"]["severity"] == "HIGH"


def test_pin_scope_flag_narrows_audit(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path,
        {
            "dependencies": {"a": "^1.0.0"},
            "devDependencies": {"b": "^2.0.0"},
        },
    )
    result = CliRunner().invoke(
        main, ["pin", str(project), "--scope", "dependencies", "--json"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["scopes"] == ["dependencies"]
    assert payload["total_checked"] == 1
    flagged_pkgs = {f["package"] for f in payload["findings"]}
    assert flagged_pkgs == {"a"}


def test_pin_include_peer_flag(tmp_path: Path) -> None:
    project = _write_pkg_only(
        tmp_path,
        {
            "dependencies": {"a": "1.0.0"},
            "peerDependencies": {"react": "^18.0.0"},
        },
    )
    result = CliRunner().invoke(
        main, ["pin", str(project), "--include-peer", "--json"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert "peerDependencies" in payload["scopes"]
    finding = next(f for f in payload["findings"] if f["package"] == "react")
    assert finding["scope"] == "peerDependencies"


def test_pin_missing_package_json_clean_error(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["pin", str(tmp_path), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["findings"][0]["type"] == "missing_package_json"
    assert payload["findings"][0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# trust — npm attestation / provenance verification
# ---------------------------------------------------------------------------


def _mock_attestation(predicates: list[str]) -> dict:
    return {"attestations": [{"predicateType": p, "bundle": {}} for p in predicates]}


def test_trust_audit_json_structure(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/pkg": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/" in url:
            return _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        result = CliRunner().invoke(
            main, ["trust", str(lf), "--json"]
        )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["command"] == "trust"
    assert payload["policy"] == "audit"
    assert payload["clean"] is True
    assert payload["total_checked"] == 1
    assert payload["findings"][0]["trust_level"] == "provenance+publish"


def test_trust_no_downgrade_exits_nonzero(tmp_path: Path) -> None:
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
    packument = {"versions": {"1.0.0": {}, "2.0.0": {}}}

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        if "attestations/regressed@2.0.0" in url:
            return _mock_attestation([PUBLISH_PREDICATE])
        if "attestations/regressed@1.0.0" in url:
            return _mock_attestation([PROVENANCE_PREDICATE, PUBLISH_PREDICATE])
        if url.endswith("/regressed"):
            return packument
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        result = CliRunner().invoke(
            main, ["trust", str(lf), "--policy", "no-downgrade", "--json"]
        )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["clean"] is False
    downgrades = [f for f in payload["findings"] if f.get("type") == "trust_downgrade"]
    assert len(downgrades) == 1
    assert downgrades[0]["severity"] == "HIGH"


def test_trust_require_provenance_fails_on_none(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "": {"name": "root", "version": "0.0.0"},
            "node_modules/unattested": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/unattested/-/unattested-1.0.0.tgz",
            },
        },
    )

    def mock_get(url: str, timeout: int, retries: int = 2) -> dict | None:
        return None

    with patch("codeartifact_shield.trust._http_get_json", mock_get):
        result = CliRunner().invoke(
            main,
            ["trust", str(lf), "--policy", "require-provenance", "--json"],
        )

    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["clean"] is False


# ---------------------------------------------------------------------------
# Phase A — multi-format CLI plumbing (--format, JSON format fields, pnpm)
# ---------------------------------------------------------------------------

PNPM_FIXTURES = Path(__file__).parent / "fixtures" / "pnpm"


def _stage_pnpm(tmp_path: Path, fixture: str) -> Path:
    import shutil

    dest = tmp_path / "pnpm-lock.yaml"
    shutil.copy(PNPM_FIXTURES / fixture, dest)
    return dest


def test_json_payloads_include_format_fields(tmp_path: Path) -> None:
    """Every command's JSON gains lockfile_format / format_version (additive)."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-" + "a" * 86 + "==",
            }
        },
    )
    result = CliRunner().invoke(main, ["sri", "verify", str(lf), "--json"])
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "npm"
    assert payload["format_version"] == "3"


def test_registry_format_flag_forces_pnpm(tmp_path: Path) -> None:
    lf = _stage_pnpm(tmp_path, "lock-v6-basic.yaml")
    result = CliRunner().invoke(
        main, ["registry", str(lf), "--format", "pnpm", "--json"]
    )
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "pnpm"
    assert payload["format_version"] == "6.0"
    assert payload["registry_implied"]
    # git + tarball sources are informational unless --fail-on-exotic is set.
    result_exotic = CliRunner().invoke(
        main, ["registry", str(lf), "--format", "pnpm", "--fail-on-exotic"]
    )
    assert result_exotic.exit_code == 1


def test_sri_verify_pnpm_autodetected(tmp_path: Path) -> None:
    lf = _stage_pnpm(tmp_path, "lock-v9-basic.yaml")
    result = CliRunner().invoke(main, ["sri", "verify", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "pnpm"
    assert payload["covered"] == payload["total"] == 5


def test_scripts_pnpm_v9_fails_closed_without_policy(tmp_path: Path) -> None:
    lf = _stage_pnpm(tmp_path, "lock-v9-basic.yaml")
    result = CliRunner().invoke(main, ["scripts", str(lf), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    types = {f["type"] for f in payload["findings"]}
    assert "install_script_policy_unknown" in types


def test_sri_patch_pnpm_unsupported_clean_error(tmp_path: Path) -> None:
    lf = _stage_pnpm(tmp_path, "lock-v6-basic.yaml")
    result = CliRunner().invoke(
        main, ["sri", "patch", str(lf), "--domain", "d", "--repository", "r"]
    )
    assert result.exit_code == 1
    assert "[HIGH] FAIL" in result.stderr
    assert "pnpm" in result.stderr


def test_unknown_format_bun_fails_cleanly_not_traceback(tmp_path: Path) -> None:
    """bun.lockb (legacy binary) is refused with a clean [HIGH] FAIL, never a trace."""
    lf = tmp_path / "bun.lockb"
    lf.write_bytes(b"\x00\x01binary-bun-lockfile")
    result = CliRunner().invoke(main, ["registry", str(lf)])
    assert result.exit_code == 1
    assert "[HIGH] FAIL" in result.stderr
    assert "save-text-lockfile" in result.stderr
    assert result.exception is None or isinstance(result.exception, SystemExit)


def test_bun_scripts_fails_on_untrusted_dependency(tmp_path: Path) -> None:
    """`cas scripts bun.lock` fails when a trustedDependency isn't allowlisted."""
    lf = tmp_path / "bun.lock"
    lf.write_text(
        '{"lockfileVersion":1,"trustedDependencies":["is-odd"],"packages":{'
        '"is-odd":["is-odd@3.0.1","",{},"sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5'
        'iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA=="]}}'
    )
    result = CliRunner().invoke(main, ["scripts", str(lf)])
    assert result.exit_code == 1
    assert "is-odd" in result.stderr


def test_bun_scripts_clean_when_allowlisted(tmp_path: Path) -> None:
    lf = tmp_path / "bun.lock"
    lf.write_text('{"lockfileVersion":1,"trustedDependencies":["is-odd"],"packages":{}}')
    result = CliRunner().invoke(main, ["scripts", str(lf), "--allow", "is-odd"])
    assert result.exit_code == 0


def test_bun_registry_json_reports_format(tmp_path: Path) -> None:
    lf = tmp_path / "bun.lock"
    lf.write_text('{"lockfileVersion":1,"workspaces":{"":{"name":"r"}},"packages":{}}')
    result = CliRunner().invoke(main, ["registry", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "bun"
    assert payload["format_version"] == "1"


def test_bun_format_override(tmp_path: Path) -> None:
    """--format bun forces the bun adapter even for a non-standard filename."""
    lf = tmp_path / "custom.lock"
    lf.write_text('{"lockfileVersion":1,"workspaces":{"":{"name":"r"}},"packages":{}}')
    result = CliRunner().invoke(main, ["registry", str(lf), "--format", "bun", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["lockfile_format"] == "bun"


def test_deno_registry_now_runs_cleanly(tmp_path: Path) -> None:
    """Phase B: an empty deno.lock parses and the registry gate exits 0."""
    lf = tmp_path / "deno.lock"
    lf.write_text(json.dumps({"version": "4", "specifiers": {}}))
    result = CliRunner().invoke(main, ["registry", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "deno"
    assert payload["format_version"] == "4"


def test_drift_multiple_lockfiles_requires_disambiguation(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(json.dumps({"name": "x"}))
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}})
    )
    _stage_pnpm(tmp_path, "lock-v9-workspace.yaml")
    result = CliRunner().invoke(main, ["drift", str(tmp_path)])
    assert result.exit_code == 1
    assert "multiple lockfiles" in result.stderr


def test_drift_pnpm_autoprobe(tmp_path: Path) -> None:
    _stage_pnpm(tmp_path, "lock-v9-workspace.yaml")
    result = CliRunner().invoke(main, ["drift", str(tmp_path), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "pnpm"
    assert payload["clean"] is True


# ---------------------------------------------------------------------------
# Phase B — Deno CLI plumbing
# ---------------------------------------------------------------------------

DENO_FIXTURES = Path(__file__).parent / "fixtures" / "deno"


def _stage_deno(tmp_path: Path, lock: str = "lock-v4.json") -> Path:
    import shutil

    dest = tmp_path / "deno.lock"
    shutil.copy(DENO_FIXTURES / lock, dest)
    return dest


def test_deno_sri_verify_json_fields(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path)
    result = CliRunner().invoke(main, ["sri", "verify", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "deno"
    assert payload["format_version"] == "4"
    assert payload["covered"] == payload["total"] == 5


def test_deno_sri_patch_unsupported_clean_error(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path)
    result = CliRunner().invoke(
        main, ["sri", "patch", str(lf), "--domain", "d", "--repository", "r"]
    )
    assert result.exit_code == 1
    assert "[HIGH] FAIL" in result.stderr


def test_deno_registry_cross_host_redirect_in_json(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path, "lock-v5.json")
    result = CliRunner().invoke(main, ["registry", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["redirect_cross_host"] == [
        {
            "source": "https://deno.land/x/foo/mod.ts",
            "target": "https://cdn.other-host.example/foo/mod.ts",
        }
    ]


def test_deno_scripts_exits_zero(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path)
    result = CliRunner().invoke(main, ["scripts", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["clean"] is True
    assert payload["script_info_available"] is False


def test_deno_audit_jsr_info_not_failing(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path)

    def mock_post(url, body, timeout, retries=2):
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        result = CliRunner().invoke(main, ["audit", str(lf), "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["clean"] is True
    types = {f["type"] for f in payload["findings"]}
    assert "unaudited_jsr" in types


def test_deno_audit_fail_on_unaudited_jsr(tmp_path: Path) -> None:
    lf = _stage_deno(tmp_path)

    def mock_post(url, body, timeout, retries=2):
        return {"results": [{} for _ in body.get("queries", [])]}

    with patch("codeartifact_shield.audit._http_post_json", mock_post):
        result = CliRunner().invoke(
            main, ["audit", str(lf), "--fail-on-unaudited-jsr", "--json"]
        )
    assert result.exit_code == 1


def test_deno_pin_autodetects_deno_json(tmp_path: Path) -> None:
    import shutil

    shutil.copy(DENO_FIXTURES / "deno.json", tmp_path / "deno.json")
    result = CliRunner().invoke(main, ["pin", str(tmp_path), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "deno"
    packages = {f["package"] for f in payload["findings"]}
    assert "chalk" in packages


def test_deno_drift_autoprobe(tmp_path: Path) -> None:
    import shutil

    _stage_deno(tmp_path)
    shutil.copy(DENO_FIXTURES / "deno.json", tmp_path / "deno.json")
    result = CliRunner().invoke(main, ["drift", str(tmp_path), "--ranges", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["lockfile_format"] == "deno"
    assert payload["clean"] is True
