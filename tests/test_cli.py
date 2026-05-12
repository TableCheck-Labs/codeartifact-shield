"""CLI-surface tests — severity badges (G11) and structured output (G10).

These exercise the user-facing output: severity prefixes that let reviewers
prioritize, and machine-readable JSON for downstream tools (SARIF /
GitHub Code Scanning).
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from codeartifact_shield.cli import main


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
