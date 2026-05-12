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
