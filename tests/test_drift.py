"""Tests for package.json / lockfile drift detection."""

from __future__ import annotations

import json
from pathlib import Path

from codeartifact_shield.drift import check_npm_drift


def _write_pair(
    tmp_path: Path,
    pkg: dict[str, object],
    lock: dict[str, object],
) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


def test_clean_when_versions_agree(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {"node_modules/react": {"version": "18.3.1"}}},
    )
    report = check_npm_drift(root)
    assert report.clean
    assert report.mismatches == []


def test_detects_version_disagreement(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {"node_modules/react": {"version": "18.3.2"}}},
    )
    report = check_npm_drift(root)
    assert not report.clean
    assert report.mismatches == [("dependencies", "react", "18.3.1", "18.3.2")]


def test_detects_missing_lockfile_entry(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {}},
    )
    report = check_npm_drift(root)
    assert report.mismatches == [("dependencies", "react", "18.3.1", "MISSING")]


def test_checks_dev_dependencies(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {
            "dependencies": {"react": "18.3.1"},
            "devDependencies": {"vite": "5.0.0"},
        },
        {
            "packages": {
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/vite": {"version": "4.9.0"},
            }
        },
    )
    report = check_npm_drift(root)
    assert report.mismatches == [("devDependencies", "vite", "5.0.0", "4.9.0")]


def test_raises_on_missing_package_json(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}")
    try:
        check_npm_drift(tmp_path)
    except FileNotFoundError as exc:
        assert "package.json" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")


def test_raises_on_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    try:
        check_npm_drift(tmp_path)
    except FileNotFoundError as exc:
        assert "package-lock.json" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")


def test_ignores_transitives(tmp_path: Path) -> None:
    """Only direct deps are checked; transitives aren't declared in package.json."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {
            "packages": {
                "node_modules/react": {"version": "18.3.1"},
                # A transitive at a different version — not declared, not checked.
                "node_modules/some-transitive": {"version": "9.9.9"},
            }
        },
    )
    assert check_npm_drift(root).clean
