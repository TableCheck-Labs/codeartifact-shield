"""Tests for registry-leakage detection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeartifact_shield.registry import check_npm_registry


def _lock(packages: dict[str, dict[str, object]]) -> dict[str, object]:
    return {"lockfileVersion": 3, "packages": packages}


def _write(tmp_path: Path, packages: dict[str, dict[str, object]]) -> Path:
    lf = tmp_path / "package-lock.json"
    lf.write_text(json.dumps(_lock(packages)))
    return lf


def test_all_from_allowed_host_is_clean(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
            "node_modules/@babel/runtime": {
                "version": "7.25.6",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/@babel/runtime/-/runtime-7.25.6.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    assert report.clean
    assert not report.mixed
    assert report.by_host == {
        "acme-1234.d.codeartifact.us-east-1.amazonaws.com": 2,
    }


def test_detects_public_registry_leak(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    assert not report.clean
    assert report.mixed
    assert report.leaked == [("node_modules/left-pad", "registry.npmjs.org")]


def test_multiple_allowed_hosts(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://internal-mirror.corp/-/a/-/a-1.0.0.tgz",
            },
            "node_modules/b": {
                "version": "2.0.0",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/b/-/b-2.0.0.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com", "internal-mirror.corp"])
    assert report.clean
    assert report.mixed  # two distinct hosts, both allowed


def test_git_sourced_classified_separately(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/forked": {
                "version": "1.0.0",
                "resolved": "git+ssh://git@github.com/example/forked.git#abcdef",
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    # Git-sourced isn't a registry leak, but ``clean`` still returns False because
    # it's worth surfacing — they bypass the registry contract entirely.
    assert not report.clean
    assert report.leaked == []
    assert len(report.git_sourced) == 1
    assert report.git_sourced[0][0] == "node_modules/forked"


def test_file_workspace_links_ignored(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/@local/scripts": {
                "version": "0.0.0",
                "resolved": "file:libs/scripts",
                "link": True,
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    assert report.clean
    assert report.file_sourced == ["node_modules/@local/scripts"]


def test_unresolved_entries_collected(tmp_path: Path) -> None:
    """Deduped phantom entries (no resolved URL) can't be classified — record them."""
    lf = _write(
        tmp_path,
        {
            "node_modules/phantom": {"version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://acme-1234.d.codeartifact.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    assert report.clean
    assert report.unresolved == ["node_modules/phantom"]


def test_empty_allowed_list_errors(tmp_path: Path) -> None:
    lf = _write(tmp_path, {})
    with pytest.raises(ValueError, match="at least one --allowed-host"):
        check_npm_registry(lf, [])


def test_v1_lockfile_rejected(tmp_path: Path) -> None:
    lf = tmp_path / "package-lock.json"
    lf.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])


def test_case_insensitive_host_match(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://ACME-1234.D.CODEARTIFACT.us-east-1.amazonaws.com/npm/lib/lodash/-/lodash-4.17.21.tgz",
            },
        },
    )
    report = check_npm_registry(lf, [".d.codeartifact.us-east-1.amazonaws.com"])
    assert report.clean


# ---------------------------------------------------------------------------
# G3 — host matching must anchor at label boundaries, not as a substring.
#
# Threat model: substring match lets an attacker register
# `evil.d.codeartifact.attacker.com` and resolve a leaked tarball through it;
# the pattern `.d.codeartifact.` matches the substring, so cas would falsely
# report "clean". The defense is label-aware suffix matching: host must
# equal the pattern, or end with `.` + pattern.
# ---------------------------------------------------------------------------


def test_suffix_attack_host_not_allowed(tmp_path: Path) -> None:
    """`evil.d.codeartifact.attacker.com` must NOT match a CA-host pattern."""
    lf = _write(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://evil.d.codeartifact.attacker.com/npm/sneaky/-/sneaky-1.0.0.tgz",
            },
        },
    )
    report = check_npm_registry(
        lf, [".d.codeartifact.ap-northeast-1.amazonaws.com"]
    )
    assert not report.clean, (
        "host doesn't end with the legitimate suffix; must be flagged"
    )
    assert report.leaked == [
        ("node_modules/sneaky", "evil.d.codeartifact.attacker.com")
    ]


def test_prefix_attack_host_not_allowed(tmp_path: Path) -> None:
    """`legitimate-host.com.attacker.example` style must NOT match a suffix pattern."""
    lf = _write(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://internal-mirror.corp.attacker.com/-/sneaky-1.0.0.tgz",
            },
        },
    )
    report = check_npm_registry(lf, ["internal-mirror.corp"])
    assert not report.clean
    assert report.leaked[0][0] == "node_modules/sneaky"


def test_partial_label_not_allowed(tmp_path: Path) -> None:
    """A pattern of `mirror.corp` must NOT match `badmirror.corp` (label boundary)."""
    lf = _write(
        tmp_path,
        {
            "node_modules/sneaky": {
                "version": "1.0.0",
                "resolved": "https://badmirror.corp/-/sneaky-1.0.0.tgz",
            },
        },
    )
    report = check_npm_registry(lf, ["mirror.corp"])
    assert not report.clean
    assert report.leaked[0][1] == "badmirror.corp"


def test_exact_host_match_allowed(tmp_path: Path) -> None:
    """An exact match between host and pattern is the strictest valid form."""
    lf = _write(
        tmp_path,
        {
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://internal-mirror.corp/-/lodash-4.17.21.tgz",
            },
        },
    )
    report = check_npm_registry(lf, ["internal-mirror.corp"])
    assert report.clean
