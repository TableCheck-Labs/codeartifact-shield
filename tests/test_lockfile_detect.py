"""Format detection and dispatch for the lockfile abstraction layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeartifact_shield.lockfiles import (
    LockFormat,
    UnsupportedLockfileOperation,
    detect_format,
    load_normalized,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pnpm"


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def test_detect_by_filename_npm(tmp_path: Path) -> None:
    p = _write(tmp_path, "package-lock.json", "{}")
    assert detect_format(p) is LockFormat.NPM


def test_detect_by_filename_shrinkwrap(tmp_path: Path) -> None:
    p = _write(tmp_path, "npm-shrinkwrap.json", "{}")
    assert detect_format(p) is LockFormat.NPM


def test_detect_by_filename_pnpm(tmp_path: Path) -> None:
    p = _write(tmp_path, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
    assert detect_format(p) is LockFormat.PNPM


def test_detect_by_filename_deno_and_bun(tmp_path: Path) -> None:
    assert detect_format(_write(tmp_path, "deno.lock", "{}")) is LockFormat.DENO
    assert detect_format(_write(tmp_path, "bun.lock", "{}")) is LockFormat.BUN


def test_bun_lockb_is_a_clean_error(tmp_path: Path) -> None:
    p = _write(tmp_path, "bun.lockb", "\x00\x01binary")
    with pytest.raises(UnsupportedLockfileOperation, match="save-text-lockfile"):
        detect_format(p)


def test_content_sniff_npm_when_nonstandard_name(tmp_path: Path) -> None:
    """A JSON lockfile with an integer lockfileVersion sniffs as npm."""
    p = _write(
        tmp_path,
        "run1-lock.json",
        json.dumps({"lockfileVersion": 3, "packages": {}}),
    )
    assert detect_format(p) is LockFormat.NPM


def test_content_sniff_pnpm_when_nonstandard_name(tmp_path: Path) -> None:
    p = _write(tmp_path, "my-lock.yaml", "lockfileVersion: '6.0'\npackages: {}\n")
    assert detect_format(p) is LockFormat.PNPM


def test_content_sniff_bun_by_tuple_packages(tmp_path: Path) -> None:
    """lockfileVersion 1 with tuple-valued packages sniffs as bun, not npm."""
    p = _write(
        tmp_path,
        "my-bun-lock.json",
        '{"lockfileVersion": 1, "packages": {"x": ["x@1.0.0", "", {}]}}',
    )
    assert detect_format(p) is LockFormat.BUN


def test_content_sniff_bun_by_workspaces_when_no_packages(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        "weird-name.json",
        '{"lockfileVersion": 0, "workspaces": {"": {"name": "r"}}}',
    )
    assert detect_format(p) is LockFormat.BUN


def test_content_sniff_bun_tolerates_jsonc(tmp_path: Path) -> None:
    """A bun.lock renamed but still JSONC (trailing commas) still sniffs as bun."""
    p = _write(
        tmp_path,
        "renamed.lock.json",
        '{"lockfileVersion": 1, "packages": {"x": ["x@1.0.0", "", {},],},}',
    )
    assert detect_format(p) is LockFormat.BUN


def test_content_sniff_npm_not_bun_when_object_packages(tmp_path: Path) -> None:
    """npm v1 lockfiles also use lockfileVersion 1, but object-valued packages."""
    p = _write(
        tmp_path,
        "npm1.json",
        '{"lockfileVersion": 1, "packages": {"node_modules/x": {"version": "1.0.0"}}}',
    )
    assert detect_format(p) is LockFormat.NPM


def test_content_sniff_unknown_raises(tmp_path: Path) -> None:
    p = _write(tmp_path, "mystery.txt", "just some text\n")
    with pytest.raises(UnsupportedLockfileOperation, match="could not determine"):
        detect_format(p)


def test_format_override_wins_over_sniffing(tmp_path: Path) -> None:
    """A pnpm file forced as npm dispatches to the npm adapter (and then fails
    npm-structurally), proving --format overrides detection."""
    p = FIXTURES / "lock-v6-basic.yaml"
    with pytest.raises(ValueError):
        # Forcing npm on a YAML file: npm's json.loads rejects it.
        load_normalized(p, LockFormat.NPM)


def test_load_normalized_deno_now_supported(tmp_path: Path) -> None:
    """Phase B: deno.lock parses into the normalized model."""
    p = _write(tmp_path, "deno.lock", json.dumps({"version": "4", "specifiers": {}}))
    nl = load_normalized(p)
    assert nl.format is LockFormat.DENO
    assert nl.format_version == "4"


def test_load_normalized_bun_now_supported(tmp_path: Path) -> None:
    """Phase C: bun.lock parses into the normalized model."""
    p = _write(
        tmp_path,
        "bun.lock",
        '{"lockfileVersion": 1, "workspaces": {"": {"name": "r"}}, "packages": {}}',
    )
    nl = load_normalized(p)
    assert nl.format is LockFormat.BUN
    assert nl.format_version == "1"
