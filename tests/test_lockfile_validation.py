"""G6 — lockfile structural validation, especially path traversal.

A tampered lockfile can carry a package key like
``node_modules/../etc/passwd``. cas itself doesn't resolve these paths, but
``npm`` at install time would write outside the project tree. cas must
refuse to operate on a structurally suspect lockfile before any subcommand
acts on it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeartifact_shield._lockfile import load_lockfile


def _write(tmp_path: Path, lock: dict) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    return p


def test_valid_lockfile_loads_cleanly(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/@babel/runtime": {"version": "7.25.6"},
                "node_modules/foo/node_modules/bar": {"version": "1.0.0"},
            },
        },
    )
    lock = load_lockfile(p)
    assert lock["lockfileVersion"] == 3


def test_dotdot_segment_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules/../etc/passwd": {"version": "0.0.0"},
            },
        },
    )
    with pytest.raises(ValueError, match="path traversal"):
        load_lockfile(p)


def test_absolute_path_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "/etc/passwd": {"version": "0.0.0"},
            },
        },
    )
    with pytest.raises(ValueError, match="absolute path"):
        load_lockfile(p)


def test_backslash_path_rejected(tmp_path: Path) -> None:
    """Windows-style backslash separators are not part of the npm lockfile
    grammar; treat as suspicious."""
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules\\foo\\..\\etc\\passwd": {"version": "0.0.0"},
            },
        },
    )
    with pytest.raises(ValueError, match="path traversal"):
        load_lockfile(p)


def test_null_byte_in_key_rejected(tmp_path: Path) -> None:
    """Null bytes in path strings are a classic confusion-attack vector."""
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules/foo\x00bar": {"version": "0.0.0"},
            },
        },
    )
    with pytest.raises(ValueError, match="control character"):
        load_lockfile(p)


def test_v1_lockfile_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, {"lockfileVersion": 1, "dependencies": {}})
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        load_lockfile(p)


def test_empty_segment_rejected(tmp_path: Path) -> None:
    """A key like 'node_modules//foo' has an empty segment — malformed."""
    p = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "x"},
                "node_modules//foo": {"version": "0.0.0"},
            },
        },
    )
    with pytest.raises(ValueError, match="empty path segment"):
        load_lockfile(p)
