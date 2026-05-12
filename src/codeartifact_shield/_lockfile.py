"""Shared lockfile validation — structural sanity checks every subcommand runs.

A tampered lockfile can carry path-traversal payloads in its package-key
strings. cas treats those keys as opaque labels (we never filesystem-resolve
them), but ``npm`` at install time uses them as install paths — a key like
``node_modules/../etc/passwd`` would write outside the project root. Fail
closed at lockfile-read time so no downstream check operates on a structurally
suspect lockfile.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_lockfile(lockfile_path: Path) -> dict[str, Any]:
    """Read a lockfile from disk, validate its structure, and return it.

    Raises ``ValueError`` for unsupported versions (v1) or any structural
    anomaly that should cause cas to refuse to operate further on the file.
    """
    lock = json.loads(lockfile_path.read_text())
    lf_version = lock.get("lockfileVersion")
    if lf_version not in (2, 3):
        raise ValueError(
            f"unsupported lockfileVersion {lf_version}; only v2 and v3 are supported"
        )
    _validate_package_keys(lock)
    return lock


def _validate_package_keys(lock: dict[str, Any]) -> None:
    """Reject lockfile keys that could be path-traversal payloads.

    Every non-root key must be a sequence of ``node_modules/<name>`` segments.
    Anything outside that grammar (``..``, leading ``/``, null bytes,
    backslashes, control chars) is rejected loudly — these are tampering
    signatures, not legitimate npm output.
    """
    pkgs = lock.get("packages", {})
    if not isinstance(pkgs, dict):
        raise ValueError("`packages` must be an object in lockfileVersion 2/3")
    for key in pkgs.keys():
        if key == "":
            continue
        if not isinstance(key, str):
            raise ValueError(f"non-string package key: {key!r}")
        if "\x00" in key or "\n" in key or "\r" in key:
            raise ValueError(f"control character in package key: {key!r}")
        if key.startswith("/") or key.startswith("\\"):
            raise ValueError(f"absolute path in package key: {key!r}")
        # Segment-by-segment check: every '..' segment is forbidden, and
        # leading segment must be 'node_modules' (or 'apps'/'libs'/... for
        # workspace layouts — but those don't have `..` either).
        segments = key.replace("\\", "/").split("/")
        if ".." in segments:
            raise ValueError(f"path traversal in package key: {key!r}")
        if "" in segments:
            # Empty segment from '//' or trailing slash — also suspicious.
            raise ValueError(f"empty path segment in package key: {key!r}")
