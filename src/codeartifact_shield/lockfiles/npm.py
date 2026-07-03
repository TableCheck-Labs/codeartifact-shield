"""npm adapter — ``package-lock.json`` / ``npm-shrinkwrap.json``.

This module owns the npm-native lockfile helpers that used to live in
``_lockfile.py`` (which is now a thin re-export shim over this file, so every
pre-existing ``from codeartifact_shield._lockfile import ...`` keeps working).
It also builds the :class:`NormalizedLockfile` view the gates consume.

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
from urllib.parse import urlparse

from codeartifact_shield.lockfiles._model import (
    Capability,
    Ecosystem,
    LockEntry,
    LockFormat,
    NormalizedLockfile,
    ResolvedKind,
)


def load_lockfile(lockfile_path: Path) -> dict[str, Any]:
    """Read a lockfile from disk, validate its structure, and return it.

    Raises ``ValueError`` for unsupported versions (v1) or any structural
    anomaly that should cause cas to refuse to operate further on the file.
    """
    lock: dict[str, Any] = json.loads(lockfile_path.read_text())
    lf_version = lock.get("lockfileVersion")
    if lf_version not in (2, 3):
        raise ValueError(
            f"unsupported lockfileVersion {lf_version}; only v2 and v3 are supported"
        )
    _validate_package_keys(lock)
    return lock


def is_installable_entry(key: str, entry: dict[str, Any]) -> bool:
    """True iff this ``packages`` entry represents a real registry install.

    npm v7+ lockfiles for workspace projects carry three classes of entry:

    1. **The root** — empty-string key (``""``). The project itself.
    2. **Workspace declarations** — keys like ``apps/foo``, ``libs/bar``,
       ``system/i18n``. The workspace's own manifest. These have a real
       ``version`` but they're NOT installed via the registry.
    3. **Installed packages** — keys like ``node_modules/<name>`` or
       ``node_modules/<a>/node_modules/<b>`` (and the workspace's own
       symlink as ``node_modules/<workspace-name>`` with ``link: true``).
       These are the things cas should examine.

    Workspace declarations (class 2) regularly slipped past the
    previous filter (only ``key == ""`` and ``link: true`` were
    rejected) and got probed against the public registry, where they
    don't exist — surfacing as bogus ``private_blocked`` /
    ``unaudited_private`` / orphan findings. This helper closes that
    gap by requiring the key to live under ``node_modules/``.
    """
    if not key:
        return False
    if not key.startswith("node_modules/"):
        return False
    return not entry.get("link")


def extract_package_name(key: str, entry: dict[str, Any] | None = None) -> str:
    """Return the canonical npm package name for a lockfile entry.

    Prefers the entry's ``name`` field, which npm sets for aliased entries
    (e.g. ``"string-width-cjs": "npm:string-width@4.2.3"`` in package.json
    produces ``packages["node_modules/string-width-cjs"].name == "string-width"``).
    Falls back to the last ``node_modules/<name>`` segment of the key when
    no ``name`` field is present (the common case for non-aliased deps).

    Getting this right is load-bearing for every subcommand that queries
    a registry by name (cooldown, audit), since the alias name doesn't
    exist on npm and would always 404.
    """
    if entry is not None:
        name = entry.get("name")
        if isinstance(name, str) and name:
            return name
    marker = "/node_modules/"
    idx = key.rfind(marker)
    tail = key[idx + len(marker) :] if idx != -1 else key
    if tail.startswith("node_modules/"):
        tail = tail[len("node_modules/") :]
    return tail


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
    for key in pkgs:
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


def _parent_node_modules_key(key: str) -> str | None:
    """Return the parent lockfile key for a nested ``node_modules`` path.

    ``node_modules/foo/node_modules/bar`` -> ``node_modules/foo``; a top-level
    ``node_modules/foo`` has no in-tree parent and returns ``None``.
    """
    marker = "/node_modules/"
    idx = key.rfind(marker)
    if idx <= 0:
        return None
    return key[:idx]


def classify_npm_resolved(entry: dict[str, Any]) -> ResolvedKind:
    """Classify an npm entry's byte source from its ``resolved`` URL / flags.

    Mirrors the inline classification the ``registry`` gate has always used so
    the normalized model agrees with the native npm path.
    """
    resolved = entry.get("resolved")
    if not resolved:
        return ResolvedKind.BUNDLED if entry.get("inBundle") else ResolvedKind.NONE
    if resolved.startswith(("file:", "./", "../", "/")):
        return ResolvedKind.FILE
    if resolved.startswith(("git+", "git:", "github:")) or "+git@" in resolved:
        return ResolvedKind.GIT
    parsed = urlparse(resolved)
    if parsed.scheme == "https" and "/-/" not in (parsed.path or ""):
        return ResolvedKind.TARBALL
    return ResolvedKind.REGISTRY


def _to_str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def build_normalized(path: Path) -> NormalizedLockfile:
    """Parse an npm lockfile into the format-agnostic model.

    The entry set is exactly :func:`is_installable_entry` — same skip rules the
    gates have always used — so consuming ``.entries`` is behaviour-preserving.
    """
    lock = load_lockfile(path)
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})

    entries: list[LockEntry] = []
    for key, entry in pkgs.items():
        if not is_installable_entry(key, entry):
            continue
        bundle_deps = entry.get("bundleDependencies") or entry.get("bundledDependencies") or []
        entries.append(
            LockEntry(
                key=key,
                name=extract_package_name(key, entry),
                version=entry.get("version") or "",
                ecosystem=Ecosystem.NPM,
                resolved=entry.get("resolved"),
                resolved_kind=classify_npm_resolved(entry),
                integrity=entry.get("integrity")
                if isinstance(entry.get("integrity"), str)
                else None,
                has_install_script=bool(entry.get("hasInstallScript")),
                dependencies=_to_str_map(entry.get("dependencies")),
                optional_dependencies=_to_str_map(entry.get("optionalDependencies")),
                peer_dependencies=_to_str_map(entry.get("peerDependencies")),
                bundle_dependencies=tuple(bundle_deps) if isinstance(bundle_deps, list) else (),
                is_bundled=bool(entry.get("inBundle")),
                parent_key=_parent_node_modules_key(key),
                raw=entry,
            )
        )

    root = pkgs.get("", {})
    workspaces = {
        "": {
            kind: _to_str_map(root.get(kind))
            for kind in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            )
            if isinstance(root.get(kind), dict)
        }
    }

    capabilities = (
        Capability.RESOLVED_URLS
        | Capability.INTEGRITY
        | Capability.INSTALL_SCRIPTS
        | Capability.DEP_GRAPH
        | Capability.DIRECT_DECLARATIONS
        | Capability.SRI_PATCH
    )

    return NormalizedLockfile(
        format=LockFormat.NPM,
        format_version=str(lock.get("lockfileVersion", "")),
        path=path,
        entries=entries,
        capabilities=capabilities,
        workspaces=workspaces,
        raw=lock,
    )
