"""Bun adapter — ``bun.lock`` (JSONC text lockfile, lockfileVersion 0 and 1).

Bun's legacy ``bun.lockb`` is a binary format; cas refuses to parse it and
:func:`codeartifact_shield.lockfiles.detect_format` steers users to
``bun install --save-text-lockfile`` (Bun >= 1.2) instead.

Shape (verified against a real ``bun install --save-text-lockfile`` from Bun
1.3)::

    {
      "lockfileVersion": 1,
      "workspaces": { "": {"name": "root", "dependencies": {...}}, "pkgs/a": {...} },
      "trustedDependencies": ["is-odd"],
      "packages": {
        "is-number":  ["is-number@6.0.0", "", {}, "sha512-..."],
        "is-odd":     ["is-odd@3.0.1", "", {"dependencies": {"is-number": "^6.0.0"}}, "sha512-..."],
        "@myorg/a":   ["@myorg/a@workspace:packages/a"],
        "left-pad":   ["left-pad@https://.../left-pad-1.3.0.tgz", {}, "sha512-..."],
        "gitdep":     ["gitdep@github:o/dep#a80ee0d", {}, "o-dep-a80ee0d", "sha512-..."],
        "mylib":      ["mylib@file:vendor/mylib", {}]
      }
    }

The ``packages`` tuple is **not** a fixed shape — its layout depends on the
source of the entry (registry / tarball / git / workspace / file), and the
positions shift accordingly. The adapter classifies the entry from the spec in
the first element and then reads the remaining elements tolerantly (a stray
extra field, or a missing trailing one, does not break parsing) so a lockfile
from a newer Bun still loads. Only an unknown ``lockfileVersion`` is a hard
reject.

Nested (version-conflicted) packages are keyed by a ``/``-separated install
path, e.g. ``is-even/is-odd/is-number`` — the canonical name/version always come
from the tuple's first element, so the key is treated as an opaque label.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import codeartifact_shield.lockfiles._jsonc as _jsonc
from codeartifact_shield.lockfiles._model import (
    Capability,
    Ecosystem,
    LockEntry,
    LockFormat,
    NormalizedLockfile,
    ResolvedKind,
)

SUPPORTED_VERSIONS = (0, 1)

_DEP_SCOPES = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)

_SRI = re.compile(r"^(?:sha1|sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$")
_CONTROL_CHARS = ("\x00", "\n", "\r")


def _reject_control(value: str, what: str) -> None:
    if any(c in value for c in _CONTROL_CHARS):
        raise ValueError(f"control character in {what}: {value!r}")


def _reject_traversal(value: str, what: str) -> None:
    """Reject ``..`` path segments, absolute paths, and backslashes."""
    if "\\" in value:
        raise ValueError(f"backslash in {what}: {value!r}")
    segments = re.split(r"[/]", value)
    if ".." in segments:
        raise ValueError(f"path traversal in {what}: {value!r}")


def _split_name_spec(first: str) -> tuple[str, str]:
    """Split a package tuple's first element into ``(name, resolution-spec)``.

    ``is-number@6.0.0`` -> ``("is-number", "6.0.0")``; scope-aware so
    ``@myorg/a@workspace:packages/a`` -> ``("@myorg/a", "workspace:packages/a")``.
    """
    at = first.find("@", 1)
    if at == -1:
        return first, ""
    return first[:at], first[at + 1 :]


def _classify(spec: str) -> ResolvedKind:
    """Classify a resolution spec (the part after ``name@``) into a source kind."""
    if spec.startswith("workspace:") or spec.startswith("link:"):
        return ResolvedKind.LINK
    if (
        spec.startswith("git+")
        or spec.startswith("github:")
        or spec.startswith("git:")
        or spec.startswith("git@")
    ):
        return ResolvedKind.GIT
    if spec.startswith("https://") or spec.startswith("http://"):
        return ResolvedKind.TARBALL
    if spec.startswith("file:"):
        return ResolvedKind.FILE
    return ResolvedKind.REGISTRY


def _find_meta(rest: list[Any]) -> dict[str, Any]:
    for item in rest:
        if isinstance(item, dict):
            return item
    return {}


def _find_integrity(rest: list[Any]) -> str | None:
    """Return the last SRI-looking string in the tuple tail, if any."""
    for item in reversed(rest):
        if isinstance(item, str) and _SRI.match(item):
            return item
    return None


def _deps(meta: dict[str, Any], scope: str) -> dict[str, str]:
    block = meta.get(scope)
    if not isinstance(block, dict):
        return {}
    return {str(k): str(v) for k, v in block.items()}


def _validate_https(url: str, what: str) -> None:
    _reject_control(url, what)
    if not url.startswith("https://"):
        raise ValueError(f"non-https {what}: {url!r}")


def _build_entry(key: str, tup: list[Any]) -> LockEntry:
    skey = str(key)
    _reject_control(skey, "bun package key")
    _reject_traversal(skey, "bun package key")

    if not tup or not isinstance(tup[0], str):
        raise ValueError(f"bun package {skey!r} has no name@spec element")
    first = tup[0]
    _reject_control(first, "bun package spec")
    name, spec = _split_name_spec(first)
    if not name:
        raise ValueError(f"bun package {skey!r} has an empty name")
    _reject_traversal(name, "bun package name")

    kind = _classify(spec)
    rest = list(tup[1:])
    meta = _find_meta(rest)
    integrity = _find_integrity(rest)
    if integrity is not None and not _SRI.match(integrity):
        raise ValueError(f"malformed integrity for {skey!r}: {integrity!r}")

    resolved: str | None = None
    resolved_kind = kind
    # Only registry entries carry a real, registry-resolvable version. git
    # (commit), tarball (URL), workspace/file (path) "versions" are not
    # registry versions, so they are blanked — the audit/cooldown/trust gates
    # skip empty-version entries, which is exactly right for these local /
    # exotic sources.
    version = ""

    if kind is ResolvedKind.REGISTRY:
        # Registry tuple: [name@version, registryURL, meta, integrity].
        # A non-empty second element is the (custom) registry URL; empty means
        # the default registry, which bun.lock does not record per entry.
        version = spec
        if rest and isinstance(rest[0], str) and rest[0]:
            _validate_https(rest[0], "bun registry URL")
            resolved = rest[0]
            resolved_kind = ResolvedKind.REGISTRY
        else:
            resolved_kind = ResolvedKind.REGISTRY_IMPLIED
    elif kind is ResolvedKind.TARBALL:
        _validate_https(spec, "bun tarball URL")
        resolved = spec
    elif kind is ResolvedKind.GIT:
        _reject_control(spec, "bun git spec")
        resolved = spec
    elif kind in (ResolvedKind.FILE, ResolvedKind.LINK):
        # file:/workspace:/link: — the path after the prefix must stay in-tree.
        prefix, _, path = spec.partition(":")
        _reject_traversal(path, f"bun {prefix} path")

    return LockEntry(
        key=skey,
        name=name,
        version=version,
        ecosystem=Ecosystem.NPM,
        resolved=resolved,
        resolved_kind=resolved_kind,
        integrity=integrity,
        has_install_script=None,  # bun.lock records no per-entry flag
        dependencies=_deps(meta, "dependencies"),
        optional_dependencies=_deps(meta, "optionalDependencies"),
        peer_dependencies=_deps(meta, "peerDependencies"),
        is_bundled=bool(meta.get("bundled")),
        raw={"tuple": tup, "meta": meta},
    )


def load_bun_lock(path: Path) -> dict[str, Any]:
    """Read and version-gate a ``bun.lock``.

    Raises ``ValueError`` for an unsupported ``lockfileVersion`` (anything other
    than 0 or 1) so the CLI surfaces a clean ``[HIGH] FAIL`` instead of guessing
    at a format shape it has never seen.
    """
    text = path.read_text()
    if "\x00" in text:
        raise ValueError("null byte in bun.lock")
    data = _jsonc.loads(text)
    if not isinstance(data, dict):
        raise ValueError("bun.lock root must be an object")
    raw_version = data.get("lockfileVersion")
    if isinstance(raw_version, bool) or not isinstance(raw_version, int):
        raise ValueError(
            f"bun.lock lockfileVersion must be an integer, got {raw_version!r}"
        )
    if raw_version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"unsupported bun.lock lockfileVersion {raw_version!r}; cas supports "
            f"{', '.join(str(v) for v in SUPPORTED_VERSIONS)} "
            f"(regenerate with a compatible Bun, or upgrade cas)"
        )
    return data


def _workspaces_view(
    workspaces: dict[str, Any],
) -> dict[str, dict[str, dict[str, str]]]:
    """Expose each bun workspace's declared dependency scopes for ``drift``."""
    out: dict[str, dict[str, dict[str, str]]] = {}
    for path, block in workspaces.items():
        if not isinstance(block, dict):
            continue
        scopes: dict[str, dict[str, str]] = {}
        for scope in _DEP_SCOPES:
            declared = block.get(scope)
            if isinstance(declared, dict) and declared:
                scopes[scope] = {str(k): str(v) for k, v in declared.items()}
        if scopes:
            out[str(path)] = scopes
    return out


def trusted_dependencies(lock: dict[str, Any]) -> list[str]:
    """Return the lockfile's ``trustedDependencies`` names.

    These are the only dependency packages Bun will run lifecycle scripts for
    (on top of its built-in default allowlist); the scripts gate audits them.
    """
    trusted = lock.get("trustedDependencies")
    if isinstance(trusted, list):
        return [str(x) for x in trusted]
    return []


def build_normalized(path: Path) -> NormalizedLockfile:
    """Parse a ``bun.lock`` into the format-agnostic model."""
    lock = load_bun_lock(path)
    version = str(lock.get("lockfileVersion"))

    packages = lock.get("packages")
    packages = packages if isinstance(packages, dict) else {}
    entries: list[LockEntry] = []
    for key, tup in packages.items():
        if not isinstance(tup, list):
            raise ValueError(f"bun package {key!r} is not a tuple")
        entries.append(_build_entry(str(key), tup))

    workspaces_raw = lock.get("workspaces")
    workspaces_raw = workspaces_raw if isinstance(workspaces_raw, dict) else {}
    for wpath in workspaces_raw:
        _reject_control(str(wpath), "bun workspace path")
        _reject_traversal(str(wpath), "bun workspace path")

    capabilities = (
        Capability.INTEGRITY
        | Capability.RESOLVED_URLS
        | Capability.DEP_GRAPH
        | Capability.DIRECT_DECLARATIONS
    )

    return NormalizedLockfile(
        format=LockFormat.BUN,
        format_version=version,
        path=path,
        entries=entries,
        capabilities=capabilities,
        workspaces=_workspaces_view(workspaces_raw),
        raw=lock,
    )
