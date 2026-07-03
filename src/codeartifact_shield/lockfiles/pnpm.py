"""pnpm adapter — ``pnpm-lock.yaml`` (lockfileVersion 6.0 and 9.0).

Two on-disk shapes, one normalized view:

* **v6.0** — ``packages`` keys are ``/name@version`` or
  ``/name@version(peer-hash)``; the dependency graph and ``resolution``
  metadata live together under each ``packages`` entry. Direct declarations are
  either a top-level ``dependencies``/``devDependencies`` block (single package)
  or an ``importers`` section (workspaces).
* **v9.0** — ``packages`` keys are ``name@version`` (no leading slash) and hold
  only ``resolution``/metadata; the dependency graph moved to a separate
  ``snapshots`` section keyed with peer suffixes. ``requiresBuild`` was dropped,
  so v9 cannot report install-script metadata at all.

Both shapes are verified against real ``pnpm install --lockfile-only`` output
(pnpm 8.15.9 for v6, pnpm 9.12.0 for v9).
"""

from __future__ import annotations

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
from codeartifact_shield.lockfiles._yaml_safe import safe_load_mapping

SUPPORTED_VERSIONS = ("6.0", "9.0")

# Tarball hosts pnpm uses for git-sourced deps (``github:`` shorthand resolves
# to a codeload tarball rather than a repo+commit resolution block).
_GIT_TARBALL_HOSTS = frozenset(
    {"codeload.github.com", "gitlab.com", "bitbucket.org"}
)

_CONTROL_CHARS = ("\x00", "\n", "\r")


def _reject_control(value: str, what: str) -> None:
    if any(c in value for c in _CONTROL_CHARS):
        raise ValueError(f"control character in {what}: {value!r}")


def _split_key(key: str) -> tuple[str, str, str]:
    """Split a pnpm package key into ``(name, version, peer_suffix)``.

    ``/react-dom@18.2.0(react@18.2.0)`` -> ``("react-dom", "18.2.0",
    "(react@18.2.0)")``; ``@esbuild/aix-ppc64@0.19.12`` ->
    ``("@esbuild/aix-ppc64", "0.19.12", "")``.
    """
    k = key[1:] if key.startswith("/") else key
    peer = ""
    paren = k.find("(")
    if paren != -1:
        peer = k[paren:]
        k = k[:paren]
    at = k.rfind("@")
    if at <= 0:
        return k, "", peer
    return k[:at], k[at + 1 :], peer


def _validate_package_key(key: str) -> None:
    """Reject tampering signatures while tolerating pnpm's real key shapes.

    pnpm keys come in two legitimate forms — registry ``name@version`` (with an
    optional single leading ``/`` and peer suffix) and path-shaped git/tarball
    keys like ``github.com/u/r/<commit>``. Both are allowed; what's rejected is
    the tampering grammar: control characters, backslashes, absolute paths,
    empty segments, and any ``..`` path segment (including a ``..`` package
    name).
    """
    _reject_control(key, "pnpm package key")
    if "\\" in key:
        raise ValueError(f"backslash in pnpm package key: {key!r}")
    k = key[1:] if key.startswith("/") else key
    if k.startswith("/"):
        raise ValueError(f"absolute path in pnpm package key: {key!r}")
    segments = k.split("/")
    if ".." in segments:
        raise ValueError(f"path traversal in pnpm package key: {key!r}")
    if "" in segments:
        raise ValueError(f"empty path segment in pnpm package key: {key!r}")
    # A registry-style key whose parsed name is ``..`` (e.g. ``/..@1.0.0``).
    name, _version, _peer = _split_key(key)
    if ".." in name.split("/"):
        raise ValueError(f"path traversal in pnpm package key: {key!r}")


def _validate_importer_key(key: str) -> None:
    _reject_control(key, "pnpm importer key")
    if key.startswith("/") or key.startswith("\\"):
        raise ValueError(f"absolute path in pnpm importer key: {key!r}")
    if ".." in key.replace("\\", "/").split("/"):
        raise ValueError(f"path traversal in pnpm importer key: {key!r}")


def _validate_resolution(key: str, resolution: dict[str, Any]) -> None:
    tarball = resolution.get("tarball")
    if isinstance(tarball, str) and tarball:
        scheme = urlparse(tarball).scheme
        if scheme and scheme != "https":
            raise ValueError(
                f"non-https tarball resolution for {key!r}: {tarball!r}"
            )
    directory = resolution.get("directory")
    if isinstance(directory, str) and ".." in directory.replace("\\", "/").split("/"):
        raise ValueError(f"path traversal in resolution.directory for {key!r}")


def _classify_resolution(resolution: dict[str, Any]) -> tuple[str | None, ResolvedKind]:
    """Return ``(resolved_url, kind)`` for a pnpm ``resolution`` block."""
    if resolution.get("type") == "git" or (
        resolution.get("repo") and resolution.get("commit")
    ):
        repo = resolution.get("repo", "")
        commit = resolution.get("commit", "")
        resolved = f"{repo}#{commit}" if commit else (repo or None)
        return resolved, ResolvedKind.GIT
    directory = resolution.get("directory")
    if isinstance(directory, str) and directory:
        return directory, ResolvedKind.FILE
    tarball = resolution.get("tarball")
    if isinstance(tarball, str) and tarball:
        parsed = urlparse(tarball)
        if (parsed.hostname or "") in _GIT_TARBALL_HOSTS:
            # ``github:`` shorthand resolves to a codeload tarball — it's a git
            # source, not a registry package.
            return tarball, ResolvedKind.GIT
        if parsed.scheme == "https" and "/-/" in (parsed.path or ""):
            return tarball, ResolvedKind.REGISTRY
        return tarball, ResolvedKind.TARBALL
    # Default registry: pnpm resolves the host from .npmrc, not the lockfile.
    return None, ResolvedKind.REGISTRY_IMPLIED


def _integrity_of(resolution: dict[str, Any]) -> str | None:
    integrity = resolution.get("integrity")
    return integrity if isinstance(integrity, str) and integrity else None


def _importers_from_lock(lock: dict[str, Any], version: str) -> dict[str, dict[str, Any]]:
    """Return pnpm's importer map, synthesizing ``"."`` for non-workspace v6.

    v6 single-package lockfiles record direct deps as top-level
    ``dependencies``/``devDependencies``; workspace lockfiles (and all of v9)
    use an ``importers`` section. Normalize both to an importer map whose values
    carry ``{scope: {name: {specifier, version}}}``.
    """
    importers = lock.get("importers")
    if isinstance(importers, dict) and importers:
        return {str(k): v for k, v in importers.items() if isinstance(v, dict)}
    root: dict[str, Any] = {}
    for scope in ("dependencies", "devDependencies", "optionalDependencies"):
        block = lock.get(scope)
        if isinstance(block, dict):
            root[scope] = block
    return {".": root} if root else {}


def _workspaces_view(
    importers: dict[str, dict[str, Any]],
) -> dict[str, dict[str, dict[str, str]]]:
    """Collapse importers to ``{importer: {scope: {name: specifier}}}``.

    The full ``{specifier, version}`` detail stays available to ``drift`` via
    ``NormalizedLockfile.raw``; this view is the generic direct-declaration
    surface (name -> declared spec) other consumers expect.
    """
    view: dict[str, dict[str, dict[str, str]]] = {}
    for importer, blocks in importers.items():
        scoped: dict[str, dict[str, str]] = {}
        for scope in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            block = blocks.get(scope)
            if not isinstance(block, dict):
                continue
            specs: dict[str, str] = {}
            for name, info in block.items():
                if isinstance(info, dict):
                    specs[str(name)] = str(info.get("specifier", ""))
                else:
                    specs[str(name)] = str(info)
            if specs:
                scoped[scope] = specs
        if scoped:
            view[str(importer)] = scoped
    return view


def _snapshot_index(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map base ``name@version`` -> its v9 ``snapshots`` entry (peers merged)."""
    index: dict[str, dict[str, Any]] = {}
    snapshots = lock.get("snapshots")
    if not isinstance(snapshots, dict):
        return index
    for skey, sval in snapshots.items():
        name, version, _peer = _split_key(str(skey))
        base = f"{name}@{version}"
        if not isinstance(sval, dict):
            continue
        existing = index.setdefault(base, {})
        for scope in ("dependencies", "optionalDependencies"):
            block = sval.get(scope)
            if isinstance(block, dict):
                merged = dict(existing.get(scope, {}))
                merged.update(block)
                existing[scope] = merged
    return index


def _str_map(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items()}


def build_normalized(path: Path) -> NormalizedLockfile:
    """Parse a ``pnpm-lock.yaml`` into the format-agnostic model."""
    lock = load_pnpm_lock(path)
    version = str(lock.get("lockfileVersion", ""))
    is_v9 = version.startswith("9")

    packages = lock.get("packages")
    if packages is not None and not isinstance(packages, dict):
        raise ValueError("`packages` must be a mapping in pnpm-lock.yaml")
    packages = packages or {}

    importers = _importers_from_lock(lock, version)
    for importer_key in importers:
        _validate_importer_key(importer_key)

    snapshots = _snapshot_index(lock) if is_v9 else {}

    entries: list[LockEntry] = []
    for key, meta in packages.items():
        skey = str(key)
        _validate_package_key(skey)
        if not isinstance(meta, dict):
            raise ValueError(f"pnpm package entry {skey!r} must be a mapping")
        name, pkg_version, _peer = _split_key(skey)
        # Git/tarball/directory entries have path-shaped keys and carry explicit
        # ``name``/``version`` fields — prefer them over the un-parseable key.
        explicit_name = meta.get("name")
        if isinstance(explicit_name, str) and explicit_name:
            name = explicit_name
        explicit_version = meta.get("version")
        if explicit_version is not None:
            pkg_version = str(explicit_version)
        resolution = meta.get("resolution")
        resolution = resolution if isinstance(resolution, dict) else {}
        _validate_resolution(skey, resolution)
        resolved, kind = _classify_resolution(resolution)

        base = f"{name}@{pkg_version}"
        if is_v9:
            snap = snapshots.get(base, {})
            deps = _str_map(snap.get("dependencies"))
            opt_deps = _str_map(snap.get("optionalDependencies"))
            has_script: bool | None = None
        else:
            deps = _str_map(meta.get("dependencies"))
            opt_deps = _str_map(meta.get("optionalDependencies"))
            has_script = bool(meta.get("requiresBuild"))

        entries.append(
            LockEntry(
                key=skey,
                name=name,
                version=pkg_version,
                ecosystem=Ecosystem.NPM,
                resolved=resolved,
                resolved_kind=kind,
                integrity=_integrity_of(resolution),
                has_install_script=has_script,
                dependencies=deps,
                optional_dependencies=opt_deps,
                peer_dependencies=_str_map(meta.get("peerDependencies")),
                bundle_dependencies=(),
                is_bundled=False,
                parent_key=None,
                raw=meta,
            )
        )

    capabilities = (
        Capability.RESOLVED_URLS
        | Capability.INTEGRITY
        | Capability.DEP_GRAPH
        | Capability.DIRECT_DECLARATIONS
    )
    if not is_v9:
        capabilities |= Capability.INSTALL_SCRIPTS

    return NormalizedLockfile(
        format=LockFormat.PNPM,
        format_version=version,
        path=path,
        entries=entries,
        capabilities=capabilities,
        workspaces=_workspaces_view(importers),
        raw=lock,
    )


def load_pnpm_lock(path: Path) -> dict[str, Any]:
    """Read and version-gate a ``pnpm-lock.yaml``.

    Raises ``ValueError`` for unsupported ``lockfileVersion`` values so the CLI
    surfaces a clean ``[HIGH] FAIL`` rather than mis-parsing an old shape.
    """
    lock = safe_load_mapping(path.read_text())
    raw_version = lock.get("lockfileVersion")
    version = str(raw_version)
    if version not in SUPPORTED_VERSIONS:
        if version.startswith("5"):
            raise ValueError(
                f"unsupported pnpm lockfileVersion {raw_version!r}; "
                f"regenerate with pnpm >= 8 (`pnpm install --lockfile-only`)"
            )
        raise ValueError(
            f"unsupported pnpm lockfileVersion {raw_version!r}; "
            f"only {', '.join(SUPPORTED_VERSIONS)} are supported"
        )
    return lock


def read_pnpm_workspace_settings(project_dir: Path) -> dict[str, Any]:
    """Read a sibling ``pnpm-workspace.yaml`` for build/cooldown policy.

    Returns ``{}`` when the file is absent. Read-only and optional — used by the
    ``scripts`` gate (``onlyBuiltDependencies``) and surfaced by ``cooldown``
    (``minimumReleaseAge``) as an informational cross-check.
    """
    ws_path = project_dir / "pnpm-workspace.yaml"
    if not ws_path.exists():
        return {}
    try:
        data = safe_load_mapping(ws_path.read_text())
    except ValueError:
        return {}
    return data
