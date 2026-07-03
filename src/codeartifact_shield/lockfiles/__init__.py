"""Lockfile abstraction layer — detection, dispatch, and the support matrix.

Public surface:

* :func:`detect_format` — filename first, content sniff second.
* :func:`load_normalized` — parse any supported lockfile into the shared model.
* :func:`require_capability` — fail an unsupported command with a clean,
  per-format explanation drawn from :data:`SUPPORT_NOTES`.

Formats not yet implemented in this phase (Deno, Bun) are detected far enough to
emit a clean ``[HIGH] FAIL`` rather than a traceback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import codeartifact_shield.lockfiles._jsonc as _jsonc
from codeartifact_shield.lockfiles import bun, deno, npm, pnpm
from codeartifact_shield.lockfiles._model import (
    Capability,
    Ecosystem,
    LockEntry,
    LockFormat,
    NormalizedLockfile,
    ResolvedKind,
    UnsupportedLockfileOperation,
)

__all__ = [
    "Capability",
    "Ecosystem",
    "LockEntry",
    "LockFormat",
    "NormalizedLockfile",
    "ResolvedKind",
    "SUPPORT_NOTES",
    "UnsupportedLockfileOperation",
    "detect_format",
    "load_normalized",
    "require_capability",
]

_SNIFF_BYTES = 4096

_FILENAME_FORMATS = {
    "package-lock.json": LockFormat.NPM,
    "npm-shrinkwrap.json": LockFormat.NPM,
    "pnpm-lock.yaml": LockFormat.PNPM,
    "deno.lock": LockFormat.DENO,
    "bun.lock": LockFormat.BUN,
}

# Central behavior-matrix copy: one note per (format, command) cell that is
# anything other than "full". Reused by the CLI, tests, and README so the
# matrix has a single source of truth.
SUPPORT_NOTES: dict[LockFormat, dict[str, str]] = {
    LockFormat.NPM: {},
    LockFormat.PNPM: {
        "sri-patch": (
            "sri patch backfills npm package-lock.json from CodeArtifact; pnpm "
            "lockfiles already carry integrity from the registry metadata — if "
            "yours are missing it, re-resolve with `pnpm install --lockfile-only`"
        ),
        "registry": (
            "pnpm lockfiles pin the registry via .npmrc, not per-entry; "
            "default-registry packages are reported as INFO registry_implied, "
            "and only explicit tarball/git resolutions are host-gated"
        ),
        "scripts": (
            "pnpm lockfileVersion 6 records requiresBuild; lockfileVersion 9 "
            "dropped it, so cas audits onlyBuiltDependencies policy instead and "
            "fails closed when no build policy is discoverable"
        ),
    },
    LockFormat.DENO: {
        "sri-patch": (
            "sri patch backfills npm package-lock.json from CodeArtifact; "
            "deno.lock is a different format entirely — deno records its own "
            "sha512/sha256 integrity when it resolves, so there is nothing to "
            "backfill. Re-resolve with `deno install` if hashes are missing"
        ),
        "registry": (
            "deno.lock host-gates its `remote` https:// modules and flags "
            "cross-host redirects; npm and jsr packages resolve from the "
            "registry configured out-of-band and are reported as INFO "
            "registry_implied, never as leaks"
        ),
        "scripts": (
            "deno does not run npm lifecycle scripts unless `deno install "
            "--allow-scripts` is used, so cas reports the npm dependency surface "
            "as INFO and never fails the scripts gate for deno.lock"
        ),
        "audit": (
            "npm dependencies in deno.lock are audited against OSV as usual; "
            "jsr packages have no OSV ecosystem and are reported as INFO "
            "unaudited_jsr (fail with --fail-on-unaudited-jsr); remote https:// "
            "modules are skipped with an aggregate INFO"
        ),
        "cooldown": (
            "npm dependencies use the npm registry publish times; jsr packages "
            "query api.jsr.io createdAt; remote https:// modules have no publish "
            "time and are skipped with an aggregate INFO"
        ),
        "trust": (
            "npm attestations are verified as usual; jsr and remote entries have "
            "no npm-style provenance and are skipped"
        ),
    },
    LockFormat.BUN: {
        "sri-patch": (
            "sri patch backfills npm package-lock.json from CodeArtifact; "
            "bun.lock is a different format entirely and already records "
            "sha512 integrity when bun resolves — re-run `bun install` if any "
            "hashes are missing rather than backfilling"
        ),
        "registry": (
            "bun.lock records a per-entry registry URL only for non-default "
            "registries; default-registry packages are reported as INFO "
            "registry_implied, and only explicit registry/tarball/git "
            "resolutions are host-gated"
        ),
        "scripts": (
            "bun runs lifecycle scripts only for packages listed in "
            "trustedDependencies (plus its built-in default allowlist), so cas "
            "audits trustedDependencies against --allow instead of a per-entry "
            "hasInstallScript flag"
        ),
    },
}


def detect_format(path: Path) -> LockFormat:
    """Determine a lockfile's format from its name, then its content.

    Raises :class:`UnsupportedLockfileOperation` for ``bun.lockb`` (Bun's legacy
    binary lockfile) and for content that matches no known format.
    """
    name = path.name
    if name == "bun.lockb":
        raise UnsupportedLockfileOperation(
            "bun.lockb is Bun's legacy binary lockfile; regenerate a text "
            "lockfile with `bun install --save-text-lockfile` (Bun >= 1.2)"
        )
    fmt = _FILENAME_FORMATS.get(name)
    if fmt is not None:
        return fmt
    return _sniff_format(path)


def _has_tuple_packages(data: dict[str, Any]) -> bool:
    """True if ``data['packages']`` is a bun-style map of tuple (list) values."""
    packages = data.get("packages")
    if not isinstance(packages, dict) or not packages:
        # An empty/absent ``packages`` bun.lock is still bun if it carries the
        # bun-only ``workspaces`` map with a "" root importer.
        workspaces = data.get("workspaces")
        return isinstance(workspaces, dict) and "" in workspaces
    return all(isinstance(v, list) for v in packages.values())


def _sniff_format(path: Path) -> LockFormat:
    head = path.read_text(errors="replace")[:_SNIFF_BYTES]
    stripped = head.lstrip()

    # YAML pnpm-lock: a top-level ``lockfileVersion:`` line.
    for line in head.splitlines():
        if line.startswith("lockfileVersion:"):
            return LockFormat.PNPM

    if stripped.startswith("{"):
        try:
            data = json.loads(path.read_text())
        except (json.JSONDecodeError, ValueError):
            # bun.lock is JSONC (comments / trailing commas) that plain json
            # can't read; fall back to the JSONC reader before giving up.
            try:
                data = _jsonc.loads(path.read_text())
            except ValueError:
                data = None
        if isinstance(data, dict):
            lf_version = data.get("lockfileVersion")
            if not isinstance(lf_version, bool) and isinstance(lf_version, int):
                # Bun and npm both key on an integer lockfileVersion; bun's
                # ``packages`` values are tuples (lists), npm's are objects.
                if _has_tuple_packages(data):
                    return LockFormat.BUN
                return LockFormat.NPM
            ver = data.get("version")
            if isinstance(ver, str) and ver in {"3", "4", "5"} and (
                "npm" in data
                or "jsr" in data
                or "remote" in data
                or "specifiers" in data
                or "redirects" in data
                or "packages" in data
            ):
                return LockFormat.DENO

    raise UnsupportedLockfileOperation(
        f"could not determine lockfile format for {path.name}; "
        f"pass --format to disambiguate"
    )


def load_normalized(
    path: Path, fmt: LockFormat | None = None
) -> NormalizedLockfile:
    """Parse ``path`` into the normalized model, auto-detecting when ``fmt`` is None.

    Raises :class:`UnsupportedLockfileOperation` for formats not implemented in
    this phase (Deno, Bun) and for undetectable files.
    """
    resolved_fmt = fmt or detect_format(path)
    if resolved_fmt is LockFormat.NPM:
        return npm.build_normalized(path)
    if resolved_fmt is LockFormat.PNPM:
        return pnpm.build_normalized(path)
    if resolved_fmt is LockFormat.DENO:
        return deno.build_normalized(path)
    if resolved_fmt is LockFormat.BUN:
        return bun.build_normalized(path)
    raise UnsupportedLockfileOperation(
        f"{resolved_fmt.value} lockfiles are not supported yet"
    )


def require_capability(
    lock: NormalizedLockfile, cap: Capability, command_name: str
) -> None:
    """Raise a clean error if ``lock`` can't support ``command_name``.

    Prefers the per-format explanation from :data:`SUPPORT_NOTES` so the CLI
    message tells the user exactly why and what to do instead.
    """
    if cap in lock.capabilities:
        return
    note = SUPPORT_NOTES.get(lock.format, {}).get(command_name)
    if note:
        raise UnsupportedLockfileOperation(note)
    raise UnsupportedLockfileOperation(
        f"`{command_name}` is not supported for {lock.format.value} lockfiles"
    )
