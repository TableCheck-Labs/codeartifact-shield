"""Normalized, format-agnostic lockfile model.

Every supported lockfile format (npm, pnpm, and — in later phases — Deno and
Bun) is parsed by a dedicated adapter into the single shape defined here. The
gates (``registry``, ``scripts``, ``sri``, ``audit``, ``cooldown``, ``trust``,
``drift``) then consume that shape instead of reaching into a format's native
structure, so adding a format is one adapter rather than a change to every
gate.

The model is deliberately lossy-with-an-escape-hatch: the common fields every
gate needs are promoted to first-class attributes, and each entry keeps its
native ``raw`` mapping for the rare gate that needs a format-specific extra.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum, Flag, auto
from pathlib import Path
from typing import Any


class LockFormat(str, Enum):
    """The lockfile ecosystem a file belongs to."""

    NPM = "npm"
    PNPM = "pnpm"
    DENO = "deno"
    BUN = "bun"


class Ecosystem(str, Enum):
    """Where a single entry is addressable from — drives the audit/cooldown path."""

    NPM = "npm"       # OSV / npm-registry addressable
    JSR = "jsr"       # jsr.io packages (deno.lock)
    REMOTE = "remote"  # https:// module (deno.lock remote section)


class ResolvedKind(str, Enum):
    """How an entry's bytes are sourced, once the adapter has classified it."""

    REGISTRY = "registry"                  # https tarball from a registry (host known)
    REGISTRY_IMPLIED = "registry_implied"  # registry package, URL not recorded
    GIT = "git"
    TARBALL = "tarball"
    FILE = "file"
    LINK = "link"
    BUNDLED = "bundled"
    NONE = "none"


@dataclass(frozen=True)
class LockEntry:
    """One resolved package (or module) in a normalized lockfile."""

    key: str
    """Format-native key — an opaque label reused verbatim in reports."""

    name: str
    """Canonical package name. jsr keeps ``@scope/x`` with ``ecosystem=JSR``;
    remote entries carry the URL as the name."""

    version: str
    """Resolved version; ``""`` for remote entries and version-less phantoms."""

    ecosystem: Ecosystem = Ecosystem.NPM
    resolved: str | None = None
    """The recorded source URL, when the format stores one."""

    resolved_kind: ResolvedKind = ResolvedKind.NONE
    integrity: str | None = None
    """SRI string. Deno's remote sha256 hex is normalized to ``sha256-<b64>``
    by that adapter so every format's integrity is comparable."""

    has_install_script: bool | None = None
    """``None`` means the format cannot represent install-script metadata
    (e.g. pnpm lockfileVersion 9), which the scripts gate treats specially."""

    dependencies: Mapping[str, str] = field(default_factory=dict)
    optional_dependencies: Mapping[str, str] = field(default_factory=dict)
    peer_dependencies: Mapping[str, str] = field(default_factory=dict)
    bundle_dependencies: tuple[str, ...] = ()
    is_bundled: bool = False
    parent_key: str | None = None
    """Bundle-anchoring parent (npm nesting). ``None`` for every other format."""

    raw: Mapping[str, Any] = field(default_factory=dict)
    """Format-native entry for gates needing extras beyond the common fields."""


class Capability(Flag):
    """What a normalized lockfile can meaningfully answer.

    Adapters advertise capabilities so a gate can degrade gracefully — e.g.
    ``sri patch`` refuses formats without :attr:`SRI_PATCH` instead of writing
    a lockfile it cannot faithfully round-trip.
    """

    NONE = 0
    RESOLVED_URLS = auto()
    INTEGRITY = auto()
    INSTALL_SCRIPTS = auto()
    DEP_GRAPH = auto()
    DIRECT_DECLARATIONS = auto()
    SRI_PATCH = auto()


@dataclass
class NormalizedLockfile:
    """The parsed, format-agnostic view of a lockfile."""

    format: LockFormat
    format_version: str
    path: Path
    entries: list[LockEntry]
    capabilities: Capability
    workspaces: dict[str, dict[str, dict[str, str]]]
    """importer/workspace path -> {"dependencies": {name: spec}, ...}.

    npm derives the single ``""`` importer from the lockfile root; pnpm reads
    ``importers``; bun reads ``workspaces``; deno derives one ``""`` importer
    from ``deno.json`` imports."""

    raw: Any = None

    def entry_map(self) -> dict[str, LockEntry]:
        """Return a ``{key: entry}`` map — the last entry wins on key clash."""
        return {e.key: e for e in self.entries}


class UnsupportedLockfileOperation(ValueError):  # noqa: N818 - stable public name
    """A command isn't available for a given lockfile format/version.

    Subclasses :class:`ValueError` on purpose: every CLI command already funnels
    ``ValueError`` through ``_emit_load_error``, so an unsupported operation
    surfaces as a clean ``[HIGH] FAIL — <message>`` line with zero new CLI
    plumbing.
    """
