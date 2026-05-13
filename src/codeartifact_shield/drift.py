"""Lockfile / manifest drift detection — direct and transitive.

Two failure modes worth catching:

1. **Direct drift.** ``package.json`` declares one version (or range);
   ``package-lock.json`` resolves a different one. CI should refuse to
   ship in that state — it's the exact inconsistency a quiet supply-chain
   attack would create by editing the lockfile alone.

2. **Transitive drift.** Every lockfile entry has its own ``dependencies``
   block declaring the SemVer ranges *its* children must satisfy. If a
   tampered or partially-regenerated lockfile resolves a child to a
   version outside the parent's declared range, the install is internally
   inconsistent — another tampering signal.

Direct drift uses literal equality by default (catches policy violations
like an exact-pinned project drifting to a range), with ``--ranges`` to
relax to SemVer-range satisfaction. Transitive drift is always
range-satisfaction — transitive declarations are nearly always ranges.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import nodesemver

from codeartifact_shield._lockfile import load_lockfile

# nodesemver logs an INFO entry with a traceback for every range it can't parse
# (e.g. ``github:org/repo#ref``, ``npm:other-name@^1.x``). We intercept the
# parse failure ourselves and decide what to do with it; the noise just makes
# the CLI output unreadable.
logging.getLogger("nodesemver").setLevel(logging.ERROR)


@dataclass
class DriftReport:
    """Findings from ``check_npm_drift``."""

    mismatches: list[tuple[str, str, str, str]] = field(default_factory=list)
    """Direct-dep disagreements: ``(dep_kind, name, declared, actual)``."""

    transitive_mismatches: list[tuple[str, str, str, str]] = field(default_factory=list)
    """Transitive-dep disagreements: ``(parent_key, child_name, declared_range, resolved)``."""

    orphan_entries: list[str] = field(default_factory=list)
    """Installable lockfile entries that are NOT reachable from the dependency
    graph rooted at ``package.json``. A clean lockfile is a closed set: every
    entry traces back through ``dependencies``/``peerDependencies``/
    ``optionalDependencies``/``bundleDependencies`` to a top-level declaration.
    An entry without that trace is a tampering signature — the most plausible
    way a malicious extra package lands in a lockfile."""

    @property
    def clean(self) -> bool:
        return (
            not self.mismatches
            and not self.transitive_mismatches
            and not self.orphan_entries
        )


_NON_SEMVER_PREFIXES = (
    "file:",
    "link:",
    "workspace:",
    "github:",
    "git:",
    "git+",
    "http:",
    "https:",
    "npm:",
)


def _is_semver_declaration(declared: str) -> bool:
    """True if the declaration looks like something nodesemver can parse.

    Excludes:
    * URL-ish prefixes (``github:``, ``npm:`` alias, tarballs, workspace paths)
    * npm dist-tags (``latest``, ``next``, ``beta``, …) — these are
      word-only strings with no digits; npm resolves them via the registry
      at install time, so they aren't constraints we can compare against.
    """
    if declared.startswith(_NON_SEMVER_PREFIXES):
        return False
    # Allow the special "*" / "x" wildcards even though they contain no digits.
    if declared.strip() in {"*", "x", "X", "any"}:
        return True
    return bool(re.search(r"\d", declared))


def _satisfies(version: str, declared: str) -> bool | None:
    """Returns True/False for SemVer range satisfaction, or None for unparseable.

    None means "the declaration isn't a SemVer range" — the caller should
    treat that as out of scope rather than as a violation.
    """
    if declared == version:
        return True
    if not _is_semver_declaration(declared):
        return None
    try:
        return bool(nodesemver.satisfies(version, declared, loose=True))
    except Exception:  # noqa: BLE001 - malformed range; out of scope
        return None


def _resolve_transitive_key(parent_key: str, child: str, lock_pkgs: dict[str, Any]) -> str | None:
    """Replicate npm's resolution: walk up every ``node_modules`` ancestor.

    For a parent at ``node_modules/A/node_modules/B/node_modules/C``, the
    candidate paths for child ``X`` are, in order:

        node_modules/A/node_modules/B/node_modules/C/node_modules/X
        node_modules/A/node_modules/B/node_modules/X
        node_modules/A/node_modules/X
        node_modules/X

    The first hit wins. A workspace parent (``parent_key == ""``) looks only at
    the top level.
    """
    root_candidate = f"node_modules/{child}"
    if not parent_key:
        return root_candidate if root_candidate in lock_pkgs else None

    # Walk from deepest to one-level-above-root by stripping ``/node_modules/<seg>``
    # suffixes. The leading ``node_modules/`` at the start of parent_key doesn't
    # have a preceding slash, so it isn't matched by rfind — we fall back to the
    # root candidate after the loop.
    base = parent_key
    while True:
        candidate = f"{base}/node_modules/{child}"
        if candidate in lock_pkgs:
            return candidate
        idx = base.rfind("/node_modules/")
        if idx == -1:
            break
        base = base[:idx]
    return root_candidate if root_candidate in lock_pkgs else None


def check_npm_drift(
    frontend_dir: Path,
    *,
    ranges: bool = False,
    transitive: bool = True,
) -> DriftReport:
    """Compare ``package.json`` declarations to ``package-lock.json`` resolutions.

    Args:
        frontend_dir: Project directory containing both files.
        ranges: If True, treat direct-dep declarations as SemVer ranges
            (``^1.2.3``, ``>=1.0``) instead of requiring literal equality.
            Useful when the project doesn't pin exact versions in
            ``package.json``. Defaults to False because a policy-pinned
            project shouldn't have ranges in ``package.json`` at all.
        transitive: If True, also walk every lockfile entry's own
            ``dependencies`` / ``optionalDependencies`` / ``peerDependencies``
            block and verify each child's resolved version satisfies the
            declared range. Defaults to True — transitive lockfile
            tampering is the more interesting threat model.
    """
    pkg_path = frontend_dir / "package.json"
    lock_path = frontend_dir / "package-lock.json"
    if not pkg_path.exists():
        raise FileNotFoundError(f"no package.json in {frontend_dir}")
    if not lock_path.exists():
        raise FileNotFoundError(f"no package-lock.json in {frontend_dir}")
    pkg = json.loads(pkg_path.read_text())
    lock = load_lockfile(lock_path)
    lock_pkgs: dict[str, Any] = lock.get("packages", {})

    report = DriftReport()

    # ---- Direct deps ---------------------------------------------------------
    for kind in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, declared in pkg.get(kind, {}).items():
            entry = lock_pkgs.get(f"node_modules/{name}", {})
            actual = entry.get("version", "MISSING")
            if actual == "MISSING":
                report.mismatches.append((kind, name, declared, actual))
                continue
            if ranges:
                outcome = _satisfies(actual, declared)
                if outcome is False:
                    report.mismatches.append((kind, name, declared, actual))
                # outcome is True (satisfies) or None (not a SemVer declaration —
                # we can't meaningfully compare, leave alone).
            else:
                if actual != declared:
                    report.mismatches.append((kind, name, declared, actual))

    # ---- Transitive deps -----------------------------------------------------
    if transitive:
        for parent_key, parent_entry in lock_pkgs.items():
            if not parent_key:
                # The root entry mirrors package.json — already covered by the
                # direct-deps loop above. Skip to avoid double-reporting.
                continue
            if parent_entry.get("link"):
                continue
            for dep_kind in ("dependencies", "optionalDependencies", "peerDependencies"):
                for child_name, declared_range in parent_entry.get(dep_kind, {}).items():
                    child_key = _resolve_transitive_key(parent_key, child_name, lock_pkgs)
                    if child_key is None:
                        # Optional and peer deps can legitimately be missing.
                        if dep_kind != "dependencies":
                            continue
                        report.transitive_mismatches.append(
                            (parent_key or "<root>", child_name, declared_range, "MISSING")
                        )
                        continue
                    resolved = lock_pkgs[child_key].get("version", "")
                    if not resolved:
                        continue
                    outcome = _satisfies(resolved, declared_range)
                    if outcome is False:
                        report.transitive_mismatches.append(
                            (parent_key or "<root>", child_name, declared_range, resolved)
                        )

        # ---- Orphan / undeclared lockfile entries ---------------------------
        # Logically depends on walking the dep graph, so tied to transitive
        # mode. ``--no-transitive`` is a "quick smoke test" flag; users who
        # want orphan detection should leave transitive on.
        report.orphan_entries = _find_orphan_entries(pkg, lock_pkgs)

    return report


def _find_orphan_entries(
    pkg: dict[str, Any],
    lock_pkgs: dict[str, Any],
) -> list[str]:
    """Return every installable lockfile entry not reachable from package.json.

    Walks the declared dep graph (``dependencies`` + ``devDependencies`` +
    ``optionalDependencies`` + ``peerDependencies`` + ``bundleDependencies``)
    via npm's nested-before-hoisted resolution rule. Any installable entry
    that isn't visited is an orphan — most plausibly inserted by a tampered
    lockfile or partial regeneration.
    """
    reachable: set[str] = set()
    queue: list[tuple[str, str]] = []

    # Seed from root's package.json declarations.
    for kind in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):
        for name in pkg.get(kind, {}):
            queue.append(("", name))

    while queue:
        parent_key, child_name = queue.pop()
        child_key = _resolve_transitive_key(parent_key, child_name, lock_pkgs)
        if child_key is None or child_key in reachable:
            continue
        reachable.add(child_key)
        entry = lock_pkgs[child_key]
        for kind in ("dependencies", "peerDependencies", "optionalDependencies"):
            for grandchild_name in entry.get(kind, {}):
                queue.append((child_key, grandchild_name))
        for bundled_name in entry.get("bundleDependencies", []) or []:
            queue.append((child_key, bundled_name))

    orphans: list[str] = []
    for key, entry in lock_pkgs.items():
        if not key:
            continue
        if entry.get("link"):
            continue
        if not entry.get("version"):
            continue
        if key not in reachable:
            orphans.append(key)
    return sorted(orphans)
