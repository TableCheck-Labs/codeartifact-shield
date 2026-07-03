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

from codeartifact_shield._lockfile import is_installable_entry, load_lockfile
from codeartifact_shield.lockfiles import LockFormat, ResolvedKind, load_normalized

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
            if not is_installable_entry(parent_key, parent_entry):
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


def check_drift(
    project_dir: Path,
    fmt: LockFormat,
    *,
    ranges: bool = False,
    transitive: bool = True,
) -> DriftReport:
    """Format-dispatching entry point for the ``drift`` gate.

    ``fmt`` is resolved by the CLI (which probes the directory and disambiguates
    multiple lockfiles). npm keeps the byte-identical native path; pnpm uses the
    importer/snapshot graph.
    """
    if fmt is LockFormat.NPM:
        return check_npm_drift(project_dir, ranges=ranges, transitive=transitive)
    if fmt is LockFormat.PNPM:
        return check_pnpm_drift(project_dir, ranges=ranges, transitive=transitive)
    if fmt is LockFormat.DENO:
        return check_deno_drift(project_dir, ranges=ranges, transitive=transitive)
    if fmt is LockFormat.BUN:
        return check_bun_drift(project_dir, ranges=ranges, transitive=transitive)
    raise ValueError(f"drift is not supported for {fmt.value} lockfiles")


def _pnpm_base(version_spec: str) -> str:
    """Strip a pnpm resolved-version's peer suffix: ``1.2.3(x@4)`` -> ``1.2.3``."""
    paren = version_spec.find("(")
    return version_spec[:paren] if paren != -1 else version_spec


def check_pnpm_drift(
    project_dir: Path,
    *,
    ranges: bool = False,
    transitive: bool = True,
) -> DriftReport:
    """Compare ``pnpm-lock.yaml`` importer declarations to resolved versions.

    Direct drift compares each importer dependency's ``specifier`` against its
    resolved ``version``. Transitive drift verifies every package's dependency
    edges point at a real ``name@version`` in the lockfile (a dangling edge is a
    tampering signature). Orphan detection walks the importer roots and flags
    any ``packages`` entry unreachable from them.
    """
    lock_path = project_dir / "pnpm-lock.yaml"
    if not lock_path.exists():
        raise FileNotFoundError(f"no pnpm-lock.yaml in {project_dir}")
    normalized = load_normalized(lock_path, LockFormat.PNPM)
    lock: dict[str, Any] = normalized.raw
    importers = lock.get("importers")
    if not isinstance(importers, dict) or not importers:
        # Single-package v6 lockfile: top-level dependencies act as importer ".".
        root_block: dict[str, Any] = {}
        for scope in ("dependencies", "devDependencies", "optionalDependencies"):
            block = lock.get(scope)
            if isinstance(block, dict):
                root_block[scope] = block
        importers = {".": root_block} if root_block else {}

    report = DriftReport()

    entries = normalized.entries
    by_key = {e.key: e for e in entries}
    # Map base ``name@version`` -> the package's native key, so a resolved
    # version string can be turned into the entry it points at.
    base_to_key: dict[str, str] = {f"{e.name}@{e.version}": e.key for e in entries}

    def resolve_node(name: str, resolved: str) -> str | None:
        """Turn a ``(dep name, resolved version-string)`` edge into a package key."""
        if resolved in by_key:
            # git/tarball entries: the resolved string *is* the package key.
            return resolved
        base = f"{name}@{_pnpm_base(resolved)}"
        return base_to_key.get(base)

    # ---- Direct deps (importer specifier vs resolved version) ----------------
    for importer_path, blocks in importers.items():
        if not isinstance(blocks, dict):
            continue
        for kind in ("dependencies", "devDependencies", "optionalDependencies"):
            block = blocks.get(kind)
            if not isinstance(block, dict):
                continue
            for name, info in block.items():
                if isinstance(info, dict):
                    declared = str(info.get("specifier", ""))
                    resolved = str(info.get("version", ""))
                else:
                    declared = str(info)
                    resolved = str(info)
                actual = _pnpm_base(resolved)
                if actual.startswith("link:") or declared.startswith("workspace:"):
                    # Intra-workspace link — resolved on-repo, not a drift.
                    continue
                label = name if importer_path in ("", ".") else f"{importer_path}:{name}"
                if ranges:
                    outcome = _satisfies(actual, declared)
                    if outcome is False:
                        report.mismatches.append((kind, label, declared, actual))
                else:
                    if not _is_semver_declaration(declared):
                        continue
                    if actual != declared:
                        report.mismatches.append((kind, label, declared, actual))

    # ---- Transitive deps (edges must reference a real package) ---------------
    if transitive:
        for entry in entries:
            parent_base = f"{entry.name}@{entry.version}"
            for dep_kind, deps in (
                ("dependencies", entry.dependencies),
                ("optionalDependencies", entry.optional_dependencies),
            ):
                for child_name, child_version in deps.items():
                    if resolve_node(child_name, str(child_version)) is not None:
                        continue
                    if dep_kind != "dependencies":
                        continue
                    report.transitive_mismatches.append(
                        (parent_base, child_name, str(child_version), "MISSING")
                    )

        # ---- Orphan detection: BFS over package keys from importer roots -----
        reachable: set[str] = set()
        queue: list[str] = []
        for blocks in importers.values():
            if not isinstance(blocks, dict):
                continue
            for kind in ("dependencies", "devDependencies", "optionalDependencies"):
                block = blocks.get(kind)
                if not isinstance(block, dict):
                    continue
                for name, info in block.items():
                    resolved = info.get("version", "") if isinstance(info, dict) else info
                    if isinstance(resolved, str) and resolved.startswith("link:"):
                        continue
                    node = resolve_node(name, str(resolved))
                    if node is not None:
                        queue.append(node)
        while queue:
            node = queue.pop()
            if node in reachable:
                continue
            reachable.add(node)
            cur = by_key.get(node)
            if cur is None:
                continue
            for deps in (cur.dependencies, cur.optional_dependencies):
                for child_name, child_version in deps.items():
                    child = resolve_node(child_name, str(child_version))
                    if child is not None and child not in reachable:
                        queue.append(child)
        report.orphan_entries = sorted(set(by_key) - reachable)

    return report


def _resolve_bun_key(
    parent_key: str, child: str, pkg_keys: set[str]
) -> str | None:
    """Resolve a bun dependency edge to a ``packages`` key.

    Bun keys nested (version-conflicted) packages by a ``/``-separated install
    path, e.g. ``is-even/is-odd/is-number``. Resolution mirrors npm's
    nested-before-hoisted rule: for a parent at ``a/b`` and child ``x`` the
    candidates are ``a/b/x``, then ``a/x``, then the hoisted ``x``; the first
    that exists wins.
    """
    if parent_key:
        base = parent_key
        while True:
            candidate = f"{base}/{child}"
            if candidate in pkg_keys:
                return candidate
            idx = base.rfind("/")
            if idx == -1:
                break
            base = base[:idx]
    return child if child in pkg_keys else None


def check_bun_drift(
    project_dir: Path,
    *,
    ranges: bool = False,
    transitive: bool = True,
) -> DriftReport:
    """Compare ``bun.lock`` workspace declarations to resolved package versions.

    Direct drift compares each workspace importer's declared dependency spec to
    the resolved version in the ``packages`` map. Transitive drift walks every
    package's own dependency edges and verifies each child resolves to a real
    entry (a dangling edge is a tampering signature). Orphan detection BFS-walks
    the workspace roots and flags any ``packages`` entry left unreachable.
    """
    lock_path = project_dir / "bun.lock"
    if not lock_path.exists():
        raise FileNotFoundError(f"no bun.lock in {project_dir}")
    normalized = load_normalized(lock_path, LockFormat.BUN)

    entries = normalized.entries
    by_key = {e.key: e for e in entries}
    pkg_keys = set(by_key)
    name_to_keys: dict[str, list[str]] = {}
    for e in entries:
        name_to_keys.setdefault(e.name, []).append(e.key)

    def top_level_version(name: str) -> str | None:
        """Resolved version for a workspace-declared dependency (hoisted first)."""
        if name in by_key:
            return by_key[name].version
        keys = name_to_keys.get(name)
        return by_key[keys[0]].version if keys else None

    report = DriftReport()

    # ---- Direct deps (workspace declaration vs resolved version) -------------
    for importer_path, blocks in normalized.workspaces.items():
        for kind in ("dependencies", "devDependencies", "optionalDependencies"):
            block = blocks.get(kind)
            if not isinstance(block, dict):
                continue
            for name, declared in block.items():
                declared = str(declared)
                if declared.startswith(("workspace:", "link:", "file:")):
                    # Intra-repo link — resolved on-repo, not a drift.
                    continue
                actual = top_level_version(name)
                label = name if importer_path in ("", ".") else f"{importer_path}:{name}"
                if actual is None:
                    report.mismatches.append((kind, label, declared, "MISSING"))
                    continue
                if ranges:
                    outcome = _satisfies(actual, declared)
                    if outcome is False:
                        report.mismatches.append((kind, label, declared, actual))
                else:
                    if not _is_semver_declaration(declared):
                        continue
                    if actual != declared:
                        report.mismatches.append((kind, label, declared, actual))

    # ---- Transitive deps (edges must reference a real package) --------------
    if transitive:
        for entry in entries:
            parent_base = f"{entry.name}@{entry.version}"
            for dep_kind, deps in (
                ("dependencies", entry.dependencies),
                ("optionalDependencies", entry.optional_dependencies),
            ):
                for child_name, child_range in deps.items():
                    if _resolve_bun_key(entry.key, child_name, pkg_keys) is not None:
                        continue
                    if dep_kind != "dependencies":
                        continue
                    report.transitive_mismatches.append(
                        (parent_base, child_name, str(child_range), "MISSING")
                    )

        # ---- Orphan detection: BFS over package keys from workspace roots ----
        reachable: set[str] = set()
        queue: list[str] = []
        for blocks in normalized.workspaces.values():
            for kind in ("dependencies", "devDependencies", "optionalDependencies"):
                block = blocks.get(kind)
                if not isinstance(block, dict):
                    continue
                for name in block:
                    node = _resolve_bun_key("", name, pkg_keys)
                    if node is not None:
                        queue.append(node)
        while queue:
            node = queue.pop()
            if node in reachable:
                continue
            reachable.add(node)
            cur = by_key.get(node)
            if cur is None:
                continue
            for deps in (cur.dependencies, cur.optional_dependencies):
                for child_name in deps:
                    child = _resolve_bun_key(node, child_name, pkg_keys)
                    if child is not None and child not in reachable:
                        queue.append(child)
        # workspace: link entries are the workspaces themselves, not orphans.
        linkish = {
            e.key
            for e in entries
            if e.resolved_kind in (ResolvedKind.LINK, ResolvedKind.FILE)
        }
        report.orphan_entries = sorted(pkg_keys - reachable - linkish)

    return report


def check_deno_drift(
    project_dir: Path,
    *,
    ranges: bool = False,
    transitive: bool = True,
) -> DriftReport:
    """Compare ``deno.json`` imports to ``deno.lock`` resolutions (direct only).

    Direct drift: every ``npm:``/``jsr:`` import in ``deno.json`` must appear in
    the lockfile ``specifiers`` map, and the resolved version must satisfy the
    declared range (``--ranges``) or equal it (default). Missing specifiers are
    reported as ``MISSING``.

    Orphan detection (``transitive`` on): npm/jsr lockfile entries not reachable
    from the ``specifiers`` roots are flagged. Remote ``https://`` modules are
    exact by construction, so there is no transitive range check for them.
    """
    from codeartifact_shield.lockfiles.deno import (
        manifest_imports,
        read_deno_manifest,
    )

    lock_path = project_dir / "deno.lock"
    if not lock_path.exists():
        raise FileNotFoundError(f"no deno.lock in {project_dir}")
    normalized = load_normalized(lock_path, LockFormat.DENO)
    specifiers: dict[str, str] = dict(
        normalized.workspaces.get("", {}).get("dependencies", {})
    )
    manifest = read_deno_manifest(project_dir)
    imports = manifest_imports(manifest)

    report = DriftReport()

    # ---- Direct deps (deno.json import spec vs lockfile resolution) ----------
    for _alias, value in imports.items():
        if not (value.startswith("npm:") or value.startswith("jsr:")):
            continue
        resolved = specifiers.get(value)
        # deno's specifiers map is keyed by the request spec (e.g. "npm:chalk@^5").
        label = value
        if resolved is None:
            report.mismatches.append(("imports", label, value, "MISSING"))
            continue
        declared_range = _deno_range(value)
        actual = _deno_resolved_version(resolved)
        if not actual:
            continue
        if ranges:
            outcome = _satisfies(actual, declared_range)
            if outcome is False:
                report.mismatches.append(("imports", label, value, actual))
        else:
            if not _is_semver_declaration(declared_range):
                continue
            if actual != declared_range:
                report.mismatches.append(("imports", label, value, actual))

    # ---- Orphan detection over the npm + jsr dependency graph ----------------
    if transitive:
        report.orphan_entries = _deno_orphans(normalized, specifiers)

    return report


def _deno_range(spec: str) -> str:
    """Extract the version range from a ``npm:``/``jsr:`` import specifier."""
    body = spec.split(":", 1)[1] if ":" in spec else spec
    at = body.find("@", 1)
    return body[at + 1 :] if at != -1 else ""


def _deno_resolved_version(resolved: str) -> str:
    """Extract the bare version from a specifiers-map value.

    Handles both the prefixed v3 form (``npm:chalk@5.3.0``) and the bare v4/v5
    form (``5.3.0``).
    """
    if resolved.startswith(("npm:", "jsr:")):
        body = resolved.split(":", 1)[1]
        at = body.find("@", 1)
        return body[at + 1 :] if at != -1 else body
    return resolved


def _deno_orphans(
    normalized: Any, specifiers: dict[str, str]
) -> list[str]:
    """Return npm/jsr lockfile keys unreachable from the ``specifiers`` roots."""
    from codeartifact_shield.lockfiles._model import Ecosystem

    pkg_entries = {
        e.key: e
        for e in normalized.entries
        if e.ecosystem in (Ecosystem.NPM, Ecosystem.JSR)
    }
    base_to_key = {f"{e.name}@{e.version}": e.key for e in pkg_entries.values()}
    name_to_keys: dict[str, list[str]] = {}
    for e in pkg_entries.values():
        name_to_keys.setdefault(e.name, []).append(e.key)

    def resolve_key(resolved: str) -> str | None:
        if resolved in pkg_entries:
            return resolved
        body = _strip_deno_prefix(resolved)
        if body in pkg_entries:
            return body
        return base_to_key.get(body)

    reachable: set[str] = set()
    queue: list[str] = []
    for spec_key, resolved in specifiers.items():
        # v4/v5 specifier values are bare versions (the name lives in the key);
        # v3 values carry the ``npm:``/``jsr:`` prefix. Recover name+version.
        name = _split_deno_spec_name(spec_key)
        version = _deno_resolved_version(resolved)
        node = resolve_key(resolved)
        if node is None and name:
            node = base_to_key.get(f"{name}@{version}")
        if node is None and name:
            keys = name_to_keys.get(name)
            node = keys[0] if keys else None
        if node is not None:
            queue.append(node)
    while queue:
        node = queue.pop()
        if node in reachable:
            continue
        reachable.add(node)
        entry = pkg_entries.get(node)
        if entry is None:
            continue
        for child_name, child_version in entry.dependencies.items():
            # Child deps carry a range (jsr) or an exact version (npm); try an
            # exact base match, then fall back to name-only (a range points at
            # whatever the lockfile resolved for that name).
            exact = base_to_key.get(f"{child_name}@{child_version}")
            candidates = [exact] if exact else name_to_keys.get(child_name, [])
            for child in candidates:
                if child is not None and child not in reachable:
                    queue.append(child)
    return sorted(set(pkg_entries) - reachable)


def _strip_deno_prefix(value: str) -> str:
    for prefix in ("npm:", "jsr:"):
        if value.startswith(prefix):
            return value[len(prefix) :]
    return value


def _split_deno_spec_name(spec_key: str) -> str:
    """Extract the package name from a specifier key (``npm:chalk@^5`` -> chalk)."""
    body = _strip_deno_prefix(spec_key)
    at = body.find("@", 1)
    return body[:at] if at != -1 else body


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
        if not is_installable_entry(key, entry):
            continue
        if not entry.get("version"):
            continue
        if key not in reachable:
            orphans.append(key)
    return sorted(orphans)
