"""Lifecycle-script detection — find every dep that runs code at install time.

Threat model
------------

When ``npm install`` (or ``npm ci``) runs, every dep whose ``package.json``
declares a ``preinstall``, ``install``, or ``postinstall`` script gets to
execute arbitrary code on the install machine — typically a developer's
laptop or a CI runner. That's the highest-blast-radius unhandled vector in
the npm ecosystem:

* Account-takeover of any dep maintainer → RCE on every consumer's CI.
* Typosquatted package added to package.json by mistake → RCE.
* Compromised tarball served by registry (mitigated by SRI, but only if
  SRI is present and verified, which is exactly what cas's other gates
  enforce).

npm marks every such entry in the lockfile with ``hasInstallScript: true``.
This module surfaces them so a project can audit-and-allowlist instead of
implicitly trusting hundreds of transitive maintainers.

Why this isn't covered by SRI
-----------------------------

SRI binds the bytes to a hash, but bytes-with-malicious-lifecycle-scripts
still execute at install time. SRI only protects you against *unexpected*
substitution — not against a maintainer who deliberately ships a malicious
``postinstall`` hook to all of their consumers. Defense is auditing the
script-running surface and pinning it to a known-good allowlist.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from codeartifact_shield._allowlist import PackageAllowlist
from codeartifact_shield.lockfiles import Capability, LockFormat, load_normalized
from codeartifact_shield.lockfiles.pnpm import read_pnpm_workspace_settings


@dataclass
class ScriptFinding:
    """One package that will execute code at install time."""

    lockfile_key: str
    """Path in the lockfile, e.g. ``node_modules/foo/node_modules/bar``."""

    package_name: str
    """Bare package name (with scope, if any), e.g. ``@scope/name``."""

    version: str
    """Resolved version of the script-running entry."""


@dataclass
class ScriptsReport:
    """Findings from :func:`check_install_scripts`."""

    flagged: list[ScriptFinding] = field(default_factory=list)
    """Entries with ``hasInstallScript: true`` that aren't in the allowlist."""

    allowed: list[ScriptFinding] = field(default_factory=list)
    """Entries with ``hasInstallScript: true`` that ARE in the allowlist.

    Tracked separately so reviewers can see what the allowlist is letting
    through — drift in the allowlist's coverage is itself a useful signal.
    """

    policy_unknown: bool = False
    """True only for a pnpm lockfileVersion-9 lockfile where the install-script
    policy (``onlyBuiltDependencies``) is nowhere discoverable. v9 dropped the
    per-entry ``requiresBuild`` flag, so with no policy cas cannot tell which
    packages may run build scripts — fail closed rather than pass blind."""

    script_info_available: bool = True
    """False when the lockfile format can't record install-script metadata
    (pnpm v9). Surfaced as an INFO note; not a failure on its own."""

    trusted_mode: bool = False
    """True for bun.lock, where the gate audits ``trustedDependencies`` (the
    only packages bun will run lifecycle scripts for) rather than a per-entry
    ``hasInstallScript`` flag. Flagged entries are trusted deps not in
    ``--allow``."""

    @property
    def clean(self) -> bool:
        return not self.flagged and not self.policy_unknown


def check_install_scripts(
    lockfile_path: Path,
    allowed: Iterable[str] = (),
    fmt: LockFormat | None = None,
) -> ScriptsReport:
    """Walk the lockfile and report every entry that will run lifecycle scripts.

    Args:
        lockfile_path: lockfile to audit (npm ``package-lock.json`` or
            ``pnpm-lock.yaml``).
        allowed: Package names (bare, including scope where applicable) that
            are permitted to run install scripts. Matched exactly against the
            entry's package name. Build-essential native modules
            (``esbuild``, ``fsevents``, ``@parcel/watcher``, etc.) typically
            need their lifecycle scripts to compile platform binaries —
            those should be reviewed and added to the allowlist deliberately.
        fmt: Force a lockfile format instead of auto-detecting from filename.

    Returns a :class:`ScriptsReport`. ``report.clean`` is True iff every
    script-running entry is in the allowlist (and, for pnpm v9, a build policy
    was discoverable).
    """
    normalized = load_normalized(lockfile_path, fmt)
    allowlist = PackageAllowlist.from_entries(allowed)
    report = ScriptsReport()

    if normalized.format is LockFormat.DENO:
        # Deno never runs npm lifecycle scripts unless explicitly opted in with
        # `deno install --allow-scripts`; the lockfile records no script flag.
        # Report the npm-dependency surface as INFO, never fail.
        report.script_info_available = False
        return report

    if normalized.format is LockFormat.BUN:
        # Bun runs lifecycle scripts only for packages named in
        # ``trustedDependencies``; audit that list against the allowlist.
        _check_bun_scripts(normalized, allowlist, report)
        return report

    if (
        normalized.format is LockFormat.PNPM
        and Capability.INSTALL_SCRIPTS not in normalized.capabilities
    ):
        # pnpm lockfileVersion 9: no per-entry ``requiresBuild``. Audit the
        # project's declared build policy (``onlyBuiltDependencies``) instead.
        _check_pnpm_v9_scripts(lockfile_path, normalized, allowlist, report)
        return report

    for entry in normalized.entries:
        if not entry.has_install_script:
            continue
        finding = ScriptFinding(
            lockfile_key=entry.key,
            package_name=entry.name,
            version=entry.version,
        )
        if allowlist.allows(finding.package_name, finding.version):
            report.allowed.append(finding)
        else:
            report.flagged.append(finding)
    return report


def _check_bun_scripts(
    normalized: object,
    allowlist: PackageAllowlist,
    report: ScriptsReport,
) -> None:
    """Audit a bun.lock's ``trustedDependencies`` against the allowlist.

    Each trusted package not covered by ``--allow`` is a HIGH ``install_script``
    finding (bun will run its lifecycle scripts at install). The version is
    recovered from the lockfile's resolved entries.
    """
    from codeartifact_shield.lockfiles._model import NormalizedLockfile
    from codeartifact_shield.lockfiles.bun import trusted_dependencies

    assert isinstance(normalized, NormalizedLockfile)
    report.trusted_mode = True
    versions = {e.name: e.version for e in normalized.entries}
    for name in trusted_dependencies(normalized.raw):
        finding = ScriptFinding(
            lockfile_key=name,
            package_name=name,
            version=versions.get(name, ""),
        )
        if allowlist.allows(finding.package_name, finding.version):
            report.allowed.append(finding)
        else:
            report.flagged.append(finding)


def _read_only_built_dependencies(project_dir: Path) -> list[str] | None:
    """Return the pnpm ``onlyBuiltDependencies`` allowlist, or None if undeclared.

    Sources, in precedence order: a sibling ``pnpm-workspace.yaml`` (pnpm 10's
    home for the setting), then ``package.json``'s ``pnpm.onlyBuiltDependencies``
    (the older location). ``None`` means the project declares no build policy at
    all — the fail-closed trigger for v9.
    """
    settings = read_pnpm_workspace_settings(project_dir)
    if "onlyBuiltDependencies" in settings:
        value = settings.get("onlyBuiltDependencies")
        return [str(x) for x in value] if isinstance(value, list) else []

    pkg_path = project_dir / "package.json"
    if pkg_path.exists():
        try:
            pkg = json.loads(pkg_path.read_text())
        except (json.JSONDecodeError, OSError):
            pkg = {}
        pnpm_cfg = pkg.get("pnpm") if isinstance(pkg, dict) else None
        if isinstance(pnpm_cfg, dict) and "onlyBuiltDependencies" in pnpm_cfg:
            value = pnpm_cfg.get("onlyBuiltDependencies")
            return [str(x) for x in value] if isinstance(value, list) else []
    return None


def _check_pnpm_v9_scripts(
    lockfile_path: Path,
    normalized: object,
    allowlist: PackageAllowlist,
    report: ScriptsReport,
) -> None:
    from codeartifact_shield.lockfiles._model import NormalizedLockfile

    assert isinstance(normalized, NormalizedLockfile)
    report.script_info_available = False
    built = _read_only_built_dependencies(lockfile_path.parent)
    if built is None:
        # No discoverable build policy — cas can't tell what runs scripts.
        report.policy_unknown = True
        return
    versions = {e.name: e.version for e in normalized.entries}
    for name in built:
        finding = ScriptFinding(
            lockfile_key=name,
            package_name=name,
            version=versions.get(name, ""),
        )
        if allowlist.allows(finding.package_name, finding.version):
            report.allowed.append(finding)
        else:
            report.flagged.append(finding)
