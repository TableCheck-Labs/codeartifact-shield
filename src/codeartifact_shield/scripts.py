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

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeartifact_shield._lockfile import extract_package_name, load_lockfile


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

    @property
    def clean(self) -> bool:
        return not self.flagged


def check_install_scripts(
    lockfile_path: Path,
    allowed: Iterable[str] = (),
) -> ScriptsReport:
    """Walk the lockfile and report every entry that will run lifecycle scripts.

    Args:
        lockfile_path: ``package-lock.json`` to audit.
        allowed: Package names (bare, including scope where applicable) that
            are permitted to run install scripts. Matched exactly against the
            entry's package name. Build-essential native modules
            (``esbuild``, ``fsevents``, ``@parcel/watcher``, etc.) typically
            need their lifecycle scripts to compile platform binaries —
            those should be reviewed and added to the allowlist deliberately.

    Returns a :class:`ScriptsReport`. ``report.clean`` is True iff every
    script-running entry is in the allowlist.
    """
    lock = load_lockfile(lockfile_path)
    allowlist = {name.lower() for name in allowed}
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})

    report = ScriptsReport()
    for key, entry in pkgs.items():
        if not key:
            continue
        if entry.get("link"):
            continue
        if not entry.get("hasInstallScript"):
            continue
        finding = ScriptFinding(
            lockfile_key=key,
            package_name=extract_package_name(key, entry),
            version=entry.get("version", ""),
        )
        if finding.package_name.lower() in allowlist:
            report.allowed.append(finding)
        else:
            report.flagged.append(finding)
    return report
