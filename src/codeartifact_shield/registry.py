"""Registry-leakage detection for npm package-lock.json.

A repo that's *meant* to install from AWS CodeArtifact can quietly start
pulling from the public registry instead — a stray ``resolved`` URL in
the lockfile is enough. Once that happens, the integrity guarantees of
the CodeArtifact proxy don't apply to that entry, and a malicious package
published under the same name on npmjs.com (dependency confusion) can
land in production.

This module walks ``package-lock.json`` only — no ``.npmrc``, no machine
config — because the lockfile is what ``npm ci`` actually obeys. The
project must declare its allowed registry hosts to the checker
explicitly via ``--allowed-host`` flags.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from codeartifact_shield._lockfile import load_lockfile


@dataclass
class RegistryReport:
    """Per-host breakdown of where a lockfile resolves its packages from."""

    by_host: dict[str, int] = field(default_factory=dict)
    """Count of lockfile entries resolved from each host."""

    leaked: list[tuple[str, str]] = field(default_factory=list)
    """``(lockfile_key, host)`` for entries resolved from a non-allowed host."""

    git_sourced: list[tuple[str, str]] = field(default_factory=list)
    """``(lockfile_key, ref)`` — entries pulled directly from git, bypassing any registry."""

    file_sourced: list[str] = field(default_factory=list)
    """Workspace / local-path entries — neither a registry resolution nor a leak."""

    unresolved: list[str] = field(default_factory=list)
    """Entries with no ``resolved`` field — usually deduped phantoms; can't be classified."""

    @property
    def clean(self) -> bool:
        return not self.leaked and not self.git_sourced

    @property
    def mixed(self) -> bool:
        """True when more than one distinct host appears in the lockfile."""
        return len(self.by_host) > 1


def host_allowed(host: str, allowed: Iterable[str]) -> bool:
    """Label-anchored, case-insensitive hostname-suffix match.

    A pattern matches a host iff the host *equals* the pattern (case-
    insensitive) or *ends with ``.`` + the pattern*. Leading/trailing dots
    in the pattern are stripped before comparison, so a user writing
    ``.foo.example.com`` (a common convention for "any subdomain of") still
    works as expected.

    This is intentionally strict. Substring matching — which was the
    previous behaviour — let an attacker-controlled host of the form
    ``evil.<pattern-as-substring>.attacker.com`` pass an allowlist; any
    pattern with internal dots (``.d.codeartifact.``) was vulnerable.
    Patterns must now specify the full host suffix
    (``.d.codeartifact.ap-northeast-1.amazonaws.com``), which gives the
    same operational result on legitimate hosts while closing the
    impersonation vector.

    Empty allowed-list means *nothing* is allowed.
    """
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for pattern in allowed:
        pat = (pattern or "").lower().strip(".")
        if not pat:
            continue
        if host == pat or host.endswith("." + pat):
            return True
    return False


# Back-compat alias for internal callers.
_host_allowed = host_allowed


def check_npm_registry(
    lockfile_path: Path,
    allowed_hosts: Iterable[str],
) -> RegistryReport:
    """Inspect every lockfile entry's ``resolved`` URL and classify by host.

    An entry is *leaked* when its tarball was resolved from a host that
    doesn't match any of the ``allowed_hosts`` substrings. Git-sourced and
    file/workspace entries are reported separately because they bypass the
    registry contract entirely — useful signal even if not a registry leak.

    Raises ``ValueError`` for unsupported lockfileVersion 1 (no per-entry
    ``resolved`` URLs to inspect).
    """
    allowed = list(allowed_hosts)
    if not allowed:
        raise ValueError("at least one --allowed-host pattern is required")

    lock = load_lockfile(lockfile_path)

    report = RegistryReport()
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})
    for key, entry in pkgs.items():
        if not key:
            # The "" entry is the project itself.
            continue
        if entry.get("link"):
            # Workspace symlinks resolve to file paths, not a registry.
            report.file_sourced.append(key)
            continue
        if not entry.get("version"):
            continue
        resolved = entry.get("resolved")
        if not resolved:
            report.unresolved.append(key)
            continue
        if resolved.startswith(("file:", "./", "../", "/")):
            report.file_sourced.append(key)
            continue
        if resolved.startswith(("git+", "git:", "github:")) or "+git@" in resolved:
            report.git_sourced.append((key, resolved))
            continue
        parsed = urlparse(resolved)
        host = parsed.hostname or "(unknown)"
        report.by_host[host] = report.by_host.get(host, 0) + 1
        # Enforce https://. http:// is MITM-able on any untrusted hop between
        # the install machine and the registry; other schemes (ftp://, ws://,
        # etc.) have no legitimate place in a modern lockfile entry. Treat
        # the entry as leaked with a scheme tag so reviewers can see why.
        if parsed.scheme != "https":
            report.leaked.append((key, f"{host} (insecure scheme: {parsed.scheme}://)"))
            continue
        if not host_allowed(host, allowed):
            report.leaked.append((key, host))

    return report
