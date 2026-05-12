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

import math
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
    """Entries with no ``resolved`` AND no ``inBundle: true`` — suspicious phantom
    entries that have a version declaration but nothing telling npm where to get
    the bytes. Most commonly dedupe artefacts; in a tampered lockfile they could
    also be a sign someone removed a ``resolved`` URL hoping cas wouldn't notice."""

    bundled: list[str] = field(default_factory=list)
    """Entries flagged ``inBundle: true`` — bytes come from the parent's tarball
    rather than a registry. Reported separately from ``unresolved`` so reviewers
    can distinguish legitimate ``bundleDependencies`` from suspicious phantoms.
    The SRI gate (``cas sri verify``) is what actually anchors these to the
    parent's integrity hash."""

    detected_primary_hosts: list[str] = field(default_factory=list)
    """When auto-detect is used (no explicit ``--allowed-host`` flags), the
    hosts cas inferred from the lockfile as the project's legitimate registries.
    A mix of CodeArtifact + public npm is common during migrations and is
    accepted — both count as primary as long as each carries a substantial
    share of the entries. One-off anomalies (an attacker-pinned host appearing
    once in a tampered lockfile) fall below the threshold and are reported as
    leaks. Empty when explicit ``--allowed-host`` patterns were supplied."""

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


_AUTO_DETECT_SECONDARY_RATIO = 0.2
"""Auto-detect threshold: any host with >= 20% of the top host's entry count
is also accepted as primary. Below that, the host is treated as an anomaly
(potential leak). 20% is high enough to accept legitimate multi-registry
setups (CodeArtifact + corporate mirror; a project mid-migration with most
entries on one registry and a chunk on another) but low enough to catch a
single dep-confusion entry slipping into an otherwise-consistent lockfile."""


def _auto_detect_primary_hosts(hosts_by_count: dict[str, int]) -> list[str]:
    """Pick every host that meets the auto-detect threshold.

    Algorithm: find the top host by entry count. Every host with at least
    ``ratio * top_count`` entries is "primary." Returns hosts sorted by
    descending count.
    """
    if not hosts_by_count:
        return []
    top_count = max(hosts_by_count.values())
    # Round UP so a 9-entry top + 1-entry secondary doesn't accidentally
    # accept the secondary at the 1-entry floor (ceil(9*0.2)=2 > 1, leak).
    threshold = max(1, math.ceil(top_count * _AUTO_DETECT_SECONDARY_RATIO))
    return [
        host
        for host, _ in sorted(hosts_by_count.items(), key=lambda kv: -kv[1])
        if hosts_by_count[host] >= threshold
    ]


def check_npm_registry(
    lockfile_path: Path,
    allowed_hosts: Iterable[str] | None = None,
) -> RegistryReport:
    """Inspect every lockfile entry's ``resolved`` URL and classify by host.

    An entry is *leaked* when its tarball was resolved from a host that
    doesn't match any of the ``allowed_hosts`` substrings. Git-sourced and
    file/workspace entries are reported separately because they bypass the
    registry contract entirely — useful signal even if not a registry leak.

    Pass ``allowed_hosts=None`` (or omit the argument) to auto-detect the
    project's primary registry from the lockfile itself. Auto-detect picks
    every host that holds at least 20% of the top host's entry count, so a
    project that legitimately uses CodeArtifact + npm (or CA + a corporate
    mirror) passes cleanly; only true one-off anomalies (which is what a
    dependency-confusion attack would look like) get flagged. The detected
    list is returned in ``report.detected_primary_hosts``.

    Raises ``ValueError`` for unsupported lockfileVersion 1 (no per-entry
    ``resolved`` URLs to inspect).
    """
    if allowed_hosts is None:
        explicit_allowed: list[str] | None = None
    else:
        explicit_allowed = list(allowed_hosts)
        if not explicit_allowed:
            # Caller passed an empty list — that's ambiguous between "use
            # auto-detect" and "I forgot to set this." Treat as a config
            # error so the caller has to pick explicitly.
            raise ValueError(
                "at least one --allowed-host pattern is required "
                "(or omit the flag entirely for auto-detect)"
            )
    auto_detect = explicit_allowed is None

    lock = load_lockfile(lockfile_path)

    # First pass: build the host-distribution histogram. We need it before
    # classifying entries when in auto-detect mode.
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})
    histogram: dict[str, int] = {}
    for key, entry in pkgs.items():
        if not key or entry.get("link") or not entry.get("version"):
            continue
        resolved = entry.get("resolved")
        if not resolved or resolved.startswith(
            ("file:", "./", "../", "/", "git+", "git:", "github:")
        ):
            continue
        if "+git@" in resolved:
            continue
        parsed = urlparse(resolved)
        if parsed.scheme != "https":
            continue
        host = parsed.hostname or "(unknown)"
        histogram[host] = histogram.get(host, 0) + 1

    if auto_detect:
        primary = _auto_detect_primary_hosts(histogram)
        allowed: list[str] = primary
    else:
        primary = []
        allowed = explicit_allowed or []

    report = RegistryReport()
    report.detected_primary_hosts = primary
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
            if entry.get("inBundle"):
                report.bundled.append(key)
            else:
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
