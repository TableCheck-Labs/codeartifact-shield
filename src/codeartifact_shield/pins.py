"""Pin-policy detection — flag direct-dep declarations that aren't exact-pinned.

Threat model
------------

``package.json`` is the trust boundary the project actually controls. Even
with a clean lockfile, unpinned ranges in ``package.json`` mean:

1. A new contributor running ``npm install`` (without ``--frozen-lockfile``)
   regenerates the lockfile to whatever satisfies the range — picking up
   any version published after the original lock was committed. If one of
   those versions is a compromised release, the contributor's machine and
   any CI step that runs ``npm install`` (vs ``npm ci``) are exposed.
2. Running ``npm install <new-package>`` opportunistically widens *other*
   deps in the same range, silently expanding the trust set.
3. Auto-bump tooling (Renovate / Dependabot / Snyk auto-PR) treats caret
   ranges as standing permission to upgrade with no review.

Reproducible-builds guidance (Google, GitHub Engineering, OWASP NPM
Top-10) all converge on the same recommendation: pin direct deps to
exact versions; let the lockfile + SRI carry the transitive guarantee.

What counts as pinned
---------------------

* Exact SemVer (``1.2.3``, ``1.2.3-rc.1``, ``1.2.3+build.7``).
* Workspace protocol (``workspace:*``, ``workspace:^``, ``workspace:1.2.3``)
  — exempt, since the dep is resolved intra-monorepo.
* npm aliases with an exact target (``npm:lodash@4.17.21``) — the
  underlying spec is recursed on.
* Git URLs with a full 40-char commit SHA fragment
  (``git+https://github.com/x/y.git#<40-hex>``).
* GitHub shorthand with a full 40-char SHA (``user/repo#<40-hex>``).

Everything else (caret/tilde/wildcard ranges, dist-tags like ``latest``,
``file:``/``link:`` paths, tarball URLs, git refs that aren't full
40-char SHAs) is flagged as ``unpinned``.

peerDependencies are excluded by default — they're idiomatically ranges
(the consumer is supposed to satisfy the range from its own tree). Pass
``include_peer=True`` to audit them too.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Pattern matchers
# ---------------------------------------------------------------------------

# Strict SemVer 2.0.0 — major.minor.patch with optional prerelease and build.
_SEMVER_EXACT = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
)

# 40-char lowercase hex (full git commit SHA). Short SHAs are rejected —
# git's collision-resistance argument only holds at full length.
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

_NPM_ALIAS = re.compile(r"^npm:(@?[^@]+)@(.+)$")

DEFAULT_SCOPES: tuple[str, ...] = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
)


@dataclass
class PinFinding:
    """One direct-dep declaration that isn't exact-pinned."""

    scope: str
    """Which package.json bucket: dependencies / devDependencies / ..."""

    package_name: str
    """Bare package name (with scope, if any), e.g. ``@scope/name``."""

    declared: str
    """The raw spec from package.json, e.g. ``^1.2.3``, ``latest``, ``file:..``."""

    kind: str
    """Why it failed: ``range`` / ``dist_tag`` / ``file`` / ``link`` /
    ``tarball`` / ``git_ref`` / ``unknown``."""


@dataclass
class PinsReport:
    """Findings from :func:`check_pinning`."""

    flagged: list[PinFinding] = field(default_factory=list)
    """Unpinned declarations that aren't on the allowlist."""

    allowed: list[PinFinding] = field(default_factory=list)
    """Unpinned declarations explicitly exempted via ``--allow``.

    Surfaced separately so reviewers can see what the allowlist covers —
    silent allowlist drift is itself worth flagging.
    """

    total_checked: int = 0
    """Direct-dep declarations across all checked scopes (denominator)."""

    @property
    def clean(self) -> bool:
        return not self.flagged


def _classify(spec: str) -> str | None:
    """Return None if ``spec`` is acceptably pinned; otherwise return the
    finding ``kind`` describing why it isn't.

    The classification taxonomy keeps the human output meaningful (so a
    reviewer sees "this is a caret range" vs "this is a file: path") and
    lets JSON consumers triage automatically.
    """
    if not isinstance(spec, str) or not spec:
        return "unknown"

    s = spec.strip()

    # workspace:* / workspace:^ / workspace:1.2.3 — intra-monorepo, exempt.
    if s.startswith("workspace:"):
        return None

    # npm:<name>@<spec> — recurse on the embedded spec only.
    alias_m = _NPM_ALIAS.match(s)
    if alias_m:
        return _classify(alias_m.group(2))

    # git+... or git://... or ssh+git@... — pinned only with full SHA fragment.
    if (
        s.startswith("git+")
        or s.startswith("git://")
        or s.startswith("git@")
        or s.startswith("ssh://")
    ):
        if "#" in s:
            ref = s.rsplit("#", 1)[1]
            if _FULL_SHA.match(ref):
                return None
        return "git_ref"

    # GitHub / GitLab / Bitbucket shorthand: "user/repo#ref" or
    # "github:user/repo#ref". Pinned only with full SHA fragment.
    for prefix in ("github:", "gitlab:", "bitbucket:", "gist:"):
        if s.startswith(prefix):
            if "#" in s:
                ref = s.rsplit("#", 1)[1]
                if _FULL_SHA.match(ref):
                    return None
            return "git_ref"

    # Bare "user/repo" shorthand (GitHub) — needs SHA fragment to be pinned.
    if re.match(r"^[\w.-]+/[\w.-]+(?:#.+)?$", s) and "/" in s and ":" not in s:
        if "#" in s:
            ref = s.rsplit("#", 1)[1]
            if _FULL_SHA.match(ref):
                return None
        return "git_ref"

    # file: / link: — local path, never pinned to bytes.
    if s.startswith("file:"):
        return "file"
    if s.startswith("link:"):
        return "link"

    # http(s):// — tarball URL. The URL bytes aren't content-addressed,
    # so even a "frozen" URL can serve different bytes over time.
    if s.startswith("http://") or s.startswith("https://"):
        return "tarball"

    # Exact SemVer — the only acceptable plain-string form.
    if _SEMVER_EXACT.match(s):
        return None

    # SemVer range operators: ^, ~, >=, >, <=, <, ||, x/X wildcards, *, latest.
    if s == "*" or s == "latest" or s.startswith("v"):
        return "dist_tag" if s in ("latest", "*") else "range"
    if s[0] in "^~<>=" or " " in s or "||" in s or "x" in s.lower():
        return "range"

    return "unknown"


def check_pinning(
    project_dir: Path,
    allowed: Iterable[str] = (),
    scopes: Iterable[str] = DEFAULT_SCOPES,
    include_peer: bool = False,
) -> PinsReport:
    """Audit a project's ``package.json`` for unpinned direct-dep declarations.

    Args:
        project_dir: Directory containing ``package.json``.
        allowed: Package names (bare, including scope) that are permitted to
            stay unpinned. Use sparingly — every entry here is a hole in the
            reproducibility guarantee. Matched exactly against the dep name.
        scopes: Which package.json buckets to audit. Defaults to
            ``dependencies`` / ``devDependencies`` / ``optionalDependencies``.
        include_peer: If True, also audit ``peerDependencies``. Default False
            because peer deps are idiomatically ranges by npm convention.

    Returns:
        :class:`PinsReport` with ``flagged`` listing unpinned-and-not-allowed
        declarations and ``allowed`` listing unpinned-but-exempted ones.

    Raises:
        FileNotFoundError: if ``package.json`` does not exist.
    """
    pkg_path = project_dir / "package.json"
    if not pkg_path.exists():
        raise FileNotFoundError(f"no package.json in {project_dir}")
    pkg = json.loads(pkg_path.read_text())

    scope_list = list(scopes)
    if include_peer and "peerDependencies" not in scope_list:
        scope_list.append("peerDependencies")

    allowlist = {name.lower() for name in allowed}
    report = PinsReport()

    for scope in scope_list:
        block = pkg.get(scope, {})
        if not isinstance(block, dict):
            continue
        for name, declared in block.items():
            report.total_checked += 1
            kind = _classify(declared)
            if kind is None:
                continue
            finding = PinFinding(
                scope=scope,
                package_name=name,
                declared=str(declared),
                kind=kind,
            )
            if name.lower() in allowlist:
                report.allowed.append(finding)
            else:
                report.flagged.append(finding)

    return report
