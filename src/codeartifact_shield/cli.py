"""CLI surface — ``cas`` (alias for ``codeartifact-shield``).

Five commands, single responsibility each:

* ``cas sri patch`` / ``cas sri verify`` — close the SRI-integrity gap
  that AWS CodeArtifact's npm proxy leaves in ``package-lock.json``.
* ``cas drift`` — fail if ``package.json`` and ``package-lock.json``
  disagree on direct or transitive dep versions, or if an unreachable
  ("orphan") entry exists in the lockfile.
* ``cas registry`` — fail if any lockfile entry was resolved from a host
  other than the configured CodeArtifact / mirror, or via http://.
* ``cas scripts`` — fail if any dep declares preinstall/install/postinstall.
* ``cas pin`` — fail if any direct ``package.json`` dep declaration is a
  range, dist-tag, or otherwise unpinned spec instead of an exact version.
* ``cas audit`` — `npm audit` equivalent that works behind CodeArtifact.
  Queries OSV.dev directly so the audit endpoint CodeArtifact doesn't
  proxy is no longer a blind spot.
* ``cas cooldown`` — fail when any installed version was published more
  recently than the configured threshold (default 14 days). Defends
  against rapid-install supply-chain attacks where a malicious version
  is live for hours before detection.

Designed to be dropped into a CI step; every command exits nonzero on a
finding, and every command supports ``--json`` for machine-readable output.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import click

from codeartifact_shield import __version__
from codeartifact_shield._http import DEFAULT_RETRIES
from codeartifact_shield._output import (
    Severity,
    emit_json,
    severity_badge,
    severity_counts,
)
from codeartifact_shield.audit import (
    DEFAULT_PROBE_WORKERS,
    SEVERITY_RANK,
    audit_lockfile,
)
from codeartifact_shield.cooldown import (
    DEFAULT_MAX_WORKERS,
    DEFAULT_MIN_AGE_DAYS,
    DEFAULT_REGISTRY,
    RegistryEndpoint,
    build_codeartifact_endpoint,
    check_cooldown,
)
from codeartifact_shield.drift import check_npm_drift
from codeartifact_shield.pins import DEFAULT_SCOPES, check_pinning
from codeartifact_shield.registry import check_npm_registry, host_allowed
from codeartifact_shield.scripts import check_install_scripts
from codeartifact_shield.sri import patch_lockfile, verify_lockfile

logger = logging.getLogger(__name__)


def _emit_load_error(
    json_output: bool, command: str, target: Path, exc: Exception
) -> None:
    """Surface a structural lockfile problem (e.g. v1 lockfileVersion, path
    traversal in a key) as a clean finding instead of an uncaught traceback.

    Every subcommand that loads a lockfile via ``load_lockfile`` should call
    this in its except branch — otherwise cas crashes mid-sweep on the first
    repo it can't parse, which is exactly what happened during the org-wide
    initial sweep against the v1-format archive repos.
    """
    payload = {
        "command": command,
        "lockfile": str(target),
        "clean": False,
        "findings": [
            {
                "severity": Severity.HIGH.value,
                "type": "lockfile_load_error",
                "message": str(exc),
            }
        ],
        "severity_counts": {Severity.HIGH.value: 1},
    }
    if json_output:
        emit_json(payload)
    else:
        click.echo(
            f"{severity_badge(Severity.HIGH)} FAIL — {exc}", err=True
        )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version", prog_name="cas")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging to stderr.")
def main(verbose: bool) -> None:
    """codeartifact-shield — npm supply-chain hardening for AWS CodeArtifact."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# sri — npm lockfile integrity hash backfill / verification
# ---------------------------------------------------------------------------


@main.group()
def sri() -> None:
    """Backfill / verify SRI integrity hashes in package-lock.json."""


@sri.command("patch")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--domain", required=True, envvar="CAS_DOMAIN", help="CodeArtifact domain.")
@click.option(
    "--repository",
    required=True,
    envvar="CAS_REPOSITORY",
    help="CodeArtifact repository within the domain.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Report what would be patched without writing the lockfile.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def sri_patch(
    lockfile: Path,
    domain: str,
    repository: str,
    dry_run: bool,
    json_output: bool,
) -> None:
    """Inject ``dist.integrity`` into every lockfile entry that's missing it.

    Uses CodeArtifact's ``ListPackageVersionAssets`` API to pull each
    package's stored SHA-512 and converts it to the SRI format
    ``npm ci`` validates against.

    Exits 0 on success, 2 if there were API errors or packages
    unreachable in CodeArtifact, 1 on configuration errors.
    """
    report = patch_lockfile(
        lockfile, domain=domain, repository=repository, dry_run=dry_run
    )

    findings: list[dict[str, Any]] = []
    for key in report.not_in_codeartifact:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "package_not_in_codeartifact",
                "lockfile_key": key,
            }
        )
    for key, msg in report.api_errors:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "codeartifact_api_error",
                "lockfile_key": key,
                "message": msg,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "sri-patch",
                "lockfile": str(lockfile),
                "clean": not findings,
                "patched": report.patched,
                "already_present": report.already_present,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
    else:
        click.echo(
            f"patched={report.patched} already_present={report.already_present} "
            f"not_in_codeartifact={len(report.not_in_codeartifact)} "
            f"api_errors={len(report.api_errors)}"
        )
        if report.not_in_codeartifact:
            click.echo("Packages not found in CodeArtifact (skipped):", err=True)
            for k in report.not_in_codeartifact[:20]:
                click.echo(f"  {severity_badge(Severity.HIGH)} {k}", err=True)
            if len(report.not_in_codeartifact) > 20:
                click.echo(
                    f"  ... and {len(report.not_in_codeartifact) - 20} more", err=True
                )
        if report.api_errors:
            click.echo("API errors:", err=True)
            for k, msg in report.api_errors[:20]:
                click.echo(
                    f"  {severity_badge(Severity.HIGH)} {k}: {msg}", err=True
                )

    if report.api_errors or report.not_in_codeartifact:
        sys.exit(2)


@sri.command("verify")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--min-coverage",
    type=click.FloatRange(0, 100),
    default=100.0,
    show_default=True,
    help="Minimum percentage of entries that must have an integrity hash.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def sri_verify(lockfile: Path, min_coverage: float, json_output: bool) -> None:
    """Fail the build if SRI coverage of the lockfile is below threshold.

    Pair with ``cas sri patch`` in a precommit or CI job so the lockfile
    is always integrity-complete before merge.
    """
    try:
        with_integrity, total = verify_lockfile(lockfile)
    except ValueError as exc:
        if json_output:
            emit_json(
                {
                    "command": "sri-verify",
                    "lockfile": str(lockfile),
                    "clean": False,
                    "findings": [
                        {
                            "severity": Severity.HIGH.value,
                            "type": "lockfile_load_error",
                            "message": str(exc),
                        }
                    ],
                    "severity_counts": {Severity.HIGH.value: 1},
                }
            )
        else:
            click.echo(f"{severity_badge(Severity.HIGH)} FAIL — {exc}", err=True)
        sys.exit(1)

    coverage = 100.0 * with_integrity / total if total else 100.0
    below_threshold = coverage < min_coverage

    findings: list[dict[str, Any]] = []
    if below_threshold:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "sri_coverage_below_threshold",
                "coverage_percent": round(coverage, 4),
                "threshold_percent": min_coverage,
                "covered": with_integrity,
                "total": total,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "sri-verify",
                "lockfile": str(lockfile),
                "clean": not findings,
                "covered": with_integrity,
                "total": total,
                "coverage_percent": round(coverage, 4),
                "threshold_percent": min_coverage,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
    else:
        click.echo(
            f"SRI integrity coverage: {with_integrity}/{total} ({coverage:.2f}%)"
        )
        if below_threshold:
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — coverage {coverage:.2f}% "
                f"is below threshold {min_coverage:.2f}%. "
                f"Run `cas sri patch` to backfill from CodeArtifact.",
                err=True,
            )

    if below_threshold:
        sys.exit(1)


# ---------------------------------------------------------------------------
# drift — package.json vs lockfile drift (direct, transitive, orphans)
# ---------------------------------------------------------------------------


@main.command("drift")
@click.argument(
    "frontend_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--ranges",
    is_flag=True,
    help="Treat package.json declarations as SemVer ranges instead of "
    "requiring literal equality. Use when the project doesn't pin exact "
    "versions in package.json.",
)
@click.option(
    "--no-transitive",
    is_flag=True,
    help="Skip transitive drift detection (only check direct deps). "
    "Also disables orphan-entry detection, since orphan detection requires "
    "walking the transitive graph.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def drift_cmd(
    frontend_dir: Path,
    ranges: bool,
    no_transitive: bool,
    json_output: bool,
) -> None:
    """Fail if ``package.json`` and ``package-lock.json`` disagree on versions,
    or if a lockfile entry is orphaned (unreachable from the dep graph).
    """
    try:
        report = check_npm_drift(
            frontend_dir, ranges=ranges, transitive=not no_transitive
        )
    except FileNotFoundError as exc:
        if json_output:
            emit_json(
                {
                    "command": "drift",
                    "frontend_dir": str(frontend_dir),
                    "clean": False,
                    "findings": [
                        {
                            "severity": Severity.HIGH.value,
                            "type": "missing_file",
                            "message": str(exc),
                        }
                    ],
                    "severity_counts": {Severity.HIGH.value: 1},
                }
            )
        else:
            click.echo(
                f"{severity_badge(Severity.HIGH)} SKIP — {exc}", err=True
            )
        sys.exit(1)
    except ValueError as exc:
        # v1 lockfile, malformed package keys, or other structural issue
        # surfaced by load_lockfile.
        _emit_load_error(json_output, "drift", frontend_dir, exc)
        sys.exit(1)

    findings: list[dict[str, Any]] = []
    for kind, name, declared, actual in report.mismatches:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "direct_drift",
                "kind": kind,
                "name": name,
                "declared": declared,
                "actual": actual,
            }
        )
    for parent, child, declared, actual in report.transitive_mismatches:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "transitive_drift",
                "parent": parent,
                "child": child,
                "declared": declared,
                "actual": actual,
            }
        )
    for key in report.orphan_entries:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "orphan_entry",
                "lockfile_key": key,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "drift",
                "frontend_dir": str(frontend_dir),
                "clean": report.clean,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
        if not report.clean:
            sys.exit(1)
        return

    if report.clean:
        click.echo("OK — package.json and package-lock.json agree on declared versions.")
        return

    if report.mismatches:
        click.echo(f"Direct drift ({len(report.mismatches)}):", err=True)
        for kind, name, declared, actual in report.mismatches:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {kind}.{name}: "
                f"package.json={declared} lockfile={actual}",
                err=True,
            )

    if report.transitive_mismatches:
        click.echo(
            f"\nTransitive drift ({len(report.transitive_mismatches)}):", err=True
        )
        for parent, child, declared, actual in report.transitive_mismatches[:50]:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {parent} -> {child}: "
                f"declared={declared} resolved={actual}",
                err=True,
            )
        if len(report.transitive_mismatches) > 50:
            click.echo(
                f"  ... and {len(report.transitive_mismatches) - 50} more", err=True
            )

    if report.orphan_entries:
        click.echo(
            f"\nOrphan lockfile entries ({len(report.orphan_entries)}) — "
            "not reachable from any declared dependency:",
            err=True,
        )
        for key in report.orphan_entries[:30]:
            click.echo(f"  {severity_badge(Severity.HIGH)} {key}", err=True)
        if len(report.orphan_entries) > 30:
            click.echo(
                f"  ... and {len(report.orphan_entries) - 30} more", err=True
            )
        click.echo(
            "  These entries have no parent in the dep graph rooted at "
            "package.json. The most plausible cause is lockfile tampering "
            "(or a partial regeneration). Re-run "
            "`npm install --package-lock-only --include=optional --force`.",
            err=True,
        )

    click.echo(
        "\nFix: re-run `npm install --package-lock-only --include=optional --force` "
        "and commit the regenerated lockfile.",
        err=True,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# registry — registry-leakage detection (CodeArtifact vs public npm vs mixed)
# ---------------------------------------------------------------------------


@main.command("registry")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--allowed-host",
    "allowed_hosts",
    multiple=True,
    envvar="CAS_ALLOWED_HOSTS",
    help=(
        "Hostname suffix (case-insensitive, label-anchored) that an entry's "
        "resolved host must equal or end with to be considered legitimate. "
        "Repeatable. Use the FULL suffix — partial patterns like "
        "`.d.codeartifact.` are no longer accepted because they let attacker-"
        "controlled hosts of the form `evil.d.codeartifact.attacker.com` slip "
        "through. e.g. "
        "`--allowed-host .d.codeartifact.ap-northeast-1.amazonaws.com`. "
        "OMIT this flag entirely to auto-detect the project's primary "
        "registry from the lockfile — useful for sweeping mixed CA + public-"
        "npm repos where you don't know each project's intended primary."
    ),
)
@click.option(
    "--fail-on-git",
    is_flag=True,
    help="Also fail if any entry was resolved directly from git (bypasses the registry).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def registry_cmd(
    lockfile: Path,
    allowed_hosts: tuple[str, ...],
    fail_on_git: bool,
    json_output: bool,
) -> None:
    """Fail the build if the lockfile resolves any package from a non-allowed host."""
    # Empty tuple from click when --allowed-host wasn't passed → auto-detect.
    allowed = allowed_hosts if allowed_hosts else None
    try:
        report = check_npm_registry(lockfile, allowed)
    except ValueError as exc:
        _emit_load_error(json_output, "registry", lockfile, exc)
        sys.exit(1)

    findings: list[dict[str, Any]] = []
    for key, host in report.leaked:
        findings.append(
            {
                "severity": Severity.CRITICAL.value,
                "type": "registry_leak",
                "lockfile_key": key,
                "host": host,
            }
        )
    for key, ref in report.git_sourced:
        findings.append(
            {
                "severity": Severity.MEDIUM.value,
                "type": "git_sourced",
                "lockfile_key": key,
                "ref": ref,
            }
        )
    for key in report.unresolved:
        findings.append(
            {
                "severity": Severity.LOW.value,
                "type": "unresolved_phantom",
                "lockfile_key": key,
            }
        )
    for key in report.bundled:
        findings.append(
            {
                "severity": Severity.INFO.value,
                "type": "bundled",
                "lockfile_key": key,
            }
        )

    is_failure = bool(report.leaked) or (fail_on_git and bool(report.git_sourced))

    if json_output:
        emit_json(
            {
                "command": "registry",
                "lockfile": str(lockfile),
                "clean": not is_failure,
                "by_host": dict(report.by_host),
                "mixed_registries": report.mixed,
                "detected_primary_hosts": report.detected_primary_hosts,
                "auto_detect": not allowed_hosts,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
        if is_failure:
            sys.exit(1)
        return

    if report.detected_primary_hosts:
        click.echo(
            "Auto-detected primary registries (no --allowed-host given): "
            + ", ".join(report.detected_primary_hosts)
        )
    click.echo("Resolved-host distribution:")
    effective_allowed = (
        report.detected_primary_hosts if not allowed_hosts else list(allowed_hosts)
    )
    for host, count in sorted(report.by_host.items(), key=lambda kv: -kv[1]):
        marker = "OK" if host_allowed(host, effective_allowed) else "LEAK"
        click.echo(f"  [{marker}] {host}: {count}")
    if report.mixed:
        click.echo("WARN — mixed registries: lockfile resolves from more than one host.")

    if report.leaked:
        click.echo(f"\nLeaked entries ({len(report.leaked)}):", err=True)
        for k, host in report.leaked[:30]:
            click.echo(
                f"  {severity_badge(Severity.CRITICAL)} {k}  <-  {host}", err=True
            )
        if len(report.leaked) > 30:
            click.echo(f"  ... and {len(report.leaked) - 30} more", err=True)

    if report.git_sourced:
        sev = Severity.MEDIUM if fail_on_git else Severity.LOW
        click.echo(
            f"\nGit-sourced entries (bypass registry) ({len(report.git_sourced)}):",
            err=fail_on_git,
        )
        for k, ref in report.git_sourced[:10]:
            click.echo(
                f"  {severity_badge(sev)} {k}  <-  {ref}",
                err=fail_on_git,
            )
        if len(report.git_sourced) > 10:
            click.echo(
                f"  ... and {len(report.git_sourced) - 10} more", err=fail_on_git
            )

    if is_failure:
        sys.exit(1)


# ---------------------------------------------------------------------------
# scripts — lifecycle-script (preinstall/install/postinstall) audit
# ---------------------------------------------------------------------------


@main.command("scripts")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--allow",
    "allowed",
    multiple=True,
    envvar="CAS_ALLOWED_SCRIPTS",
    help=(
        "Package name (including scope, e.g. `@parcel/watcher`) that is "
        "permitted to run install scripts. Repeatable. Build-essential "
        "native modules (esbuild, fsevents, etc.) typically need this — "
        "review and allowlist deliberately."
    ),
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def scripts_cmd(
    lockfile: Path,
    allowed: tuple[str, ...],
    json_output: bool,
) -> None:
    """Fail if any lockfile entry will run lifecycle scripts at install time."""
    try:
        report = check_install_scripts(lockfile, allowed=allowed)
    except ValueError as exc:
        _emit_load_error(json_output, "scripts", lockfile, exc)
        sys.exit(1)

    findings: list[dict[str, Any]] = []
    for f in report.flagged:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "install_script",
                "package": f.package_name,
                "version": f.version,
                "lockfile_key": f.lockfile_key,
            }
        )
    for f in report.allowed:
        findings.append(
            {
                "severity": Severity.INFO.value,
                "type": "install_script_allowed",
                "package": f.package_name,
                "version": f.version,
                "lockfile_key": f.lockfile_key,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "scripts",
                "lockfile": str(lockfile),
                "clean": report.clean,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
        if not report.clean:
            sys.exit(1)
        return

    if report.allowed:
        click.echo(
            f"Allowlisted script-running packages ({len(report.allowed)}):"
        )
        for f in report.allowed:
            click.echo(f"  [OK] {f.package_name}@{f.version}")

    if report.flagged:
        click.echo(
            f"\nPackages that will execute code at install time "
            f"({len(report.flagged)}):",
            err=True,
        )
        for f in report.flagged:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {f.package_name}@{f.version}"
                f"  ({f.lockfile_key})",
                err=True,
            )
        click.echo(
            "\nFix: audit each package's preinstall/install/postinstall "
            "scripts. To allowlist, pass `--allow <package-name>` (repeat as "
            "needed). To eliminate, run `npm ci --ignore-scripts` and replace "
            "the dep.",
            err=True,
        )
        sys.exit(1)

    if not report.allowed:
        click.echo("OK — no install scripts in the lockfile.")


# ---------------------------------------------------------------------------
# pin — direct-dep pinning policy audit (package.json)
# ---------------------------------------------------------------------------


@main.command("pin")
@click.argument(
    "project_dir", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option(
    "--allow",
    "allowed",
    multiple=True,
    envvar="CAS_ALLOWED_UNPINNED",
    help=(
        "Package name (including scope) permitted to stay unpinned. "
        "Repeatable. Every entry is a hole in the reproducibility "
        "guarantee — review deliberately."
    ),
)
@click.option(
    "--scope",
    "scopes",
    multiple=True,
    type=click.Choice(
        [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ]
    ),
    help=(
        "Limit the audit to specific package.json scopes. Repeatable. "
        "Default: dependencies, devDependencies, optionalDependencies. "
        "peerDependencies is excluded by default because peers are "
        "idiomatically ranges; pass `--scope peerDependencies` to opt in."
    ),
)
@click.option(
    "--include-peer",
    is_flag=True,
    help=(
        "Also audit `peerDependencies`. Equivalent to adding "
        "`--scope peerDependencies` to the default scope set."
    ),
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def pin_cmd(
    project_dir: Path,
    allowed: tuple[str, ...],
    scopes: tuple[str, ...],
    include_peer: bool,
    json_output: bool,
) -> None:
    """Fail if any direct dep in package.json isn't pinned to an exact version."""
    scope_list = list(scopes) if scopes else list(DEFAULT_SCOPES)
    try:
        report = check_pinning(
            project_dir,
            allowed=allowed,
            scopes=scope_list,
            include_peer=include_peer,
        )
    except FileNotFoundError as exc:
        if json_output:
            emit_json(
                {
                    "command": "pin",
                    "project_dir": str(project_dir),
                    "clean": False,
                    "findings": [
                        {
                            "severity": Severity.HIGH.value,
                            "type": "missing_package_json",
                            "message": str(exc),
                        }
                    ],
                    "severity_counts": {Severity.HIGH.value: 1},
                }
            )
        else:
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — {exc}", err=True
            )
        sys.exit(1)

    findings: list[dict[str, Any]] = []
    for f in report.flagged:
        findings.append(
            {
                "severity": Severity.HIGH.value,
                "type": "unpinned",
                "scope": f.scope,
                "package": f.package_name,
                "declared": f.declared,
                "kind": f.kind,
            }
        )
    for f in report.allowed:
        findings.append(
            {
                "severity": Severity.INFO.value,
                "type": "unpinned_allowed",
                "scope": f.scope,
                "package": f.package_name,
                "declared": f.declared,
                "kind": f.kind,
            }
        )

    effective_scopes = list(scope_list)
    if include_peer and "peerDependencies" not in effective_scopes:
        effective_scopes.append("peerDependencies")

    if json_output:
        emit_json(
            {
                "command": "pin",
                "project_dir": str(project_dir),
                "clean": report.clean,
                "scopes": effective_scopes,
                "total_checked": report.total_checked,
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
        if not report.clean:
            sys.exit(1)
        return

    if report.allowed:
        click.echo(f"Allowlisted unpinned deps ({len(report.allowed)}):")
        for f in report.allowed:
            click.echo(f"  [OK] {f.scope}: {f.package_name} = {f.declared} ({f.kind})")

    if report.flagged:
        click.echo(
            f"\nUnpinned direct deps in package.json "
            f"({len(report.flagged)} of {report.total_checked} checked):",
            err=True,
        )
        for f in report.flagged:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {f.scope}: "
                f"{f.package_name} = {f.declared}  ({f.kind})",
                err=True,
            )
        click.echo(
            "\nFix: replace each range/tag with the exact version currently "
            "in package-lock.json. To allowlist (e.g. for a workspace-internal "
            "tool with a stable API), pass `--allow <package-name>` "
            "(repeat as needed).",
            err=True,
        )
        sys.exit(1)

    click.echo(
        f"OK — all {report.total_checked} direct-dep declarations are pinned "
        f"({', '.join(effective_scopes)})."
    )


# ---------------------------------------------------------------------------
# audit — vulnerability audit against OSV.dev (npm audit for CodeArtifact)
# ---------------------------------------------------------------------------


_AUDIT_SEVERITY_TO_CAS = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.LOW,
}


@main.command("audit")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--allow",
    "allowed",
    multiple=True,
    envvar="CAS_AUDIT_ALLOW",
    help=(
        "Vuln ID (GHSA / CVE / OSV) to suppress. Repeatable. Matched "
        "case-insensitively against the primary id and aliases."
    ),
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "moderate", "low"]),
    default=None,
    help=(
        "Only report findings at or above this severity. Default: report "
        "all findings (matches `npm audit` default)."
    ),
)
@click.option(
    "--whitelist",
    "whitelist_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    envvar="CAS_AUDIT_WHITELIST",
    default=None,
    help=(
        "Path to a whitelist file. Two formats accepted: the `auditjs` / "
        "Sonatype OSS Index format `{\"ignore\":[{\"id\":\"CVE-...\"}]}`, "
        "or a plain JSON array of vuln IDs. IDs from the file are merged "
        "with any `--allow` flags."
    ),
)
@click.option(
    "--probe-private",
    "probe_registry",
    default=None,
    envvar="CAS_AUDIT_PROBE_REGISTRY",
    help=(
        "Public-registry URL used to detect packages NOT covered by OSV "
        "(typically CodeArtifact-only org-internal deps). When set, cas "
        "GETs each unhit package against this URL; any 404 is surfaced "
        "as HIGH `unaudited_private` (the package can't be vouched for "
        "by OSV or by the public registry — possible typo / tampering / "
        "internal-only). One extra HTTP request per unique package with "
        "no OSV finding. Recommended value: `https://registry.npmjs.org`."
    ),
)
@click.option(
    "--allow-private",
    "allow_unaudited",
    multiple=True,
    envvar="CAS_ALLOW_PRIVATE",
    help=(
        "Package name (including scope) permitted to be unauditable. "
        "Repeatable. Shared with `cas cooldown` — set once via "
        "`CAS_ALLOW_PRIVATE` to apply to both commands. Demotes the "
        "HIGH `unaudited_private` finding to INFO for that name. Use "
        "sparingly — prefer `--ca-domain` so CodeArtifact vouches for "
        "an entire scope at once."
    ),
)
@click.option(
    "--ca-domain",
    "ca_domain",
    default=None,
    envvar="CAS_DOMAIN",
    help=(
        "CodeArtifact domain. When set, packages not on the "
        "`--probe-private` public registry are checked against this "
        "CA endpoint (with a fresh bearer token via boto3). A hit "
        "demotes the finding to INFO `unaudited_allowed`. "
        "Lets `cas audit` mirror `cas cooldown`'s deployment model."
    ),
)
@click.option(
    "--ca-repository",
    "ca_repository",
    default=None,
    envvar="CAS_REPOSITORY",
    help="CodeArtifact repository name. Required when `--ca-domain` is set.",
)
@click.option(
    "--ca-domain-owner",
    "ca_domain_owner",
    default=None,
    envvar="CAS_DOMAIN_OWNER",
    help=(
        "CodeArtifact domain-owner AWS account ID. Optional — boto3 "
        "infers it from the caller account if omitted."
    ),
)
@click.option(
    "--max-workers",
    type=int,
    default=DEFAULT_PROBE_WORKERS,
    show_default=True,
    envvar="CAS_AUDIT_MAX_WORKERS",
    help=(
        "Thread-pool size for parallel `--probe-private` / CA probe "
        "HTTP requests. I/O-bound, so high values are safe. Lower to "
        "1 to force serial mode for debugging."
    ),
)
@click.option(
    "--retries",
    type=int,
    default=DEFAULT_RETRIES,
    show_default=True,
    envvar="CAS_RETRIES",
    help=(
        "How many times to retry a transient HTTP error (network "
        "unreachable, 5xx, 429) before failing. Default 2 (3 total "
        "attempts) with exponential backoff. `0` disables retry. "
        "Shared with `cas cooldown` via `CAS_RETRIES`."
    ),
)
@click.option(
    "--probe-cache",
    "probe_cache_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    envvar="CAS_AUDIT_PROBE_CACHE",
    help=(
        "Path to a JSON cache of probe results (which packages exist on "
        "which registries). Massively speeds up re-runs in CI: a fully-"
        "cached audit completes in well under a second on a 2500-package "
        "lockfile. Cache entries never invalidate — package existence is "
        "stable enough that staleness isn't a correctness concern."
    ),
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def audit_cmd(
    lockfile: Path,
    allowed: tuple[str, ...],
    min_severity: str | None,
    whitelist_file: Path | None,
    probe_registry: str | None,
    allow_unaudited: tuple[str, ...],
    ca_domain: str | None,
    ca_repository: str | None,
    ca_domain_owner: str | None,
    max_workers: int,
    retries: int,
    probe_cache_path: Path | None,
    json_output: bool,
) -> None:
    """Query OSV.dev for known vulnerabilities in every (name, version) in the lockfile."""
    floor = None
    if min_severity:
        floor = "MEDIUM" if min_severity.lower() == "moderate" else min_severity.upper()

    trusted_endpoints: list[RegistryEndpoint] = []
    if ca_domain:
        if not ca_repository:
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — "
                f"`--ca-domain` requires `--ca-repository`",
                err=True,
            )
            sys.exit(1)
        try:
            ca = build_codeartifact_endpoint(
                domain=ca_domain,
                repository=ca_repository,
                domain_owner=ca_domain_owner,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — "
                f"CodeArtifact auth failed: {exc}",
                err=True,
            )
            sys.exit(1)
        trusted_endpoints.append(ca)

    try:
        report = audit_lockfile(
            lockfile,
            allow_ids=allowed,
            allow_unaudited=allow_unaudited,
            severity_floor=floor,
            whitelist_file=whitelist_file,
            probe_registry=probe_registry,
            trusted_endpoints=trusted_endpoints or None,
            probe_cache_path=probe_cache_path,
            max_workers=max_workers,
            retries=retries,
        )
    except ValueError as exc:
        _emit_load_error(json_output, "audit", lockfile, exc)
        sys.exit(1)

    if report.network_error:
        if json_output:
            emit_json(
                {
                    "command": "audit",
                    "lockfile": str(lockfile),
                    "clean": False,
                    "total_checked": report.total_checked,
                    "findings": [
                        {
                            "severity": Severity.HIGH.value,
                            "type": "audit_network_error",
                            "message": report.network_error,
                        }
                    ],
                    "severity_counts": {Severity.HIGH.value: 1},
                }
            )
        else:
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — {report.network_error}",
                err=True,
            )
        sys.exit(1)

    findings_payload: list[dict[str, Any]] = []
    for f in report.findings:
        sev = _AUDIT_SEVERITY_TO_CAS.get(f.severity, Severity.LOW)
        findings_payload.append(
            {
                "severity": sev.value,
                "type": "vulnerability",
                "package": f.package_name,
                "version": f.version,
                "vuln_id": f.vuln_id,
                "vuln_severity": f.severity,
                "summary": f.summary,
                "fixed_in": f.fixed_in,
                "aliases": f.aliases,
            }
        )
    for name in report.unaudited_blocked:
        findings_payload.append(
            {
                "severity": Severity.HIGH.value,
                "type": "unaudited_private",
                "package": name,
            }
        )
    for name in report.unaudited_allowed:
        findings_payload.append(
            {
                "severity": Severity.INFO.value,
                "type": "unaudited_private_allowed",
                "package": name,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "audit",
                "lockfile": str(lockfile),
                "clean": report.clean,
                "total_checked": report.total_checked,
                "findings": findings_payload,
                "severity_counts": severity_counts(findings_payload),
            }
        )
        if not report.clean:
            sys.exit(1)
        return

    if not report.findings:
        click.echo(
            f"OK — {report.total_checked} packages audited, no vulnerabilities."
        )
        return

    by_severity_rank = sorted(
        report.findings,
        key=lambda f: -SEVERITY_RANK.get(f.severity, 0),
    )
    click.echo(
        f"\nVulnerabilities found ({len(report.findings)} across "
        f"{report.total_checked} packages):",
        err=True,
    )
    for f in by_severity_rank:
        cas_sev = _AUDIT_SEVERITY_TO_CAS.get(f.severity, Severity.LOW)
        aliases = f", aliases: {', '.join(f.aliases)}" if f.aliases else ""
        fixed = f"  Fixed in: {f.fixed_in}" if f.fixed_in else "  Fixed in: (no patch)"
        click.echo(
            f"  {severity_badge(cas_sev)} {f.package_name}@{f.version}  "
            f"{f.vuln_id}{aliases}",
            err=True,
        )
        if f.summary:
            click.echo(f"    {f.summary}", err=True)
        click.echo(fixed, err=True)
    click.echo(
        "\nFix: bump to the indicated `Fixed in` versions. To suppress an "
        "accepted-risk finding, pass `--allow <GHSA-id>` (repeat as needed) "
        "or set `CAS_AUDIT_ALLOW`. To gate only on high+, pass "
        "`--min-severity high`.",
        err=True,
    )
    sys.exit(1)


# ---------------------------------------------------------------------------
# cooldown — block recently-published versions (npm minimumReleaseAge gate)
# ---------------------------------------------------------------------------


@main.command("cooldown")
@click.argument("lockfile", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--min-age",
    "min_age_days",
    type=int,
    default=DEFAULT_MIN_AGE_DAYS,
    show_default=True,
    envvar="CAS_COOLDOWN_MIN_AGE",
    help=(
        "Minimum age in days. Any installed version published more "
        "recently than this is flagged. Matches StepSecurity's default."
    ),
)
@click.option(
    "--allow",
    "allowed",
    multiple=True,
    envvar="CAS_COOLDOWN_ALLOW",
    help=(
        "Package name (including scope) permitted to ship without "
        "a cooldown delay. Repeatable. Typical use: org-internal "
        "packages where you control the publish."
    ),
)
@click.option(
    "--allow-private",
    "allow_private",
    multiple=True,
    envvar="CAS_ALLOW_PRIVATE",
    help=(
        "Package name (including scope) permitted to be unresolvable on "
        "every configured registry. Repeatable. Shared across `cas "
        "cooldown` and `cas audit` — set once via `CAS_ALLOW_PRIVATE` "
        "to apply to both. Use sparingly: a name no registry knows is "
        "secure-by-default HIGH (typosquat / tampering / config gap)."
    ),
)
@click.option(
    "--registry",
    "registry",
    default=DEFAULT_REGISTRY,
    show_default=True,
    envvar="CAS_COOLDOWN_REGISTRY",
    help=(
        "Primary npm registry to query for publish times. Default is "
        "`https://registry.npmjs.org`. For CodeArtifact-proxied "
        "lockfiles, leave this on npmjs.org for public deps and pair "
        "with `--ca-domain` for any private-only deps."
    ),
)
@click.option(
    "--ca-domain",
    "ca_domain",
    default=None,
    envvar="CAS_DOMAIN",
    help=(
        "CodeArtifact domain. When set, cas queries the CodeArtifact "
        "npm endpoint (with a fresh bearer token via boto3) before "
        "falling back to `--registry`. Required for CodeArtifact-only "
        "private packages that don't exist on public npm."
    ),
)
@click.option(
    "--ca-repository",
    "ca_repository",
    default=None,
    envvar="CAS_REPOSITORY",
    help="CodeArtifact repository name. Required when `--ca-domain` is set.",
)
@click.option(
    "--ca-domain-owner",
    "ca_domain_owner",
    default=None,
    envvar="CAS_DOMAIN_OWNER",
    help=(
        "CodeArtifact domain-owner AWS account ID. Optional — boto3 "
        "infers it from the caller account if omitted."
    ),
)
@click.option(
    "--ca-first",
    is_flag=True,
    help=(
        "When `--ca-domain` is set, query CodeArtifact FIRST and fall "
        "back to `--registry` only on 404. Default order is "
        "`--registry` first (saves a token round-trip for public deps)."
    ),
)
@click.option(
    "--cache",
    "cache_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    envvar="CAS_COOLDOWN_CACHE",
    help=(
        "Path to a JSON cache file. Publish times are immutable, so "
        "cached entries are always valid. Drastically speeds up "
        "re-runs in CI when lockfile churn is small."
    ),
)
@click.option(
    "--max-workers",
    type=int,
    default=DEFAULT_MAX_WORKERS,
    show_default=True,
    envvar="CAS_COOLDOWN_MAX_WORKERS",
    help=(
        "Thread-pool size for parallel registry fetches. I/O-bound, so "
        "high values are safe — 20 fits comfortably under npm's rate "
        "limits. Lower to 1 to force serial mode for debugging."
    ),
)
@click.option(
    "--retries",
    type=int,
    default=DEFAULT_RETRIES,
    show_default=True,
    envvar="CAS_RETRIES",
    help=(
        "How many times to retry a transient HTTP error (network "
        "unreachable, 5xx, 429) before failing. Default 2 (3 total "
        "attempts) with exponential backoff. `0` disables retry. "
        "Shared with `cas audit` via `CAS_RETRIES`."
    ),
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a machine-readable JSON report on stdout instead of human text.",
)
def cooldown_cmd(
    lockfile: Path,
    min_age_days: int,
    allowed: tuple[str, ...],
    allow_private: tuple[str, ...],
    registry: str,
    ca_domain: str | None,
    ca_repository: str | None,
    ca_domain_owner: str | None,
    ca_first: bool,
    cache_path: Path | None,
    max_workers: int,
    retries: int,
    json_output: bool,
) -> None:
    """Fail if any installed version is younger than --min-age days."""
    endpoints: list[RegistryEndpoint] = []
    public = RegistryEndpoint(url=registry)

    if ca_domain:
        if not ca_repository:
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — `--ca-domain` requires `--ca-repository`",
                err=True,
            )
            sys.exit(1)
        try:
            ca = build_codeartifact_endpoint(
                domain=ca_domain,
                repository=ca_repository,
                domain_owner=ca_domain_owner,
            )
        except Exception as exc:  # noqa: BLE001
            click.echo(
                f"{severity_badge(Severity.HIGH)} FAIL — CodeArtifact auth failed: {exc}",
                err=True,
            )
            sys.exit(1)
        endpoints = [ca, public] if ca_first else [public, ca]
    else:
        endpoints = [public]

    try:
        report = check_cooldown(
            lockfile,
            min_age_days=min_age_days,
            allowed=allowed,
            allow_private=allow_private,
            endpoints=endpoints,
            cache_path=cache_path,
            max_workers=max_workers,
            retries=retries,
        )
    except ValueError as exc:
        _emit_load_error(json_output, "cooldown", lockfile, exc)
        sys.exit(1)

    findings_payload: list[dict[str, Any]] = []
    for f in report.flagged:
        findings_payload.append(
            {
                "severity": Severity.HIGH.value,
                "type": "cooldown_too_young",
                "package": f.package_name,
                "version": f.version,
                "published_at": f.published_at,
                "age_days": f.age_days,
                "source": f.source,
            }
        )
    for f in report.allowed:
        findings_payload.append(
            {
                "severity": Severity.INFO.value,
                "type": "cooldown_too_young_allowed",
                "package": f.package_name,
                "version": f.version,
                "published_at": f.published_at,
                "age_days": f.age_days,
                "source": f.source,
            }
        )
    for entry in report.private_blocked:
        findings_payload.append(
            {
                "severity": Severity.HIGH.value,
                "type": "cooldown_private_unresolvable",
                "package": entry,
            }
        )
    for entry in report.private_allowed:
        findings_payload.append(
            {
                "severity": Severity.INFO.value,
                "type": "cooldown_private_allowed",
                "package": entry,
            }
        )
    for msg in report.network_errors:
        findings_payload.append(
            {
                "severity": Severity.HIGH.value,
                "type": "cooldown_network_error",
                "message": msg,
            }
        )

    if json_output:
        emit_json(
            {
                "command": "cooldown",
                "lockfile": str(lockfile),
                "clean": report.clean,
                "min_age_days": min_age_days,
                "total_checked": report.total_checked,
                "endpoints": [e.label for e in endpoints],
                "findings": findings_payload,
                "severity_counts": severity_counts(findings_payload),
            }
        )
        if not report.clean:
            sys.exit(1)
        return

    if report.private_allowed:
        click.echo(
            f"Allowlisted unresolvable packages ({len(report.private_allowed)}):"
        )
        for entry in report.private_allowed[:20]:
            click.echo(f"  [OK] {entry} (allowed-private)")
        if len(report.private_allowed) > 20:
            click.echo(f"  ... and {len(report.private_allowed) - 20} more")

    if report.private_blocked:
        click.echo(
            f"\nPackages not resolvable on any configured registry "
            f"({len(report.private_blocked)}):",
            err=True,
        )
        for entry in report.private_blocked[:30]:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {entry}  "
                f"(no publish time on any endpoint)",
                err=True,
            )
        if len(report.private_blocked) > 30:
            click.echo(
                f"  ... and {len(report.private_blocked) - 30} more", err=True
            )
        click.echo(
            "\nLikely causes: typo in lockfile entry, lockfile tampering, "
            "or your CodeArtifact endpoint isn't configured. To allow a "
            "legitimate intra-workspace dep, pass `--allow-private <name>`. "
            "To resolve private packages on CodeArtifact, pass "
            "`--ca-domain` and `--ca-repository`.",
            err=True,
        )

    if report.allowed:
        click.echo(
            f"\nAllowlisted young packages ({len(report.allowed)}):", err=True
        )
        for f in report.allowed:
            click.echo(
                f"  [OK] {f.package_name}@{f.version}  "
                f"({f.age_days}d old, published {f.published_at})",
                err=True,
            )

    if report.flagged:
        click.echo(
            f"\nVersions younger than {min_age_days} days "
            f"({len(report.flagged)} of {report.total_checked} checked):",
            err=True,
        )
        for f in report.flagged:
            click.echo(
                f"  {severity_badge(Severity.HIGH)} {f.package_name}@{f.version}  "
                f"({f.age_days}d old, published {f.published_at}, source={f.source})",
                err=True,
            )

    if report.network_errors:
        click.echo(
            f"\nRegistry errors ({len(report.network_errors)}):", err=True
        )
        for msg in report.network_errors:
            click.echo(f"  {severity_badge(Severity.HIGH)} {msg}", err=True)

    if not report.clean:
        click.echo(
            "\nFix: wait until the flagged versions reach the cooldown "
            "threshold before installing them, or pin the lockfile to an "
            "older known-good version. To allowlist (e.g. an org-internal "
            "package), pass `--allow <name>`.",
            err=True,
        )
        sys.exit(1)

    click.echo(
        f"OK — {report.total_checked} packages audited, all ≥ {min_age_days} days old."
    )
