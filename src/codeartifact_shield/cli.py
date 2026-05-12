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
from codeartifact_shield._output import (
    Severity,
    emit_json,
    severity_badge,
    severity_counts,
)
from codeartifact_shield.drift import check_npm_drift
from codeartifact_shield.registry import check_npm_registry, host_allowed
from codeartifact_shield.scripts import check_install_scripts
from codeartifact_shield.sri import patch_lockfile, verify_lockfile

logger = logging.getLogger(__name__)


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
            "(or a partial regeneration). Re-run `npm install --package-lock-only --include=optional --force`.",
            err=True,
        )

    click.echo(
        "\nFix: re-run `npm install --package-lock-only --include=optional --force` and commit\n"
        "the regenerated lockfile.\n"
        "\n"
        "  The `--force` flag is REQUIRED — without it, npm prunes every non-current-\n"
        "  platform optional dep (e.g. `@nx/nx-linux-x64-gnu`, `@rollup/rollup-darwin-\n"
        "  arm64`) and the Docker build / cross-platform CI breaks at install time.\n"
        "  See npm/cli#4828 + #7961 — long-standing bug across npm 9, 10, 11.",
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
    required=True,
    envvar="CAS_ALLOWED_HOSTS",
    help=(
        "Hostname suffix (case-insensitive, label-anchored) that an entry's "
        "resolved host must equal or end with to be considered legitimate. "
        "Repeatable. Use the FULL suffix — partial patterns like "
        "`.d.codeartifact.` are no longer accepted because they let attacker-"
        "controlled hosts of the form `evil.d.codeartifact.attacker.com` slip "
        "through. e.g. "
        "`--allowed-host .d.codeartifact.ap-northeast-1.amazonaws.com`."
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
    try:
        report = check_npm_registry(lockfile, allowed_hosts)
    except ValueError as exc:
        if json_output:
            emit_json(
                {
                    "command": "registry",
                    "lockfile": str(lockfile),
                    "clean": False,
                    "findings": [
                        {
                            "severity": Severity.HIGH.value,
                            "type": "configuration_error",
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
                "findings": findings,
                "severity_counts": severity_counts(findings),
            }
        )
        if is_failure:
            sys.exit(1)
        return

    click.echo("Resolved-host distribution:")
    for host, count in sorted(report.by_host.items(), key=lambda kv: -kv[1]):
        marker = "OK" if host_allowed(host, allowed_hosts) else "LEAK"
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
    report = check_install_scripts(lockfile, allowed=allowed)

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
