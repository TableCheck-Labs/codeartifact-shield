"""CLI surface — ``cas`` (alias for ``codeartifact-shield``).

Two commands, single responsibility each:

* ``cas sri patch`` / ``cas sri verify`` — close the SRI-integrity gap
  that AWS CodeArtifact's npm proxy leaves in ``package-lock.json``.
* ``cas drift`` — fail if ``package.json`` and ``package-lock.json``
  disagree on direct-dep versions.

Designed to be dropped into a CI step; every command exits nonzero
on a finding.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from codeartifact_shield import __version__
from codeartifact_shield.drift import check_npm_drift
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
def sri_patch(lockfile: Path, domain: str, repository: str, dry_run: bool) -> None:
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
    click.echo(
        f"patched={report.patched} already_present={report.already_present} "
        f"not_in_codeartifact={len(report.not_in_codeartifact)} "
        f"api_errors={len(report.api_errors)}"
    )
    if report.not_in_codeartifact:
        click.echo("Packages not found in CodeArtifact (skipped):", err=True)
        for k in report.not_in_codeartifact[:20]:
            click.echo(f"  {k}", err=True)
        if len(report.not_in_codeartifact) > 20:
            click.echo(f"  ... and {len(report.not_in_codeartifact) - 20} more", err=True)
    if report.api_errors:
        click.echo("API errors:", err=True)
        for k, msg in report.api_errors[:20]:
            click.echo(f"  {k}: {msg}", err=True)
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
def sri_verify(lockfile: Path, min_coverage: float) -> None:
    """Fail the build if SRI coverage of the lockfile is below threshold.

    Pair with ``cas sri patch`` in a precommit or CI job so the lockfile
    is always integrity-complete before merge.
    """
    with_integrity, total = verify_lockfile(lockfile)
    coverage = 100.0 * with_integrity / total if total else 100.0
    click.echo(
        f"SRI integrity coverage: {with_integrity}/{total} ({coverage:.2f}%)"
    )
    if coverage < min_coverage:
        click.echo(
            f"FAIL — coverage {coverage:.2f}% is below threshold {min_coverage:.2f}%. "
            f"Run `cas sri patch` to backfill from CodeArtifact.",
            err=True,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# drift — package.json vs lockfile drift
# ---------------------------------------------------------------------------


@main.command("drift")
@click.argument(
    "frontend_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
def drift_cmd(frontend_dir: Path) -> None:
    """Fail if ``package.json`` and ``package-lock.json`` disagree on versions.

    Catches the case where a developer edits one file but forgets the
    other — exactly the inconsistent state an attacker would create by
    tampering with the lockfile alone.
    """
    report = check_npm_drift(frontend_dir)
    if report.clean:
        click.echo("OK — package.json and package-lock.json agree on direct-dep versions.")
        return
    click.echo("Drift detected:", err=True)
    for kind, name, declared, actual in report.mismatches:
        click.echo(f"  {kind}.{name}: package.json={declared} lockfile={actual}", err=True)
    click.echo(
        "\nFix: re-run `npm install --package-lock-only` and commit the regenerated lockfile.",
        err=True,
    )
    sys.exit(1)
