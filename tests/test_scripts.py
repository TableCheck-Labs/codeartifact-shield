"""G5 — lifecycle-script detection (``cas scripts`` subcommand).

Threat model: any package with ``preinstall``/``install``/``postinstall``
runs arbitrary code on the install machine. cas surfaces every such entry
so it can be allowlisted explicitly rather than trusted implicitly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeartifact_shield.scripts import check_install_scripts


def _write(tmp_path: Path, packages: dict[str, dict[str, object]]) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return p


def test_scripts_uses_name_field_for_npm_aliases(tmp_path: Path) -> None:
    # Aliased lockfile entry: key is `node_modules/string-width-cjs` but
    # the canonical npm name (in the `name` field) is `string-width`.
    # The finding must surface the canonical name so allowlist matches.
    lf = _write(
        tmp_path,
        {
            "node_modules/string-width-cjs": {
                "name": "string-width",
                "version": "4.2.3",
                "hasInstallScript": True,
            },
        },
    )
    report = check_install_scripts(lf, allowed=["string-width"])
    assert report.clean
    assert len(report.allowed) == 1
    assert report.allowed[0].package_name == "string-width"


def test_flags_entry_with_hasInstallScript(tmp_path: Path) -> None:  # noqa: N802
    lf = _write(
        tmp_path,
        {
            "node_modules/esbuild": {
                "version": "0.20.0",
                "hasInstallScript": True,
            },
            "node_modules/lodash": {
                "version": "4.17.21",
            },
        },
    )
    report = check_install_scripts(lf)
    assert not report.clean
    assert len(report.flagged) == 1
    assert report.flagged[0].package_name == "esbuild"
    assert report.flagged[0].version == "0.20.0"


def test_allowlist_lets_named_package_through(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/esbuild": {
                "version": "0.20.0",
                "hasInstallScript": True,
            },
            "node_modules/sneaky": {
                "version": "1.0.0",
                "hasInstallScript": True,
            },
        },
    )
    report = check_install_scripts(lf, allowed=["esbuild"])
    assert not report.clean, "sneaky is not allowlisted and must remain flagged"
    assert [f.package_name for f in report.flagged] == ["sneaky"]
    assert [f.package_name for f in report.allowed] == ["esbuild"]


def test_clean_when_no_install_scripts(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/@babel/runtime": {"version": "7.25.6"},
        },
    )
    report = check_install_scripts(lf)
    assert report.clean
    assert report.flagged == []


def test_scoped_package_matched_by_full_name(tmp_path: Path) -> None:
    """Allowlist entries use the FULL package name including scope, not just the bare name."""
    lf = _write(
        tmp_path,
        {
            "node_modules/@parcel/watcher": {
                "version": "2.4.0",
                "hasInstallScript": True,
            },
        },
    )
    # Just "watcher" must NOT match — that would let an attacker register
    # `watcher` on public npm and slip a script past the allowlist.
    report_partial = check_install_scripts(lf, allowed=["watcher"])
    assert not report_partial.clean

    # The correctly-scoped form is what allowlist requires.
    report_full = check_install_scripts(lf, allowed=["@parcel/watcher"])
    assert report_full.clean


def test_nested_package_extracts_correct_name(tmp_path: Path) -> None:
    """Nested node_modules paths use the leaf as the package name for allowlist matching."""
    lf = _write(
        tmp_path,
        {
            "node_modules/parent/node_modules/inner-build-tool": {
                "version": "1.0.0",
                "hasInstallScript": True,
            },
        },
    )
    report = check_install_scripts(lf, allowed=["inner-build-tool"])
    assert report.clean
    assert report.allowed[0].lockfile_key == (
        "node_modules/parent/node_modules/inner-build-tool"
    )


def test_link_entries_ignored(tmp_path: Path) -> None:
    """Workspace symlinks don't run install scripts as separate entries."""
    lf = _write(
        tmp_path,
        {
            "node_modules/@local/scripts": {
                "version": "0.0.0",
                "link": True,
                "hasInstallScript": True,  # ignored on link entries
            },
        },
    )
    report = check_install_scripts(lf)
    assert report.clean


def test_allowlist_is_case_insensitive(tmp_path: Path) -> None:
    lf = _write(
        tmp_path,
        {
            "node_modules/EsBuild": {
                "version": "0.20.0",
                "hasInstallScript": True,
            },
        },
    )
    report = check_install_scripts(lf, allowed=["esbuild"])
    assert report.clean


def test_v1_lockfile_rejected(tmp_path: Path) -> None:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 1}))
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        check_install_scripts(p)
