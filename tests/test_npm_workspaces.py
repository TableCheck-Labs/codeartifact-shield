"""Regression: npm v7+ workspace declaration entries must not be examined.

The bug, as reported by a downstream maintainer:

> CAS cooldown already filters "link": true entries — those are the
> node_modules/<workspace-name> symlink entries. But npm v7+ workspace
> lockfiles ALSO have a SECOND representation: top-level keys keyed by
> workspace path (system/i18n, system/i18n-name), with no link: true,
> just a regular name + version. Those slip through the existing filter
> and get probed against the registry, where they unsurprisingly don't
> exist.

Every command that iterates ``lock["packages"]`` (audit, cooldown,
scripts, registry, drift's orphan walker) must skip those.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield._lockfile import is_installable_entry
from codeartifact_shield.audit import audit_lockfile
from codeartifact_shield.cooldown import check_cooldown
from codeartifact_shield.drift import check_npm_drift
from codeartifact_shield.registry import check_npm_registry
from codeartifact_shield.scripts import check_install_scripts


def _workspace_lockfile(tmp_path: Path) -> Path:
    """A realistic npm v7+ workspace lockfile.

    Two workspaces (``system/i18n``, ``system/widgets``) plus one regular
    install (``lodash``). Each workspace appears twice in ``packages``:
      * once at the workspace path key (declaration — *not* installable),
      * once at ``node_modules/<workspace-name>`` with ``link: true``
        (the symlink — also not installable).
    """
    lf = tmp_path / "package-lock.json"
    lf.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "name": "monorepo-root",
                        "version": "0.0.0",
                        "workspaces": ["system/*"],
                    },
                    # Workspace declarations — NOT installable.
                    "system/i18n": {
                        "name": "@example/i18n",
                        "version": "2.1.1",
                    },
                    "system/widgets": {
                        "name": "@example/widgets",
                        "version": "1.4.0",
                    },
                    # Workspace symlinks — also NOT installable.
                    "node_modules/@example/i18n": {
                        "resolved": "system/i18n",
                        "link": True,
                    },
                    "node_modules/@example/widgets": {
                        "resolved": "system/widgets",
                        "link": True,
                    },
                    # Regular registry install.
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": (
                            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
                        ),
                        "integrity": (
                            "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgX"
                            "ZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
                        ),
                    },
                },
            }
        )
    )
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "name": "monorepo-root",
                "version": "0.0.0",
                "workspaces": ["system/*"],
                "dependencies": {"lodash": "4.17.21"},
            }
        )
    )
    return lf


def test_is_installable_entry_rejects_root_workspaces_and_symlinks() -> None:
    assert is_installable_entry("node_modules/lodash", {"version": "4.17.21"})
    assert is_installable_entry(
        "node_modules/@scope/pkg", {"version": "1.0.0"}
    )
    assert is_installable_entry(
        "node_modules/a/node_modules/b", {"version": "1.0.0"}
    )
    # Rejected:
    assert not is_installable_entry("", {"version": "0.0.0"})
    assert not is_installable_entry("system/i18n", {"version": "2.1.1"})
    assert not is_installable_entry(
        "node_modules/@scope/pkg", {"link": True}
    )
    assert not is_installable_entry("apps/web", {"version": "1.0.0"})


def test_cooldown_skips_workspace_declaration_entries(tmp_path: Path) -> None:
    """Regression: ``system/i18n`` style keys must not be probed against the
    registry. Before the fix, they appeared as private_blocked."""
    lf = _workspace_lockfile(tmp_path)

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "lodash" in url:
            return {"time": {"4.17.21": "2021-02-21T02:46:48.218Z"}}
        # Any other registry call would be a workspace leak.
        raise AssertionError(
            f"unexpected registry call (workspace leak?): {url}"
        )

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, min_age_days=14)
    assert report.private_blocked == []
    assert report.private_allowed == []
    assert report.clean


def test_audit_skips_workspace_declaration_entries(tmp_path: Path) -> None:
    """Same regression at the audit layer — workspaces would have been
    flagged as unaudited_private."""
    lf = _workspace_lockfile(tmp_path)

    def mock_post(
        url: str, body: dict[str, Any], timeout: int, retries: int = 2
    ) -> dict[str, Any]:
        # OSV batch only ever asked about real installs.
        for q in body.get("queries", []):
            name = q["package"]["name"]
            assert name == "lodash", (
                f"OSV asked about non-installable: {name} (workspace leak)"
            )
        return {"results": [{}]}

    def mock_head(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> int:
        # Probe never sees workspace names.
        assert "i18n" not in url and "widgets" not in url, url
        return 200

    with patch("codeartifact_shield.audit._http_post_json", mock_post), patch(
        "codeartifact_shield.audit._http_head_status", mock_head
    ):
        report = audit_lockfile(lf, probe_registry="https://registry.npmjs.org")
    assert report.unaudited_blocked == []
    assert report.unaudited_allowed == []
    assert report.clean


def test_scripts_skips_workspace_declaration_entries(tmp_path: Path) -> None:
    """If a workspace declaration happens to carry ``hasInstallScript: true``,
    we must not surface it as a finding."""
    lf = tmp_path / "package-lock.json"
    lf.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "root"},
                    "system/with-script": {
                        "name": "@example/with-script",
                        "version": "1.0.0",
                        "hasInstallScript": True,  # workspaces may declare this
                    },
                    "node_modules/@example/with-script": {"link": True},
                },
            }
        )
    )
    report = check_install_scripts(lf)
    assert report.flagged == []
    assert report.allowed == []
    assert report.clean


def test_drift_orphan_walker_does_not_flag_workspaces(tmp_path: Path) -> None:
    """Workspace declarations were getting flagged as orphan_entries because
    the BFS only walks ``node_modules/<name>`` paths and doesn't reach them.
    Now they're filtered out at iteration time so they can't be candidates."""
    _workspace_lockfile(tmp_path)
    report = check_npm_drift(tmp_path)
    assert report.orphan_entries == []
    assert report.mismatches == []


def test_registry_skips_workspace_declaration_entries(tmp_path: Path) -> None:
    """Workspaces have no ``resolved`` URL; without filtering, the
    classification pass routes them to ``unresolved`` — a false-positive
    tampering signal. Filtered out at iteration time."""
    lf = _workspace_lockfile(tmp_path)
    report = check_npm_registry(lf, allowed_hosts=("registry.npmjs.org",))
    assert report.leaked == []
    assert report.unresolved == []
    assert report.clean
