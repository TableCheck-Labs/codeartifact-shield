"""pnpm adapter — parsing, key handling, validation, and rejection cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeartifact_shield.lockfiles import (
    Capability,
    LockFormat,
    load_normalized,
)
from codeartifact_shield.lockfiles._model import ResolvedKind
from codeartifact_shield.lockfiles.pnpm import (
    _split_key,
    read_pnpm_workspace_settings,
)

FIXTURES = Path(__file__).parent / "fixtures" / "pnpm"


# ---------------------------------------------------------------------------
# Key splitting
# ---------------------------------------------------------------------------


def test_split_key_v6_leading_slash() -> None:
    assert _split_key("/is-odd@3.0.1") == ("is-odd", "3.0.1", "")


def test_split_key_scoped() -> None:
    assert _split_key("@esbuild/aix-ppc64@0.19.12") == (
        "@esbuild/aix-ppc64",
        "0.19.12",
        "",
    )


def test_split_key_peer_suffix() -> None:
    assert _split_key("react-dom@18.2.0(react@18.2.0)") == (
        "react-dom",
        "18.2.0",
        "(react@18.2.0)",
    )


def test_split_key_v6_scoped_with_peer() -> None:
    assert _split_key("/@scope/pkg@1.2.3(peer@4.5.6)") == (
        "@scope/pkg",
        "1.2.3",
        "(peer@4.5.6)",
    )


# ---------------------------------------------------------------------------
# v6 parsing
# ---------------------------------------------------------------------------


def test_v6_basic_parses() -> None:
    nl = load_normalized(FIXTURES / "lock-v6-basic.yaml")
    assert nl.format is LockFormat.PNPM
    assert nl.format_version == "6.0"
    assert len(nl.entries) == 5
    kinds = {e.name: e.resolved_kind for e in nl.entries}
    assert kinds["is-odd"] is ResolvedKind.REGISTRY_IMPLIED
    assert kinds["forked-dep"] is ResolvedKind.GIT
    assert kinds["@example/tarball-dep"] is ResolvedKind.TARBALL


def test_v6_requires_build_sets_install_script() -> None:
    nl = load_normalized(FIXTURES / "lock-v6-basic.yaml")
    scripts = {e.name: e.has_install_script for e in nl.entries}
    assert scripts["native-mod"] is True
    assert scripts["is-odd"] is False
    assert Capability.INSTALL_SCRIPTS in nl.capabilities


def test_v6_git_entry_uses_explicit_name_version() -> None:
    nl = load_normalized(FIXTURES / "lock-v6-basic.yaml")
    git = next(e for e in nl.entries if e.name == "forked-dep")
    assert git.version == "2.0.0"  # from the entry's explicit `version`, not the key
    assert git.key.startswith("github.com/example/forked-dep/")


def test_v6_transitive_dependencies_captured() -> None:
    nl = load_normalized(FIXTURES / "lock-v6-basic.yaml")
    is_odd = next(e for e in nl.entries if e.name == "is-odd")
    assert dict(is_odd.dependencies) == {"is-number": "6.0.0"}


# ---------------------------------------------------------------------------
# v9 parsing (packages/snapshots split, peer suffixes)
# ---------------------------------------------------------------------------


def test_v9_basic_parses_and_merges_snapshots() -> None:
    nl = load_normalized(FIXTURES / "lock-v9-basic.yaml")
    assert nl.format_version == "9.0"
    rd = next(e for e in nl.entries if e.name == "react-dom")
    # packages key is the base; snapshot key carries the peer suffix.
    assert rd.version == "18.2.0"
    assert dict(rd.dependencies) == {
        "loose-envify": "1.4.0",
        "react": "18.2.0",
        "scheduler": "0.23.2",
    }


def test_v9_has_no_install_script_capability() -> None:
    nl = load_normalized(FIXTURES / "lock-v9-basic.yaml")
    assert Capability.INSTALL_SCRIPTS not in nl.capabilities
    assert all(e.has_install_script is None for e in nl.entries)


def test_v9_integrity_present() -> None:
    nl = load_normalized(FIXTURES / "lock-v9-basic.yaml")
    react = next(e for e in nl.entries if e.name == "react")
    assert react.integrity is not None
    assert react.integrity.startswith("sha512-")


def test_v9_workspace_importers() -> None:
    nl = load_normalized(FIXTURES / "lock-v9-workspace.yaml")
    assert set(nl.workspaces) == {".", "packages/a"}
    assert nl.workspaces["packages/a"]["dependencies"]["leftpad"] == "0.0.1"
    assert nl.workspaces["packages/a"]["dependencies"]["root"] == "workspace:*"


# ---------------------------------------------------------------------------
# Validation / rejection
# ---------------------------------------------------------------------------


def test_traversal_key_rejected() -> None:
    with pytest.raises(ValueError, match="path traversal"):
        load_normalized(FIXTURES / "lock-tampered-traversal.yaml")


def test_alias_bomb_rejected() -> None:
    with pytest.raises(ValueError, match="anchors|aliases"):
        load_normalized(FIXTURES / "lock-alias-bomb.yaml")


def test_v5_lockfile_rejected() -> None:
    with pytest.raises(ValueError, match="pnpm >= 8"):
        load_normalized(FIXTURES / "lock-v5-old.yaml")


def test_unsupported_version_rejected(tmp_path: Path) -> None:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text("lockfileVersion: '7.0'\npackages: {}\n")
    with pytest.raises(ValueError, match="only 6.0, 9.0"):
        load_normalized(p)


def test_importer_traversal_rejected(tmp_path: Path) -> None:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(
        "lockfileVersion: '9.0'\n"
        "importers:\n"
        "  ../../etc:\n"
        "    dependencies: {}\n"
        "packages: {}\n"
    )
    with pytest.raises(ValueError, match="importer key"):
        load_normalized(p)


def test_non_https_tarball_rejected(tmp_path: Path) -> None:
    p = tmp_path / "pnpm-lock.yaml"
    p.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  evil@1.0.0:\n"
        "    resolution: {tarball: 'http://evil.example/x.tgz'}\n"
    )
    with pytest.raises(ValueError, match="non-https tarball"):
        load_normalized(p)


def test_size_cap_rejects_oversized(tmp_path: Path) -> None:
    from codeartifact_shield.lockfiles._yaml_safe import (
        YamlSafetyError,
        safe_load_mapping,
    )

    with pytest.raises(YamlSafetyError, match="safety cap"):
        safe_load_mapping("lockfileVersion: '9.0'\n", max_bytes=4)


# ---------------------------------------------------------------------------
# Workspace settings helper
# ---------------------------------------------------------------------------


def test_read_pnpm_workspace_settings() -> None:
    settings = read_pnpm_workspace_settings(FIXTURES)
    assert settings.get("onlyBuiltDependencies") == ["esbuild"]
    assert settings.get("minimumReleaseAge") == 1440


def test_read_pnpm_workspace_settings_absent(tmp_path: Path) -> None:
    assert read_pnpm_workspace_settings(tmp_path) == {}
