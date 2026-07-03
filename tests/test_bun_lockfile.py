"""Bun adapter — parsing, tuple-shape classification, and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeartifact_shield.lockfiles import (
    Ecosystem,
    LockFormat,
    ResolvedKind,
    load_normalized,
)
from codeartifact_shield.lockfiles.bun import build_normalized, trusted_dependencies

FIXTURES = Path(__file__).parent / "fixtures" / "bun"


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "bun.lock"
    p.write_text(text)
    return p


# ---------------------------------------------------------------------------
# parsing — JSONC, all source kinds
# ---------------------------------------------------------------------------


def test_basic_parse_jsonc_and_metadata() -> None:
    nl = build_normalized(FIXTURES / "bun-basic.lock")
    assert nl.format is LockFormat.BUN
    assert nl.format_version == "1"
    # 8 package entries survive comment/trailing-comma stripping.
    assert len(nl.entries) == 8
    assert all(e.ecosystem is Ecosystem.NPM for e in nl.entries)


def test_source_kind_classification() -> None:
    entries = {e.key: e for e in build_normalized(FIXTURES / "bun-basic.lock").entries}

    # default registry: no per-entry URL recorded.
    assert entries["is-number"].resolved_kind is ResolvedKind.REGISTRY_IMPLIED
    assert entries["is-number"].resolved is None
    assert entries["is-number"].version == "6.0.0"

    # explicit custom registry URL.
    assert entries["scoped-registry-pkg"].resolved_kind is ResolvedKind.REGISTRY
    assert entries["scoped-registry-pkg"].resolved == "https://npm.example.com/"

    # git / tarball / workspace / file.
    assert entries["gitdep"].resolved_kind is ResolvedKind.GIT
    assert entries["gitdep"].resolved == "github:example/gitdep#abc1234"
    assert entries["tardep"].resolved_kind is ResolvedKind.TARBALL
    assert entries["tardep"].resolved.endswith("tardep-1.0.0.tgz")
    assert entries["linkdep"].resolved_kind is ResolvedKind.LINK
    assert entries["filedep"].resolved_kind is ResolvedKind.FILE


def test_integrity_extracted_regardless_of_tuple_position() -> None:
    entries = {e.key: e for e in build_normalized(FIXTURES / "bun-basic.lock").entries}
    # registry tuple: integrity is element 3; git tuple: element 3 after a
    # string extract-dir; tarball tuple: element 2. All land on ``integrity``.
    assert entries["is-number"].integrity.startswith("sha512-")
    assert entries["gitdep"].integrity.startswith("sha512-")
    assert entries["tardep"].integrity.startswith("sha512-")
    # workspace/file entries carry no integrity.
    assert entries["linkdep"].integrity is None
    assert entries["filedep"].integrity is None


def test_dependency_graph_from_meta() -> None:
    entries = {e.key: e for e in build_normalized(FIXTURES / "bun-basic.lock").entries}
    assert entries["is-odd"].dependencies == {"is-number": "^6.0.0"}
    assert entries["is-number"].dependencies == {}


def test_workspaces_view_and_scopes() -> None:
    nl = build_normalized(FIXTURES / "bun-workspace.lock")
    assert set(nl.workspaces) == {"", "packages/a", "packages/b"}
    assert nl.workspaces[""]["dependencies"] == {
        "is-odd": "3.0.1",
        "left-pad": "1.3.0",
    }
    assert nl.workspaces["packages/b"]["dependencies"] == {"@myorg/a": "workspace:*"}


def test_trusted_dependencies_read() -> None:
    nl = build_normalized(FIXTURES / "bun-basic.lock")
    assert trusted_dependencies(nl.raw) == ["is-odd", "esbuild"]


def test_nested_conflict_keys_keep_canonical_name() -> None:
    nl = build_normalized(
        _write_tmp(
            '{"lockfileVersion":1,"packages":{'
            '"is-even/is-odd":["is-odd@0.1.2","",{"dependencies":{"is-number":"^3.0.0"}},'
            '"sha512-Ri7C2K7o5IrUU9UEI8losXJCCD/UtsaIrkR5sxIcFg4xQ9cRJXlWA5DQvTE0yDc0krvSNLsRGXN11UPS6KyfBw=="]'
            "}}"
        )
    )
    entry = nl.entries[0]
    assert entry.key == "is-even/is-odd"
    assert entry.name == "is-odd"
    assert entry.version == "0.1.2"


_TMP: dict[str, Path] = {}


def _write_tmp(text: str) -> Path:
    import tempfile

    d = Path(tempfile.mkdtemp())
    p = d / "bun.lock"
    p.write_text(text)
    return p


# ---------------------------------------------------------------------------
# version gating
# ---------------------------------------------------------------------------


def test_lockfile_version_0_accepted(tmp_path: Path) -> None:
    p = _write(tmp_path, '{"lockfileVersion": 0, "packages": {}}')
    assert build_normalized(p).format_version == "0"


def test_unknown_lockfile_version_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '{"lockfileVersion": 2, "packages": {}}')
    with pytest.raises(ValueError, match="unsupported bun.lock lockfileVersion"):
        build_normalized(p)


def test_missing_lockfile_version_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '{"packages": {}}')
    with pytest.raises(ValueError, match="must be an integer"):
        build_normalized(p)


def test_bool_lockfile_version_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '{"lockfileVersion": true, "packages": {}}')
    with pytest.raises(ValueError, match="must be an integer"):
        build_normalized(p)


# ---------------------------------------------------------------------------
# validation / tampering
# ---------------------------------------------------------------------------


def test_path_traversal_key_rejected() -> None:
    with pytest.raises(ValueError, match="path traversal"):
        build_normalized(FIXTURES / "bun-tampered.lock")


def test_http_registry_url_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        '{"lockfileVersion":1,"packages":{'
        '"x":["x@1.0.0","http://npm.example.com/",{},"sha512-'
        + "a" * 86
        + '=="]}}',
    )
    with pytest.raises(ValueError, match="non-https bun registry URL"):
        build_normalized(p)


def test_http_tarball_url_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        '{"lockfileVersion":1,"packages":{'
        '"x":["x@http://evil.example.com/x.tgz",{},"sha512-'
        + "a" * 86
        + '=="]}}',
    )
    with pytest.raises(ValueError, match="non-https bun tarball URL"):
        build_normalized(p)


def test_malformed_integrity_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        '{"lockfileVersion":1,"packages":{'
        '"x":["x@1.0.0","",{},"not-an-sri-hash"]}}',
    )
    # A non-SRI trailing string is simply not treated as integrity; the entry
    # parses with integrity=None rather than raising.
    nl = build_normalized(p)
    assert nl.entries[0].integrity is None


def test_sha1_integrity_is_valid_sri_but_weak(tmp_path: Path) -> None:
    # sha1 is well-formed SRI (accepted), just not a *strong* algorithm — the
    # sri gate counts it as uncovered, but parsing does not reject it.
    p = _write(
        tmp_path,
        '{"lockfileVersion":1,"packages":{'
        '"x":["x@1.0.0","",{},"sha1-' + "a" * 27 + '="]}}',
    )
    nl = build_normalized(p)
    assert nl.entries[0].integrity == "sha1-" + "a" * 27 + "="


def test_file_path_traversal_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        '{"lockfileVersion":1,"packages":{"x":["x@file:../../etc/passwd",{}]}}',
    )
    with pytest.raises(ValueError, match="path traversal"):
        build_normalized(p)


def test_null_byte_rejected(tmp_path: Path) -> None:
    p = tmp_path / "bun.lock"
    p.write_text('{"lockfileVersion":1,"packages":{}}\x00')
    with pytest.raises(ValueError, match="null byte"):
        build_normalized(p)


# ---------------------------------------------------------------------------
# detection routes through load_normalized
# ---------------------------------------------------------------------------


def test_load_normalized_by_filename() -> None:
    nl = load_normalized(FIXTURES / "bun-basic.lock")
    assert nl.format is LockFormat.BUN
