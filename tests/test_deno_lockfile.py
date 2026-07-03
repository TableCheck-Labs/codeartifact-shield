"""Deno adapter — parsing, key handling, integrity normalization, rejection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codeartifact_shield.lockfiles import (
    Capability,
    Ecosystem,
    LockFormat,
    ResolvedKind,
    load_normalized,
)
from codeartifact_shield.lockfiles.deno import (
    _split_npm_key,
    read_deno_manifest,
)

FIXTURES = Path(__file__).parent / "fixtures" / "deno"


def _write(tmp_path: Path, content: dict) -> Path:
    p = tmp_path / "deno.lock"
    p.write_text(json.dumps(content))
    return p


# ---------------------------------------------------------------------------
# Key splitting
# ---------------------------------------------------------------------------


def test_split_npm_key_plain() -> None:
    assert _split_npm_key("chalk@5.3.0") == ("chalk", "5.3.0")


def test_split_npm_key_peer_suffix() -> None:
    assert _split_npm_key("vite@5.0.0_@types+node@20.0.0") == ("vite", "5.0.0")


# ---------------------------------------------------------------------------
# Parsing across versions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version", ["v3", "v4", "v5"])
def test_parses_all_versions(version: str) -> None:
    nl = load_normalized(FIXTURES / f"lock-{version}.json")
    assert nl.format is LockFormat.DENO
    assert nl.format_version == version[1:]
    assert len(nl.entries) == 5
    by_eco = {e.ecosystem for e in nl.entries}
    assert by_eco == {Ecosystem.NPM, Ecosystem.JSR, Ecosystem.REMOTE}


def test_npm_entry_fields() -> None:
    nl = load_normalized(FIXTURES / "lock-v4.json")
    chalk = next(e for e in nl.entries if e.name == "chalk")
    assert chalk.version == "5.3.0"
    assert chalk.ecosystem is Ecosystem.NPM
    assert chalk.resolved_kind is ResolvedKind.REGISTRY_IMPLIED
    assert chalk.integrity is not None and chalk.integrity.startswith("sha512-")
    assert dict(chalk.dependencies) == {"ansi-styles": "6.2.1"}


def test_npm_v3_dependencies_map_form() -> None:
    nl = load_normalized(FIXTURES / "lock-v3.json")
    chalk = next(e for e in nl.entries if e.name == "chalk")
    assert dict(chalk.dependencies) == {"ansi-styles": "6.2.1"}


def test_jsr_entry_integrity_normalized_to_sri() -> None:
    nl = load_normalized(FIXTURES / "lock-v4.json")
    jsr = next(e for e in nl.entries if e.name == "@std/assert")
    assert jsr.ecosystem is Ecosystem.JSR
    assert jsr.version == "1.0.0"
    # bare sha256 hex is normalized to sha256-<base64> SRI form.
    assert jsr.integrity is not None and jsr.integrity.startswith("sha256-")


def test_remote_entry_is_registry_with_url_and_sri() -> None:
    nl = load_normalized(FIXTURES / "lock-v4.json")
    remote = next(e for e in nl.entries if e.ecosystem is Ecosystem.REMOTE)
    assert remote.resolved_kind is ResolvedKind.REGISTRY
    assert remote.resolved == remote.name
    assert remote.name.startswith("https://")
    assert remote.version == ""
    assert remote.integrity is not None and remote.integrity.startswith("sha256-")


def test_capabilities() -> None:
    nl = load_normalized(FIXTURES / "lock-v4.json")
    assert Capability.INTEGRITY in nl.capabilities
    assert Capability.RESOLVED_URLS in nl.capabilities
    assert Capability.SRI_PATCH not in nl.capabilities
    assert Capability.INSTALL_SCRIPTS not in nl.capabilities


def test_workspace_specifiers_view() -> None:
    nl = load_normalized(FIXTURES / "lock-v4.json")
    deps = nl.workspaces[""]["dependencies"]
    assert deps["npm:chalk@^5"] == "5.3.0"


# ---------------------------------------------------------------------------
# Validation / rejection
# ---------------------------------------------------------------------------


def test_version_1_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, {"version": "1", "remote": {}})
    with pytest.raises(ValueError, match="modern Deno"):
        load_normalized(p)


def test_http_remote_rejected() -> None:
    with pytest.raises(ValueError, match="non-https remote URL"):
        load_normalized(FIXTURES / "lock-tampered.json")


def test_bad_remote_hex_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "version": "4",
            "remote": {"https://deno.land/x/a.ts": "not-64-hex"},
        },
    )
    with pytest.raises(ValueError, match="64 lowercase hex"):
        load_normalized(p)


def test_traversal_in_npm_key_rejected(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {"version": "4", "npm": {"..@1.0.0": {"integrity": "sha512-x"}}},
    )
    with pytest.raises(ValueError, match="path traversal"):
        load_normalized(p)


def test_cross_host_redirect_rejected_when_not_https(tmp_path: Path) -> None:
    p = _write(
        tmp_path,
        {
            "version": "4",
            "redirects": {"https://a.example/x": "http://b.example/x"},
        },
    )
    with pytest.raises(ValueError, match="non-https redirect target"):
        load_normalized(p)


def test_null_byte_rejected(tmp_path: Path) -> None:
    p = tmp_path / "deno.lock"
    p.write_text('{"version": "4", "npm": {"a\x00@1": {}}}')
    with pytest.raises(ValueError, match="null byte"):
        load_normalized(p)


# ---------------------------------------------------------------------------
# Manifest reading (deno.json / deno.jsonc)
# ---------------------------------------------------------------------------


def test_read_deno_manifest_plain_json() -> None:
    manifest = read_deno_manifest(FIXTURES)
    assert manifest["imports"]["chalk"] == "npm:chalk@^5"


def test_read_deno_manifest_jsonc(tmp_path: Path) -> None:
    (tmp_path / "deno.jsonc").write_text(
        '{\n  // a comment\n  "imports": {"x": "npm:x@1.0.0",}\n}'
    )
    manifest = read_deno_manifest(tmp_path)
    assert manifest["imports"]["x"] == "npm:x@1.0.0"


def test_read_deno_manifest_absent(tmp_path: Path) -> None:
    assert read_deno_manifest(tmp_path) == {}
