"""Tests for SRI integrity backfill."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from codeartifact_shield.sri import (
    PackageRef,
    _iter_lockfile_packages,
    _ref_from_lockfile_key,
    patch_lockfile,
    sri_from_sha512_hex,
    verify_lockfile,
)

FIXTURE = Path(__file__).parent / "fixtures" / "sample-package-lock.json"


def test_sri_from_sha512_hex_matches_public_format() -> None:
    """The output must be exactly what npm publishes as ``dist.integrity``."""
    # Known good: SHA-512 of the literal bytes b"hello", in lowercase hex.
    hex_digest = hashlib.sha512(b"hello").hexdigest()
    sri = sri_from_sha512_hex(hex_digest)
    assert sri.startswith("sha512-")
    # base64-encoded SHA-512 is 88 chars including padding.
    assert len(sri) == len("sha512-") + 88


def test_sri_from_sha512_hex_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="expected 64-byte SHA-512"):
        sri_from_sha512_hex("deadbeef")


def test_ref_from_lockfile_key_unscoped() -> None:
    ref = _ref_from_lockfile_key("node_modules/react")
    assert ref == PackageRef(namespace=None, name="react", version="")


def test_ref_from_lockfile_key_scoped() -> None:
    ref = _ref_from_lockfile_key("node_modules/@tanstack/react-query")
    assert ref == PackageRef(namespace="tanstack", name="react-query", version="")


def test_ref_from_lockfile_key_nested() -> None:
    """Nested node_modules paths resolve to the actual installed package."""
    ref = _ref_from_lockfile_key("node_modules/foo/node_modules/@scope/bar")
    assert ref == PackageRef(namespace="scope", name="bar", version="")


def test_ref_from_lockfile_key_rejects_non_node_modules() -> None:
    assert _ref_from_lockfile_key("packages/whatever") is None


def test_lockfile_key_round_trip() -> None:
    for key in (
        "node_modules/react",
        "node_modules/@tanstack/react-query",
    ):
        ref = _ref_from_lockfile_key(key)
        assert ref is not None
        assert ref.lockfile_key == key


def test_iter_lockfile_packages_skips_root() -> None:
    lock = json.loads(FIXTURE.read_text())
    keys = [k for k, _ in _iter_lockfile_packages(lock)]
    assert "" not in keys
    assert "node_modules/react" in keys


def test_verify_lockfile_counts_correctly() -> None:
    with_integrity, total = verify_lockfile(FIXTURE)
    # Fixture has 4 installable entries; one already has integrity.
    assert total == 4
    assert with_integrity == 1


def _fake_client(asset_table: dict[tuple[str, str, str | None], str]) -> Any:
    """Build a MagicMock that resolves SHA-512 from a (name, version, namespace) lookup."""
    client = MagicMock()

    class _NotFoundError(Exception):
        pass

    client.exceptions.ResourceNotFoundException = _NotFoundError

    def _list(**kwargs: Any) -> dict[str, Any]:
        key = (kwargs["package"], kwargs["packageVersion"], kwargs.get("namespace"))
        sha = asset_table.get(key)
        if sha is None:
            raise _NotFoundError("nope")
        return {"assets": [{"name": "package.tgz", "hashes": {"SHA-512": sha}}]}

    client.list_package_version_assets.side_effect = _list
    return client


def _fake_session(client: Any) -> Any:
    session = MagicMock()
    session.client.return_value = client
    return session


def test_patch_lockfile_backfills_missing_integrity(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(FIXTURE.read_text())

    # 64-byte SHA-512s — content doesn't matter, just length.
    sha_react = "a" * 128
    sha_rq = "b" * 128
    sha_qc = "c" * 128

    client = _fake_client(
        {
            ("react", "18.3.1", None): sha_react,
            ("react-query", "5.90.21", "tanstack"): sha_rq,
            ("query-core", "5.90.20", "tanstack"): sha_qc,
        }
    )

    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
    )

    assert report.patched == 3
    assert report.already_present == 1
    assert report.not_in_codeartifact == []
    assert report.api_errors == []

    written = json.loads(lockfile.read_text())
    assert written["packages"]["node_modules/react"]["integrity"] == sri_from_sha512_hex(sha_react)
    assert (
        written["packages"]["node_modules/@tanstack/react-query"]["integrity"]
        == sri_from_sha512_hex(sha_rq)
    )
    # Pre-existing integrity left untouched.
    assert written["packages"]["node_modules/already-has-integrity"]["integrity"].startswith(
        "sha512-aaaa"
    )


def test_patch_lockfile_dry_run_leaves_file_alone(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    original = FIXTURE.read_text()
    lockfile.write_text(original)

    client = _fake_client(
        {
            ("react", "18.3.1", None): "a" * 128,
            ("react-query", "5.90.21", "tanstack"): "b" * 128,
            ("query-core", "5.90.20", "tanstack"): "c" * 128,
        }
    )

    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
        dry_run=True,
    )

    assert report.patched == 3
    assert lockfile.read_text() == original


def test_patch_lockfile_records_missing_packages(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(FIXTURE.read_text())

    # Only react is in CodeArtifact; the others 404.
    client = _fake_client({("react", "18.3.1", None): "a" * 128})

    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
    )

    assert report.patched == 1
    assert sorted(report.not_in_codeartifact) == [
        "node_modules/@tanstack/query-core",
        "node_modules/@tanstack/react-query",
    ]


def test_patch_lockfile_rejects_unsupported_version(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({"lockfileVersion": 1, "packages": {}}))
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        patch_lockfile(
            lockfile,
            domain="d",
            repository="r",
            boto3_session=_fake_session(_fake_client({})),
        )
