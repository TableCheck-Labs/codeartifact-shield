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
    ref = _ref_from_lockfile_key("node_modules/lodash")
    assert ref == PackageRef(namespace=None, name="lodash", version="")


def test_ref_from_lockfile_key_scoped() -> None:
    ref = _ref_from_lockfile_key("node_modules/@babel/runtime")
    assert ref == PackageRef(namespace="babel", name="runtime", version="")


def test_ref_from_lockfile_key_nested() -> None:
    """Nested node_modules paths resolve to the actual installed package."""
    ref = _ref_from_lockfile_key("node_modules/foo/node_modules/@scope/bar")
    assert ref == PackageRef(namespace="scope", name="bar", version="")


def test_ref_from_lockfile_key_rejects_non_node_modules() -> None:
    assert _ref_from_lockfile_key("packages/whatever") is None


def test_lockfile_key_round_trip() -> None:
    for key in (
        "node_modules/lodash",
        "node_modules/@babel/runtime",
    ):
        ref = _ref_from_lockfile_key(key)
        assert ref is not None
        assert ref.lockfile_key == key


def test_iter_lockfile_packages_skips_root() -> None:
    lock = json.loads(FIXTURE.read_text())
    keys = [k for k, _ in _iter_lockfile_packages(lock)]
    assert "" not in keys
    assert "node_modules/lodash" in keys


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
    sha_lodash = "a" * 128
    sha_runtime = "b" * 128
    sha_codeframe = "c" * 128

    client = _fake_client(
        {
            ("lodash", "4.17.21", None): sha_lodash,
            ("runtime", "7.25.6", "babel"): sha_runtime,
            ("code-frame", "7.24.7", "babel"): sha_codeframe,
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
    assert written["packages"]["node_modules/lodash"]["integrity"] == sri_from_sha512_hex(
        sha_lodash
    )
    assert (
        written["packages"]["node_modules/@babel/runtime"]["integrity"]
        == sri_from_sha512_hex(sha_runtime)
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
            ("lodash", "4.17.21", None): "a" * 128,
            ("runtime", "7.25.6", "babel"): "b" * 128,
            ("code-frame", "7.24.7", "babel"): "c" * 128,
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

    # Only lodash is in CodeArtifact; the others 404.
    client = _fake_client({("lodash", "4.17.21", None): "a" * 128})

    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
    )

    assert report.patched == 1
    assert sorted(report.not_in_codeartifact) == [
        "node_modules/@babel/code-frame",
        "node_modules/@babel/runtime",
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


def test_verify_lockfile_rejects_v1(tmp_path: Path) -> None:
    """v1 lockfiles must fail loudly, not silently report 0/0 = 100%."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        verify_lockfile(lockfile)


# ---------------------------------------------------------------------------
# G1 — bundleDependencies are integrity-anchored by the parent's hash.
#
# Threat model: at install time npm re-derives `inDepBundle` from the
# *parent's* package.json (which lives inside the parent's tarball, which
# is itself integrity-pinned). Tampering with the lockfile's `inBundle: true`
# flag has no install-time effect. So a bundled child whose parent has
# integrity is cryptographically covered — but a bundled child whose
# parent has no integrity is an orphan and must fail closed.
# ---------------------------------------------------------------------------

_VALID_SRI = "sha512-" + ("a" * 86) + "=="


def _write_lock(tmp_path: Path, packages: dict[str, dict[str, Any]]) -> Path:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2)
    )
    return lockfile


def test_verify_counts_bundled_via_parent_integrity_as_covered(tmp_path: Path) -> None:
    """A bundled child whose parent has integrity is covered transitively."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/parent": {
                "version": "1.0.0",
                "resolved": "https://r/parent.tgz",
                "integrity": _VALID_SRI,
            },
            "node_modules/parent/node_modules/bundled-child": {
                "version": "2.0.0",
                "inBundle": True,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 2, "bundled child must still be counted in the denominator"
    assert covered == 2, "bundled child must count as covered via parent integrity"


def test_verify_bundled_without_parent_integrity_fails_closed(tmp_path: Path) -> None:
    """If parent has no integrity, the bundled child cannot be trusted."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/parent": {
                "version": "1.0.0",
                # No resolved, no integrity — e.g. git source, file source.
            },
            "node_modules/parent/node_modules/bundled-orphan": {
                "version": "2.0.0",
                "inBundle": True,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 2
    assert covered == 0, "no trust root exists; both entries are uncovered"


def test_verify_bundled_transitive_chain(tmp_path: Path) -> None:
    """A -> bundles B -> bundles C. C is covered iff A has integrity."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://r/a.tgz",
                "integrity": _VALID_SRI,
            },
            "node_modules/a/node_modules/b": {
                "version": "2.0.0",
                "inBundle": True,
            },
            "node_modules/a/node_modules/b/node_modules/c": {
                "version": "3.0.0",
                "inBundle": True,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 3
    assert covered == 3, "the chain anchors to A's integrity"


def test_verify_bundled_chain_breaks_when_top_lacks_integrity(tmp_path: Path) -> None:
    """If the chain's anchor (top of bundle ancestry) has no integrity, nothing is covered."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                # No integrity — chain broken at root.
            },
            "node_modules/a/node_modules/b": {
                "version": "2.0.0",
                "inBundle": True,
            },
            "node_modules/a/node_modules/b/node_modules/c": {
                "version": "3.0.0",
                "inBundle": True,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 3
    assert covered == 0


def test_verify_inBundle_at_top_level_uncovered(tmp_path: Path) -> None:
    """`inBundle: true` at top-level node_modules (no parent in nm) is suspicious — fail closed."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/rogue-bundled": {
                "version": "1.0.0",
                "inBundle": True,
                # No parent in node_modules — bundleDependencies relationship
                # cannot be cryptographically anchored.
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 1
    assert covered == 0, "top-level inBundle has no parent to anchor to"


# ---------------------------------------------------------------------------
# G2 — patch must NOT inject a standalone hash for bundled entries.
#
# The hash CodeArtifact stores for is-unicode-supported@1.3.0 (a standalone
# publication) only equals the bytes inside @clack/prompts@0.6.3's tarball
# by coincidence — a parent author could have modified the bundled package
# at publish time. Writing the standalone hash would create false confidence:
# `npm ci` doesn't verify bundled bytes against any hash, so the wrong
# integrity value would silently pass install while misleading auditors.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# G7 — SRI algorithm strength. SHA-1 is cryptographically broken (SHA-1 was
# removed from the SRI spec years ago). An entry whose only `integrity` is
# `sha1-...` must not be counted as covered, and `patch` must upgrade it.
# Acceptable algorithms: sha256, sha384, sha512 (npm's modern default).
# ---------------------------------------------------------------------------

_WEAK_SRI_SHA1 = "sha1-" + ("a" * 27) + "="  # 20-byte SHA-1, base64 ~28 chars
_STRONG_SRI_SHA256 = "sha256-" + ("a" * 43) + "="  # 32-byte SHA-256
_STRONG_SRI_SHA384 = "sha384-" + ("a" * 64)  # 48-byte SHA-384
_STRONG_SRI_SHA512 = "sha512-" + ("a" * 86) + "=="


def test_verify_treats_sha1_integrity_as_missing(tmp_path: Path) -> None:
    """`sha1-...` is collision-broken and not in modern SRI spec — fail closed."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/legacy": {
                "version": "1.0.0",
                "resolved": "https://r/legacy.tgz",
                "integrity": _WEAK_SRI_SHA1,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert total == 1
    assert covered == 0, "sha1 must not count as covered"


def test_verify_accepts_sha256_sha384_sha512(tmp_path: Path) -> None:
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://r/a.tgz",
                "integrity": _STRONG_SRI_SHA256,
            },
            "node_modules/b": {
                "version": "1.0.0",
                "resolved": "https://r/b.tgz",
                "integrity": _STRONG_SRI_SHA384,
            },
            "node_modules/c": {
                "version": "1.0.0",
                "resolved": "https://r/c.tgz",
                "integrity": _STRONG_SRI_SHA512,
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert (covered, total) == (3, 3)


def test_verify_accepts_mixed_when_at_least_one_is_strong(tmp_path: Path) -> None:
    """SRI strings can be space-separated; if any algorithm is strong, the entry is covered."""
    lockfile = _write_lock(
        tmp_path,
        {
            "node_modules/upgraded": {
                "version": "1.0.0",
                "resolved": "https://r/upgraded.tgz",
                "integrity": f"{_WEAK_SRI_SHA1} {_STRONG_SRI_SHA512}",
            },
        },
    )
    covered, total = verify_lockfile(lockfile)
    assert (covered, total) == (1, 1)


def test_patch_upgrades_weak_sha1_integrity_to_sha512(tmp_path: Path) -> None:
    """A lockfile with sha1 must be patched to sha512 by `cas sri patch`."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/legacy": {
                        "version": "1.0.0",
                        "resolved": "https://r/legacy.tgz",
                        "integrity": _WEAK_SRI_SHA1,
                    },
                },
            }
        )
    )
    client = _fake_client({("legacy", "1.0.0", None): "f" * 128})
    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
    )
    assert report.patched == 1
    written = json.loads(lockfile.read_text())
    new_integrity = written["packages"]["node_modules/legacy"]["integrity"]
    assert new_integrity.startswith("sha512-")
    assert "sha1-" not in new_integrity


def test_patch_lockfile_skips_bundled_entries(tmp_path: Path) -> None:
    """A bundled entry must not have integrity injected from CA."""
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/parent": {
                        "version": "1.0.0",
                        "resolved": "https://r/parent.tgz",
                        "integrity": _VALID_SRI,
                    },
                    "node_modules/parent/node_modules/bundled-child": {
                        "version": "2.0.0",
                        "inBundle": True,
                    },
                },
            }
        )
    )

    # The fake client WOULD return a hash for bundled-child if asked, which
    # would be wrong to inject — so the test asserts we never asked.
    client = _fake_client({("bundled-child", "2.0.0", None): "b" * 128})

    report = patch_lockfile(
        lockfile,
        domain="d",
        repository="r",
        boto3_session=_fake_session(client),
    )

    assert report.patched == 0, "no bundled entry should be patched"
    written = json.loads(lockfile.read_text())
    assert (
        "integrity"
        not in written["packages"]["node_modules/parent/node_modules/bundled-child"]
    ), "bundled entry must not have a fabricated standalone hash injected"
    # And we must not have made a CA API call for the bundled entry.
    assert client.list_package_version_assets.call_count == 0, (
        "patch should skip bundled entries without touching CodeArtifact"
    )
