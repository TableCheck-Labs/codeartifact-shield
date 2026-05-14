"""Shared package-name allowlist with optional version pinning."""

from __future__ import annotations

import pytest

from codeartifact_shield._allowlist import PackageAllowlist, parse_spec


def test_parse_unscoped_name_only() -> None:
    assert parse_spec("lodash") == ("lodash", None)


def test_parse_unscoped_name_at_version() -> None:
    assert parse_spec("lodash@4.17.21") == ("lodash", "4.17.21")


def test_parse_scoped_name_only() -> None:
    assert parse_spec("@my/pkg") == ("@my/pkg", None)


def test_parse_scoped_name_at_version() -> None:
    assert parse_spec("@my/pkg@1.0.0") == ("@my/pkg", "1.0.0")


def test_parse_scoped_with_prerelease() -> None:
    assert parse_spec("@my/pkg@1.0.0-rc.1") == ("@my/pkg", "1.0.0-rc.1")


def test_parse_unscoped_with_complex_version() -> None:
    # Versions with their own at-signs aren't valid SemVer; we still split
    # at the first separator.
    assert parse_spec("react@18.3.1-canary.20240101+build.99") == (
        "react",
        "18.3.1-canary.20240101+build.99",
    )


def test_parse_rejects_empty_string() -> None:
    with pytest.raises(ValueError, match="empty allowlist entry"):
        parse_spec("")


def test_parse_rejects_lone_at() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        parse_spec("@")


def test_parse_rejects_at_without_name() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        parse_spec("@version")


def test_parse_rejects_trailing_at_with_no_version() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        parse_spec("lodash@")


def test_parse_rejects_scoped_with_no_pkg_name() -> None:
    with pytest.raises(ValueError, match="not a valid"):
        parse_spec("@scope/")


def test_allowlist_empty_matches_nothing() -> None:
    al = PackageAllowlist.from_entries([])
    assert not al.allows("lodash", "4.17.21")
    assert not al.allows("@my/pkg", "1.0.0")


def test_allowlist_name_only_matches_every_version() -> None:
    al = PackageAllowlist.from_entries(["lodash"])
    assert al.allows("lodash", "4.17.21")
    assert al.allows("lodash", "3.10.0")
    assert al.allows("LODASH", "4.17.21")  # case-insensitive on name


def test_allowlist_versioned_matches_only_that_version() -> None:
    al = PackageAllowlist.from_entries(["lodash@4.17.21"])
    assert al.allows("lodash", "4.17.21")
    assert not al.allows("lodash", "4.17.20")
    assert not al.allows("lodash", "5.0.0")


def test_allowlist_name_only_takes_precedence_over_versioned() -> None:
    # If user supplies both forms, the broader name-only wins.
    al = PackageAllowlist.from_entries(["lodash", "lodash@4.17.21"])
    assert al.allows("lodash", "1.0.0")
    assert al.allows("lodash", "999.999.999")


def test_allowlist_scoped_versioned() -> None:
    al = PackageAllowlist.from_entries(["@my/pkg@1.0.0"])
    assert al.allows("@my/pkg", "1.0.0")
    assert not al.allows("@my/pkg", "1.0.1")
    assert not al.allows("@my/other", "1.0.0")


def test_allowlist_mixed_entries() -> None:
    al = PackageAllowlist.from_entries(
        ["@trusted/lib", "lodash@4.17.21", "@my/pkg@2.0.0"]
    )
    assert al.allows("@trusted/lib", "0.0.1")  # name-only
    assert al.allows("@trusted/lib", "99.99.99")  # name-only
    assert al.allows("lodash", "4.17.21")  # versioned
    assert not al.allows("lodash", "4.17.20")  # versioned, miss
    assert al.allows("@my/pkg", "2.0.0")  # versioned
    assert not al.allows("@my/pkg", "1.0.0")  # versioned, miss
    assert not al.allows("axios", "1.6.7")  # unknown


def test_allowlist_versions_are_case_sensitive() -> None:
    # SemVer is case-sensitive for prereleases. We match the version exactly.
    al = PackageAllowlist.from_entries(["foo@1.0.0-RC.1"])
    assert al.allows("foo", "1.0.0-RC.1")
    assert not al.allows("foo", "1.0.0-rc.1")


def test_allowlist_invalid_entry_propagates_error() -> None:
    with pytest.raises(ValueError):
        PackageAllowlist.from_entries(["valid-name", ""])
