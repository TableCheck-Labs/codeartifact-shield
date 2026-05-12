"""Tests for the pinning-policy audit module."""

from __future__ import annotations

import json
from pathlib import Path

from codeartifact_shield.pins import (
    DEFAULT_SCOPES,
    PinFinding,
    _classify,
    check_pinning,
)


def _write_pkg(tmp_path: Path, content: dict[str, object]) -> Path:
    p = tmp_path / "package.json"
    p.write_text(json.dumps(content))
    return tmp_path


# ---------------------------------------------------------------------------
# _classify — pattern matchers
# ---------------------------------------------------------------------------


def test_classify_exact_semver() -> None:
    assert _classify("1.2.3") is None
    assert _classify("0.0.1") is None
    assert _classify("10.20.30") is None


def test_classify_semver_with_prerelease_and_build() -> None:
    assert _classify("1.2.3-rc.1") is None
    assert _classify("1.2.3-alpha.0.beta") is None
    assert _classify("1.2.3+build.7") is None
    assert _classify("1.2.3-rc.1+meta") is None


def test_classify_caret_range() -> None:
    assert _classify("^1.2.3") == "range"


def test_classify_tilde_range() -> None:
    assert _classify("~1.2.3") == "range"


def test_classify_comparator_ranges() -> None:
    assert _classify(">=1.2.3") == "range"
    assert _classify(">1.2.3") == "range"
    assert _classify("<=2.0.0") == "range"
    assert _classify("<2.0.0") == "range"


def test_classify_wildcard_ranges() -> None:
    assert _classify("1.2.x") == "range"
    assert _classify("1.X") == "range"
    assert _classify("*") == "dist_tag"


def test_classify_dist_tag_latest() -> None:
    assert _classify("latest") == "dist_tag"


def test_classify_union_and_compound_ranges() -> None:
    assert _classify("1.2.3 || 1.2.4") == "range"
    assert _classify(">=1.0.0 <2.0.0") == "range"


def test_classify_workspace_protocol_exempt() -> None:
    assert _classify("workspace:*") is None
    assert _classify("workspace:^") is None
    assert _classify("workspace:1.2.3") is None


def test_classify_npm_alias_recurses_on_target_spec() -> None:
    # Exact target → pinned.
    assert _classify("npm:lodash@4.17.21") is None
    # Range target → flagged as range.
    assert _classify("npm:lodash@^4.17.0") == "range"
    # Scoped alias.
    assert _classify("npm:@scope/name@1.0.0") is None


def test_classify_git_url_with_full_sha_is_pinned() -> None:
    sha = "a" * 40
    assert _classify(f"git+https://github.com/x/y.git#{sha}") is None
    assert _classify(f"git+ssh://git@github.com/x/y.git#{sha}") is None


def test_classify_git_url_without_sha_or_short_sha_is_flagged() -> None:
    # No fragment at all.
    assert _classify("git+https://github.com/x/y.git") == "git_ref"
    # Branch / tag fragment.
    assert _classify("git+https://github.com/x/y.git#main") == "git_ref"
    assert _classify("git+https://github.com/x/y.git#v1.0.0") == "git_ref"
    # Short SHA (rejected — only full 40-char SHAs).
    assert _classify("git+https://github.com/x/y.git#abc1234") == "git_ref"


def test_classify_github_shorthand_requires_full_sha() -> None:
    sha = "b" * 40
    assert _classify(f"github:user/repo#{sha}") is None
    assert _classify(f"user/repo#{sha}") is None
    assert _classify("github:user/repo#main") == "git_ref"
    assert _classify("user/repo") == "git_ref"


def test_classify_file_and_link_protocols() -> None:
    assert _classify("file:../local-dep") == "file"
    assert _classify("link:../symlinked") == "link"


def test_classify_tarball_url() -> None:
    assert _classify("https://example.com/x-1.0.0.tgz") == "tarball"
    assert _classify("http://example.com/x.tgz") == "tarball"


def test_classify_empty_and_non_string() -> None:
    assert _classify("") == "unknown"
    assert _classify(123) == "unknown"  # type: ignore[arg-type]
    assert _classify(None) == "unknown"  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# check_pinning — integration over package.json
# ---------------------------------------------------------------------------


def test_check_pinning_all_exact_passes(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {
            "dependencies": {"a": "1.2.3", "b": "2.0.0"},
            "devDependencies": {"c": "3.4.5"},
        },
    )
    report = check_pinning(project)
    assert report.clean
    assert report.total_checked == 3
    assert report.flagged == []


def test_check_pinning_flags_caret_range(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {"dependencies": {"a": "^1.2.3"}},
    )
    report = check_pinning(project)
    assert not report.clean
    assert len(report.flagged) == 1
    assert report.flagged[0] == PinFinding(
        scope="dependencies",
        package_name="a",
        declared="^1.2.3",
        kind="range",
    )


def test_check_pinning_flags_multiple_scopes(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {
            "dependencies": {"a": "^1.0.0"},
            "devDependencies": {"b": "~2.0.0"},
            "optionalDependencies": {"c": "latest"},
        },
    )
    report = check_pinning(project)
    assert len(report.flagged) == 3
    scopes_found = {f.scope for f in report.flagged}
    assert scopes_found == {"dependencies", "devDependencies", "optionalDependencies"}


def test_check_pinning_excludes_peer_by_default(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {
            "dependencies": {"a": "1.0.0"},
            "peerDependencies": {"react": "^18.0.0"},
        },
    )
    report = check_pinning(project)
    # peerDependencies range should NOT show up by default.
    assert report.clean
    assert report.total_checked == 1


def test_check_pinning_include_peer_audits_peer_deps(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {
            "dependencies": {"a": "1.0.0"},
            "peerDependencies": {"react": "^18.0.0"},
        },
    )
    report = check_pinning(project, include_peer=True)
    assert not report.clean
    assert len(report.flagged) == 1
    assert report.flagged[0].scope == "peerDependencies"


def test_check_pinning_allowlist_moves_to_allowed_bucket(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}},
    )
    report = check_pinning(project, allowed=["a"])
    assert not report.clean  # b is still flagged
    assert len(report.flagged) == 1
    assert report.flagged[0].package_name == "b"
    assert len(report.allowed) == 1
    assert report.allowed[0].package_name == "a"


def test_check_pinning_scope_filter_narrows_audit(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {
            "dependencies": {"a": "^1.0.0"},
            "devDependencies": {"b": "^2.0.0"},
        },
    )
    report = check_pinning(project, scopes=["dependencies"])
    # devDependencies skipped → only `a` checked.
    assert len(report.flagged) == 1
    assert report.flagged[0].package_name == "a"
    assert report.total_checked == 1


def test_check_pinning_workspace_protocol_passes(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {"dependencies": {"@my/lib": "workspace:*"}},
    )
    report = check_pinning(project)
    assert report.clean


def test_check_pinning_git_url_with_sha_passes(tmp_path: Path) -> None:
    sha = "f" * 40
    project = _write_pkg(
        tmp_path,
        {"dependencies": {"x": f"git+https://github.com/a/b.git#{sha}"}},
    )
    report = check_pinning(project)
    assert report.clean


def test_check_pinning_git_url_with_branch_flagged(tmp_path: Path) -> None:
    project = _write_pkg(
        tmp_path,
        {"dependencies": {"x": "git+https://github.com/a/b.git#main"}},
    )
    report = check_pinning(project)
    assert not report.clean
    assert report.flagged[0].kind == "git_ref"


def test_check_pinning_missing_package_json_raises(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        check_pinning(tmp_path / "nonexistent")


def test_check_pinning_default_scopes_constant() -> None:
    # Lock in the public contract — install-cas.sh and CI configs
    # implicitly rely on this default ordering / set.
    assert DEFAULT_SCOPES == (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
    )


def test_check_pinning_non_dict_scope_skipped(tmp_path: Path) -> None:
    # A malformed package.json with `dependencies: []` shouldn't crash.
    project = _write_pkg(tmp_path, {"dependencies": []})
    report = check_pinning(project)
    assert report.clean
    assert report.total_checked == 0
