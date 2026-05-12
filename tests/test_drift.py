"""Tests for package.json / lockfile drift detection."""

from __future__ import annotations

import json
from pathlib import Path

from codeartifact_shield.drift import check_npm_drift


def _write_pair(
    tmp_path: Path,
    pkg: dict[str, object],
    lock: dict[str, object],
) -> Path:
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    return tmp_path


# --- direct drift ---------------------------------------------------------


def test_clean_when_versions_agree(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {"node_modules/react": {"version": "18.3.1"}}},
    )
    report = check_npm_drift(root, transitive=False)
    assert report.clean
    assert report.mismatches == []


def test_detects_version_disagreement(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {"node_modules/react": {"version": "18.3.2"}}},
    )
    report = check_npm_drift(root, transitive=False)
    assert not report.clean
    assert report.mismatches == [("dependencies", "react", "18.3.1", "18.3.2")]


def test_detects_missing_lockfile_entry(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {"packages": {}},
    )
    report = check_npm_drift(root, transitive=False)
    assert report.mismatches == [("dependencies", "react", "18.3.1", "MISSING")]


def test_checks_dev_dependencies(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {
            "dependencies": {"react": "18.3.1"},
            "devDependencies": {"vite": "5.0.0"},
        },
        {
            "packages": {
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/vite": {"version": "4.9.0"},
            }
        },
    )
    report = check_npm_drift(root, transitive=False)
    assert report.mismatches == [("devDependencies", "vite", "5.0.0", "4.9.0")]


def test_raises_on_missing_package_json(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text("{}")
    try:
        check_npm_drift(tmp_path)
    except FileNotFoundError as exc:
        assert "package.json" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")


def test_raises_on_missing_lockfile(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}")
    try:
        check_npm_drift(tmp_path)
    except FileNotFoundError as exc:
        assert "package-lock.json" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")


def test_ignores_transitives_when_disabled(tmp_path: Path) -> None:
    """Top-level package.json doesn't declare transitives; with --no-transitive nothing flags."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {
            "packages": {
                "node_modules/react": {"version": "18.3.1"},
                "node_modules/some-transitive": {"version": "9.9.9"},
            }
        },
    )
    assert check_npm_drift(root, transitive=False).clean


# --- ranges mode ---------------------------------------------------------


def test_ranges_mode_accepts_satisfying_resolution(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "^18.3.0"}},
        {"packages": {"node_modules/react": {"version": "18.3.1"}}},
    )
    assert check_npm_drift(root, ranges=True, transitive=False).clean


def test_ranges_mode_rejects_out_of_range(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "^18.3.0"}},
        {"packages": {"node_modules/react": {"version": "19.0.0"}}},
    )
    report = check_npm_drift(root, ranges=True, transitive=False)
    assert not report.clean
    assert report.mismatches == [("dependencies", "react", "^18.3.0", "19.0.0")]


def test_strict_mode_rejects_range_declarations(tmp_path: Path) -> None:
    """Default (non-range) mode treats ^1.x as drift even if resolved is in range —
    that's the point: catches policy violations in projects with save-exact=true."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "^18.3.0"}},
        {"packages": {"node_modules/react": {"version": "18.3.1"}}},
    )
    report = check_npm_drift(root, transitive=False)
    assert not report.clean
    assert report.mismatches == [("dependencies", "react", "^18.3.0", "18.3.1")]


# --- transitive drift ----------------------------------------------------


def test_transitive_clean_when_range_satisfied(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {
            "packages": {
                "node_modules/react": {
                    "version": "18.3.1",
                    "dependencies": {"loose-envify": "^1.1.0"},
                },
                "node_modules/loose-envify": {"version": "1.4.0"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_drift_when_resolved_outside_range(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"react": "18.3.1"}},
        {
            "packages": {
                "node_modules/react": {
                    "version": "18.3.1",
                    "dependencies": {"loose-envify": "^1.1.0"},
                },
                # tampered: bumped to 2.0.0 while react still declares ^1.1.0
                "node_modules/loose-envify": {"version": "2.0.0"},
            }
        },
    )
    report = check_npm_drift(root, transitive=True)
    assert not report.clean
    assert report.transitive_mismatches == [
        ("node_modules/react", "loose-envify", "^1.1.0", "2.0.0")
    ]


def test_transitive_resolves_nested_node_modules_first(tmp_path: Path) -> None:
    """foo depends on bar @ ^1; both a hoisted bar @ 2.0.0 and a nested bar @ 1.5.0 exist.
    The nested one wins, so this should be clean."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "dependencies": {"bar": "^1.0.0"},
                },
                "node_modules/foo/node_modules/bar": {"version": "1.5.0"},
                "node_modules/bar": {"version": "2.0.0"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_walks_intermediate_ancestor_node_modules(tmp_path: Path) -> None:
    """A deeply nested parent's child should resolve from an intermediate
    ancestor node_modules, not skip straight to the root.

    Real example: ``A/node_modules/B/node_modules/C`` declares X@^2; X is
    installed at ``A/node_modules/X@2.27`` (one ancestor up). A naïve
    nested-then-root resolver would jump to ``node_modules/X@2.0`` and
    falsely flag drift.
    """
    root = _write_pair(
        tmp_path,
        {"dependencies": {"a": "1.0.0"}},
        {
            "packages": {
                "node_modules/a": {
                    "version": "1.0.0",
                    "dependencies": {"b": "^1.0.0"},
                },
                "node_modules/a/node_modules/b": {
                    "version": "1.0.0",
                    "dependencies": {"c": "^1.0.0"},
                },
                "node_modules/a/node_modules/b/node_modules/c": {
                    "version": "1.0.0",
                    "dependencies": {"x": "^2.0.0"},
                },
                # x is hoisted up to A's node_modules at the correct version
                "node_modules/a/node_modules/x": {"version": "2.27.1"},
                # …and a different, incompatible x sits at the root
                "node_modules/x": {"version": "2.0.30"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_missing_required_dependency(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "dependencies": {"bar": "^1.0.0"},
                },
            }
        },
    )
    report = check_npm_drift(root, transitive=True)
    assert report.transitive_mismatches == [
        ("node_modules/foo", "bar", "^1.0.0", "MISSING")
    ]


def test_transitive_missing_optional_dep_is_clean(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "optionalDependencies": {"bar": "^1.0.0"},
                },
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_non_semver_declaration_is_skipped(tmp_path: Path) -> None:
    """``github:``, ``npm:``, ``file:`` declarations aren't semver ranges — out of scope."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "dependencies": {
                        "bar": "github:example/bar#abc",
                        "baz": "npm:other-baz@^1.0.0",
                    },
                },
                "node_modules/bar": {"version": "1.0.0"},
                "node_modules/baz": {"version": "1.5.0"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_dist_tag_declaration_is_skipped(tmp_path: Path) -> None:
    """npm dist-tags like ``latest`` aren't version constraints — out of scope."""
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "dependencies": {
                        "bar": "latest",
                        "baz": "next",
                    },
                },
                "node_modules/bar": {"version": "0.0.1"},
                "node_modules/baz": {"version": "0.5.0"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean


def test_transitive_wildcard_declaration_is_clean(tmp_path: Path) -> None:
    root = _write_pair(
        tmp_path,
        {"dependencies": {"foo": "1.0.0"}},
        {
            "packages": {
                "node_modules/foo": {
                    "version": "1.0.0",
                    "dependencies": {"bar": "*"},
                },
                "node_modules/bar": {"version": "99.0.0"},
            }
        },
    )
    assert check_npm_drift(root, transitive=True).clean
