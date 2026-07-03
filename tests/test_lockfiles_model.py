"""npm adapter parity — the normalized model must reproduce the legacy iteration.

Phase A refactors the npm gates to consume ``load_normalized().entries``. This
guards that the npm adapter's entry set (and the ``(name, version)`` pairs it
yields) is exactly what ``is_installable_entry`` + ``extract_package_name`` used
to produce, so no gate silently changes behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path

from codeartifact_shield._lockfile import (
    extract_package_name,
    is_installable_entry,
    load_lockfile,
)
from codeartifact_shield.lockfiles import LockFormat, load_normalized
from codeartifact_shield.lockfiles._model import ResolvedKind

FIXTURE = Path(__file__).parent / "fixtures" / "sample-package-lock.json"


def _legacy_pairs(lockfile_path: Path) -> set[tuple[str, str]]:
    lock = load_lockfile(lockfile_path)
    pairs: set[tuple[str, str]] = set()
    for key, entry in lock.get("packages", {}).items():
        if not is_installable_entry(key, entry):
            continue
        name = extract_package_name(key, entry)
        version = entry.get("version")
        if not name or not isinstance(version, str) or not version:
            continue
        pairs.add((name, version))
    return pairs


def test_npm_adapter_pairs_match_legacy_iteration() -> None:
    normalized = load_normalized(FIXTURE)
    assert normalized.format is LockFormat.NPM
    model_pairs = {
        (e.name, e.version) for e in normalized.entries if e.name and e.version
    }
    assert model_pairs == _legacy_pairs(FIXTURE)


def test_npm_adapter_keys_are_all_installable(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "root"},
            "system/i18n": {"name": "@x/i18n", "version": "1.0.0"},
            "node_modules/@x/i18n": {"link": True},
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-" + "a" * 86 + "==",
                "hasInstallScript": True,
            },
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    normalized = load_normalized(p)
    keys = {e.key for e in normalized.entries}
    assert keys == {"node_modules/lodash"}
    entry = normalized.entries[0]
    assert entry.name == "lodash"
    assert entry.has_install_script is True
    assert entry.resolved_kind is ResolvedKind.REGISTRY


def test_npm_adapter_classifies_git_and_tarball(tmp_path: Path) -> None:
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/g": {
                "version": "1.0.0",
                "resolved": "git+ssh://git@github.com/o/g.git#abc",
            },
            "node_modules/t": {
                "version": "1.0.0",
                "resolved": "https://example.com/t-1.0.0.tgz",
            },
        },
    }
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps(lock))
    kinds = {e.name: e.resolved_kind for e in load_normalized(p).entries}
    assert kinds["g"] is ResolvedKind.GIT
    assert kinds["t"] is ResolvedKind.TARBALL
