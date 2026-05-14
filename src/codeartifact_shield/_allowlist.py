"""Shared parser + matcher for package-name allowlists.

Supports two entry forms, mixable in a single list:

* ``name`` — match every installed version of the package.
* ``name@version`` — match only that exact version.

Used by ``cas cooldown --allow``, ``cas cooldown --allow-private``,
``cas audit --allow-private``, and ``cas scripts --allow``. Name matching
is case-insensitive (npm normalises package names to lowercase on
publish); version matching is exact and case-sensitive (SemVer
prerelease identifiers are case-significant).

Scoped packages are handled by detecting a leading ``@`` and splitting
on the *last* ``@`` thereafter — so ``@scope/pkg@1.0.0`` parses as
``("@scope/pkg", "1.0.0")`` and ``@scope/pkg`` parses as ``("@scope/pkg",
None)``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


def parse_spec(raw: str) -> tuple[str, str | None]:
    """Split an allowlist entry into ``(name, version_or_None)``.

    Raises ``ValueError`` if the entry is empty, missing the package
    name, or trailing-``@``-with-no-version. Trusts npm conventions on
    name shape — does not validate that the name is a legal npm package
    identifier.
    """
    if not raw:
        raise ValueError("empty allowlist entry")
    if raw.startswith("@"):
        # Scoped. Search for a `@` AFTER position 0.
        idx = raw.rfind("@")
        if idx == 0:
            # The only `@` is the scope marker. Need at least `@scope/name`.
            if "/" not in raw or raw == "@" or raw.endswith("/"):
                raise ValueError(f"'{raw}' is not a valid package spec")
            return raw, None
        name, version = raw[:idx], raw[idx + 1 :]
        if not name or "/" not in name or name.endswith("/") or not version:
            raise ValueError(f"'{raw}' is not a valid package spec")
        return name, version
    if "@" in raw:
        idx = raw.index("@")
        name, version = raw[:idx], raw[idx + 1 :]
        if not name or not version:
            raise ValueError(f"'{raw}' is not a valid package spec")
        return name, version
    return raw, None


@dataclass(frozen=True)
class PackageAllowlist:
    """Match a ``(name, version)`` against a parsed allowlist.

    Build via :meth:`from_entries`. Use :meth:`allows` for the test;
    :meth:`has_versioned_entries` for diagnostics (e.g. CLI rendering).
    """

    names: frozenset[str]
    """Package names (lowercased) that match every version."""

    versioned: frozenset[tuple[str, str]]
    """``(name_lowercase, version_exact)`` pairs."""

    @classmethod
    def from_entries(cls, entries: Iterable[str]) -> PackageAllowlist:
        names: set[str] = set()
        versioned: set[tuple[str, str]] = set()
        for entry in entries:
            name, version = parse_spec(entry)
            if version is None:
                names.add(name.lower())
            else:
                versioned.add((name.lower(), version))
        return cls(names=frozenset(names), versioned=frozenset(versioned))

    def allows(self, name: str, version: str) -> bool:
        lower = name.lower()
        return lower in self.names or (lower, version) in self.versioned

    def allows_name(self, name: str) -> bool:
        """True iff this name is allowlisted at the name level (any version).

        Versioned-only entries do NOT count — callers asking ``allows_name``
        want to know whether the whole package is unconditionally trusted.
        """
        return name.lower() in self.names

    def has_versioned_entries(self) -> bool:
        return bool(self.versioned)
