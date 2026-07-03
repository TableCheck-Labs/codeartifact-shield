"""Shared npm lockfile helpers — re-export shim over ``lockfiles.npm``.

The npm-native loader/validator/entry-parser moved into
``codeartifact_shield.lockfiles.npm`` when cas grew multi-format support. This
module stays as a stable re-export so every existing
``from codeartifact_shield._lockfile import ...`` keeps working unchanged.

See :mod:`codeartifact_shield.lockfiles.npm` for the implementation and the
security rationale for structural validation.
"""

from __future__ import annotations

from codeartifact_shield.lockfiles.npm import (
    _validate_package_keys,
    extract_package_name,
    is_installable_entry,
    load_lockfile,
)

__all__ = [
    "_validate_package_keys",
    "extract_package_name",
    "is_installable_entry",
    "load_lockfile",
]
