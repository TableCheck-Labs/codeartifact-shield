"""Lockfile / manifest drift detection.

Pinning exact versions in ``package.json`` only helps if the lockfile
agrees. Drift = ``package.json`` says ``react==18.3.1`` but
``package-lock.json`` says ``18.3.2`` because someone bumped one without
the other. CI should refuse to ship in that state — it's the exact
inconsistency a quiet supply-chain attack would create by editing the
lockfile alone.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DriftReport:
    mismatches: list[tuple[str, str, str, str]] = field(default_factory=list)
    """``(dep_kind, name, declared, actual)`` for each disagreement."""

    @property
    def clean(self) -> bool:
        return not self.mismatches


def check_npm_drift(frontend_dir: Path) -> DriftReport:
    """Compare every direct dep in ``package.json`` to its lockfile entry.

    Only checks top-level entries (``dependencies``, ``devDependencies``).
    Transitives aren't checked because the package.json doesn't declare
    them; their integrity is the lockfile's responsibility alone.
    """
    pkg_path = frontend_dir / "package.json"
    lock_path = frontend_dir / "package-lock.json"
    if not pkg_path.exists():
        raise FileNotFoundError(f"no package.json in {frontend_dir}")
    if not lock_path.exists():
        raise FileNotFoundError(f"no package-lock.json in {frontend_dir}")
    pkg = json.loads(pkg_path.read_text())
    lock = json.loads(lock_path.read_text())
    lock_pkgs = lock.get("packages", {})

    report = DriftReport()
    for kind in ("dependencies", "devDependencies"):
        for name, declared in pkg.get(kind, {}).items():
            entry = lock_pkgs.get(f"node_modules/{name}", {})
            actual = entry.get("version", "MISSING")
            if actual != declared:
                report.mismatches.append((kind, name, declared, actual))
    return report
