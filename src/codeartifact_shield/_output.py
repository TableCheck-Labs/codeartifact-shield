"""Shared output helpers — severity tags + JSON serialization.

Two purposes:

1. **Severity badges** (G11). Every finding gets a tag like ``[CRITICAL]`` /
   ``[HIGH]`` / ``[MEDIUM]`` so reviewers can triage when several gates fail
   in the same CI run. Severities are assigned per finding *type* (see the
   table in each subcommand below) and reflect blast radius, not the
   findings's count.

2. **Structured JSON output** (G10). Every subcommand can emit machine-
   readable JSON via ``--json`` for downstream consumption (SARIF, GitHub
   Code Scanning, custom CI dashboards). The shape is intentionally simple
   and stable:

   ::

       {
         "command": "registry",
         "lockfile": "/path/to/package-lock.json",
         "clean": false,
         "findings": [
           {"severity": "CRITICAL", "type": "registry_leak", ...},
           ...
         ],
         "severity_counts": {"CRITICAL": 1, "HIGH": 0, ...}
       }
"""

from __future__ import annotations

import json
import sys
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity tiers. String values match the badges in human output and the
    severity field in JSON output."""

    CRITICAL = "CRITICAL"
    """Active supply-chain compromise surface — a route to untrusted bytes
    *right now*. Examples: registry leak, insecure scheme on a resolved URL."""

    HIGH = "HIGH"
    """Tampering signature or pending RCE. Examples: package.json/lockfile
    drift, orphan lockfile entry, lifecycle-script-running package not in
    the allowlist, SRI coverage below threshold."""

    MEDIUM = "MEDIUM"
    """Weak primitive in use or registry-contract bypass. Examples: sha1
    integrity hash, git-sourced dependency."""

    LOW = "LOW"
    """Suspicious-but-explainable anomaly. Examples: dedupe phantom entry
    with no ``resolved`` URL."""

    INFO = "INFO"
    """Informational context, not a finding by itself."""


def severity_badge(sev: Severity) -> str:
    """``[CRITICAL]`` / ``[HIGH]`` / etc. — for prefixing human output lines."""
    return f"[{sev.value}]"


def emit_json(payload: dict[str, Any]) -> None:
    """Print a JSON payload to stdout. Used by --json mode in every command.

    All non-JSON output (warnings, banner text) must go to stderr in
    JSON mode so the stdout stream remains parseable by downstream tools.
    """
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Count findings by severity for the top-level summary in JSON output."""
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts
