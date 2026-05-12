"""Vulnerability audit — `npm audit` but works behind CodeArtifact.

AWS CodeArtifact's npm proxy does not implement the audit endpoint
(`/-/npm/v1/security/advisories/bulk`), so ``npm audit`` against a
CodeArtifact-proxied registry silently returns no findings. This module
queries the OSV.dev API directly — the same federated vulnerability
database that `osv-scanner` uses, with no auth requirement.

OSV.dev federates data from the GitHub Advisory Database, npm's own
advisory feed, the Python Package Index, and others. For npm projects
the practical coverage is equivalent to ``npm audit`` against the
public registry plus what Dependabot sees.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeartifact_shield._lockfile import load_lockfile

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns"
OSV_TIMEOUT_SECONDS = 30
OSV_BATCH_SIZE = 1000

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


@dataclass
class AuditFinding:
    """One vulnerability for one (package, version) pair."""

    package_name: str
    version: str
    vuln_id: str
    severity: str
    summary: str
    fixed_in: str | None
    aliases: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    findings: list[AuditFinding] = field(default_factory=list)
    total_checked: int = 0
    network_error: str | None = None

    @property
    def clean(self) -> bool:
        return not self.findings and self.network_error is None


def _package_name_from_key(key: str) -> str:
    marker = "/node_modules/"
    idx = key.rfind(marker)
    tail = key[idx + len(marker) :] if idx != -1 else key
    if tail.startswith("node_modules/"):
        tail = tail[len("node_modules/") :]
    return tail


def _http_post_json(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return payload


def _http_get_json(url: str, timeout: int) -> dict[str, Any]:
    req = urllib.request.Request(
        url, method="GET", headers={"Accept": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return payload


def _extract_severity(vuln: dict[str, Any]) -> str:
    db = vuln.get("database_specific", {})
    if isinstance(db, dict):
        sev = db.get("severity")
        if isinstance(sev, str):
            up = sev.upper()
            if up == "MODERATE":
                return "MEDIUM"
            if up in SEVERITY_RANK:
                return up
    return "UNKNOWN"


def _extract_fixed_version(vuln: dict[str, Any], package_name: str) -> str | None:
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != "npm":
            continue
        if pkg.get("name") != package_name:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed: str = event["fixed"]
                    return fixed
    return None


def _meets_floor(severity: str, floor: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(floor.upper(), 0)


def load_whitelist_file(path: Path) -> list[str]:
    """Load suppressed vuln IDs from a whitelist file.

    Two formats are supported:

    1. ``auditjs`` / Sonatype OSS Index format::

           {"ignore": [{"id": "CVE-2023-42282"}, ...]}

       This is the file the ``auditjs`` CLI emits and what TableCheck-style
       projects already maintain. The top-level ``affected`` array (if
       present) is ignored — only ``ignore[].id`` is read.

    2. Plain JSON array of strings::

           ["GHSA-...", "CVE-...", ...]

    Raises ``ValueError`` for any other structure.
    """
    parsed = json.loads(path.read_text())
    if isinstance(parsed, list):
        if not all(isinstance(x, str) for x in parsed):
            raise ValueError(
                f"{path}: plain-array whitelist must contain only strings"
            )
        return list(parsed)
    if isinstance(parsed, dict) and isinstance(parsed.get("ignore"), list):
        ids: list[str] = []
        for entry in parsed["ignore"]:
            if isinstance(entry, dict) and isinstance(entry.get("id"), str):
                ids.append(entry["id"])
            else:
                raise ValueError(
                    f"{path}: each `ignore[]` entry must be an object with a string `id`"
                )
        return ids
    raise ValueError(
        f"{path}: unrecognised whitelist format — expected `{{\"ignore\": [...]}}` "
        f"(auditjs) or a plain JSON array of strings"
    )


def audit_lockfile(
    lockfile_path: Path,
    allow_ids: Iterable[str] = (),
    severity_floor: str | None = None,
    whitelist_file: Path | None = None,
    batch_endpoint: str = OSV_BATCH_ENDPOINT,
    vuln_endpoint: str = OSV_VULN_ENDPOINT,
    timeout: int = OSV_TIMEOUT_SECONDS,
) -> AuditReport:
    """Audit every (name, version) pair in the lockfile against OSV.dev.

    Args:
        lockfile_path: ``package-lock.json`` to audit.
        allow_ids: Vuln IDs (GHSA / CVE / OSV) to suppress. Matched
            case-insensitively against the primary id and the aliases list.
        severity_floor: Drop findings below this severity. One of
            ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` (case-insensitive).
            ``None`` means report all.
        batch_endpoint: Override the OSV.dev batch URL (for tests or
            air-gapped mirrors).
        vuln_endpoint: Override the OSV.dev single-vuln URL.
        timeout: HTTP timeout in seconds, applied per request.
    """
    lock = load_lockfile(lockfile_path)
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})

    seen: dict[tuple[str, str], None] = {}
    for key, entry in pkgs.items():
        if not key:
            continue
        if entry.get("link"):
            continue
        name = _package_name_from_key(key)
        version = entry.get("version")
        if not name or not isinstance(version, str):
            continue
        seen[(name, version)] = None

    pkg_list = list(seen)
    report = AuditReport(total_checked=len(pkg_list))
    if not pkg_list:
        return report

    queries = [
        {"package": {"name": name, "ecosystem": "npm"}, "version": version}
        for (name, version) in pkg_list
    ]

    all_results: list[list[str]] = []
    try:
        for chunk_start in range(0, len(queries), OSV_BATCH_SIZE):
            chunk = queries[chunk_start : chunk_start + OSV_BATCH_SIZE]
            payload = _http_post_json(
                batch_endpoint, {"queries": chunk}, timeout=timeout
            )
            for entry in payload.get("results", []):
                ids = [v["id"] for v in entry.get("vulns", []) if "id" in v]
                all_results.append(ids)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        report.network_error = f"OSV.dev batch query failed: {exc}"
        return report

    unique_ids: set[str] = set()
    for ids in all_results:
        unique_ids.update(ids)

    details: dict[str, dict[str, Any]] = {}
    try:
        for vid in sorted(unique_ids):
            details[vid] = _http_get_json(f"{vuln_endpoint}/{vid}", timeout=timeout)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        report.network_error = f"OSV.dev vuln detail fetch failed: {exc}"
        return report

    combined_allow: list[str] = list(allow_ids)
    if whitelist_file is not None:
        combined_allow.extend(load_whitelist_file(whitelist_file))
    allowlist = {x.upper() for x in combined_allow}

    for i, ids in enumerate(all_results):
        if not ids:
            continue
        name, version = pkg_list[i]
        for vid in ids:
            d = details.get(vid, {})
            aliases = d.get("aliases", []) or []
            if vid.upper() in allowlist:
                continue
            if any(alias.upper() in allowlist for alias in aliases):
                continue
            severity = _extract_severity(d)
            if severity_floor and not _meets_floor(severity, severity_floor):
                continue
            report.findings.append(
                AuditFinding(
                    package_name=name,
                    version=version,
                    vuln_id=vid,
                    severity=severity,
                    summary=d.get("summary", ""),
                    fixed_in=_extract_fixed_version(d, name),
                    aliases=list(aliases),
                )
            )

    return report
