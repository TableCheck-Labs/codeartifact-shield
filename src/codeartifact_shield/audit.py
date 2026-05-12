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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codeartifact_shield._http import DEFAULT_RETRIES, with_retry
from codeartifact_shield._lockfile import extract_package_name, load_lockfile
from codeartifact_shield._registry import RegistryEndpoint, package_url

OSV_BATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"
OSV_VULN_ENDPOINT = "https://api.osv.dev/v1/vulns"
OSV_TIMEOUT_SECONDS = 30
OSV_BATCH_SIZE = 1000
DEFAULT_PROBE_WORKERS = 20
PROBE_CACHE_SCHEMA_VERSION = 1

# Cache shape: {endpoint_label: {package_name: "found" | "404"}}
ProbeCache = dict[str, dict[str, str]]


def load_probe_cache(path: Path) -> ProbeCache:
    """Read a probe-result cache file. Returns empty cache on missing /
    corrupt / version-mismatched file."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("schema_version") != PROBE_CACHE_SCHEMA_VERSION:
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def save_probe_cache(path: Path, entries: ProbeCache) -> None:
    path.write_text(
        json.dumps(
            {"schema_version": PROBE_CACHE_SCHEMA_VERSION, "entries": entries},
            indent=2,
            sort_keys=True,
        )
    )

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
    unaudited_blocked: list[str] = field(default_factory=list)
    """Package names not on the configured public registry AND not covered
    by OSV. HIGH-severity under the secure-by-default policy: a name no
    public source can verify is either a typo, lockfile tampering, or an
    internal package the user must explicitly trust via ``allow_unaudited``.

    Populated only when ``probe_registry`` is supplied."""

    unaudited_allowed: list[str] = field(default_factory=list)
    """Same condition as ``unaudited_blocked`` but explicitly allowlisted.
    INFO-severity; doesn't fail the gate."""

    @property
    def clean(self) -> bool:
        return (
            not self.findings
            and not self.unaudited_blocked
            and self.network_error is None
        )


def _http_post_json_once(
    url: str, body: dict[str, Any], timeout: int
) -> dict[str, Any]:
    """Single HTTP POST — no retry. Patch in retry-aware tests."""
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


def _http_post_json(
    url: str,
    body: dict[str, Any],
    timeout: int,
    retries: int = DEFAULT_RETRIES,
) -> dict[str, Any]:
    """HTTP POST with retry on transient errors."""
    return with_retry(
        lambda: _http_post_json_once(url, body, timeout), retries=retries
    )


def _http_get_json_once(
    url: str, timeout: int, auth_header: str | None = None
) -> dict[str, Any]:
    """Single HTTP GET — no retry. Patch in retry-aware tests."""
    headers: dict[str, str] = {"Accept": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        payload: dict[str, Any] = json.loads(resp.read().decode("utf-8"))
        return payload


def _http_get_json(
    url: str,
    timeout: int,
    auth_header: str | None = None,
    retries: int = DEFAULT_RETRIES,
) -> dict[str, Any]:
    """HTTP GET with retry on transient errors."""
    return with_retry(
        lambda: _http_get_json_once(url, timeout, auth_header),
        retries=retries,
    )


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


def _http_head_status_once(
    url: str, timeout: int, auth_header: str | None = None
) -> int:
    """Single HEAD request — no retry. Patch in retry-aware tests."""
    headers: dict[str, str] = {"Accept": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(url, method="HEAD", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        status: int = resp.status
        return status


def _http_head_status(
    url: str,
    timeout: int,
    auth_header: str | None = None,
    retries: int = DEFAULT_RETRIES,
) -> int:
    """HEAD with retry on transient errors. Used by the probe phase —
    only the status code matters, not the body."""
    return with_retry(
        lambda: _http_head_status_once(url, timeout, auth_header),
        retries=retries,
    )


def _probe_endpoint(
    endpoint: RegistryEndpoint,
    name: str,
    timeout: int,
    retries: int = DEFAULT_RETRIES,
) -> str:
    """Return ``"found"`` if the registry has metadata for ``name``,
    ``"404"`` if explicitly absent, ``"error"`` on any other failure
    (after retries are exhausted).
    """
    url = package_url(endpoint, name)
    try:
        _http_head_status(
            url, timeout=timeout, auth_header=endpoint.auth_header, retries=retries
        )
        return "found"
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return "404"
        return "error"
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
    ):
        return "error"


def _probe_parallel(
    endpoint: RegistryEndpoint,
    names: Iterable[str],
    timeout: int,
    max_workers: int,
    retries: int = DEFAULT_RETRIES,
) -> dict[str, str]:
    """Probe many package names against one endpoint concurrently.

    Returns ``{name: "found" | "404" | "error"}``. The probe phase is
    pure I/O so threading scales well even though Python has a GIL.
    """
    results: dict[str, str] = {}
    name_list = list(names)
    if not name_list:
        return results
    workers = max(1, min(max_workers, len(name_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_probe_endpoint, endpoint, name, timeout, retries): name
            for name in name_list
        }
        for future in as_completed(futures):
            name = futures[future]
            results[name] = future.result()
    return results


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
    allow_unaudited: Iterable[str] = (),
    severity_floor: str | None = None,
    whitelist_file: Path | None = None,
    batch_endpoint: str = OSV_BATCH_ENDPOINT,
    vuln_endpoint: str = OSV_VULN_ENDPOINT,
    probe_registry: str | None = None,
    trusted_endpoints: Iterable[RegistryEndpoint] | None = None,
    probe_cache_path: Path | None = None,
    max_workers: int = DEFAULT_PROBE_WORKERS,
    retries: int = DEFAULT_RETRIES,
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
        name = extract_package_name(key, entry)
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
                batch_endpoint, {"queries": chunk}, timeout=timeout, retries=retries
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
    if unique_ids:
        sorted_ids = sorted(unique_ids)
        detail_workers = max(1, min(max_workers, len(sorted_ids)))

        def fetch_detail(vid: str) -> tuple[str, dict[str, Any]]:
            return vid, _http_get_json(
                f"{vuln_endpoint}/{vid}", timeout=timeout, retries=retries
            )

        try:
            with ThreadPoolExecutor(max_workers=detail_workers) as pool:
                for future in as_completed(
                    [pool.submit(fetch_detail, vid) for vid in sorted_ids]
                ):
                    vid, detail = future.result()
                    details[vid] = detail
        except (
            urllib.error.URLError,
            TimeoutError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            report.network_error = f"OSV.dev vuln detail fetch failed: {exc}"
            return report

    combined_allow: list[str] = list(allow_ids)
    if whitelist_file is not None:
        combined_allow.extend(load_whitelist_file(whitelist_file))
    allowlist = {x.upper() for x in combined_allow}

    name_had_findings: dict[str, bool] = {}
    for (name, _version), ids in zip(pkg_list, all_results, strict=True):
        name_had_findings[name] = name_had_findings.get(name, False) or bool(ids)

    trusted_list = list(trusted_endpoints) if trusted_endpoints else []
    if probe_registry is not None or trusted_list:
        probe_endpoint: RegistryEndpoint | None = None
        if probe_registry is not None:
            probe_endpoint = RegistryEndpoint(
                url=probe_registry.rstrip("/"),
                label="probe-registry",
            )

        unaudited_allowlist = {n.lower() for n in allow_unaudited}
        candidates = sorted(
            {name for (name, _) in pkg_list if not name_had_findings.get(name)}
        )

        probe_cache: ProbeCache = (
            load_probe_cache(probe_cache_path) if probe_cache_path else {}
        )

        # Track per-name outcomes across endpoints. A name is resolved if
        # ANY endpoint returned 200 ("found"). An endpoint error is NOT
        # an immediate build failure — fall through to the next endpoint
        # and only surface as network_error if the name never resolves.
        confirmed_via: dict[str, str] = {}  # name → endpoint label (200)
        seen_any_404: dict[str, bool] = dict.fromkeys(candidates, False)
        seen_error: dict[str, str] = {}  # name → first error endpoint label

        def query_with_cache(
            endpoint: RegistryEndpoint, names: list[str]
        ) -> dict[str, str]:
            cached_section = probe_cache.get(endpoint.label, {})
            results: dict[str, str] = {}
            uncached: list[str] = []
            for n in names:
                hit = cached_section.get(n)
                if hit in ("found", "404"):
                    results[n] = hit
                else:
                    uncached.append(n)
            if uncached:
                fresh = _probe_parallel(
                    endpoint,
                    uncached,
                    timeout=timeout,
                    max_workers=max_workers,
                    retries=retries,
                )
                section = probe_cache.setdefault(endpoint.label, {})
                for n, status in fresh.items():
                    results[n] = status
                    if status in ("found", "404"):
                        section[n] = status
            return results

        # Phase 1 — parallel probe against the public probe registry.
        if probe_endpoint is not None and candidates:
            phase1_results = query_with_cache(probe_endpoint, candidates)
            for name, result in phase1_results.items():
                if result == "found":
                    confirmed_via[name] = "probe-registry"
                elif result == "404":
                    seen_any_404[name] = True
                else:  # "error"
                    seen_error.setdefault(name, "probe-registry")

        # Phase 2 — for each trusted endpoint in order, parallel-probe
        # the names still unresolved. Probe errors fall through.
        for endpoint in trusted_list:
            pending = sorted(
                n for n in candidates if n not in confirmed_via
            )
            if not pending:
                break
            phase2_results = query_with_cache(endpoint, pending)
            for name, result in phase2_results.items():
                if result == "found":
                    confirmed_via[name] = endpoint.label
                elif result == "404":
                    seen_any_404[name] = True
                else:  # "error"
                    seen_error.setdefault(name, endpoint.label)

        for name in candidates:
            via = confirmed_via.get(name)
            if via == "probe-registry":
                # Public + no OSV findings → silently clean.
                continue
            if via is not None:
                # Resolved on a trusted endpoint → INFO.
                report.unaudited_allowed.append(name)
                continue
            if name.lower() in unaudited_allowlist:
                report.unaudited_allowed.append(name)
                continue
            if seen_any_404.get(name) and name not in seen_error:
                # 404'd cleanly on every endpoint we asked → known-blocked.
                report.unaudited_blocked.append(name)
                continue
            if name in seen_error:
                # No endpoint resolved it AND at least one errored — we
                # genuinely couldn't determine. Surface the first error as
                # the build-failing finding.
                report.network_error = (
                    f"Private-package probe failed for {name} "
                    f"({seen_error[name]})"
                )
                return report
            # Defensive fallback: no resolution, no 404, no error. Should
            # be unreachable but treat as blocked rather than silently OK.
            report.unaudited_blocked.append(name)

        if probe_cache_path is not None:
            try:
                save_probe_cache(probe_cache_path, probe_cache)
            except OSError as exc:
                report.network_error = (
                    f"failed to save probe cache to {probe_cache_path}: {exc}"
                )

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
