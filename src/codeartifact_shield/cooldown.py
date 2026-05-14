"""Package cooldown — fail when any installed version is too young.

Threat model
------------

A malicious version published in the last few hours hasn't been caught
by any vulnerability scanner yet. Several real npm supply-chain attacks
(``ua-parser-js``, ``event-stream``, the September 2024 typosquat
campaign) were live on the registry for hours-to-days before detection.
A project that installs whatever satisfies its lockfile the moment a
new version lands carries that window of risk every time it builds.

The cooldown check refuses to install any version whose publish time
is younger than a configurable threshold (default 14 days, matching
StepSecurity and pnpm guidance). This gives the security community
and npm itself a window to detect and unpublish or deprecate malicious
releases before they propagate.

Inspiration: StepSecurity npm-package-cooldown-check, kevinslin/safe-npm,
pnpm's ``minimumReleaseAge`` setting.

Registry coverage — all three deployment scenarios
--------------------------------------------------

cas cooldown takes an ordered list of registry endpoints. For each
``(name, version)`` it tries endpoints in order; the first one whose
``time[<version>]`` exists wins. If an endpoint returns 404 OR returns
metadata without that specific version, cas treats it as a miss and
moves on (this matters: the public npm registry sometimes returns a
placeholder metadata response for org scopes without serving the
private versions).

* **Public npm only.** Default: a single ``registry.npmjs.org`` endpoint.
* **CodeArtifact + npm proxy.** Public deps resolve at npm; private
  deps fall through to a configured CodeArtifact endpoint.
* **CodeArtifact-only private.** Configure only the CA endpoint.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codeartifact_shield._allowlist import PackageAllowlist
from codeartifact_shield._http import DEFAULT_RETRIES, with_retry
from codeartifact_shield._lockfile import extract_package_name, load_lockfile
from codeartifact_shield._registry import (
    RegistryEndpoint,
    build_codeartifact_endpoint,
    package_url,
)

# Re-export so existing `from codeartifact_shield.cooldown import RegistryEndpoint`
# imports keep working after the refactor.
__all__ = [
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_MIN_AGE_DAYS",
    "DEFAULT_REGISTRY",
    "CooldownFinding",
    "CooldownReport",
    "RegistryEndpoint",
    "build_codeartifact_endpoint",
    "check_cooldown",
    "load_cache",
    "save_cache",
]

DEFAULT_REGISTRY = "https://registry.npmjs.org"
DEFAULT_MIN_AGE_DAYS = 14
DEFAULT_MAX_WORKERS = 20
COOLDOWN_TIMEOUT_SECONDS = 30
CACHE_SCHEMA_VERSION = 1


@dataclass
class CooldownFinding:
    """One package version younger than the cooldown threshold."""

    package_name: str
    version: str
    published_at: str
    age_days: float
    source: str


@dataclass
class CooldownReport:
    flagged: list[CooldownFinding] = field(default_factory=list)
    allowed: list[CooldownFinding] = field(default_factory=list)
    private_blocked: list[str] = field(default_factory=list)
    """(name, version) pairs unresolvable on any configured endpoint —
    not allowlisted. HIGH-severity findings; fail the gate.

    Under the secure-by-default policy in cas 0.7+: a package whose
    publish time cannot be confirmed on any registry cas was told about
    is treated as a hard finding. This catches:

    * Typo'd dependency names (``lodahs`` for ``lodash``).
    * Lockfile tampering that inserted a bogus entry.
    * Configuration gaps (a private package whose CA endpoint cas
      wasn't told about).

    Each is suspicious; the user can suppress legitimate cases with
    ``--allow-private <name>``.
    """

    private_allowed: list[str] = field(default_factory=list)
    """(name, version) pairs unresolvable on any endpoint AND explicitly
    allowlisted via ``allow_private``. INFO-severity; do not fail the gate."""

    network_errors: list[str] = field(default_factory=list)
    total_checked: int = 0
    cache_hits: int = 0
    cache_misses: int = 0

    @property
    def clean(self) -> bool:
        return (
            not self.flagged
            and not self.private_blocked
            and not self.network_errors
        )


def _http_get_json_once(
    url: str, timeout: int, auth_header: str | None = None
) -> dict[str, Any]:
    """Single HTTP GET — no retry. Patch this in retry-aware tests."""
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
    """HTTP GET with retry on transient errors. Existing tests that patch
    this function bypass retry entirely — that's intentional, they're
    asserting deterministic outcomes."""
    return with_retry(
        lambda: _http_get_json_once(url, timeout, auth_header),
        retries=retries,
    )


def _parse_iso8601(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


# ---------------------------------------------------------------------------
# Disk cache — publish times are immutable, so we only ever add entries.
# ---------------------------------------------------------------------------

# Shape: {endpoint_label: {package_name: {version: published_at_iso}}}
PublishCache = dict[str, dict[str, dict[str, str]]]


def load_cache(path: Path) -> PublishCache:
    """Read a cache file. Returns empty cache on missing/corrupt file."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    if data.get("schema_version") != CACHE_SCHEMA_VERSION:
        return {}
    entries = data.get("entries", {})
    return entries if isinstance(entries, dict) else {}


def save_cache(path: Path, entries: PublishCache) -> None:
    path.write_text(
        json.dumps(
            {"schema_version": CACHE_SCHEMA_VERSION, "entries": entries},
            indent=2,
            sort_keys=True,
        )
    )


def _cache_lookup(
    cache: PublishCache, endpoint_label: str, name: str, version: str
) -> str | None:
    return cache.get(endpoint_label, {}).get(name, {}).get(version)


def _cache_populate_from_metadata(
    cache: PublishCache, endpoint_label: str, name: str, metadata: dict[str, Any]
) -> None:
    time_map = metadata.get("time", {})
    if not isinstance(time_map, dict):
        return
    target = cache.setdefault(endpoint_label, {}).setdefault(name, {})
    for ver, ts in time_map.items():
        if ver in ("created", "modified"):
            continue
        if isinstance(ver, str) and isinstance(ts, str):
            target[ver] = ts


# ---------------------------------------------------------------------------
# Fetch — parallel metadata retrieval per endpoint
# ---------------------------------------------------------------------------


@dataclass
class _FetchResult:
    """Outcome of one (endpoint, name) HTTP probe."""

    name: str
    status: str  # "ok" | "404" | "error"
    metadata: dict[str, Any] | None = None
    error_message: str | None = None


def _fetch_one(
    endpoint: RegistryEndpoint,
    name: str,
    timeout: int,
    retries: int = DEFAULT_RETRIES,
) -> _FetchResult:
    url = package_url(endpoint, name)
    try:
        metadata = _http_get_json(
            url, timeout=timeout, auth_header=endpoint.auth_header, retries=retries
        )
        return _FetchResult(name=name, status="ok", metadata=metadata)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return _FetchResult(name=name, status="404")
        return _FetchResult(
            name=name,
            status="error",
            error_message=f"HTTP {exc.code} — {exc.reason}",
        )
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        return _FetchResult(name=name, status="error", error_message=str(exc))


def _fetch_endpoint_parallel(
    endpoint: RegistryEndpoint,
    names: Iterable[str],
    timeout: int,
    max_workers: int,
    retries: int = DEFAULT_RETRIES,
) -> dict[str, _FetchResult]:
    results: dict[str, _FetchResult] = {}
    name_list = list(names)
    if not name_list:
        return results
    workers = max(1, min(max_workers, len(name_list)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_fetch_one, endpoint, name, timeout, retries): name
            for name in name_list
        }
        for future in as_completed(futures):
            result = future.result()
            results[result.name] = result
    return results


# ---------------------------------------------------------------------------
# Main entry — orchestrate cache + parallel fetch + per-version fallthrough
# ---------------------------------------------------------------------------


def check_cooldown(
    lockfile_path: Path,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allowed: Iterable[str] = (),
    allow_private: Iterable[str] = (),
    endpoints: Iterable[RegistryEndpoint] = (),
    cache_path: Path | None = None,
    max_workers: int = DEFAULT_MAX_WORKERS,
    retries: int = DEFAULT_RETRIES,
    timeout: int = COOLDOWN_TIMEOUT_SECONDS,
    now: datetime | None = None,
) -> CooldownReport:
    """Audit the lockfile, flagging any (name, version) younger than the threshold.

    Args:
        lockfile_path: ``package-lock.json`` to audit.
        min_age_days: Versions younger than this are flagged. Default 14.
        allowed: Package names permitted without a cooldown delay.
        endpoints: Registries to consult in order. Defaults to a single
            ``registry.npmjs.org`` endpoint.
        cache_path: Optional JSON cache file. Publish times are immutable,
            so cache hits are always valid. Cache is augmented (never
            invalidated) with every metadata fetch.
        max_workers: Thread-pool size for parallel HTTP fetches. Default 20.
        timeout: Per-request HTTP timeout in seconds.
        now: Override "current time" for deterministic testing.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    endpoint_list = list(endpoints) or [RegistryEndpoint(url=DEFAULT_REGISTRY)]

    lock = load_lockfile(lockfile_path)
    pkgs: dict[str, dict[str, Any]] = lock.get("packages", {})

    pending: dict[tuple[str, str], None] = {}
    for key, entry in pkgs.items():
        if not key:
            continue
        if entry.get("link"):
            continue
        name = extract_package_name(key, entry)
        version = entry.get("version")
        if not name or not isinstance(version, str):
            continue
        pending[(name, version)] = None

    allowlist = PackageAllowlist.from_entries(allowed)
    private_allowlist = PackageAllowlist.from_entries(allow_private)
    report = CooldownReport(total_checked=len(pending))

    cache: PublishCache = load_cache(cache_path) if cache_path else {}

    def resolve(name: str, version: str, published_str: str, source: str) -> None:
        try:
            published = _parse_iso8601(published_str)
        except ValueError as exc:
            report.network_errors.append(
                f"{name}@{version} ({source}): unparseable publish time "
                f"'{published_str}' ({exc})"
            )
            return
        age_days = (now - published).total_seconds() / 86400.0
        if age_days >= min_age_days:
            return
        finding = CooldownFinding(
            package_name=name,
            version=version,
            published_at=published_str,
            age_days=round(age_days, 2),
            source=source,
        )
        if allowlist.allows(name, version):
            report.allowed.append(finding)
        else:
            report.flagged.append(finding)

    # Track per-name fetch errors so a later endpoint resolving the same
    # name can wipe out the earlier transient error. The build only fails
    # on a name that errored on at least one endpoint AND was never
    # resolved on any other endpoint.
    pending_errors: dict[str, str] = {}  # name → first error message seen

    for endpoint in endpoint_list:
        if not pending:
            break

        # Cache pre-pass: resolve anything this endpoint already has cached.
        resolved_here: list[tuple[str, str]] = []
        for name, version in list(pending):
            cached_ts = _cache_lookup(cache, endpoint.label, name, version)
            if cached_ts is not None:
                report.cache_hits += 1
                resolve(name, version, cached_ts, endpoint.label)
                resolved_here.append((name, version))
        for nv in resolved_here:
            pending.pop(nv, None)
            pending_errors.pop(nv[0], None)

        if not pending:
            break

        # Names still needing this endpoint. One HTTP call per unique name.
        names_to_fetch = sorted({name for (name, _) in pending})
        report.cache_misses += len(names_to_fetch)
        results = _fetch_endpoint_parallel(
            endpoint,
            names_to_fetch,
            timeout=timeout,
            max_workers=max_workers,
            retries=retries,
        )

        resolved_here = []
        for name in names_to_fetch:
            result = results.get(name)
            if result is None or result.status == "404":
                continue  # try next endpoint
            if result.status == "error":
                # Don't fail the build yet — a later endpoint may resolve
                # this name. Record the first error and move on.
                pending_errors.setdefault(
                    name, f"{name} ({endpoint.label}): {result.error_message}"
                )
                continue

            metadata = result.metadata or {}
            _cache_populate_from_metadata(cache, endpoint.label, name, metadata)
            time_map = metadata.get("time", {})
            if not isinstance(time_map, dict):
                continue

            for nv in [nv for nv in pending if nv[0] == name]:
                _, version = nv
                published_str = time_map.get(version)
                if isinstance(published_str, str):
                    resolve(name, version, published_str, endpoint.label)
                    resolved_here.append(nv)
        for nv in resolved_here:
            pending.pop(nv, None)
            pending_errors.pop(nv[0], None)

    for name, version in pending:
        nv_label = f"{name}@{version}"
        if name in pending_errors:
            # Never resolved AND we hit at least one transient error.
            # Surface as a real network_error rather than silently
            # treating as private_blocked.
            report.network_errors.append(pending_errors[name])
            continue
        if private_allowlist.allows(name, version):
            report.private_allowed.append(nv_label)
        else:
            report.private_blocked.append(nv_label)

    if cache_path:
        try:
            save_cache(cache_path, cache)
        except OSError as exc:
            report.network_errors.append(f"failed to save cache to {cache_path}: {exc}")

    return report
