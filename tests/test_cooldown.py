"""Tests for the package cooldown module."""

from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

from codeartifact_shield.cooldown import (
    DEFAULT_MIN_AGE_DAYS,
    CooldownFinding,
    RegistryEndpoint,
    _parse_iso8601,
    check_cooldown,
)

FIXTURES = Path(__file__).parent / "fixtures" / "npm"


def _load_fixture(name: str) -> dict[str, Any]:
    payload: dict[str, Any] = json.loads((FIXTURES / name).read_text())
    return payload


def _write_lock(tmp_path: Path, packages: dict[str, dict]) -> Path:
    p = tmp_path / "package-lock.json"
    p.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}))
    return p


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_parse_iso8601_zulu_form() -> None:
    dt = _parse_iso8601("2014-02-26T15:51:27.777Z")
    assert dt.tzinfo is not None
    assert dt.year == 2014


def test_parse_iso8601_offset_form() -> None:
    dt = _parse_iso8601("2020-01-01T00:00:00+00:00")
    assert dt.tzinfo is not None


def test_real_npm_fixture_shape() -> None:
    # Sanity check that the captured npm registry response has the fields
    # we rely on (top-level `time` dict with version keys).
    d = _load_fixture("is-array.json")
    assert d["name"] == "is-array"
    assert isinstance(d["time"], dict)
    assert "1.0.1" in d["time"]
    assert "created" in d["time"] and "modified" in d["time"]


# ---------------------------------------------------------------------------
# check_cooldown — npm-only scenario
# ---------------------------------------------------------------------------


def _now(year: int = 2024, month: int = 1, day: int = 15) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


def _mock_responses(by_name: dict[str, dict[str, Any] | int]):
    """Build a mock _http_get_json that dispatches by package name in URL.

    Map values that are ints are treated as HTTP status codes for errors
    (typically 404 to simulate "not found on this registry").
    """

    def mock_get(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        # Last URL segment is the (URL-encoded) package name.
        name = url.rsplit("/", 1)[-1]
        # urllib.parse.quote turns "@" into "@" (safe) and "/" into "%2F" — but
        # we only run scoped names through _registry_url, and we set safe="@"
        # so the slash IS encoded. Decode for lookup convenience.
        import urllib.parse as up

        decoded = up.unquote(name)
        if decoded not in by_name:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
        val = by_name[decoded]
        if isinstance(val, int):
            raise urllib.error.HTTPError(url, val, "Error", {}, None)  # type: ignore[arg-type]
        return val

    return mock_get


def test_cooldown_clean_when_all_old_enough(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    mock = _mock_responses(
        {"lodash": {"time": {"4.17.21": "2021-02-21T02:46:48.218Z"}}}
    )
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now(2024, 1, 15))
    assert report.clean
    assert report.total_checked == 1
    assert report.flagged == []


def test_cooldown_flags_young_version(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/young-pkg": {"version": "1.0.0"}})
    now = _now(2024, 1, 15)
    published = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mock = _mock_responses(
        {"young-pkg": {"time": {"1.0.0": published}}}
    )
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, min_age_days=14, now=now)
    assert not report.clean
    assert len(report.flagged) == 1
    f = report.flagged[0]
    assert f.package_name == "young-pkg"
    assert f.version == "1.0.0"
    assert 2.9 < f.age_days < 3.1  # ~3 days
    assert f.source == "registry.npmjs.org"


def test_cooldown_threshold_boundary(tmp_path: Path) -> None:
    # A package published exactly min_age_days ago is NOT flagged.
    lf = _write_lock(tmp_path, {"node_modules/edge": {"version": "1.0.0"}})
    now = _now(2024, 1, 15)
    published_exact = (now - timedelta(days=14)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mock = _mock_responses({"edge": {"time": {"1.0.0": published_exact}}})
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, min_age_days=14, now=now)
    assert report.clean


def test_cooldown_allowlist(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/internal-thing": {"version": "1.0.0"},
            "node_modules/external-thing": {"version": "2.0.0"},
        },
    )
    now = _now(2024, 1, 15)
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    mock = _mock_responses(
        {
            "internal-thing": {"time": {"1.0.0": yesterday}},
            "external-thing": {"time": {"2.0.0": yesterday}},
        }
    )
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(
            lf, allowed=["internal-thing"], min_age_days=14, now=now
        )
    flagged_names = {f.package_name for f in report.flagged}
    allowed_names = {f.package_name for f in report.allowed}
    assert flagged_names == {"external-thing"}
    assert allowed_names == {"internal-thing"}


def test_cooldown_private_no_data_surfaced_when_only_npm_endpoint(
    tmp_path: Path,
) -> None:
    lf = _write_lock(tmp_path, {"node_modules/@my/internal": {"version": "1.0.0"}})
    # No mock entry for @my/internal → 404 from the only registry.
    mock = _mock_responses({})
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now())
    # Secure-by-default: a name no configured registry knows is a HIGH
    # finding (typosquat / lockfile tampering / config gap). Use
    # `--allow-private` to opt out for legitimately-internal deps.
    assert "@my/internal@1.0.0" in report.private_blocked
    assert report.private_allowed == []
    assert report.flagged == []
    assert not report.clean


def test_cooldown_network_error_surfaced(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/sumthing": {"version": "1.0.0"}})

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.URLError("connection refused")

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now())
    assert not report.clean
    assert any("connection refused" in m for m in report.network_errors)


# ---------------------------------------------------------------------------
# check_cooldown — CodeArtifact-only / mixed-registry scenarios
# ---------------------------------------------------------------------------


def test_cooldown_falls_back_to_codeartifact_on_404(tmp_path: Path) -> None:
    # A CA-only private package: public registry returns 404, CA returns
    # real data with a fresh publish time. cas must consult CA after
    # the public 404 and use that.
    lf = _write_lock(
        tmp_path, {"node_modules/@my/internal": {"version": "1.0.0"}}
    )
    now = _now(2024, 1, 15)
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "codeartifact" in url:
            # Confirm the bearer token was attached.
            assert auth_header == "Bearer fake-token"
            return {"time": {"1.0.0": yesterday}}
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    endpoints = [
        RegistryEndpoint(url="https://registry.npmjs.org", label="registry.npmjs.org"),
        RegistryEndpoint(
            url="https://my-ca-12345.d.codeartifact.us-east-1.amazonaws.com/npm/my-repo",
            auth_header="Bearer fake-token",
            label="my-ca-12345.d.codeartifact.us-east-1.amazonaws.com",
        ),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=now)
    assert len(report.flagged) == 1
    f = report.flagged[0]
    assert f.package_name == "@my/internal"
    assert f.source == "my-ca-12345.d.codeartifact.us-east-1.amazonaws.com"


def test_cooldown_ca_first_order(tmp_path: Path) -> None:
    # When CA is listed first, even public packages get queried at CA.
    # CA's npm proxy preserves the upstream `time` field, so the result
    # is functionally identical.
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    queried_hosts: list[str] = []

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        queried_hosts.append(url)
        return {"time": {"4.17.21": "2021-02-21T02:46:48.218Z"}}

    endpoints = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="ca",
        ),
        RegistryEndpoint(url="https://registry.npmjs.org", label="npm"),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=_now(2024, 1, 15))
    assert report.clean
    # Only one HTTP call expected (CA succeeds on first try).
    assert len(queried_hosts) == 1
    assert "codeartifact" in queried_hosts[0]


def test_cooldown_only_ca_endpoint_handles_404_as_private(tmp_path: Path) -> None:
    # A CodeArtifact-only project (no npm fallback) with a typo in the
    # package name returning 404 → surfaced as private_no_data, not as
    # a hard error.
    lf = _write_lock(
        tmp_path, {"node_modules/@my/typo": {"version": "1.0.0"}}
    )

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    endpoints = [
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        )
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=_now())
    assert "@my/typo@1.0.0" in report.private_blocked
    assert report.network_errors == []


def test_cooldown_skips_workspace_link_entries(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/real-lib": {"version": "1.0.0"},
            "node_modules/@my/workspace-pkg": {"link": True, "resolved": "apps/foo"},
        },
    )
    queried: list[str] = []

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        queried.append(url)
        return {"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        check_cooldown(lf, now=_now())
    assert len(queried) == 1
    assert queried[0].endswith("/real-lib")


def test_cooldown_dedupes_same_name_version(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/foo": {"version": "1.0.0"},
            "node_modules/parent/node_modules/foo": {"version": "1.0.0"},
        },
    )
    queried: list[str] = []

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        queried.append(url)
        return {"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now())
    assert len(queried) == 1
    # total_checked counts unique (name, version) pairs.
    assert report.total_checked == 1


def test_cooldown_finding_dataclass_round_trip() -> None:
    f = CooldownFinding(
        package_name="x",
        version="1.0.0",
        published_at="2024-01-01T00:00:00.000Z",
        age_days=2.5,
        source="registry.npmjs.org",
    )
    assert f.package_name == "x"
    assert f.age_days == 2.5


def test_cooldown_uses_default_threshold() -> None:
    # Sanity check on the published constant — if this changes, every
    # downstream CI config implicitly changes too.
    assert DEFAULT_MIN_AGE_DAYS == 14


# ---------------------------------------------------------------------------
# v0.7.0 fixes — aliased names, fallthrough on version-missing, parallelism, cache
# ---------------------------------------------------------------------------


def test_cooldown_uses_name_field_for_npm_aliases(tmp_path: Path) -> None:
    # npm aliases (`"string-width-cjs": "npm:string-width@4.2.3"`) end up in
    # the lockfile as `node_modules/string-width-cjs` with a `name` field of
    # `string-width`. cas must query the registry for the canonical name.
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/string-width-cjs": {
                "name": "string-width",
                "version": "4.2.3",
            },
        },
    )
    queried_names: list[str] = []

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        queried_names.append(url.rsplit("/", 1)[-1])
        return {"time": {"4.2.3": "2020-01-01T00:00:00.000Z"}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now(2024, 1, 15))
    assert queried_names == ["string-width"]  # NOT "string-width-cjs"
    assert report.clean


def test_cooldown_falls_through_when_version_missing_from_time_dict(
    tmp_path: Path,
) -> None:
    # Real-world: public npm returns metadata for scoped names but without
    # the specific version in `time`. cas must treat that as "endpoint
    # doesn't have this version" and fall through, not as a hard error.
    lf = _write_lock(
        tmp_path, {"node_modules/@my/internal": {"version": "2.0.0"}}
    )
    now = _now(2024, 1, 15)
    yesterday = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "registry.npmjs.org" in url:
            # Public registry: returns 200 with a placeholder `time` that
            # doesn't contain version 2.0.0.
            return {"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}
        # CA endpoint: has the real version.
        return {"time": {"2.0.0": yesterday}}

    endpoints = [
        RegistryEndpoint(url="https://registry.npmjs.org", label="registry.npmjs.org"),
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=now)
    # Resolved at CA, not erroneously surfaced as "no publish time".
    assert len(report.flagged) == 1
    assert report.flagged[0].source == "my-ca"
    assert report.network_errors == []


def test_cooldown_typosquat_of_nothing_is_high(tmp_path: Path) -> None:
    # The case that motivated secure-by-default: a typo'd dep name that
    # doesn't exist anywhere. Used to be silently INFO; now HIGH.
    lf = _write_lock(tmp_path, {"node_modules/lodahzzz": {"version": "1.0.0"}})

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now())
    assert "lodahzzz@1.0.0" in report.private_blocked
    assert not report.clean


def test_cooldown_allow_private_demotes_to_info(tmp_path: Path) -> None:
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/@org/typo": {"version": "1.0.0"},
            "node_modules/@org/legit-internal": {"version": "2.0.0"},
        },
    )

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(
            lf,
            allow_private=["@org/legit-internal"],
            now=_now(),
        )
    assert "@org/legit-internal@2.0.0" in report.private_allowed
    assert "@org/typo@1.0.0" in report.private_blocked
    # Build still fails because of the unallowlisted entry.
    assert not report.clean


def test_cooldown_parallel_dispatches_concurrently(tmp_path: Path) -> None:
    """Performance: with N packages and 50ms simulated latency per request,
    serial would take ~N*50ms; parallel should fit in well under a quarter
    of that. Verifies the executor is actually parallelising, not just
    serialising under the hood.
    """
    import time

    n_packages = 40
    pkgs = {
        f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(n_packages)
    }
    lf = _write_lock(tmp_path, pkgs)

    def slow_mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        time.sleep(0.05)
        return {"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}

    start = time.monotonic()
    with patch("codeartifact_shield.cooldown._http_get_json", slow_mock):
        report = check_cooldown(lf, max_workers=20, now=_now(2024, 1, 15))
    elapsed = time.monotonic() - start

    # Serial budget: 40 * 50ms = 2000ms. Parallel with 20 workers should
    # finish in ~2 rounds (~120ms total + overhead). Generous ceiling so
    # the test doesn't flake on a loaded CI host.
    serial_budget_seconds = n_packages * 0.05
    assert elapsed < serial_budget_seconds / 3, (
        f"parallelism broken: {elapsed:.2f}s elapsed, "
        f"serial budget {serial_budget_seconds:.2f}s"
    )
    assert report.clean


def test_cooldown_serial_when_max_workers_is_one(tmp_path: Path) -> None:
    """`--max-workers 1` should force the single-threaded path (useful for
    debugging or rate-limit-strict registries)."""
    import time

    lf = _write_lock(
        tmp_path,
        {f"node_modules/pkg-{i}": {"version": "1.0.0"} for i in range(5)},
    )

    def slow_mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        time.sleep(0.05)
        return {"time": {"1.0.0": "2020-01-01T00:00:00.000Z"}}

    start = time.monotonic()
    with patch("codeartifact_shield.cooldown._http_get_json", slow_mock):
        check_cooldown(lf, max_workers=1, now=_now())
    elapsed = time.monotonic() - start
    # 5 * 50ms = 250ms expected serial. Allow up to 500ms.
    assert elapsed >= 0.20, f"serial mode unexpectedly fast: {elapsed:.2f}s"


def test_cooldown_cache_hit_avoids_http(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    cache_file = tmp_path / "cache.json"
    cache_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entries": {
                    "registry.npmjs.org": {
                        "lodash": {"4.17.21": "2021-02-21T02:46:48.218Z"}
                    }
                },
            }
        )
    )
    http_calls: list[str] = []

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        http_calls.append(url)
        raise AssertionError("HTTP must not be called on cache hit")

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, cache_path=cache_file, now=_now(2024, 1, 15))
    assert http_calls == []
    assert report.cache_hits == 1
    assert report.cache_misses == 0
    assert report.clean


def test_cooldown_cache_miss_fetches_and_persists(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    cache_file = tmp_path / "cache.json"  # doesn't exist yet

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {
            "time": {
                "4.17.20": "2020-07-09T18:46:44.196Z",
                "4.17.21": "2021-02-21T02:46:48.218Z",
                "created": "2011-09-21T05:42:31.345Z",
                "modified": "2024-01-02T01:23:45.678Z",
            }
        }

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        check_cooldown(lf, cache_path=cache_file, now=_now(2024, 1, 15))

    # Cache should now exist and contain both versions (aggressive populate).
    persisted = json.loads(cache_file.read_text())
    entries = persisted["entries"]
    assert (
        entries["registry.npmjs.org"]["lodash"]["4.17.21"]
        == "2021-02-21T02:46:48.218Z"
    )
    assert (
        entries["registry.npmjs.org"]["lodash"]["4.17.20"]
        == "2020-07-09T18:46:44.196Z"
    )
    # Special keys ("created" / "modified") not cached as version keys.
    assert "created" not in entries["registry.npmjs.org"]["lodash"]


def test_cooldown_corrupt_cache_falls_back_silently(tmp_path: Path) -> None:
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    cache_file = tmp_path / "cache.json"
    cache_file.write_text("{not valid json")  # corrupt

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {"time": {"4.17.21": "2021-02-21T02:46:48.218Z"}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, cache_path=cache_file, now=_now(2024, 1, 15))
    # Corrupt cache treated as empty; HTTP runs; result is correct.
    assert report.clean
    # Cache is then re-written with valid content.
    persisted = json.loads(cache_file.read_text())
    assert persisted["schema_version"] == 1


def test_cooldown_cache_aggressive_populate_helps_next_run(tmp_path: Path) -> None:
    """First run: fetch lodash@4.17.21 (which returns time data for many
    versions). Second run on a lockfile that needs lodash@4.17.20 should
    be served entirely from cache — no HTTP."""
    cache_file = tmp_path / "cache.json"

    def mock_first(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {
            "time": {
                "4.17.20": "2020-07-09T18:46:44.196Z",
                "4.17.21": "2021-02-21T02:46:48.218Z",
            }
        }

    lf1 = tmp_path / "run1-lock.json"
    lf1.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/lodash": {"version": "4.17.21"}},
            }
        )
    )

    with patch("codeartifact_shield.cooldown._http_get_json", mock_first):
        check_cooldown(lf1, cache_path=cache_file, now=_now(2024, 1, 15))

    # Second run: now needs 4.17.20 — should hit cache.
    lf2 = tmp_path / "run2-lock.json"
    lf2.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/lodash": {"version": "4.17.20"}},
            }
        )
    )

    def mock_second(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise AssertionError("must not hit HTTP — answer is in the cache")

    with patch("codeartifact_shield.cooldown._http_get_json", mock_second):
        report = check_cooldown(lf2, cache_path=cache_file, now=_now(2024, 1, 15))
    assert report.cache_hits == 1
    assert report.cache_misses == 0
    assert report.clean


# ---------------------------------------------------------------------------
# Resilient fallthrough — a transient error on one endpoint must not fail
# the build when a later endpoint successfully resolves the same name.
# ---------------------------------------------------------------------------


def test_cooldown_endpoint1_error_endpoint2_resolves_is_clean(
    tmp_path: Path,
) -> None:
    """Public registry blips (URLError) but CA resolves the package —
    no spurious network_error in the report.

    Regression guard for the v0.7.1 CI failure:
        [HIGH] @vitest/expect (registry.npmjs.org):
          <urlopen error [Errno 101] Network is unreachable>
    """
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})
    now = _now(2024, 1, 15)

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "registry.npmjs.org" in url:
            raise urllib.error.URLError("network unreachable")
        if "codeartifact" in url:
            return {"time": {"4.17.21": "2021-02-21T02:46:48.218Z"}}
        raise AssertionError(f"unexpected URL: {url}")

    endpoints = [
        RegistryEndpoint(url="https://registry.npmjs.org", label="registry.npmjs.org"),
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=now)
    assert report.network_errors == []
    assert report.private_blocked == []
    assert report.clean


def test_cooldown_error_on_all_endpoints_surfaces_network_error(
    tmp_path: Path,
) -> None:
    """If every endpoint errors and the name is never resolved, the first
    error should surface — not vanish into ``private_blocked``."""
    lf = _write_lock(tmp_path, {"node_modules/something": {"version": "1.0.0"}})

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.URLError("network unreachable")

    endpoints = [
        RegistryEndpoint(url="https://registry.npmjs.org", label="registry.npmjs.org"),
        RegistryEndpoint(
            url="https://my-ca.d.codeartifact.us-east-1.amazonaws.com/npm/repo",
            auth_header="Bearer xxx",
            label="my-ca",
        ),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=_now())
    assert len(report.network_errors) == 1
    assert "network unreachable" in report.network_errors[0]
    assert "something" in report.network_errors[0]
    assert report.private_blocked == []
    assert not report.clean


def test_cooldown_error_then_404_then_resolved_is_clean(tmp_path: Path) -> None:
    """Three endpoints: first errors, second 404s, third resolves. Should be
    clean — the error on endpoint 1 is wiped once endpoint 3 succeeds."""
    lf = _write_lock(tmp_path, {"node_modules/@my/pkg": {"version": "1.0.0"}})
    now = _now(2024, 1, 15)
    old = (now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        if "ep1" in url:
            raise urllib.error.URLError("transient")
        if "ep2" in url:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
        if "ep3" in url:
            return {"time": {"1.0.0": old}}
        raise AssertionError(f"unexpected URL: {url}")

    endpoints = [
        RegistryEndpoint(url="https://ep1.example.com", label="ep1"),
        RegistryEndpoint(url="https://ep2.example.com", label="ep2"),
        RegistryEndpoint(url="https://ep3.example.com", label="ep3"),
    ]
    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, endpoints=endpoints, now=now)
    assert report.clean
    assert report.network_errors == []


def test_cooldown_error_does_not_leak_into_private_blocked(
    tmp_path: Path,
) -> None:
    """Single-endpoint error must NOT silently end up in ``private_blocked``.
    A blocked-private finding is a different signal than a transient error
    — confusing them was the v0.7.1 misclassification."""
    lf = _write_lock(tmp_path, {"node_modules/lodash": {"version": "4.17.21"}})

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.URLError("network unreachable")

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now())
    assert "lodash@4.17.21" not in report.private_blocked
    assert report.private_blocked == []
    assert len(report.network_errors) == 1


# ---------------------------------------------------------------------------
# Versioned allowlist — v0.8.0
# ---------------------------------------------------------------------------


def test_cooldown_versioned_allow_demotes_only_that_version(tmp_path: Path) -> None:
    """`--allow lodash@4.17.21` demotes only that version. Other lodash
    versions still get flagged if young."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/old-lodash/node_modules/lodash": {"version": "3.10.0"},
        },
    )
    now = _now(2024, 1, 15)
    yesterday_iso = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {"time": {"4.17.21": yesterday_iso, "3.10.0": yesterday_iso}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=now, allowed=["lodash@4.17.21"])
    flagged = {(f.package_name, f.version) for f in report.flagged}
    allowed = {(f.package_name, f.version) for f in report.allowed}
    assert ("lodash", "3.10.0") in flagged
    assert ("lodash", "4.17.21") in allowed


def test_cooldown_versioned_allow_private(tmp_path: Path) -> None:
    """`--allow-private @my/pkg@1.0.0` demotes only that version of an
    unresolvable private package."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/@my/pkg": {"version": "1.0.0"},
            "node_modules/@my/pkg-other/node_modules/@my/pkg": {"version": "2.0.0"},
        },
    )

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=_now(), allow_private=["@my/pkg@1.0.0"])
    assert "@my/pkg@1.0.0" in report.private_allowed
    assert "@my/pkg@2.0.0" in report.private_blocked


def test_cooldown_name_only_allow_still_works(tmp_path: Path) -> None:
    """Back-compat: `--allow lodash` continues to demote every version."""
    lf = _write_lock(
        tmp_path,
        {
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/old-lodash/node_modules/lodash": {"version": "3.10.0"},
        },
    )
    now = _now(2024, 1, 15)
    yesterday_iso = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def mock(
        url: str, timeout: int, auth_header: str | None = None, retries: int = 2
    ) -> dict[str, Any]:
        return {"time": {"4.17.21": yesterday_iso, "3.10.0": yesterday_iso}}

    with patch("codeartifact_shield.cooldown._http_get_json", mock):
        report = check_cooldown(lf, now=now, allowed=["lodash"])
    assert report.flagged == []
    assert len(report.allowed) == 2
