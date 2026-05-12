"""Tests for the shared HTTP retry helper."""

from __future__ import annotations

import urllib.error
from typing import Any

import pytest

from codeartifact_shield._http import with_retry


def test_retry_succeeds_first_try() -> None:
    """No retry needed when the call succeeds immediately."""
    calls: list[int] = []

    def fn() -> str:
        calls.append(1)
        return "ok"

    result = with_retry(fn, retries=2, sleep=lambda _s: None)
    assert result == "ok"
    assert len(calls) == 1


def test_retry_succeeds_on_attempt_two() -> None:
    """Transient URLError on first try, success on retry — should NOT raise."""
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise urllib.error.URLError("network unreachable")
        return "ok"

    result = with_retry(fn, retries=2, sleep=lambda _s: None)
    assert result == "ok"
    assert len(attempts) == 2


def test_retry_succeeds_on_final_attempt() -> None:
    """Two transient failures, success on attempt 3 (retries=2 → 3 total)."""
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) <= 2:
            raise urllib.error.URLError("network unreachable")
        return "ok"

    result = with_retry(fn, retries=2, sleep=lambda _s: None)
    assert result == "ok"
    assert len(attempts) == 3


def test_retry_exhausted_raises_final_exception() -> None:
    """retries=2 means 3 attempts; after that, the last exception bubbles up."""
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        raise urllib.error.URLError("network unreachable")

    with pytest.raises(urllib.error.URLError, match="network unreachable"):
        with_retry(fn, retries=2, sleep=lambda _s: None)
    assert len(attempts) == 3  # initial + 2 retries


def test_retry_zero_disables_retry() -> None:
    """retries=0 means single attempt, no retry."""
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        raise urllib.error.URLError("immediate fail")

    with pytest.raises(urllib.error.URLError):
        with_retry(fn, retries=0, sleep=lambda _s: None)
    assert len(attempts) == 1


def test_404_is_not_retried() -> None:
    """A 404 is a legitimate "not found" — retry can't help, don't waste time."""
    attempts: list[int] = []

    def fn() -> dict[str, Any]:
        attempts.append(1)
        raise urllib.error.HTTPError(
            "http://x", 404, "Not Found", {}, None  # type: ignore[arg-type]
        )

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        with_retry(fn, retries=3, sleep=lambda _s: None)
    assert excinfo.value.code == 404
    assert len(attempts) == 1  # single attempt only


def test_other_4xx_is_not_retried() -> None:
    """403, 400 etc. are client errors. Retry doesn't fix them."""
    attempts: list[int] = []

    def fn() -> dict[str, Any]:
        attempts.append(1)
        raise urllib.error.HTTPError(
            "http://x", 403, "Forbidden", {}, None  # type: ignore[arg-type]
        )

    with pytest.raises(urllib.error.HTTPError):
        with_retry(fn, retries=3, sleep=lambda _s: None)
    assert len(attempts) == 1


def test_5xx_is_retried() -> None:
    """500-class is server-side transient. Retry until success."""
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) <= 1:
            raise urllib.error.HTTPError(
                "http://x", 503, "Service Unavailable", {}, None  # type: ignore[arg-type]
            )
        return "ok"

    result = with_retry(fn, retries=2, sleep=lambda _s: None)
    assert result == "ok"
    assert len(attempts) == 2


def test_429_is_retried_and_honors_retry_after() -> None:
    """429 is rate-limit. Retry should respect the server's Retry-After hint."""
    import email.message
    attempts: list[int] = []
    sleep_calls: list[float] = []

    headers = email.message.Message()
    headers["Retry-After"] = "3"

    def fn() -> str:
        attempts.append(1)
        if len(attempts) <= 1:
            raise urllib.error.HTTPError(
                "http://x", 429, "Too Many Requests", headers, None  # type: ignore[arg-type]
            )
        return "ok"

    result = with_retry(fn, retries=2, sleep=lambda s: sleep_calls.append(s))
    assert result == "ok"
    assert len(attempts) == 2
    # The Retry-After=3 should drive the sleep, not the base_delay backoff.
    assert sleep_calls == [3.0]


def test_429_retry_after_caps_at_60_seconds() -> None:
    """A misbehaving server returning Retry-After: 86400 shouldn't stall CI."""
    import email.message
    sleep_calls: list[float] = []

    headers = email.message.Message()
    headers["Retry-After"] = "86400"  # 1 day

    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) <= 1:
            raise urllib.error.HTTPError(
                "http://x", 429, "Too Many", headers, None  # type: ignore[arg-type]
            )
        return "ok"

    with_retry(fn, retries=1, sleep=lambda s: sleep_calls.append(s))
    assert sleep_calls == [60.0]  # capped


def test_json_decode_error_not_retried() -> None:
    """Malformed response body isn't a transient issue."""
    import json
    attempts: list[int] = []

    def fn() -> dict[str, Any]:
        attempts.append(1)
        raise json.JSONDecodeError("expecting value", "", 0)

    with pytest.raises(json.JSONDecodeError):
        with_retry(fn, retries=3, sleep=lambda _s: None)
    assert len(attempts) == 1


def test_backoff_grows_exponentially() -> None:
    """Sleep durations should follow base_delay * 4**attempt."""
    sleep_calls: list[float] = []
    attempts: list[int] = []

    def fn() -> str:
        attempts.append(1)
        if len(attempts) <= 2:
            raise urllib.error.URLError("transient")
        return "ok"

    with_retry(fn, retries=2, base_delay=0.1, sleep=lambda s: sleep_calls.append(s))
    # Two retries → two sleep calls. base_delay=0.1, factor=4: [0.1, 0.4].
    assert sleep_calls == pytest.approx([0.1, 0.4])
