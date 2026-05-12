"""Shared HTTP retry helper used by every cas command that talks to a
remote registry or vuln database.

Transient errors (DNS hiccup, TCP reset, server 5xx, rate limit) are a
fact of life in CI. The default behavior in cas 0.7.1 was to fail the
build on the first such error, which was correct but unkind. This
module retries those errors with exponential backoff before giving up.

What gets retried
-----------------

* ``URLError`` — DNS / connect / "Network unreachable".
* ``TimeoutError`` / ``OSError`` — read timeout, broken pipe.
* HTTP **5xx** — server-side temporary.
* HTTP **429** — rate limit. Honors the ``Retry-After`` header when
  present (capped at 60s so a misbehaving server can't stall CI).

What does NOT get retried
-------------------------

* HTTP **404** — legitimate "not found". Retrying can't make a missing
  package appear.
* HTTP **4xx** other than 429 — client error.
* ``json.JSONDecodeError`` — body was non-JSON. Retrying won't help.
"""

from __future__ import annotations

import json
import time
import urllib.error
from collections.abc import Callable
from typing import TypeVar

DEFAULT_RETRIES = 2
DEFAULT_BASE_DELAY = 0.1
MAX_RETRY_AFTER_SECONDS = 60.0

T = TypeVar("T")


def _is_retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    code = exc.code
    if code == 429:
        return True
    return 500 <= code < 600


def _retry_after_delay(exc: urllib.error.HTTPError) -> float | None:
    if exc.headers is None:
        return None
    raw = exc.headers.get("Retry-After")
    if not raw:
        return None
    try:
        delay = float(raw)
        return min(max(delay, 0.0), MAX_RETRY_AFTER_SECONDS)
    except (TypeError, ValueError):
        return None


def with_retry(
    func: Callable[[], T],
    retries: int = DEFAULT_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Invoke ``func()`` with up to ``retries`` retries on transient errors.

    Args:
        func: Zero-arg callable to invoke. Typically a ``lambda`` closing
            over the actual request parameters.
        retries: Number of retries (not counting the first attempt).
            Total attempts = ``retries + 1``. Default 2 (3 attempts).
        base_delay: Backoff base in seconds. Per-attempt delay is
            ``base_delay * 4**attempt`` — 100ms, 400ms, 1600ms by default.
        sleep: Override for ``time.sleep``, used in tests to make
            backoff instant.
    """
    last_exc: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            return func()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise
            if not _is_retryable_http_error(exc):
                raise
            last_exc = exc
            if attempt < retries:
                retry_after = _retry_after_delay(exc)
                delay = retry_after if retry_after is not None else base_delay * (4**attempt)
                sleep(delay)
            else:
                raise
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt < retries:
                sleep(base_delay * (4**attempt))
            else:
                raise
        except json.JSONDecodeError:
            # Body wasn't valid JSON — retry won't help.
            raise

    assert last_exc is not None  # unreachable; retries-exhausted path raises above
    raise last_exc
