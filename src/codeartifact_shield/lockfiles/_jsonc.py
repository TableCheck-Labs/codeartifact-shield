"""Strict, dependency-free JSONC pre-processor.

Deno's ``deno.jsonc`` (and, in Phase C, ``bun.lock``) are JSON-with-comments:
plain JSON plus ``//`` line comments, ``/* */`` block comments, and trailing
commas. Python's ``json`` can't read them, and we refuse to add a parser
dependency for a format this small.

This module strips comments and trailing commas *outside string literals* and
then hands the result to ``json.loads``. It is deliberately strict:

* comment markers inside strings are preserved verbatim,
* an unterminated block comment is an error,
* a **nested** ``/*`` inside a block comment is an error (JSONC does not nest
  block comments; tolerating it would let a tampered file smuggle bytes past a
  reviewer who reads it as a single comment).
"""

from __future__ import annotations

import json
from typing import Any


class JsoncError(ValueError):
    """Malformed JSONC (unterminated or nested block comment, bad JSON)."""


def strip_comments(text: str) -> str:
    """Return ``text`` with ``//`` and ``/* */`` comments replaced by spaces.

    String literals are scanned (respecting ``\\`` escapes) so a ``//`` or
    ``/*`` inside a string is left untouched. Newlines inside comments are
    preserved so ``json`` error line numbers still line up.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            # Line comment: skip to end of line, keeping the newline.
            i += 2
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            # Block comment: skip to the terminating '*/', rejecting a nested
            # '/*'. Preserve newlines so line numbers survive.
            i += 2
            while i < n:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    raise JsoncError("nested block comment is not valid JSONC")
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    i += 2
                    break
                if text[i] in ("\n", "\r"):
                    out.append(text[i])
                i += 1
            else:
                raise JsoncError("unterminated block comment")
            continue
        out.append(ch)
        i += 1
    if in_string:
        raise JsoncError("unterminated string literal")
    return "".join(out)


def strip_trailing_commas(text: str) -> str:
    """Remove commas that immediately precede a ``}`` or ``]`` (JSONC allows
    them; ``json`` does not). String-aware so a comma inside a string stays."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in ("}", "]"):
                # Drop the comma; keep the whitespace/closing brace for output.
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Any:
    """Parse a JSONC document into Python objects.

    Raises :class:`JsoncError` for malformed comments and for JSON that fails
    to parse after comment/trailing-comma stripping.
    """
    cleaned = strip_trailing_commas(strip_comments(text))
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise JsoncError(f"invalid JSONC: {exc}") from exc
