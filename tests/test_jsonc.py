"""Unit tests for the in-house JSONC pre-processor (reused by deno + bun)."""

from __future__ import annotations

import pytest

from codeartifact_shield.lockfiles import _jsonc


def test_line_comment_stripped() -> None:
    assert _jsonc.loads('{"a": 1 // trailing\n}') == {"a": 1}


def test_block_comment_stripped() -> None:
    assert _jsonc.loads('{/* hi */ "a": 1}') == {"a": 1}


def test_trailing_comma_object() -> None:
    assert _jsonc.loads('{"a": 1, "b": 2,}') == {"a": 1, "b": 2}


def test_trailing_comma_array() -> None:
    assert _jsonc.loads('{"a": [1, 2, 3,]}') == {"a": [1, 2, 3]}


def test_comment_markers_inside_string_preserved() -> None:
    # The // and /* inside the string value must survive verbatim.
    assert _jsonc.loads('{"url": "https://x/y", "c": "/* not a comment */"}') == {
        "url": "https://x/y",
        "c": "/* not a comment */",
    }


def test_comma_inside_string_not_stripped() -> None:
    assert _jsonc.loads('{"a": "x,}"}') == {"a": "x,}"}


def test_nested_block_comment_rejected() -> None:
    with pytest.raises(_jsonc.JsoncError, match="nested block comment"):
        _jsonc.loads("{/* outer /* inner */ */}")


def test_unterminated_block_comment_rejected() -> None:
    with pytest.raises(_jsonc.JsoncError, match="unterminated block comment"):
        _jsonc.loads('{"a": 1 /* never closed')


def test_invalid_json_after_stripping_rejected() -> None:
    with pytest.raises(_jsonc.JsoncError, match="invalid JSONC"):
        _jsonc.loads("{not json}")


def test_escaped_quote_in_string() -> None:
    assert _jsonc.loads(r'{"a": "he said \"hi\" // x"}') == {"a": 'he said "hi" // x'}


def test_multiline_block_preserves_line_numbers() -> None:
    # A JSON error after a multi-line comment should still parse the good part.
    text = '{\n/* a\nb\nc */\n"a": 1\n}'
    assert _jsonc.loads(text) == {"a": 1}
