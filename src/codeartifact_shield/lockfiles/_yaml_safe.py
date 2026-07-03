"""Hardened YAML loader for lockfile parsing.

``yaml.safe_load`` blocks arbitrary object construction, but it does **not**
protect against the classic YAML denial-of-service: anchors and aliases let a
small document expand to gigabytes ("billion laughs" / alias bomb). pnpm never
emits anchors or aliases in ``pnpm-lock.yaml``, so a lockfile that contains one
is either corrupt or hostile — we reject it outright rather than expand it.

On top of that we cap the input size and require the document root to be a
mapping, so a gate never operates on a structurally absurd file.
"""

from __future__ import annotations

from typing import Any

import yaml

DEFAULT_MAX_BYTES = 100 * 1024 * 1024
"""100 MiB — comfortably above any real lockfile, low enough that a
pathological file can't exhaust memory before the size check fires."""


class YamlSafetyError(ValueError):
    """A YAML document tripped one of the hardening checks."""


class _NoAliasLoader(yaml.SafeLoader):
    """A ``SafeLoader`` that refuses anchors and aliases."""


def _reject_alias(loader: yaml.SafeLoader, node: yaml.Node) -> Any:
    raise YamlSafetyError(
        "YAML anchors/aliases are not permitted in a lockfile "
        "(alias expansion is a denial-of-service vector; pnpm never emits them)"
    )


def _compose_node_no_anchors(
    loader: _NoAliasLoader, parent: Any, index: Any
) -> Any:
    # ``compose_node`` is where PyYAML both registers an anchor and resolves an
    # alias reference. Intercept the alias event, and forbid any node that
    # declares an anchor, before the loader can build the (potentially
    # exponentially-expanded) object graph.
    if loader.check_event(yaml.events.AliasEvent):  # type: ignore[no-untyped-call]
        raise YamlSafetyError(
            "YAML aliases are not permitted in a lockfile "
            "(alias expansion is a denial-of-service vector)"
        )
    event = loader.peek_event()  # type: ignore[no-untyped-call]
    anchor = getattr(event, "anchor", None)
    if anchor is not None:
        raise YamlSafetyError(
            "YAML anchors are not permitted in a lockfile "
            "(anchor/alias expansion is a denial-of-service vector)"
        )
    return yaml.SafeLoader.compose_node(loader, parent, index)


_NoAliasLoader.compose_node = _compose_node_no_anchors  # type: ignore[assignment]


def safe_load_mapping(text: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Parse ``text`` as YAML, enforcing the lockfile hardening invariants.

    Raises :class:`YamlSafetyError` (a ``ValueError``) if the input exceeds
    ``max_bytes``, contains anchors/aliases, or does not deserialize to a
    mapping.
    """
    if len(text.encode("utf-8", errors="ignore")) > max_bytes:
        raise YamlSafetyError(
            f"lockfile exceeds the {max_bytes}-byte safety cap; refusing to parse"
        )
    try:
        data = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 - hardened subclass
    except yaml.YAMLError as exc:
        raise YamlSafetyError(f"malformed YAML: {exc}") from exc
    if data is None:
        raise YamlSafetyError("empty YAML document; expected a mapping root")
    if not isinstance(data, dict):
        raise YamlSafetyError(
            f"YAML root must be a mapping, got {type(data).__name__}"
        )
    return data
