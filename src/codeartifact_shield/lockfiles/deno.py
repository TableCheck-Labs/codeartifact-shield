"""Deno adapter — ``deno.lock`` (versions 3, 4, 5).

One normalized view over three on-disk shapes:

* **v3** — the resolved packages live under a top-level ``packages`` object
  holding ``specifiers`` / ``npm`` / ``jsr`` sub-maps; ``remote`` and
  ``redirects`` are top-level. npm entry ``dependencies`` are a
  ``{alias: name@version}`` mapping.
* **v4 / v5** — ``specifiers`` / ``npm`` / ``jsr`` / ``remote`` / ``redirects``
  are all top-level, plus a ``workspace`` block of declared specifiers. npm
  entry ``dependencies`` are a list of ``name@version`` strings. v5 is treated
  as v4 with the same layout (the delta between them doesn't touch the fields
  cas consumes).

Three ecosystems land in the model:

* **npm** — ``name@version`` keys, sha512 SRI integrity → ``Ecosystem.NPM``,
  ``REGISTRY_IMPLIED`` (deno resolves the registry from config, not per-entry).
* **jsr** — ``@scope/name@version`` keys, sha256 integrity → ``Ecosystem.JSR``.
  The recorded sha256 (bare hex in real lockfiles) is normalized to
  ``sha256-<base64>`` SRI form so ``sri verify`` counts it uniformly.
* **remote** — ``url -> sha256-hex`` → one entry per URL, ``Ecosystem.REMOTE``,
  ``resolved_kind=REGISTRY`` (host known), hex normalized to SRI.

.. note::

   No ``deno`` binary was available at implementation time, so the layouts
   below follow Deno's documented ``deno.lock`` schema. The parser is tolerant
   where the schema has drifted across Deno releases (specifier values that do
   or don't carry an ``npm:``/``jsr:`` prefix; npm ``dependencies`` as a list
   *or* a map) so a real lockfile that differs in those details still parses.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import codeartifact_shield.lockfiles._jsonc as _jsonc
from codeartifact_shield.lockfiles._model import (
    Capability,
    Ecosystem,
    LockEntry,
    LockFormat,
    NormalizedLockfile,
    ResolvedKind,
)

SUPPORTED_VERSIONS = ("3", "4", "5")

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_CHARS = ("\x00", "\n", "\r")


def _reject_control(value: str, what: str) -> None:
    if any(c in value for c in _CONTROL_CHARS):
        raise ValueError(f"control character in {what}: {value!r}")


def _split_at_version(spec: str) -> tuple[str, str]:
    """Split ``name@version`` (scope-aware) into ``(name, version)``.

    ``chalk@5.3.0`` -> ``("chalk", "5.3.0")``; ``@std/assert@1.0.0`` ->
    ``("@std/assert", "1.0.0")``. A leading ``@`` (scope) is skipped so the
    version separator is found correctly.
    """
    at = spec.find("@", 1)
    if at == -1:
        return spec, ""
    return spec[:at], spec[at + 1 :]


def _split_npm_key(key: str) -> tuple[str, str]:
    """Split a deno npm key into ``(name, version)``, dropping any peer suffix.

    Deno appends peer-dependency resolution to npm keys with an underscore,
    e.g. ``vite@5.0.0_@types+node@20.0.0``. The peer suffix is stripped before
    the version is parsed.
    """
    at = key.find("@", 1)
    if at == -1:
        return key, ""
    underscore = key.find("_", at)
    base = key[:underscore] if underscore != -1 else key
    return _split_at_version(base)


def _strip_specifier_prefix(spec: str) -> str:
    for prefix in ("npm:", "jsr:"):
        if spec.startswith(prefix):
            return spec[len(prefix) :]
    return spec


def _validate_pkg_key(key: str, ecosystem: str) -> None:
    _reject_control(key, f"deno {ecosystem} key")
    name, _version = (
        _split_npm_key(key) if ecosystem == "npm" else _split_at_version(key)
    )
    if ".." in name.split("/"):
        raise ValueError(f"path traversal in deno {ecosystem} key: {key!r}")
    if "\\" in key:
        raise ValueError(f"backslash in deno {ecosystem} key: {key!r}")


def _validate_https_url(url: str, what: str) -> None:
    _reject_control(url, what)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"non-https {what}: {url!r}")
    if not parsed.hostname:
        raise ValueError(f"empty host in {what}: {url!r}")


def _sha256_hex_to_sri(hex_digest: str) -> str:
    return "sha256-" + base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _normalize_jsr_integrity(value: Any) -> str | None:
    """jsr records a bare sha256 hex digest; normalize it to ``sha256-<b64>``.

    Values already in SRI form (some Deno versions) are passed through so the
    strong-algorithm check in ``sri verify`` still sees them.
    """
    if not isinstance(value, str) or not value:
        return None
    if _SHA256_HEX.match(value):
        return _sha256_hex_to_sri(value)
    return value


def _npm_deps(value: Any) -> dict[str, str]:
    """Normalize an npm entry's ``dependencies`` (list *or* map) to name->version."""
    items: list[Any]
    if isinstance(value, dict):
        items = list(value.values())
    elif isinstance(value, list):
        items = value
    else:
        return {}
    out: dict[str, str] = {}
    for item in items:
        if not isinstance(item, str):
            continue
        name, version = _split_npm_key(item)
        if name:
            out[name] = version
    return out


def _jsr_deps(value: Any) -> dict[str, str]:
    """Normalize a jsr entry's ``dependencies`` (list of specifiers) to
    name->range. Both ``jsr:`` and ``npm:`` dependency specifiers are accepted."""
    out: dict[str, str] = {}
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                continue
            name, version = _split_at_version(_strip_specifier_prefix(item))
            if name:
                out[name] = version
    elif isinstance(value, dict):
        for k, v in value.items():
            out[str(k)] = str(v)
    return out


def _sections(
    lock: dict[str, Any],
) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]
]:
    """Return ``(specifiers, npm, jsr, remote, redirects)`` for any lock version."""
    version = str(lock.get("version", ""))
    if version == "3":
        packages = lock.get("packages")
        packages = packages if isinstance(packages, dict) else {}
        specifiers = packages.get("specifiers")
        npm = packages.get("npm")
        jsr = packages.get("jsr")
    else:
        specifiers = lock.get("specifiers")
        npm = lock.get("npm")
        jsr = lock.get("jsr")
    remote = lock.get("remote")
    redirects = lock.get("redirects")
    return (
        specifiers if isinstance(specifiers, dict) else {},
        npm if isinstance(npm, dict) else {},
        jsr if isinstance(jsr, dict) else {},
        remote if isinstance(remote, dict) else {},
        redirects if isinstance(redirects, dict) else {},
    )


def load_deno_lock(path: Path) -> dict[str, Any]:
    """Read and version-gate a ``deno.lock``.

    Raises ``ValueError`` for unsupported ``version`` values (1/2 → regenerate
    with a modern Deno) so the CLI surfaces a clean ``[HIGH] FAIL``.
    """
    text = path.read_text()
    if "\x00" in text:
        raise ValueError("null byte in deno.lock")
    data = _jsonc.loads(text)
    if not isinstance(data, dict):
        raise ValueError("deno.lock root must be an object")
    raw_version = data.get("version")
    version = str(raw_version)
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(
            f"unsupported deno.lock version {raw_version!r}; "
            f"regenerate with a modern Deno (only {', '.join(SUPPORTED_VERSIONS)} "
            f"are supported)"
        )
    return data


def build_normalized(path: Path) -> NormalizedLockfile:
    """Parse a ``deno.lock`` into the format-agnostic model."""
    lock = load_deno_lock(path)
    version = str(lock.get("version", ""))
    specifiers, npm, jsr, remote, redirects = _sections(lock)

    entries: list[LockEntry] = []

    for key, meta in npm.items():
        skey = str(key)
        _validate_pkg_key(skey, "npm")
        meta = meta if isinstance(meta, dict) else {}
        name, ver = _split_npm_key(skey)
        integrity = meta.get("integrity")
        entries.append(
            LockEntry(
                key=skey,
                name=name,
                version=ver,
                ecosystem=Ecosystem.NPM,
                resolved=None,
                resolved_kind=ResolvedKind.REGISTRY_IMPLIED,
                integrity=integrity if isinstance(integrity, str) and integrity else None,
                has_install_script=None,
                dependencies=_npm_deps(meta.get("dependencies")),
                raw=meta,
            )
        )

    for key, meta in jsr.items():
        skey = str(key)
        _validate_pkg_key(skey, "jsr")
        meta = meta if isinstance(meta, dict) else {}
        name, ver = _split_at_version(skey)
        entries.append(
            LockEntry(
                key=skey,
                name=name,
                version=ver,
                ecosystem=Ecosystem.JSR,
                resolved=None,
                resolved_kind=ResolvedKind.REGISTRY_IMPLIED,
                integrity=_normalize_jsr_integrity(meta.get("integrity")),
                has_install_script=None,
                dependencies=_jsr_deps(meta.get("dependencies")),
                raw=meta,
            )
        )

    for url, digest in remote.items():
        surl = str(url)
        _validate_https_url(surl, "remote URL")
        sdigest = str(digest)
        if not _SHA256_HEX.match(sdigest):
            raise ValueError(f"remote hash for {surl!r} is not 64 lowercase hex")
        entries.append(
            LockEntry(
                key=surl,
                name=surl,
                version="",
                ecosystem=Ecosystem.REMOTE,
                resolved=surl,
                resolved_kind=ResolvedKind.REGISTRY,
                integrity=_sha256_hex_to_sri(sdigest),
                has_install_script=None,
                raw={"url": surl, "integrity": sdigest},
            )
        )

    # Redirects are not entries, but they are validated (https on both sides)
    # and stashed on ``raw`` so the registry gate can flag cross-host ones.
    for src, dst in redirects.items():
        _validate_https_url(str(src), "redirect source")
        _validate_https_url(str(dst), "redirect target")

    capabilities = (
        Capability.INTEGRITY
        | Capability.RESOLVED_URLS
        | Capability.DEP_GRAPH
        | Capability.DIRECT_DECLARATIONS
    )

    workspaces = _workspaces_view(specifiers)

    return NormalizedLockfile(
        format=LockFormat.DENO,
        format_version=version,
        path=path,
        entries=entries,
        capabilities=capabilities,
        workspaces=workspaces,
        raw=lock,
    )


def _workspaces_view(
    specifiers: dict[str, Any],
) -> dict[str, dict[str, dict[str, str]]]:
    """Expose the lockfile ``specifiers`` as a single ``""`` importer.

    deno has no per-workspace dependency scopes in the lockfile; the declared
    request specifiers (``npm:x@^1`` -> resolved) are the closest analogue and
    are what ``drift`` compares against ``deno.json`` imports.
    """
    deps: dict[str, str] = {str(k): str(v) for k, v in specifiers.items()}
    return {"": {"dependencies": deps}} if deps else {}


def cross_host_redirects(lock: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(source, target)`` redirects whose hosts differ.

    A redirect that lands on a different host than its source is a supply-chain
    smell — the pinned URL a reviewer sees is not where the bytes come from.
    """
    _specifiers, _npm, _jsr, _remote, redirects = _sections(lock)
    findings: list[tuple[str, str]] = []
    for src, dst in redirects.items():
        src_host = urlparse(str(src)).hostname or ""
        dst_host = urlparse(str(dst)).hostname or ""
        if src_host and dst_host and src_host != dst_host:
            findings.append((str(src), str(dst)))
    return findings


def read_deno_manifest(project_dir: Path) -> dict[str, Any]:
    """Read ``deno.json`` / ``deno.jsonc`` and return its parsed contents.

    Prefers ``deno.json``; falls back to ``deno.jsonc``. Returns ``{}`` when no
    manifest is present. Parsed with the in-house JSONC reader so comments and
    trailing commas are tolerated.
    """
    for name in ("deno.json", "deno.jsonc"):
        candidate = project_dir / name
        if candidate.exists():
            data = _jsonc.loads(candidate.read_text())
            return data if isinstance(data, dict) else {}
    return {}


def manifest_imports(manifest: dict[str, Any]) -> dict[str, str]:
    """Return the flat ``{specifier-key: import-value}`` map from a deno manifest.

    Reads ``imports`` and the legacy ``importMap`` inline ``imports`` block.
    """
    imports: dict[str, str] = {}
    block = manifest.get("imports")
    if isinstance(block, dict):
        for k, v in block.items():
            if isinstance(v, str):
                imports[str(k)] = v
    import_map = manifest.get("importMap")
    if isinstance(import_map, dict):
        inner = import_map.get("imports")
        if isinstance(inner, dict):
            for k, v in inner.items():
                if isinstance(v, str):
                    imports.setdefault(str(k), v)
    return imports
