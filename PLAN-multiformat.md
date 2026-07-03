# Implementation Plan: pnpm, Deno, and Bun lockfile support for `cas`

Plan authored 2026-07-03. Three sequential phases (A: abstraction + pnpm, B: Deno, C: Bun); the test suite, ruff, and mypy must be green after each phase.

## 0. Current-state summary (verified against source)

- `src/codeartifact_shield/_lockfile.py` is the only loader: `load_lockfile()` (JSON, `lockfileVersion in (2,3)`, key validation), `is_installable_entry()` (requires `node_modules/` prefix, rejects `link`), `extract_package_name()` (npm alias handling). All gates import these three.
- Gate consumption of lockfile fields:
  - `registry.py` — `resolved` URL, `inBundle`, `link`, `version`; classifies git/tarball/file/registry; npm-specific `/-/` path heuristic; auto-detect histogram.
  - `scripts.py` — `hasInstallScript`.
  - `sri.py` — `integrity` (SRI string, strong-algo set), `inBundle` parent-anchoring via `node_modules/` key nesting; `patch_lockfile` writes JSON back with npm formatting and is CodeArtifact-API-bound.
  - `drift.py` — `package.json` scopes vs `packages` dict; transitive via per-entry `dependencies`/`optionalDependencies`/`peerDependencies`; nested-before-hoisted resolution over `node_modules/` keys; orphan BFS.
  - `audit.py`, `cooldown.py`, `trust.py` — iterate `(key, entry)` with `is_installable_entry` + `extract_package_name`, need only `(name, version)` pairs; audit hard-codes OSV ecosystem `npm`; cooldown queries npm-metadata `time` dicts.
  - `pins.py` — `package.json` only; no lockfile.
- CLI (`cli.py`): every lockfile command takes a `LOCKFILE` path argument; `drift`/`pin` take a directory. Structural errors surface via `_emit_load_error` catching `ValueError`.
- `pyproject.toml`: deps pinned `==` (`boto3`, `click`, `node-semver`); hatchling; mypy strict; ruff.
- Tests: per-gate `tests/test_*.py`, fixtures under `tests/fixtures/{npm,osv}/`, lockfiles mostly built inline via dict + `tmp_path` (see `tests/test_lockfile_validation.py::_write`, `tests/test_npm_workspaces.py`).
- `README.md` "npm only" non-goal (Scope section) — must be rewritten.

---

## 1. Lockfile abstraction layer

New package: `src/codeartifact_shield/lockfiles/`

### 1.1 `lockfiles/_model.py` — normalized model

```python
class LockFormat(str, Enum):
    NPM = "npm"; PNPM = "pnpm"; DENO = "deno"; BUN = "bun"

class Ecosystem(str, Enum):
    NPM = "npm"       # OSV/npm-registry addressable
    JSR = "jsr"       # jsr.io packages (deno.lock)
    REMOTE = "remote" # https:// module (deno.lock remote section)

class ResolvedKind(str, Enum):
    REGISTRY = "registry"   # https tarball from a registry (host known)
    REGISTRY_IMPLIED = "registry_implied"  # registry package, URL not recorded (pnpm/deno/bun default registry)
    GIT = "git"; TARBALL = "tarball"; FILE = "file"; LINK = "link"
    BUNDLED = "bundled"; NONE = "none"

@dataclass(frozen=True)
class LockEntry:
    key: str                      # format-native key (opaque label for reports)
    name: str                     # canonical package name; jsr stays "@scope/x" with ecosystem=JSR; remote: the URL
    version: str                  # "" for remote entries
    ecosystem: Ecosystem
    resolved: str | None          # URL when the lockfile records one
    resolved_kind: ResolvedKind
    integrity: str | None         # SRI string — Deno remote sha256 hex is converted to "sha256-<b64>" SRI form by the adapter
    has_install_script: bool | None   # None = format cannot represent this
    dependencies: dict[str, str]      # child name -> declared range/spec
    optional_dependencies: dict[str, str]
    peer_dependencies: dict[str, str]
    bundle_dependencies: tuple[str, ...]
    is_bundled: bool
    parent_key: str | None        # for bundle-anchoring (npm nesting); None elsewhere
    raw: Mapping[str, Any]        # format-native entry for gates needing extras

class Capability(Flag):
    RESOLVED_URLS = auto(); INTEGRITY = auto(); INSTALL_SCRIPTS = auto()
    DEP_GRAPH = auto(); DIRECT_DECLARATIONS = auto(); SRI_PATCH = auto()

@dataclass
class NormalizedLockfile:
    format: LockFormat
    format_version: str           # "3", "6.0", "9.0", "4", "1", ...
    path: Path
    entries: list[LockEntry]
    capabilities: Capability
    workspaces: dict[str, dict[str, dict[str, str]]]
    # workspace/importer path -> {"dependencies": {...}, "devDependencies": {...}, ...}
    # npm: derived from root ""; pnpm: importers; bun: workspaces; deno: deno.json imports (single "" importer)
    raw: Any
```

Also `class UnsupportedLockfileOperation(ValueError)` — subclassing `ValueError` means `cli.py`'s existing `except ValueError → _emit_load_error` paths produce the clean `[HIGH] FAIL — <message>` line with **zero CLI plumbing changes** for the unsupported cases.

### 1.2 `lockfiles/__init__.py` — detection + dispatch

- `detect_format(path: Path) -> LockFormat`:
  1. Filename: `package-lock.json`/`npm-shrinkwrap.json` → NPM; `pnpm-lock.yaml` → PNPM; `deno.lock` → DENO; `bun.lock` → BUN; `bun.lockb` → raise `UnsupportedLockfileOperation("bun.lockb is Bun's legacy binary lockfile; regenerate a text lockfile with `bun install --save-text-lockfile` (Bun >= 1.2)")`.
  2. Content sniff (unknown filename): first 4 KiB — YAML `lockfileVersion:` line → pnpm; JSON with integer `lockfileVersion` → npm; JSON with string `"version"` in `{"3","4","5"}` plus any of `npm`/`jsr`/`remote`/`specifiers` keys → deno; JSONC with `"lockfileVersion": 0|1` and tuple-valued `"packages"` → bun.
- `load_normalized(path: Path, fmt: LockFormat | None = None) -> NormalizedLockfile` — dispatches to adapters; `fmt=None` means auto-detect.
- `require_capability(lock, cap, command_name)` — raises `UnsupportedLockfileOperation` with a per-format explanation string from a central `SUPPORT_NOTES` table (single source of truth for the behavior matrix, reused by tests and README generation).

### 1.3 Adapters

- `lockfiles/npm.py` — wraps the existing logic. Move `_validate_package_keys`, `is_installable_entry`, `extract_package_name` here; **keep `_lockfile.py` as a re-export shim** (`from codeartifact_shield.lockfiles.npm import ...`) so `audit.py`/`cooldown.py`/`trust.py`/`scripts.py` imports and all existing tests keep working untouched in Phase A. The adapter builds `LockEntry` per installable entry, computes `resolved_kind` using the classification currently inlined in `registry.py` (git prefixes, `file:`/relative, `/-/` heuristic, `inBundle`), sets `parent_key` from `node_modules` nesting.
- `lockfiles/pnpm.py` — see section 2.
- `lockfiles/deno.py` — see section 3.
- `lockfiles/bun.py` — see section 4.
- `lockfiles/_yaml_safe.py` — thin wrapper over `yaml.safe_load` using a custom `Loader(yaml.SafeLoader)` whose `compose_node`/alias handling **rejects anchors and aliases outright** (pnpm never emits them; an alias bomb is the classic YAML DoS and `safe_load` does not protect against it), plus a hard input-size cap (default 100 MiB) and a "root must be a mapping" check.
- `lockfiles/_jsonc.py` — strict, hand-written JSONC pre-processor for `bun.lock` and `deno.jsonc`: strips `//` and `/* */` comments outside strings and trailing commas, then `json.loads`. ~80 lines, fully unit-tested. No dependency.

### 1.4 Gate refactor strategy (minimal churn)

- `scripts.py`, `audit.py`, `cooldown.py`, `trust.py`, `sri.verify`, `registry.py` each gain a `fmt: LockFormat | None = None` keyword and switch their iteration to `load_normalized(path, fmt).entries`. The npm adapter reproduces today's entry set exactly (same skip rules), so existing tests stay green.
- `registry.py`: host histogram and classification move to consuming `entry.resolved` / `entry.resolved_kind`. New bucket in `RegistryReport`: `registry_implied: list[str]` for entries where the format doesn't record a URL (pnpm/deno/bun default registry) — reported as INFO with an explanatory line, never counted as leaks.
- `sri.py::verify_lockfile` becomes format-generic: covered iff strong SRI on `entry.integrity`, or `is_bundled` with covered ancestor via `parent_key` (npm only sets `parent_key`).
- `drift.py`: add dispatcher `check_drift(project_dir, fmt, ...)`; the current `check_npm_drift` stays byte-identical; per-format drift functions are format-specific because they read manifests + native graphs (see matrix).

---

## 2. pnpm adapter (`lockfiles/pnpm.py`)

Parses `pnpm-lock.yaml`, `lockfileVersion: '6.0'` and `'9.0'` (reject others: `'5.x'` → "regenerate with pnpm >= 8").

- **Keys**: v6 `packages` keys are `/name@version` or `/name@version(peer-hash)`; v9 `packages` keys are `name@version(...)` (no leading slash) and the dep graph lives in `snapshots` (keys with peer suffixes) while `packages` holds `resolution`/metadata. Adapter strips `(...)` peer suffixes to derive `(name, version)`; keeps original key as `LockEntry.key`.
- **Per-entry fields**: `resolution.integrity` → `integrity`; `resolution.tarball` (non-default-registry) → `resolved`, kind `TARBALL`/`REGISTRY`; `resolution.repo`+`commit` → `GIT`; `resolution.directory` → `FILE`; otherwise `REGISTRY_IMPLIED` (pnpm does not record the registry URL for default-registry packages — the registry comes from `.npmrc`). `requiresBuild: true` (v6) → `has_install_script=True`; v6 without it → `False`; **v9 → `None`** (field removed from the lockfile in v9).
- **Graph**: v6 per-package `dependencies`/`optionalDependencies` (name → resolved version string); v9 from `snapshots`. `importers` section → `workspaces` (each importer's `dependencies: {name: {specifier, version}}` gives both declared spec and resolved version — exactly what drift needs).
- **Validation** (pnpm equivalent of `_validate_package_keys`): every package key must match `^/?(@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+@[^\s/\\]+(\(.*\))?$` after suffix handling; reject `..` segments, control chars, absolute-path importer keys, `..` in importer keys and in `resolution.directory`/`tarball` `file:` paths; reject non-https `resolution.tarball`.
- **Workspace settings**: read sibling `pnpm-workspace.yaml` when present (helper `read_pnpm_workspace_settings(dir)`) for `onlyBuiltDependencies` and `minimumReleaseAge` — used by `scripts` (v9) and surfaced by `cooldown` as an informational cross-check (`--min-age` vs project's own `minimumReleaseAge`, warn if cas is looser). Keep this read-only and optional.

**Gate behavior for pnpm**

| Command | Status | Behavior |
|---|---|---|
| `drift` | full | new `check_pnpm_drift`: direct via `importers[*].dependencies[name].specifier` vs `.version`; transitive via snapshot deps vs resolved versions (range check with nodesemver); orphan = packages/snapshots entries unreachable from importer roots |
| `sri verify` | full | `resolution.integrity` coverage; sha1-only treated as missing (same rule) |
| `sri patch` | **unsupported** | `UnsupportedLockfileOperation`: "sri patch backfills npm package-lock.json from CodeArtifact; pnpm lockfiles already carry integrity from the registry metadata — if yours are missing it, re-resolve with `pnpm install --lockfile-only`" |
| `registry` | partial | explicit `resolution.tarball`/git classified; default-registry entries → `registry_implied` INFO bucket; auto-detect runs only over entries with URLs; human output notes "pnpm lockfiles pin the registry via .npmrc, not per-entry" |
| `scripts` | v6 full / v9 partial | v6: `requiresBuild`. v9: error-free INFO path — report that lockfile carries no script info, then audit `onlyBuiltDependencies` from `pnpm-workspace.yaml`/`package.json#pnpm` against `--allow`; if neither file constrains builds and pnpm major can't be inferred, emit HIGH `install_script_policy_unknown` (fail closed) |
| `pin` | full | unchanged — reads `package.json` (works today) |
| `audit` | full | all entries `ecosystem=NPM` |
| `cooldown` | full | same npm registry publish-time lookups |
| `trust` | full | npm attestations by (name, version) |

---

## 3. Deno adapter (`lockfiles/deno.py`)

Parses `deno.lock` JSON, `"version"` in `{"3","4","5"}` (reject 1/2 → "regenerate with a modern Deno").

- **Sections**: v3: `packages.specifiers`, `packages.npm`, `packages.jsr`, `remote`, `redirects`. v4/v5: top-level `specifiers`, `npm`, `jsr`, `remote`, `redirects`, `workspace`. Adapter normalizes both shapes.
- **npm section**: key `name@version` (possibly with `_peerhash`) → `LockEntry(ecosystem=NPM, integrity=<sha512 SRI>, dependencies=<deps map>, resolved_kind=REGISTRY_IMPLIED)`.
- **jsr section**: key `@scope/name@version` → `ecosystem=JSR`, `integrity` (sha256 SRI as recorded), deps map.
- **remote section**: `url -> sha256-hex` → one `LockEntry` per URL: `name=url`, `version=""`, `ecosystem=REMOTE`, `resolved=url`, `resolved_kind=REGISTRY` (host = URL host), `integrity="sha256-" + b64(hex)` — normalizing to SRI lets `sri verify` count them uniformly.
- **redirects**: validated (https-only on both sides) and surfaced to the registry gate: a redirect whose target host differs from source host is a MEDIUM `redirect_cross_host` finding.
- **Manifest**: `read_deno_manifest(dir)` parses `deno.json`/`deno.jsonc` (reuse `_jsonc.py`) `imports` / `importMap` for `npm:`/`jsr:`/`https:` specifiers — feeds `drift` and the new deno mode of `pin`.
- **Validation**: npm/jsr keys must match name@version grammar (no `..`, no control chars); every `remote`/`redirects` URL must parse, be `https:`, host non-empty; sha256 values must be 64 lowercase hex chars; reject null bytes anywhere.

**Gate behavior for Deno**

| Command | Status | Behavior |
|---|---|---|
| `drift` | partial (direct only) | `check_deno_drift`: `deno.json` `imports` `npm:pkg@spec` / `jsr:@s/p@spec` vs lockfile `specifiers` map and resolved versions; orphan detection over npm+jsr dep graph seeded from specifiers. No transitive-range check for remote URLs (exact by construction) |
| `sri verify` | full | npm sha512 + jsr sha256 + remote sha256 all count (sha256 already in the strong set) |
| `sri patch` | unsupported | clear error: CodeArtifact/npm-format-specific |
| `registry` | partial | full host gating for `remote` entries + cross-host redirect findings; npm/jsr entries → `registry_implied` INFO |
| `scripts` | n/a — clean by design | Deno does not run npm lifecycle scripts unless `deno install --allow-scripts`; command exits 0 with an INFO note listing npm deps (so the surface is visible), never fails |
| `pin` | new mode | when `PROJECT_DIR` has `deno.json[c]` and no `package.json`, audit `imports`: `npm:x@^1` / `jsr:@s/x@~1` ranges and un-versioned `https://` imports flagged HIGH; versioned https imports OK |
| `audit` | partial | npm entries → OSV ecosystem `npm` (full). jsr packages: OSV has no JSR ecosystem — emit per-package INFO `unaudited_jsr` (count surfaced in report; `--fail-on-unaudited-jsr` flag optional, default off). remote URLs: skipped with an aggregate INFO |
| `cooldown` | partial→full | npm entries: unchanged. jsr entries: new `JsrEndpoint` in `_registry.py` querying `https://api.jsr.io/scopes/{scope}/packages/{name}/versions` (`createdAt` per version). Remote URLs: no publish time exists — aggregate INFO `cooldown_remote_skipped` |
| `trust` | npm entries only | jsr/remote skipped with INFO |

---

## 4. Bun adapter (`lockfiles/bun.py`)

Parses `bun.lock` (JSONC via `_jsonc.py`), `"lockfileVersion"` 0 or 1. `bun.lockb` → the clean error from `detect_format` (decision: **do not** parse the binary format; the official migration is `bun install --save-text-lockfile`).

- **Shape**: `workspaces` map (`""` = root; each has `name` + dependency scopes) → `workspaces`; `packages` map: install-path-ish key → tuple `["name@version-or-spec", <registry string, "" = default>, {deps/peer/optional/os/cpu/bundled meta}, "sha512-..."]`; git/github/tarball/workspace entries have variant tuple shapes (shorter tuples, `"name@github:..."` style first element).
- Adapter parses the first element into `(name, version, source-kind)`: `name@1.2.3` → registry; `name@git+...#commit` → GIT; `name@https://...tgz` → TARBALL; `name@workspace:...` → LINK; `name@file:...` → FILE. Second element non-empty → `resolved` (registry URL) with kind REGISTRY, else `REGISTRY_IMPLIED`. Fourth element → `integrity`. Meta `bundled: true` → `is_bundled`.
- **Install scripts**: `bun.lock` does not record `hasInstallScript`. Bun only executes dependency lifecycle scripts for packages in `trustedDependencies` (plus a built-in default allowlist). Gate = audit `trustedDependencies` from the root workspace entry / `package.json` against `--allow`: each trusted package not in `--allow` is a HIGH `install_script` finding (name-level; version resolved from the lockfile).
- **Validation**: package keys and first-tuple-element names validated with the same name grammar; reject `..`/control chars/absolute paths in keys and in `file:`/`workspace:` paths; integrity strings must be well-formed SRI; registry URLs https-only.

**Gate behavior for Bun**

| Command | Status | Behavior |
|---|---|---|
| `drift` | full (direct + orphan), transitive partial | direct: root/workspace declared scopes vs resolved versions; transitive: per-entry deps map vs resolved (specs are ranges → nodesemver); orphan BFS over packages map |
| `sri verify` | full | tuple integrity element; git/workspace/file entries excluded from denominator like npm link entries |
| `sri patch` | unsupported | clear error |
| `registry` | partial | entries with explicit registry URL fully gated; default-registry → `registry_implied` INFO; git/tarball classified as today |
| `scripts` | partial (by design) | `trustedDependencies` audit as above; note in output that Bun blocks all other dep scripts |
| `pin` | full | `package.json` — works today |
| `audit` / `cooldown` / `trust` | full | all npm ecosystem |

---

## 5. CLI surface changes (`cli.py`)

1. Every command that takes `LOCKFILE` (`sri verify`, `registry`, `scripts`, `audit`, `cooldown`, `trust`) gains:
   ```python
   @click.option("--format", "lockfile_format",
       type=click.Choice(["auto", "npm", "pnpm", "deno", "bun"]), default="auto",
       envvar="CAS_LOCKFILE_FORMAT", show_default=True)
   ```
   passed through as `fmt` to the gate function. `sri patch` gains it too but immediately errors for non-npm (consistent UX, discoverable message).
2. `drift` and `pin` (directory arguments) gain the same flag; on `auto` they probe in fixed order `package-lock.json`, `pnpm-lock.yaml`, `bun.lock`, `deno.lock` and **error if more than one is present** ("multiple lockfiles found: ...; disambiguate with --format"). `pin` with `--format deno` (or auto-detected `deno.json` and no `package.json`) uses the deno-imports mode.
3. JSON reports gain `"lockfile_format": "<fmt>"` and `"format_version": "<v>"` fields on all commands (additive, back-compat).
4. Unsupported combinations exit 1 via the existing `ValueError → _emit_load_error` path — no new plumbing; message text comes from the central `SUPPORT_NOTES` table.

---

## 6. pyproject changes

- Add `"PyYAML==6.0.2"` to `dependencies` (verify the exact latest release at implementation time and pin it). **Recommendation: dependency, not vendoring.** Rationale: the project already carries three pinned deps (boto3, click, node-semver) — "zero-dep" is not actually the current posture, "pinned-dep" is. A hand-rolled YAML-subset parser is the worse security trade: pnpm-lock.yaml uses multi-line nested mappings, quoted keys with `@`/`(`/`)`, and folded strings, and a subtle mis-parse in a security gate is a bypass. Mitigate PyYAML's known risks in `_yaml_safe.py` instead (SafeLoader + alias/anchor rejection + size cap).
- Add `types-PyYAML==<pin>` to `dev` extras for strict mypy.
- No new deps for Deno (stdlib JSON) or Bun (`_jsonc.py` in-house).

---

## 7. Test plan

Fixture layout (all small, hand-crafted, committed):

```
tests/fixtures/pnpm/
  lock-v6-basic.yaml            # 4-5 packages, one requiresBuild, one git resolution, one tarball resolution
  lock-v9-basic.yaml            # snapshots split, peer-suffix keys
  lock-v9-workspace.yaml        # importers: ".", "packages/a"; workspace: protocol dep
  pnpm-workspace.yaml           # onlyBuiltDependencies + minimumReleaseAge
  lock-tampered-traversal.yaml  # key "/..@1.0.0/evil", importer "../../etc"
  lock-alias-bomb.yaml          # YAML anchors/aliases → must be rejected
  lock-v5-old.yaml              # rejected version
tests/fixtures/deno/
  lock-v3.json  lock-v4.json  lock-v5.json      # npm + jsr + remote + redirects
  lock-tampered.json            # http:// remote URL, bad hex hash, name with ".."
  deno.json                     # imports with npm:/jsr:/https: specifiers (for drift/pin)
tests/fixtures/bun/
  bun-basic.lock                # JSONC with comments/trailing commas, registry + git + tarball + workspace entries, trustedDependencies
  bun-workspace.lock
  bun-tampered.lock             # traversal in key, sha1-only integrity, http registry URL
```

New test files:

- `tests/test_lockfile_detect.py` — filename detection, content sniffing, `bun.lockb` error, multiple-lockfiles-in-dir error, `--format` override winning over sniffing.
- `tests/test_lockfiles_model.py` — npm adapter parity: for the existing inline npm lockfile dicts, `load_normalized().entries` matches `is_installable_entry` iteration exactly (guard against Phase-A regressions).
- `tests/test_pnpm_lockfile.py` — v6/v9 parsing, key→(name,version) incl. peer suffixes and scoped names, requiresBuild, importers, all tampered/rejection cases, alias-bomb rejection.
- `tests/test_pnpm_gates.py` — drift (clean/direct/transitive/orphan), sri verify coverage, registry partial buckets, scripts v6 vs v9 (+onlyBuiltDependencies), audit/cooldown name-version extraction (mock HTTP as `test_cooldown.py` does).
- `tests/test_deno_lockfile.py`, `tests/test_deno_gates.py` — incl. jsr `unaudited_jsr`, remote host gating, cross-host redirect finding, JsrEndpoint cooldown (mocked), pin-on-deno.json.
- `tests/test_bun_lockfile.py` (incl. `_jsonc.py` unit tests: comments in strings, nested block comments rejected, trailing commas), `tests/test_bun_gates.py` — incl. trustedDependencies scripts gate.
- Extend `tests/test_cli.py` — `--format` flag on each command, unsupported-op exit 1 with `[HIGH] FAIL`, `lockfile_format` in `--json` payloads.

Acceptance for every phase: `pytest`, `ruff check`, `mypy` all clean.

---

## 8. README updates

- Replace scope bullet "npm only" with a **format support matrix** (commands × npm/pnpm/deno/bun: full / partial / unsupported, one footnote per partial cell — pull wording from `SUPPORT_NOTES`).
- Document `--format` / `CAS_LOCKFILE_FORMAT`, the multi-lockfile disambiguation rule, `bun.lockb` guidance, pnpm v9 scripts semantics, jsr audit gap, and the new JSON fields.
- Update the intro command list and "Lockfile structure validation" section (per-format validation rules).
- Only document shipped formats each phase.

---

## 9. Phased breakdown (three sequential implementers; suite green after each phase)

### Phase A — abstraction layer + pnpm
1. **Create** `src/codeartifact_shield/lockfiles/{__init__.py,_model.py,npm.py,pnpm.py,_yaml_safe.py}`.
2. **Modify** `_lockfile.py` → re-export shim over `lockfiles/npm.py` (public names unchanged).
3. **Modify** `registry.py`, `scripts.py`, `sri.py` (verify path only), `audit.py`, `cooldown.py`, `trust.py`: iterate `load_normalized(...).entries`; add `fmt` kwarg; `registry.py` gains `registry_implied` bucket; `sri patch` gains explicit format check.
4. **Modify** `drift.py`: add `check_drift` dispatcher + `check_pnpm_drift`.
5. **Modify** `cli.py`: `--format` on all commands; drift/pin auto-probe; JSON fields.
6. **Modify** `pyproject.toml`: PyYAML + types-PyYAML pins.
7. **Add tests**: `test_lockfile_detect.py`, `test_lockfiles_model.py`, `test_pnpm_lockfile.py`, `test_pnpm_gates.py`; extend `test_cli.py`; fixtures `tests/fixtures/pnpm/`.
8. **README**: pnpm rows of the matrix.

Acceptance: all pre-existing tests pass unmodified (ideally zero mechanical import updates); `cas <cmd> pnpm-lock.yaml` works per matrix; `cas registry deno.lock` (unknown format in Phase A) fails with clean `[HIGH] FAIL`, not a traceback.

### Phase B — Deno
1. **Create** `lockfiles/deno.py`, `lockfiles/_jsonc.py` (needed for `deno.jsonc`; Bun reuses it in C).
2. **Modify** `lockfiles/__init__.py` (detection + SUPPORT_NOTES rows), `drift.py` (`check_deno_drift`), `pins.py` (deno-imports mode), `audit.py` (`unaudited_jsr` reporting, ecosystem filter), `cooldown.py` + `_registry.py` (`JsrEndpoint`), `registry.py` (remote host gating + redirect finding).
3. **Add tests/fixtures** per section 7; `_jsonc` unit tests land here.
4. **README**: Deno rows + jsr/remote caveats.

Acceptance: Phase A suite untouched and green; deno v3/v4/v5 fixtures parse; tampered fixture rejected; `cas audit deno.lock` audits npm deps and reports jsr INFO without failing.

### Phase C — Bun
1. **Create** `lockfiles/bun.py`.
2. **Modify** `lockfiles/__init__.py` (bun detection incl. `bun.lockb` error), `scripts.py` (trustedDependencies mode), `drift.py` (`check_bun_drift`).
3. **Add tests/fixtures** per section 7.
4. **README**: Bun rows, `bun.lockb` migration note; remove any remaining "npm only" language; final full matrix.

Acceptance: full suite green; `cas scripts bun.lock` fails on an un-allowed trustedDependencies entry; `cas registry bun.lockb` prints the save-text-lockfile guidance and exits 1.

---

## 10. Open questions — with recommended resolutions

1. **PyYAML vs vendored parser** → PyYAML pinned, with anchor/alias-rejecting SafeLoader subclass and size cap (section 6). Vendoring a YAML parser is a larger attack surface than the dependency.
2. **pnpm v9 scripts gate semantics** → fail-closed `install_script_policy_unknown` HIGH when no `onlyBuiltDependencies` policy is discoverable; INFO when policy exists and matches `--allow`. Verify during implementation exactly which pnpm versions dropped `requiresBuild` (believed: gone in lockfileVersion 9.0) and whether `pnpm-workspace.yaml` vs `package.json#pnpm.onlyBuiltDependencies` precedence matters — encode whichever pnpm 10 documents.
3. **jsr cooldown endpoint** → implement `JsrEndpoint` against `api.jsr.io` (versions carry `createdAt`); if the API shape differs at implementation time, fall back to skipping jsr with aggregate INFO rather than HIGH-failing every jsr package.
4. **`sri patch` for pnpm behind CodeArtifact** → out of scope (writing pnpm YAML back faithfully is risky and pnpm keeps integrity through CA's metadata in practice); documented as a non-goal with the regenerate command. Revisit only on user demand.
5. **Bun tuple-shape drift across Bun versions** → the text format is young; adapter must treat unknown tuple lengths/extra fields as tolerated-if-parseable, and unknown `lockfileVersion` as a hard reject. Pin fixtures to shapes emitted by Bun 1.2.x and verify against a real `bun install --save-text-lockfile` output during Phase C.
6. **Registry gate value for URL-less formats** → keep the command runnable (partial) rather than unsupported: git/tarball/explicit-URL detection still catches the exotic-source vectors; the INFO `registry_implied` line makes the limitation explicit.
