# codeartifact-shield

npm supply-chain hardening for projects that proxy through **AWS CodeArtifact**
(or use any internal registry, or stay on public npm — every command works for
all three).

```
cas drift       fail on package.json / package-lock.json disagreement
                (direct + transitive + orphan-entry detection)
cas sri patch   backfill the SRI integrity hashes CodeArtifact strips
                from npm-format metadata responses
cas sri verify  fail when integrity coverage drops below threshold
                (sha256/sha384/sha512 required; sha1 rejected)
cas registry    fail when the lockfile resolves packages from a host
                that isn't the project's primary registry (label-anchored
                allowlist or auto-detect)
cas scripts     fail when any lockfile entry will execute preinstall /
                install / postinstall scripts at install time
cas pin         fail when any direct package.json declaration is a
                range (^1.2.3, ~1.2.3, >=1.0), dist-tag (latest, *),
                tarball URL, file:/link: path, or git ref that isn't a
                full 40-char commit SHA
```

Every command:
* exits **nonzero** on a finding, so it drops straight into a CI gate;
* supports `--json` for SARIF / GitHub Code Scanning / dashboard ingestion;
* prefixes finding lines with `[CRITICAL]` / `[HIGH]` / `[MEDIUM]` / `[LOW]` /
  `[INFO]` so reviewers can triage when several gates fail in the same run;
* refuses to operate on a structurally-suspect lockfile (path-traversal in
  package keys, malformed grammar, unsupported v1 format) with a clean
  `[HIGH] FAIL` line — never a Python traceback.

---

## Severity ladder

| Severity | Type                                  | Meaning                                                        |
| -------- | ------------------------------------- | -------------------------------------------------------------- |
| CRITICAL | `registry_leak`, insecure scheme on a `resolved` URL | Active route to untrusted bytes at next `npm install`   |
| HIGH     | `direct_drift`, `transitive_drift`, `orphan_entry`, `install_script`, `sri_coverage_below_threshold`, `lockfile_load_error` | Tampering signature, pending RCE, or missing integrity  |
| MEDIUM   | `git_sourced`                         | Bypasses the registry contract (content-pinned to commit)      |
| LOW      | `unresolved_phantom`                  | Suspicious-but-explainable lockfile entry                      |
| INFO     | `bundled`, `install_script_allowed`   | Context only, not a failure                                    |

## `--json` output schema

```json
{
  "command": "registry",
  "lockfile": "/path/to/package-lock.json",
  "clean": false,
  "by_host": {"acme-1.d.codeartifact.us-east-1.amazonaws.com": 2790, "registry.npmjs.org": 1},
  "mixed_registries": true,
  "detected_primary_hosts": ["acme-1.d.codeartifact.us-east-1.amazonaws.com"],
  "auto_detect": true,
  "findings": [
    {"severity": "CRITICAL", "type": "registry_leak", "lockfile_key": "node_modules/sneaky", "host": "registry.npmjs.org"}
  ],
  "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
}
```

Exit code is still `1` on any failure-tier finding; `--json` only changes
the output format. All human banner text in `--json` mode is routed to
stderr so stdout remains a clean JSON document for piping into `jq` or
SARIF converters.

## Why this exists

AWS CodeArtifact's npm proxy is a great supply-chain mitigation in theory:
pin every install through one repository, gate ingestion with internal
policy, audit who pulled what. In practice three gaps slip past it:

1. **CodeArtifact strips `dist.integrity`.** Its npm-format metadata
   response omits the integrity field, so every `package-lock.json` entry
   written through the proxy comes out without an SRI hash. `npm ci` then
   version-pins without content-pinning — it installs whatever bytes the
   registry currently returns.
2. **The lockfile silently drifts from `package.json`.** A bad merge, a
   partial regeneration, or deliberate tampering can leave declared and
   resolved versions inconsistent. The threat is small bumps you'd never
   notice in review.
3. **Public-registry leakage.** It only takes one stray `resolved` URL
   pointing at `registry.npmjs.org` for the CodeArtifact contract to
   break — and that one entry is exactly where a dependency-confusion
   attack would land.

`cas` closes all three plus a fourth — lifecycle scripts — in a CLI you
drop into CI.

## Install

The package isn't on PyPI. Install directly from GitHub, **pinned to a
specific commit SHA**:

```bash
pip install "git+https://github.com/TableCheck-Labs/codeartifact-shield.git@<sha>"
```

Floating refs (`@main`, `@v0.4.0` as a tag) are technically supported but
should not be used in CI: tags can be force-pushed, branches change over
time. The threat model is "the trust root of your supply-chain scanner is
itself supply-chain-controllable" — so always pin to a full SHA. Find the
SHA matching a tag at the [releases page](https://github.com/TableCheck-Labs/codeartifact-shield/releases).

For development:

```bash
git clone https://github.com/TableCheck-Labs/codeartifact-shield.git
cd codeartifact-shield
pip install -e ".[dev]"
```

Requires Python 3.10+. The entry points `cas` and `codeartifact-shield`
are equivalent.

## Quickstart

```bash
# Direct + transitive + orphan drift check.
cas drift ./frontend

# Auto-detect primary registry — works for CA, public-npm, or mixed repos.
cas registry ./frontend/package-lock.json

# Or be explicit (strict): every entry must be on this CA host.
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com'

# 100% integrity coverage required.
cas sri verify ./frontend/package-lock.json --min-coverage 100

# Every install-script-running dep must be on the allowlist.
cas scripts ./frontend/package-lock.json \
  --allow esbuild --allow fsevents --allow @parcel/watcher
```

Each command exits nonzero on a finding.

---

## Top-level options

```
cas [OPTIONS] COMMAND [ARGS]...
```

| Flag                   | Behavior                                           |
| ---------------------- | -------------------------------------------------- |
| `-V`, `--version`      | Print cas version and exit.                        |
| `-v`, `--verbose`      | Verbose logging to stderr (DEBUG level).           |
| `-h`, `--help`         | Show top-level help.                               |

---

## `cas drift`

Compare `package.json` declarations to `package-lock.json` resolutions
and report inconsistencies — both legitimate drift and the more subtle
signatures of lockfile tampering.

```
cas drift [OPTIONS] FRONTEND_DIR
```

`FRONTEND_DIR` is the project root containing both `package.json` and
`package-lock.json`.

Three categories of finding:

1. **Direct drift.** Every dependency declared in `package.json`
   (`dependencies`, `devDependencies`, `optionalDependencies`) must
   resolve to a matching entry in the lockfile. Defaults to literal
   equality — catches policy violations in projects that use
   `save-exact=true` in their `.npmrc`.
2. **Transitive drift.** Every lockfile entry's own `dependencies` /
   `optionalDependencies` declarations are walked; each child's resolved
   version is checked against its parent's declared SemVer range.
   Resolution mirrors npm's nested-before-hoisted lookup. Catches
   lockfile tampering that touches only a transitive — the parent's
   declared range no longer matches the resolved child. Respects
   `optionalDependencies` (missing is fine) and `peerDependencies`
   (missing is fine — consumer may provide).
3. **Orphan entries.** Installable lockfile entries not reachable from
   any `package.json` declaration via BFS over the dep graph
   (`dependencies` / `peerDependencies` / `optionalDependencies` /
   `bundleDependencies`). The most plausible footprint of a malicious
   extra package inserted into the lockfile.

| Flag                | Behavior                                                                                                              |
| ------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `--ranges`          | Treat `package.json` declarations as SemVer ranges instead of requiring literal equality. Use when the project doesn't pin exact versions. |
| `--no-transitive`   | Skip transitive drift detection (only check direct deps). Also disables orphan-entry detection, since orphan detection walks the transitive graph. |
| `--json`            | Machine-readable JSON on stdout instead of human text.                                                                |
| `-h`, `--help`      | Show help.                                                                                                            |

```bash
cas drift ./frontend                # direct strict + transitive + orphans
cas drift ./frontend --ranges       # direct as range + transitive + orphans
cas drift ./frontend --no-transitive  # direct strict only
cas drift ./frontend --json
```

Fix message includes the exact regen command:
`npm install --package-lock-only --include=optional --force`. The `--force`
matters — without it, npm prunes foreign-platform optional deps from the
lockfile (npm/cli#4828, #7961) and the Docker build breaks at install time.

---

## `cas sri patch`

Walk `package-lock.json` and inject `dist.integrity` into every entry
that's missing it (or has only weak sha1), using CodeArtifact's
`ListPackageVersionAssets` API to pull each package's stored SHA-512.

```
cas sri patch [OPTIONS] LOCKFILE
```

The hash CodeArtifact returns matches what the public npm registry
publishes as `dist.integrity` for the same tarball — verified by
cross-reference against multiple popular packages.

**Bundled entries** (`inBundle: true`) are skipped: the standalone hash
CodeArtifact returns for those describes the registry publication, not
the bytes the parent author may have modified before bundling. The
parent's integrity hash is the legitimate trust root for bundled
content (and `cas sri verify` checks that anchoring).

**Weak-algorithm upgrade.** Any entry whose only integrity value is
`sha1-…` gets overwritten with `sha512-…` from CodeArtifact. SHA-1 was
removed from the modern SRI spec.

| Flag                | Behavior                                                                                            |
| ------------------- | --------------------------------------------------------------------------------------------------- |
| `--domain TEXT`     | **Required.** CodeArtifact domain. Env: `CAS_DOMAIN`.                                               |
| `--repository TEXT` | **Required.** CodeArtifact repository within the domain. Env: `CAS_REPOSITORY`.                     |
| `--dry-run`         | Report what would be patched without writing the lockfile. Still makes the CodeArtifact API calls. |
| `--json`            | Machine-readable JSON on stdout instead of human text.                                              |
| `-h`, `--help`      | Show help.                                                                                          |

```bash
cas sri patch ./frontend/package-lock.json \
  --domain my-domain \
  --repository my-repo

cas sri patch ./frontend/package-lock.json \
  --domain my-domain --repository my-repo --dry-run

# Via env vars (cleaner in CI):
export CAS_DOMAIN=my-domain
export CAS_REPOSITORY=my-repo
cas sri patch ./frontend/package-lock.json
```

Uses your AWS credential chain (env, profile, IRSA, etc.). Needs the IAM
permission `codeartifact:ListPackageVersionAssets` on the target repository.

Exit codes: `0` on success, `1` on configuration errors,
`2` if there were AWS API errors or packages unreachable in
CodeArtifact (e.g., a dep that's never been ingested).

---

## `cas sri verify`

Pure-lockfile read — no AWS calls — that reports SRI coverage and fails
below threshold. Pair with `cas sri patch` so the lockfile is always
integrity-complete before merge.

```
cas sri verify [OPTIONS] LOCKFILE
```

**Coverage semantics:** an entry counts as covered iff (1) it has its own
`integrity` field using sha256/sha384/sha512, OR (2) it's a bundled entry
(`inBundle: true`) whose **parent** is itself covered. Parent-anchoring is
recursive — a bundle chain anchors to the topmost non-bundled ancestor's
hash.

Why parent-anchoring is sound: npm at install time re-derives the bundle
relationship from the parent's `package.json` (which lives inside the
parent's tarball, which is integrity-verified). An attacker cannot forge
`inBundle: true` to escape gating without also arranging a parent whose
hash anchors the real `bundleDependencies` list — and forging that hash
requires breaking SHA-512.

**SHA-1 is treated as missing.** Entries whose only integrity value is
`sha1-…` do not count toward coverage. Combined SRI strings
(`"sha1-... sha512-..."`) count as covered as long as at least one
algorithm is in the strong set (sha256/sha384/sha512).

| Flag                            | Behavior                                                                |
| ------------------------------- | ----------------------------------------------------------------------- |
| `--min-coverage FLOAT`          | Minimum percent of entries that must be covered. Range `0–100`. Default `100.0`. |
| `--json`                        | Machine-readable JSON on stdout instead of human text.                  |
| `-h`, `--help`                  | Show help.                                                              |

```bash
cas sri verify ./frontend/package-lock.json --min-coverage 100
cas sri verify ./frontend/package-lock.json --min-coverage 99.9 --json
```

Refuses to operate on a v1 lockfile (would otherwise report 0/0 = 100%
and silently pass).

---

## `cas registry`

Walk every `resolved` URL in the lockfile and fail when:
* the host doesn't match the allowed-host list (or, in auto-detect, isn't
  one of the project's primary registries), OR
* the URL uses a non-HTTPS scheme.

```
cas registry [OPTIONS] LOCKFILE
```

Reads the lockfile only — never `.npmrc` or machine-level npm config —
because the lockfile is what `npm ci` actually obeys at install time.

### Two modes

**Strict mode** — supply one or more `--allowed-host`:

Every entry's resolved host must equal or end with `.` + one of the
patterns. Patterns are **label-anchored**: a host must equal the pattern
or end with `.` + the pattern. Substring matching is intentionally not
supported because it lets attacker-controlled hosts like
`evil.d.codeartifact.attacker.com` pass an allowlist of `.d.codeartifact.`.

```bash
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com'

cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com' \
  --allowed-host 'mirror.corp.example'
```

Use strict mode in CI for a project with a known, declared registry policy.

**Auto-detect mode** — omit `--allowed-host`:

cas reads the lockfile's `resolved` URL distribution and treats every host
carrying ≥20% of the top host's entry count as primary. A
100%-CodeArtifact lockfile, a 100%-public-npm lockfile, a CodeArtifact +
corporate-mirror mix — all three pass cleanly without per-project
configuration. One-off anomalies (the dependency-confusion attack
signature) still fall below the threshold and are flagged as CRITICAL.

```bash
# Sweep mixed repos without per-project config:
for lf in */package-lock.json; do cas registry "$lf" --json; done
```

The detected primaries are surfaced in human output (`Auto-detected
primary registries: …`) and in JSON (`detected_primary_hosts` field).

| Flag                       | Behavior                                                                                                    |
| -------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `--allowed-host TEXT`      | Hostname suffix (case-insensitive, label-anchored). Repeatable. Use the FULL suffix. **Omit entirely** to enter auto-detect mode. Env: `CAS_ALLOWED_HOSTS` (whitespace-separated). |
| `--fail-on-git`            | Also fail (exit 1) on any entry resolved directly from git. By default git-sourced entries are reported as MEDIUM but don't fail the run. |
| `--json`                   | Machine-readable JSON on stdout instead of human text.                                                      |
| `-h`, `--help`             | Show help.                                                                                                  |

### Entry classification

Each lockfile entry lands in exactly one bucket:

| Bucket                 | Severity | Meaning                                                          |
| ---------------------- | -------- | ---------------------------------------------------------------- |
| `registry_leak`        | CRITICAL | Resolved from a host that isn't allowed (or is primary in auto). |
| `git_sourced`          | MEDIUM   | `git+ssh:` / `github:` / similar. Bypasses any registry.         |
| `unresolved_phantom`   | LOW      | Has a `version` but no `resolved` and is not `inBundle: true`. Usually dedupe artefact, occasionally a tampering signature. |
| `bundled`              | INFO     | Marked `inBundle: true`. Bytes come from the parent's tarball.   |
| File / workspace       | —        | `file:` paths or `link: true` symlinks. Not registry-classified. |
| (insecure scheme)      | CRITICAL | http://, ftp://, ws:// etc. — rejected regardless of host.       |

A `mixed registries` warning appears whenever more than one distinct host
shows up — useful signal that the install path isn't homogeneous, even
when all hosts are allowed.

---

## `cas scripts`

Fail on any lockfile entry whose `hasInstallScript: true` — meaning npm
will execute that package's `preinstall`, `install`, or `postinstall`
hook when `npm install` runs. This is the highest-blast-radius
unhandled vector in the npm ecosystem: SRI binds bytes to hashes but
doesn't prevent a maintainer from deliberately shipping a malicious
lifecycle hook.

```
cas scripts [OPTIONS] LOCKFILE
```

| Flag              | Behavior                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------- |
| `--allow TEXT`    | Package name (including scope, e.g. `@parcel/watcher`) permitted to run install scripts. Repeatable. Env: `CAS_ALLOWED_SCRIPTS` (whitespace-separated). |
| `--json`          | Machine-readable JSON on stdout instead of human text.                                            |
| `-h`, `--help`    | Show help.                                                                                        |

```bash
# Fail on any unaudited script-runner:
cas scripts ./frontend/package-lock.json

# Allowlist build-essentials that legitimately need to compile platform binaries:
cas scripts ./frontend/package-lock.json \
  --allow esbuild \
  --allow fsevents \
  --allow @parcel/watcher \
  --allow @swc/core
```

Allowlist matching is by **full package name including scope**.
`watcher` does NOT match `@parcel/watcher` — preventing typo-squat
substitution attacks against the allowlist itself. Matching is
case-insensitive.

To eliminate lifecycle scripts entirely, install with
`npm ci --ignore-scripts` and find replacements for any script-running
deps.

---

## `cas pin`

Fail when any direct dep declaration in `package.json` isn't pinned to
an exact version. The lockfile + SRI gates protect the bytes you've
already approved; this gate protects what happens **next time someone
runs `npm install`** (without `--frozen-lockfile`) or accepts a Renovate
PR — that's when caret/tilde ranges silently widen the trust set to
whatever version was published most recently.

```
cas pin [OPTIONS] PROJECT_DIR
```

`PROJECT_DIR` must contain a `package.json` at its root. A missing
`package.json` exits `1` with a `[HIGH] FAIL — no package.json in
<dir>` finding.

| Flag                | Behavior                                                                                                                                                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--allow TEXT`      | Package name (including scope, e.g. `@scope/name`) permitted to stay unpinned. Repeatable. Env: `CAS_ALLOWED_UNPINNED` (whitespace-separated). Use sparingly — every entry is a hole in the reproducibility guarantee.        |
| `--scope CHOICE`    | Limit the audit to specific `package.json` buckets. Choices: `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`. Repeatable. Default: the first three (peer excluded by convention).               |
| `--include-peer`    | Also audit `peerDependencies`. Equivalent to adding `--scope peerDependencies` to the default set.                                                                                                                            |
| `--json`            | Machine-readable JSON on stdout instead of human text.                                                                                                                                                                        |
| `-h`, `--help`      | Show help.                                                                                                                                                                                                                    |

### What counts as pinned

| Form                                              | Verdict | Notes                                                                       |
| ------------------------------------------------- | ------- | --------------------------------------------------------------------------- |
| `1.2.3`                                           | pinned  | Exact SemVer 2.0.0 — the only acceptable plain-string form.                 |
| `1.2.3-rc.1`, `1.2.3+build.7`                     | pinned  | Prerelease and build metadata are allowed (still exact).                    |
| `workspace:*`, `workspace:1.2.3`, `workspace:^`   | pinned  | Workspace protocol — resolved intra-monorepo, exempt.                       |
| `npm:lodash@4.17.21`                              | pinned  | npm alias — the target spec is checked recursively (must itself be pinned). |
| `git+https://github.com/x/y.git#<40-char SHA>`    | pinned  | Git URL with a full commit SHA fragment. Short SHAs and branch/tag refs are rejected. |
| `github:user/repo#<40-char SHA>`, `user/repo#<40-char SHA>` | pinned | GitHub shorthand with a full commit SHA fragment.                  |
| `^1.2.3`, `~1.2.3`, `>=1.0`, `1.2.x`, `1.x`, `*`  | **flagged** as `range`     | Any SemVer range operator.                          |
| `latest`, dist-tags                               | **flagged** as `dist_tag`  | npm dist-tags resolve to whatever was published last. |
| `file:../local-pkg`                               | **flagged** as `file`      | Local path — not content-addressed.                   |
| `link:../symlinked`                               | **flagged** as `link`      | Local symlink — not content-addressed.                |
| `https://example.com/x-1.0.0.tgz`                 | **flagged** as `tarball`   | Tarball URLs aren't content-addressed; the bytes at the URL can change. |
| `git+...#main`, `git+...#abc1234` (short SHA)     | **flagged** as `git_ref`   | Branch/tag fragments and short SHAs aren't pinned.    |
| Anything else                                     | **flagged** as `unknown`   | Unrecognized spec — treated as unsafe.                |

### Severity

Every flagged declaration is reported at **`HIGH`** severity (it's a
direct hole in the project's reproducibility guarantee). Allowlisted
declarations are surfaced at `INFO` so reviewers can see what the
allowlist is letting through.

### Examples

```bash
# Strict audit — every direct dep must be exact-pinned:
cas pin .

# Audit only production deps (skip devDependencies):
cas pin . --scope dependencies --scope optionalDependencies

# Also audit peerDependencies (uncommon — peers are idiomatically ranges):
cas pin . --include-peer

# Allowlist a known-stable internal tool:
cas pin . --allow @internal/cli-tool

# Machine-readable for CI dashboards:
cas pin . --json | jq '.findings[] | select(.severity == "HIGH")'
```

### JSON schema

```json
{
  "command": "pin",
  "project_dir": "/path/to/project",
  "clean": false,
  "scopes": ["dependencies", "devDependencies", "optionalDependencies"],
  "total_checked": 124,
  "findings": [
    {
      "severity": "HIGH",
      "type": "unpinned",
      "scope": "dependencies",
      "package": "react",
      "declared": "^18.0.0",
      "kind": "range"
    },
    {
      "severity": "INFO",
      "type": "unpinned_allowed",
      "scope": "devDependencies",
      "package": "@internal/cli-tool",
      "declared": "^2.0.0",
      "kind": "range"
    }
  ],
  "severity_counts": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "INFO": 1}
}
```

---

## Lockfile structure validation

Every command refuses to operate on a structurally-suspect lockfile
before any other check runs. Specifically, the loader rejects:

* Lockfile version 1 (no per-entry `resolved` URLs; obsoletes the whole
  premise of SRI gating).
* Package keys containing `..` (path traversal).
* Package keys starting with `/` or `\` (absolute paths).
* Package keys containing null bytes or control characters.
* Package keys with empty path segments (`node_modules//foo`).

All of these emit `[HIGH] FAIL — <reason>` and exit `1` cleanly — never
a Python traceback. The whole loader is shared across subcommands, so
the check is consistent everywhere.

---

## Environment variables

| Variable                  | Used by              | Effect                                                      |
| ------------------------- | -------------------- | ----------------------------------------------------------- |
| `CAS_DOMAIN`              | `cas sri patch`      | Default for `--domain`.                                     |
| `CAS_REPOSITORY`          | `cas sri patch`      | Default for `--repository`.                                 |
| `CAS_ALLOWED_HOSTS`       | `cas registry`       | Whitespace-separated default for `--allowed-host`.          |
| `CAS_ALLOWED_SCRIPTS`     | `cas scripts`        | Whitespace-separated default for `--allow`.                 |
| `CAS_ALLOWED_UNPINNED`    | `cas pin`            | Whitespace-separated default for `--allow`.                 |
| Standard `AWS_*`          | `cas sri patch`      | Picked up by boto3 for CodeArtifact API auth.               |

---

## Wiring into CI

A complete gate looks like this (Semaphore CI):

```yaml
- name: Supply Chain Checks
  task:
    agent:
      machine: { type: s1-supernode-x86-small }
      containers:
        - name: main
          image: 'public.ecr.aws/docker/library/python:3.12'
    jobs:
      - name: Drift
        commands:
          - source ./.semaphore/commands/install-cas.sh
          - cas drift .
      - name: SRI Coverage
        commands:
          - source ./.semaphore/commands/install-cas.sh
          - cas sri patch ./package-lock.json --domain my-domain --repository my-repo
          - cas sri verify ./package-lock.json --min-coverage 100
      - name: Registry Leakage
        commands:
          - source ./.semaphore/commands/install-cas.sh
          - cas registry ./package-lock.json --allowed-host '.d.codeartifact.<region>.amazonaws.com'
      - name: Lifecycle Scripts
        commands:
          - source ./.semaphore/commands/install-cas.sh
          - cas scripts ./package-lock.json --allow esbuild --allow fsevents
      - name: Pin Policy
        commands:
          - source ./.semaphore/commands/install-cas.sh
          - cas pin .
```

`install-cas.sh` should pin cas by **literal SHA**, not via a
`${CAS_REF:-…}` fallback that lets a hostile env var redirect pip. Example:

```bash
#!/usr/bin/env bash
set -e
# Hard-coded — not configurable via env. The version check below is
# operational sanity, not a security control.
readonly _CAS_INSTALL_REF="git+https://github.com/TableCheck-Labs/codeartifact-shield.git@<full-sha>"
readonly _CAS_EXPECTED_VERSION="0.4.0"
if ! command -v cas >/dev/null 2>&1; then
  pip install --quiet "$_CAS_INSTALL_REF"
fi
actual=$(cas --version | awk '{print $NF}')
[ "$actual" = "$_CAS_EXPECTED_VERSION" ] || { echo "[FATAL] cas version mismatch"; exit 1; }
```

---

## Exit codes

| Command       | `0`                                  | `1`                                                                       | `2`                                                       |
| ------------- | ------------------------------------ | ------------------------------------------------------------------------- | --------------------------------------------------------- |
| `drift`       | no drift, no orphans                 | drift detected (direct/transitive/orphan) or unsupported lockfile         | —                                                         |
| `sri patch`   | all entries reconciled               | configuration / lockfile-load error                                       | AWS API errors **or** packages missing from CodeArtifact  |
| `sri verify`  | coverage ≥ threshold                 | coverage below threshold or unsupported lockfile                          | —                                                         |
| `registry`    | every entry on an allowed host       | leaks detected (or `--fail-on-git` with any git-sourced) or load error    | —                                                         |
| `scripts`     | every script-runner is allowlisted   | unallowlisted script-running entry found or load error                    | —                                                         |
| `pin`         | every checked direct dep is pinned   | unpinned direct dep found, or `package.json` missing                      | —                                                         |

---

## Scope and non-goals

* **npm only.** Built for the CodeArtifact-vs-npm gap. pip / Maven /
  NuGet / Cargo have their own integrity stories.
* **Lockfile v2 and v3.** Older v1 lockfiles use a different structure and
  aren't supported — every subcommand errors out so a v1 lockfile can't
  accidentally pass a 100% gate. Regenerate the lockfile with Node 16+.
* **No `.npmrc` parsing.** The lockfile is the source of truth for what
  `npm ci` will fetch.
* **No deep dependency review.** `cas` doesn't fetch package contents or
  audit source code. It validates the *shape* of the supply chain
  (where bytes come from, whether they're integrity-pinned, whether they
  run code at install time).

---

## License

MIT
