# codeartifact-shield

npm supply-chain hardening for projects that proxy through **AWS CodeArtifact**.

```
cas drift       fail on package.json / package-lock.json disagreement (direct + transitive + orphans)
cas sri patch   backfill the SRI integrity hashes CodeArtifact strips from npm metadata
cas sri verify  fail when SRI coverage drops below threshold (sha256+ required; sha1 rejected)
cas registry    fail when the lockfile resolves packages from a non-allowed host (label-anchored)
cas scripts     fail when any lockfile entry will execute lifecycle scripts at install time
```

## What changed in v0.3.0

- **Severity badges in human output.** Every finding line gets a
  `[CRITICAL]` / `[HIGH]` / `[MEDIUM]` / `[LOW]` / `[INFO]` prefix so
  reviewers can triage when multiple gates fail in the same CI run.
  Severities reflect blast radius (see table below), not finding count.
- **`--json` flag on every subcommand.** Emits a stable, parseable schema
  on stdout for downstream consumption (SARIF conversion, GitHub Code
  Scanning, custom dashboards). Human-readable output continues to be
  available without the flag.

### Severity ladder

| Severity | Type                                  | Meaning                                                    |
| -------- | ------------------------------------- | ---------------------------------------------------------- |
| CRITICAL | `registry_leak`, `insecure_scheme`    | Active route to untrusted bytes at next `npm install`      |
| HIGH     | `direct_drift`, `transitive_drift`, `orphan_entry`, `install_script`, `sri_coverage_below_threshold` | Tampering signature, pending RCE, or missing integrity    |
| MEDIUM   | `git_sourced`                         | Bypasses the registry contract (content-pinned to commit)  |
| LOW      | `unresolved_phantom`                  | Suspicious-but-explainable lockfile entry                  |
| INFO     | `bundled`, `install_script_allowed`   | Context only, not a failure                                |

### `--json` output schema

```json
{
  "command": "registry",
  "lockfile": "/path/to/package-lock.json",
  "clean": false,
  "findings": [
    {"severity": "CRITICAL", "type": "registry_leak", "lockfile_key": "...", "host": "..."}
  ],
  "severity_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
}
```

Exit code is still 1 on any failure-tier finding; `--json` does not change
gating, only the output format. All human-readable lines (banner text,
warnings) are routed to stderr in `--json` mode so stdout remains a clean
JSON document for piping into `jq` / SARIF converters.

## What changed in v0.2.0

Security-driven changes; **some are breaking**. Review before upgrading.

- **`cas registry` is label-anchored, not substring.** A pattern like
  `.d.codeartifact.` used to substring-match anything containing those
  characters — including attacker-controlled hosts of the form
  `evil.d.codeartifact.attacker.com`. Patterns now match at hostname-label
  boundaries: a host must *equal* the pattern or *end with* `.` + the pattern.
  Update existing config from `.d.codeartifact.` to the full suffix
  `.d.codeartifact.<region>.amazonaws.com`.
- **`cas registry` requires HTTPS.** A `resolved` URL using `http://`,
  `ftp://`, or any non-https scheme is treated as leaked, even if the host
  is in the allowlist.
- **`cas sri verify` rejects sha1 integrity.** SHA-1 is collision-broken and
  was removed from the modern SRI spec. Lockfile entries whose only integrity
  is `sha1-…` count as missing; `cas sri patch` overwrites them with sha512
  from CodeArtifact.
- **`cas sri verify` correctly handles `bundleDependencies`.** Bundled
  entries are now counted in the denominator AND credited to their parent's
  integrity hash. A 100% threshold is again honestly reachable; an
  orphan-bundled entry (parent has no integrity) fails closed.
- **`cas drift` detects orphan lockfile entries** that no `package.json`
  (root or transitive) declares — the most plausible footprint of a
  malicious lockfile insertion.
- **`cas scripts` is new.** Fails the build on any lockfile entry whose
  `hasInstallScript: true` (i.e., will run `preinstall`/`install`/
  `postinstall` at `npm install` time). Allowlist the build-essentials
  you need via `--allow <package>`.
- **Lockfile path-traversal validation.** Every subcommand refuses to
  operate on a lockfile whose package keys contain `..`, leading `/`,
  null bytes, or other malformed path segments.

## Why this exists

AWS CodeArtifact's npm proxy is a great supply-chain mitigation in theory: pin every
install through one repository, gate ingestion with internal policy, audit who pulled
what. In practice three gaps slip past it:

1. **CodeArtifact strips `dist.integrity`.** Its npm-format metadata response
   omits the integrity field, so every `package-lock.json` entry written through
   the proxy comes out without an SRI hash. `npm ci` then version-pins without
   content-pinning — it installs whatever bytes the registry currently returns.
2. **The lockfile silently drifts from `package.json`.** A bad merge, a partial
   regeneration, or deliberate tampering can leave declared and resolved
   versions inconsistent. The threat is small bumps you'd never notice in
   review.
3. **Public-registry leakage.** It only takes one stray `resolved` URL pointing
   at `registry.npmjs.org` for the CodeArtifact contract to break — and that
   one entry is exactly where a dependency-confusion attack would land.

`codeartifact-shield` closes all three in a CLI you drop into CI.

## Install

The package isn't on PyPI yet. Install directly from GitHub:

```bash
pip install "git+https://github.com/alexandernicholson/codeartifact-shield.git"
```

…or clone and install editable for development:

```bash
git clone https://github.com/alexandernicholson/codeartifact-shield.git
cd codeartifact-shield
pip install -e ".[dev]"
```

Requires Python 3.10+. The two entry points `cas` and `codeartifact-shield`
are equivalent.

## Quickstart

For a typical setup (CodeArtifact as the only intended registry):

```bash
# 1. Make sure declared and resolved versions agree, including transitives.
cas drift ./frontend

# 2. Make sure every lockfile entry has an SRI hash.
cas sri verify ./frontend/package-lock.json --min-coverage 100

# 3. Make sure no entry was resolved from a non-CodeArtifact host.
cas registry ./frontend/package-lock.json --allowed-host '.d.codeartifact.'
```

Each command exits nonzero on a finding, so it's directly usable as a CI gate.

## Commands

### `cas drift`

Compares `package.json` declarations to `package-lock.json` resolutions.
Checks two things:

* **Direct deps.** Every dependency in `package.json` resolves to a matching
  entry in the lockfile. Defaults to literal-equality (catches policy
  violations in projects that use `save-exact=true`); pass `--ranges` to relax
  to SemVer-range satisfaction (`^1.2.3` accepts `1.2.5`).
* **Transitive deps.** Every lockfile entry's own dependency declarations are
  walked, and each child's resolved version is checked against the parent's
  declared range. This catches lockfile tampering that touches only a
  transitive — the parent's declared range no longer matches the resolved
  child.

```bash
cas drift ./frontend                # direct (strict) + transitive (range)
cas drift ./frontend --ranges       # direct (range) + transitive (range)
cas drift ./frontend --no-transitive
```

Resolution mirrors npm's nested-before-hoisted lookup, and respects
`optionalDependencies` (missing is fine) and `peerDependencies` (missing is
fine — the consumer may provide them).

### `cas sri patch`

Walks `package-lock.json` and injects `dist.integrity` into every entry that
doesn't have one, using CodeArtifact's `ListPackageVersionAssets` API to pull
the SHA-512 each package stores. The hash CodeArtifact returns matches what
the public npm registry publishes as `dist.integrity` for the same tarball
— verified by cross-reference across several popular packages.

```bash
cas sri patch ./frontend/package-lock.json \
  --domain my-domain \
  --repository my-repo

# Don't write the file, just report what would change:
cas sri patch ./frontend/package-lock.json \
  --domain my-domain --repository my-repo --dry-run
```

Uses your AWS credential chain (env, profile, IRSA, etc.). Needs
`codeartifact:ListPackageVersionAssets` on the target repository.

### `cas sri verify`

Pure-lockfile read — no AWS calls — that reports SRI coverage and fails
below threshold. Pair with `sri patch` so the lockfile is always
integrity-complete before merge.

```bash
cas sri verify ./frontend/package-lock.json --min-coverage 100
```

### `cas registry`

Walks every `resolved` URL in the lockfile and fails when any host doesn't
match one of the `--allowed-host` patterns or when any URL uses a non-HTTPS
scheme. Reads the lockfile only — never `.npmrc` or machine-level npm
config — because the lockfile is what `npm ci` obeys at install time. The
project must declare its allowed registry hosts to the checker explicitly.

`--allowed-host` is **label-anchored**: the host must equal the pattern or
end with `.` + the pattern. Substring matching is intentionally not
supported because it lets attacker-controlled hosts like
`evil.d.codeartifact.attacker.com` pass an allowlist of `.d.codeartifact.`.

```bash
# Single allowed host (note the FULL suffix — region + amazonaws.com):
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com'

# Multiple (CodeArtifact + a corporate mirror):
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com' \
  --allowed-host 'mirror.corp.example'

# Also fail on git-sourced deps (they bypass any registry contract):
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com' \
  --fail-on-git
```

`http://` and other non-HTTPS schemes are always rejected, regardless of host.

### `cas scripts`

Lifecycle-script audit. Fails the build on any lockfile entry whose
`hasInstallScript: true` — meaning npm will execute that package's
`preinstall`, `install`, or `postinstall` hook at `npm install` time.
This is the highest-blast-radius unhandled vector in the npm ecosystem:
SRI binds bytes to hashes but doesn't prevent a maintainer from
deliberately shipping a malicious lifecycle hook.

```bash
# Fail on any unaudited script-runner:
cas scripts ./frontend/package-lock.json

# Allowlist the build-essentials that legitimately need to compile
# platform binaries at install time:
cas scripts ./frontend/package-lock.json \
  --allow esbuild \
  --allow fsevents \
  --allow @parcel/watcher
```

Allowlist entries are matched by full package name (including scope).
`watcher` does NOT match `@parcel/watcher` — preventing typo-squat
substitution attacks against the allowlist itself.

To eliminate lifecycle scripts entirely, install with
`npm ci --ignore-scripts` and find replacements for any script-running deps.

### Registry classification

Classifies each entry into one of:
* **Allowed host** — counted in the per-host distribution.
* **Leaked** — resolved from a host that doesn't match any allowed pattern.
* **Git-sourced** — `git+ssh:` / `github:` etc., bypasses any registry.
* **File / workspace** — `file:` paths or `link: true` symlinks.
* **Unresolved** — deduped phantom entries with no `resolved` field.

A `mixed registries` warning appears whenever more than one distinct host
shows up, even if both are allowed — useful signal that the install path
isn't homogeneous.

## Wiring into CI

A complete gate looks like:

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }

- name: Install codeartifact-shield
  run: pip install "git+https://github.com/alexandernicholson/codeartifact-shield.git"

- name: Drift + orphan check
  run: cas drift ./frontend

- name: Integrity coverage
  run: cas sri verify ./frontend/package-lock.json --min-coverage 100

- name: Registry-leakage check
  run: cas registry ./frontend/package-lock.json --allowed-host '.d.codeartifact.ap-northeast-1.amazonaws.com'

- name: Lifecycle-script audit
  run: cas scripts ./frontend/package-lock.json --allow esbuild --allow fsevents
```

If you regenerate the lockfile in CI (e.g. after `npm install`), patch
integrity hashes before verifying:

```yaml
- run: |
    cas sri patch ./frontend/package-lock.json \
      --domain "$CAS_DOMAIN" --repository "$CAS_REPOSITORY"
    cas sri verify ./frontend/package-lock.json --min-coverage 100
  env:
    CAS_DOMAIN: ${{ vars.CAS_DOMAIN }}
    CAS_REPOSITORY: ${{ vars.CAS_REPOSITORY }}
    # standard AWS_* creds from your assume-role step also need to be present
```

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `drift` | no drift | drift detected (direct or transitive) | — |
| `sri patch` | all entries reconciled | config error | API errors or packages missing from CodeArtifact |
| `sri verify` | coverage ≥ threshold | coverage below threshold or unsupported lockfile | — |
| `registry` | every entry resolved from an allowed host | leaked entries (or `--fail-on-git` and any git-sourced) | — |

## Scope and non-goals

* **npm only.** This tool exists for the specific CodeArtifact-vs-npm gap.
  pip / Maven / NuGet have their own integrity stories.
* **Lockfile v2 and v3.** Older v1 lockfiles use a different structure and
  aren't supported — `sri verify` and `registry` will error out so a v1
  lockfile can't accidentally pass a 100% gate. Regenerate with Node 16+.
* **No `.npmrc` parsing.** The lockfile is the source of truth. A project
  that wants its registry policy checked must pass the allowed hosts to the
  tool explicitly.

## License

MIT
