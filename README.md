# codeartifact-shield

npm supply-chain hardening for projects that proxy through **AWS CodeArtifact**.

```
cas drift       fail on package.json / package-lock.json disagreement (direct + transitive)
cas sri patch   backfill the SRI integrity hashes CodeArtifact strips from npm metadata
cas sri verify  fail when SRI coverage drops below threshold
cas registry    fail when the lockfile resolves packages from a non-allowed host
```

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
match one of the `--allowed-host` substring patterns. Reads the lockfile
only — never `.npmrc` or machine-level npm config — because the lockfile is
what `npm ci` obeys at install time. The project must declare its allowed
registry hosts to the checker explicitly.

```bash
# Single allowed host:
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.'

# Multiple (CodeArtifact + a corporate mirror):
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.' \
  --allowed-host 'mirror.corp.example'

# Also fail on git-sourced deps (they bypass any registry contract):
cas registry ./frontend/package-lock.json \
  --allowed-host '.d.codeartifact.' \
  --fail-on-git
```

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

- name: Drift check
  run: cas drift ./frontend

- name: Integrity coverage
  run: cas sri verify ./frontend/package-lock.json --min-coverage 100

- name: Registry-leakage check
  run: cas registry ./frontend/package-lock.json --allowed-host '.d.codeartifact.'
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
