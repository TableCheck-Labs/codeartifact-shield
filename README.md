# codeartifact-shield

npm supply-chain hardening for projects that proxy through **AWS CodeArtifact**.

```
pip install codeartifact-shield
```

Two problems, two commands.

## 1. CodeArtifact strips `dist.integrity` — `cas sri patch` puts it back

AWS CodeArtifact's npm proxy does **not** return the `dist.integrity` field in
its npm-registry metadata. When the npm client resolves dependencies through
CodeArtifact, every entry in `package-lock.json` is written **without** an
integrity hash. `npm ci` will then happily install whatever bytes the registry
currently returns at the resolved URL — version-pinning without
content-pinning.

CodeArtifact *does* store and expose SHA-512 for every package asset, just not
in the npm-format response. `cas sri patch` calls
`ListPackageVersionAssets` for each lockfile entry, converts the stored
SHA-512 to SRI format, and writes the hashes back into the lockfile.

```bash
cas sri patch package-lock.json \
  --domain my-domain \
  --repository my-repo

# Verify in CI that nothing is missing:
cas sri verify package-lock.json --min-coverage 100
```

After patching, `npm ci` validates every tarball against the SRI hash and
fails fast on any mismatch — the integrity guarantee you'd have gotten from
the public registry, restored.

**Hash correctness**: the SHA-512 CodeArtifact stores is the SHA-512 of the
exact tarball bytes — cross-checked against the public npm registry's
published `dist.integrity` for several popular packages and matched bit-for-bit.

## 2. `package.json` vs lockfile drift — `cas drift`

Pinning exact versions in `package.json` only helps if the lockfile agrees.
Drift is the exact inconsistency a quiet supply-chain attack would create by
editing the lockfile alone.

```bash
cas drift ./frontend
```

Fails (exit 1) with a per-dependency report if `package.json` and
`package-lock.json` disagree on direct-dep versions.

## Wiring it into CI

```yaml
- name: SRI integrity gate
  run: |
    cas drift ./frontend
    cas sri verify ./frontend/package-lock.json --min-coverage 100
```

If you're regenerating the lockfile in CI (e.g. after `npm install`), patch
before verifying:

```yaml
- run: cas sri patch ./frontend/package-lock.json \
         --domain $CAS_DOMAIN --repository $CAS_REPOSITORY
- run: cas sri verify ./frontend/package-lock.json --min-coverage 100
```

`cas sri patch` uses your AWS credential chain (env, profile, IRSA, etc.) — it
just needs `codeartifact:ListPackageVersionAssets` on the repository.

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `sri patch` | all entries reconciled | config error | API errors or packages missing from CodeArtifact |
| `sri verify` | coverage ≥ threshold | coverage below threshold | — |
| `drift` | no drift | drift detected | — |

## Scope

- **npm only.** This tool exists for the specific CodeArtifact-vs-npm gap.
  pip / Maven / NuGet have their own integrity stories.
- **Lockfile v2 and v3.** Older v1 lockfiles use a different structure.
- **No detection-evasion features.** All findings are surfaced; nothing is
  silently filtered.

## License

MIT
