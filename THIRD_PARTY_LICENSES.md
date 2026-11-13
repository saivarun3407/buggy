# Third-Party Licenses

Buggy vendors external knowledge bases as git submodules under
`skills/_corpus/` and references additional resources at runtime. Each
upstream's license terms are preserved alongside the source in the
submodule itself; this file is a summary attribution.

## Vendored (git submodule)

### PayloadsAllTheThings
- **Path**: `skills/_corpus/payloads/`
- **Upstream**: https://github.com/swisskyrepo/PayloadsAllTheThings
- **License**: MIT
- **Copyright**: © Swissky and contributors
- **Use**: Reference payload catalog cited by `skills/exploit/web/*` leaves
  for additional bypass variants and encoding tricks.

The complete MIT license text ships in `skills/_corpus/payloads/LICENSE`.

## Bundled catalog data

### OWASP Application Security Verification Standard 5.0.0
- **Path**: `packages/buggy/buggy/sandbox_kernel/OWASP_Application_Security_Verification_Standard_5.0.0_en.json`
- **Upstream**: https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release
- **Pinned commit**: `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`
- **License**: CC-BY-SA-4.0 — https://creativecommons.org/licenses/by-sa/4.0/
- **Attribution**: OWASP ASVS project and contributors
- **Use**: Unmodified English requirement data for catalog-backed defensive assessment planning and review. Requirement text retains its upstream license; no OWASP endorsement or certification is implied.

The packaged `sandbox_kernel/ASVS-NOTICE.txt` preserves attribution, provenance,
and the upstream license reference alongside the catalog.

## Referenced (not vendored)

### h4cker
- **Upstream**: https://github.com/The-Art-of-Hacking/h4cker
- **License**: MIT
- **Copyright**: © Omar Santos and contributors
- **Use**: Referenced via `skills/_corpus/h4cker_manifest.yaml` (when present)
  — high-value subtrees cloned shallow on demand, not vendored due to size.

### Awesome-Hacking
- **Upstream**: https://github.com/Hack-with-Github/Awesome-Hacking
- **License**: CC0 1.0 Universal (public domain dedication)
- **Use**: Link index flattened into `skills/_corpus/awesome_index.json`
  (when present) for recon-agent learning-resource lookups.

## Buggy's own license

This repository's own license terms are in `LICENSE` at the repo root.
Vendoring third-party content does not relicense any part of this repo
— the upstream MIT and CC0 licenses remain attached to their respective
submodule contents.

## Updating

```bash
# Pull all submodules to upstream HEAD
git submodule update --remote --recursive

# Or just the payload corpus
git submodule update --remote skills/_corpus/payloads

# Refresh the drift manifest
python3 scripts/ingest_corpus.py
```

The `scripts/ingest_corpus.py --check` command exits non-zero on drift
(new vuln classes, stale hashes, missing leaf mappings); wire into CI
to keep the corpus pinned and the leaf coverage current.
