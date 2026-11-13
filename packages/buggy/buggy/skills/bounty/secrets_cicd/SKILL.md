---
name: secrets-cicd-exposure
description: Hunt leaked credentials and exposed build/deploy infrastructure — secrets in JS bundles and source maps, exposed .git/.env/backup files, and CI/CD misconfigurations. Validates each candidate secret is live and maps its in-scope blast radius before reporting.
metadata:
  subdomain: supply-chain
  when_to_use: "secrets leaked credentials api keys tokens javascript bundle source map exposed .git .env backup file git-dumper trufflehog gitleaks cicd pipeline ci config disclosure"
  mitre_attack: T1552.001, T1552.004, T1078
---

# Secrets & CI/CD Exposure Playbook

You hunt what the *target* has exposed externally (complements the
supply-chain operator's dependency focus). The decisive step is
**validation** — an unverified key is noise.

## 1. Lane A — Client-side secrets

- Fetch JS bundles and **source maps** (`.map` reverses minified bundles
  to readable source with hardcoded endpoints/keys — always check).
- Run `scan_secrets` over fetched assets; extract endpoints and keys.

## 2. Lane B — Exposed VCS / config

- Probe `/.git/`, `/.env`, `/.svn/`, and config/backup files (`.bak`,
  `~`, `.swp`, `.orig`).
- Exposed `.git`: dump it (`git-dumper`) and mine **history** — the
  working tree is often scrubbed but history is not.

## 3. Lane C — CI/CD exposure

Exposed CI configs, build logs, artifact stores, and public pipeline
output that leak tokens or internal infrastructure.

## 4. Lane D — Validate & scope (the important step)

- Confirm each candidate secret is **live** using the narrowest
  read-only call (e.g. an identity/`whoami` endpoint). Never use a
  discovered credential to access, modify, or exfiltrate data beyond the
  minimal proof, and never touch out-of-scope systems with it.
- Map the secret's blast radius to in-scope assets/impact.

## 5. Don't report public-by-design keys

Distinguish a real leak from a key meant to be public: Stripe `pk_live`
(publishable) vs `sk_live` (secret), Google browser API keys, and
Firebase web configs are usually public — don't report them without a
concrete demonstrated abuse.

## 6. Proof & report

`bounty_scope_check` the asset and class, then `report_hackerone` /
`report_bugcrowd_csv`. `h1_search` for disclosed secret-leak chains.
