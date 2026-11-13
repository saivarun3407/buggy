# Quick Start — run a hunt in one command

The fastest path from zero to a running hunt. If you want the full tour
(providers, OAuth, dashboard), see [Getting Started](getting-started.md).

## 1. Install

**macOS / Linux / WSL2**
```bash
curl -fsSL https://buggy.red/install | bash
```
**Windows (PowerShell)**
```powershell
irm https://buggy.red/install.ps1 | iex
```

## 2. Configure once

```bash
buggy onboard
```
Pick a provider and paste one API key (or a subscription login). That's the
only setup. Config is saved to `~/.buggy/.env`.

> You need Docker + Docker Compose v2 installed and running. Everything else
> runs in containers.

## 3. Hunt

Point it at a target you're authorized to test — one command brings the
whole stack up (first run is ~75s cold) and runs the engagement:

```bash
buggy hunt example.com
```

More targets and wider scope, still one command:

```bash
# Several assets at once
buggy hunt api.example.com app.example.com

# Include subdomains explicitly (scope is never widened for you)
buggy hunt example.com --include-subdomains

# A URL, a custom in-scope pattern, an exclusion, and a focus note
buggy hunt https://example.com \
    --scope "*.example.com" \
    --exclude "admin.example.com" \
    --instruction "focus on auth and access control"

# Write the scope/plan bundle and stop — review before anything runs
buggy hunt example.com --plan-only
```

Scope defaults to **exactly the targets you name** — subdomains and extra
hosts are only added when you ask with `--include-subdomains` / `--scope`.
The scope is written to an enforced Rules-of-Engagement file
(`plan/roe.json`) before any packet leaves the wire.

## 3b. Bug bounty (HackerOne / Bugcrowd)

For platform programs, let the Scout pull the scope straight from the
program so you never hand-type it:

```bash
# Export your platform credentials first
export HACKERONE_API_USERNAME=... HACKERONE_API_TOKEN=...
export BUGCROWD_API_TOKEN=...

buggy bounty                     # both platforms
buggy bounty --platform hackerone
```

It authenticates, lists the programs you can access, lets you pick one,
ingests that program's scope + exclusions + reporting policy into the
enforced RoE, and then hunts — no manual scope entry.

## 4. Review results

Findings and evidence land under:

```
~/.buggy/workspace/<engagement>/
  findings/FIND-*.md        # one file per verified finding
  audit/roe-decisions.jsonl # every scope decision, for your records
```

Open the full terminal UI to watch or resume a run, and the attack-graph
sidebar:

```bash
buggy            # interactive UI + engagement picker
```

Verify the audit ledger anytime:

```bash
buggy-cli audit verify --engagement <engagement>
```

## 5. Stop

```bash
buggy stop       # stop services, keep data
```

---

### Headless / CI

`hunt` and `bounty` are also available without the launcher, against an
already-running stack, via the Python CLI:

```bash
buggy-cli hunt example.com --non-interactive
buggy-cli bounty --print-kickoff        # inspect the Scout kickoff
```

> **Authorization**: only run Buggy against systems you own or have
> explicit written permission to test. See the disclaimer in the README.
