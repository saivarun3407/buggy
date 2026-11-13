# GitHub Actions Integration

> Run Buggy security scans on every pull request, upload SARIF to
> Code Scanning, gate merges by severity.

## The composite action

Buggy ships a composite action at
[`.github/actions/buggy-scan`](../../.github/actions/buggy-scan)
that orchestrates: stack boot → scan → SARIF emit → Code Scanning upload
→ stack teardown.

## Minimal workflow

```yaml
name: buggy
on:
  pull_request:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with: { fetch-depth: 0 }
      - uses: PurpleAILAB/Buggy/.github/actions/buggy-scan@main
        with:
          fail-on: high
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `target` | `./` | What to scan. Path, URL, or git URL. |
| `scan-mode` | `quick` | `quick` / `standard` / `deep`. |
| `scope-mode` | `diff` | `full` (whole target) or `diff` (changed files only). |
| `diff-base` | `origin/main` | Git ref for diff-scope. |
| `fail-on` | `high` | Threshold severity for non-zero exit. |
| `sarif-output` | `buggy.sarif` | Where to write SARIF. |
| `upload-sarif` | `true` | Upload to GitHub Code Scanning. |
| `instruction` | `""` | Free-form scope/focus note. |
| `instruction-file` | `""` | Path to a RoE/scope file. |
| `langgraph-url` | `""` | Remote LangGraph URL; empty → boot local stack. |
| `buggy-version` | `latest` | Container tag when booting local stack. |

## Outputs

| Output | Notes |
|---|---|
| `sarif-path` | File path of the produced SARIF. |
| `finding-count` | Total findings across all SARIF runs. |
| `exit-code` | `0` (ok) / `1` (findings ≥ threshold) / `2` (config) / `3` (internal). |

## Secrets required

At minimum one model-provider API key in repo secrets (the same set
supported by `buggy onboard`):

- `ANTHROPIC_API_KEY` *(recommended for the orchestrator tier)*
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`
- `DEEPSEEK_API_KEY`
- `OPENROUTER_API_KEY`
- `NVIDIA_API_KEY`

Set `BUGGY_AUTH_PRIORITY` (also as an env var) to control fallback ordering.

## PR comment integration

Combine with `github/codeql-action/upload-sarif@v3` (the action handles
this for you) and findings will appear:

1. In the **Code Scanning alerts** tab of the repository.
2. As annotated diffs on the pull request when source line locations are
   in the SARIF (which they are when the orchestrator's
   `Patcher` agent produces patches with file:line references).

## Diff-scoped scans

When `scope-mode: diff` and `fetch-depth: 0` on checkout, Buggy
runs `git diff --name-only "<diff-base>...HEAD"` and limits the scan to
those files. This drops PR-time scan times from minutes to tens of seconds
for typical PRs. Falls back to full scope when the git diff fails (no
network, shallow clone, etc.) with a warning in the workflow log.

## Example workflows

- **PR gate** (recommended): `quick` mode, `diff` scope, `fail-on: high`.
- **Nightly full scan**: `standard` mode, `full` scope, `fail-on: high`,
  scheduled with `on: schedule: - cron: "0 3 * * *"`.
- **Pre-release deep audit**: `deep` mode, `full` scope, `fail-on: medium`,
  triggered manually via `workflow_dispatch`.
