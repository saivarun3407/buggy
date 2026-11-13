# CI/CD Integration

> Run Buggy as part of any CI/CD pipeline. Produce SARIF v2.1.0 results,
> upload to GitHub Code Scanning, and gate merges on severity thresholds.

Buggy ships a **headless scan CLI** (`python -m buggy.cli scan`)
and a **composite GitHub Action** (`.github/actions/buggy-scan`)
designed for a pull-request gating pattern,
with Buggy's engagement / OPPLAN / RoE discipline preserved.

## Quick start — GitHub Actions

`.github/workflows/security-scan.yml`:

```yaml
name: "Buggy security scan"

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write   # required for Code Scanning upload

jobs:
  buggy:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0     # required for diff-scope resolution

      - uses: PurpleAILAB/Buggy/.github/actions/buggy-scan@main
        with:
          target: "./"
          scan-mode: "quick"
          scope-mode: "diff"
          diff-base: "origin/${{ github.base_ref || 'main' }}"
          fail-on: "high"
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

The action:

1. Installs the Buggy Python CLI from PyPI.
2. Either uses a remote LangGraph URL you provide (`langgraph-url` input)
   or boots a local Buggy stack via `docker compose` for the
   duration of the scan and tears it down on exit.
3. Runs `buggy-cli scan` against the changed files only
   (`scope-mode: diff`) for a fast PR gate.
4. Emits SARIF v2.1.0 at `buggy.sarif`.
5. Uploads the SARIF to GitHub Code Scanning (visible under
   *Security → Code scanning alerts*).
6. Fails the workflow when findings hit `fail-on` severity or higher.

## Scan modes

| Mode | Default timeout | Reasoning effort | Use case |
|---|---|---|---|
| `quick` | 10 min | medium | PR-time gates, diff-scoped reviews |
| `standard` | 60 min | high | Pre-merge full source scans, nightly builds |
| `deep` | 4 hr | high (with dynamic analysis when supported) | Pre-release deep audits |

## Severity gating

`--fail-on <level>` controls the exit code:

| Flag value | Exit non-zero when… |
|---|---|
| `critical` | only `critical` findings present |
| `high` (default) | any `high` or `critical` |
| `medium` | any `medium` or above |
| `low` | any finding at all |
| `none` | never fail — pure reporting mode |

Internal exit codes:

- `0` — clean (no findings ≥ threshold).
- `1` — findings at or above threshold.
- `2` — config / invocation error (bad flags, missing target, missing
  `langgraph-sdk`).
- `3` — internal scan error (LangGraph unreachable, timeout, etc.).

## Other CI systems

The action wraps `python -m buggy.cli scan` which works on any
runner with Python 3.13+ and `pip install buggy`. For GitLab CI:

```yaml
buggy:
  image: python:3.13
  stage: security
  script:
    - pip install buggy buggy-core langgraph-sdk
    - python -m buggy.cli scan
        --target ./
        --scan-mode quick
        --scope-mode diff
        --diff-base "$CI_MERGE_REQUEST_DIFF_BASE_SHA"
        --sarif-output buggy.sarif
        --fail-on high
        --non-interactive
  artifacts:
    paths: [buggy.sarif]
    reports:
      sast: buggy.sarif
```

For Jenkins (declarative):

```groovy
stage('Buggy') {
  steps {
    sh '''
      pip install buggy buggy-core langgraph-sdk
      python -m buggy.cli scan \
        --target ./ \
        --scan-mode quick \
        --scope-mode diff \
        --diff-base "$CHANGE_TARGET" \
        --sarif-output buggy.sarif \
        --fail-on high \
        --non-interactive
    '''
  }
  post {
    always {
      archiveArtifacts artifacts: 'buggy.sarif'
    }
  }
}
```

## Engagement context in CI

Even in `--non-interactive` mode, Buggy enforces RoE: pass an
`--instruction-file` pointing at a markdown document declaring scope and
exclusions. Anything outside that scope produces a structured refusal in
the SARIF properties rather than a finding. This is the safety boundary
that distinguishes Buggy from naive SAST tools.
