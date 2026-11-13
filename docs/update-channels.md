# Update channels

Buggy publishes two update channels, modeled on
[Claude Code's release channels](https://code.claude.com/docs/en/setup#configure-release-channel).
**Both channels deliver only _final_ releases** (never pre-releases /
betas). The difference is a **bake/soak delay**, not pre-release inclusion.

| Channel | Tracks | GHCR tag | Default |
|---------|--------|----------|---------|
| **stable** | The newest **final** release that has baked for at least the soak window (default 7 days). | `:stable` | ✅ default |
| **latest** | The newest **final** release, immediately. | `:latest` | opt-in |

So `latest` gets every release the moment it ships, and `stable` adopts it
about a week later — long enough to surface regressions before
conservative users see it.

> **Claude Code parity, with one deliberate difference.** The *semantics*
> match Claude Code (soak model, final-only). Claude Code defaults to
> `latest`; Buggy defaults to **`stable`** because it is an autonomous
> offensive-security tool where a conservative default is the safer choice.

`latest` is **not** "the main branch." It only moves when a release is
cut — not on every commit. (To track a git branch's config instead of a
release, use the separate `BUGGY_BRANCH` override.)

## Selecting a channel

The channel lives in `BUGGY_CHANNEL` in `~/.buggy/.env` (default
`stable`; unrecognized values resolve to `stable`):

```bash
# ~/.buggy/.env
BUGGY_CHANNEL=latest
# optional — override the stable soak window (days):
BUGGY_STABLE_SOAK_DAYS=7
```

Three ways to set it:

- **At install** — `CHANNEL=latest curl -fsSL https://buggy.red/install | bash`.
- **In `.env`** — `BUGGY_CHANNEL=stable|latest`. The launch-time
  self-update and `buggy update` both honor it.
- **Per command** — `buggy update --channel latest` (one run only).

Pinning an exact version still wins over the channel: `VERSION=1.2.0
curl … | bash` (install) or `BUGGY_VERSION=1.2.0` (compose).

## How it works

- **Launcher self-update / `buggy update`** (`internal/updater`):
  - `latest` → GitHub `…/releases/latest` (newest final; the endpoint
    already excludes pre-releases and drafts).
  - `stable` → lists `…/releases` and picks the newest **final** whose
    `published_at` is at least `BUGGY_STABLE_SOAK_DAYS` (default 7) in
    the past, by SemVer. If nothing has soaked yet, it falls back to the
    newest final so stable always resolves.
- **Install** (`scripts/install.sh`) resolves the same way (the stable
  date filter needs `python3`; without it, it falls back to the newest
  final).
- **Docker image tags**:
  - `:latest` is moved to every **final** release immediately by the
    release workflow's `publish-release` job.
  - `:stable` is moved to the newest soaked final by the **scheduled**
    `promote-stable.yml` workflow (daily), *not* on release.
  - Pre-releases move neither tag.
- **Compose fallback.** When `BUGGY_VERSION` is unset, the images in
  `docker-compose.yml` fall back to `:stable` (the conservative default).
  In normal operation the launcher pins `BUGGY_VERSION` to a concrete
  version, so the fallback is only a safety net for direct `docker compose`
  use.

## Notes

- Pre-releases (`vX.Y.Z-rc.N`) are never auto-selected by either channel.
  Install one explicitly with `VERSION=…` if needed.
- The channel is independent of `AUTO_UPDATE` (whether updates apply
  automatically) and `BUGGY_BRANCH` (track a git branch's config
  instead of a release tag).
- Switching from `latest` to `stable` will not downgrade an
  already-installed newer version (updates are forward-only); stable simply
  stops advancing until the soaked stable catches up.
