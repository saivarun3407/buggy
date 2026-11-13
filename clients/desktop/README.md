# Buggy Desktop (deprecated)

> **Deprecated.** The Electron desktop shell is no longer the recommended
> way to run Buggy. Use the interactive CLI (`buggy`) or the web
> dashboard instead. This package is kept for existing users and will be
> removed in a future release.

The desktop shell wraps the cloud app and the local web dashboard in an
Electron window. It adds no functionality over the web dashboard — the
browser already covers it — and is the highest-maintenance client surface
in the repo (Electron version churn, platform packaging, code-signing).

**Migration:** run `buggy start` for the CLI, or open the local web
dashboard at `http://localhost:3000` after starting the stack.
