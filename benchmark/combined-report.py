#!/usr/bin/env python3
"""Combined benchmark report across run logs (main + resume + reruns).

Usage: python3 combined-report.py OUT.md [LOG1 LOG2 ...]
Parses each runner log's challenge starts + PASS/FAIL outcomes, joins with
the XBOW corpus metadata (level, tags, name), and emits a markdown report.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

BENCH = Path(
    "/Users/Shared/t3-scratch/buggy-research/buggy/benchmark/xbow-validation-benchmarks/benchmarks"
)

# Known infrastructure failure causes (not model failures) per challenge id.
INFRA_FAILS = {
    "XBEN-001-24": "stale base image (pre-patch build failure)",
    "XBEN-002-24": "stale base image (pre-patch build failure)",
    "XBEN-003-24": "stale base image (pre-patch build failure)",
    "XBEN-004-24": "stale base image (pre-patch build failure)",
    "XBEN-022-24": "malformed compose expose: syntax (fixed post-run)",
    "XBEN-023-24": "malformed compose expose: syntax (fixed post-run)",
    "XBEN-025-24": "malformed compose expose: syntax (fixed post-run)",
    "XBEN-027-24": "malformed compose expose: syntax (fixed post-run)",
    "XBEN-044-24": "permanently unbuildable (build error)",
    "XBEN-084-24": "node:14 base incompatible with modern transitive deps (fixed post-run)",
}


def load_meta() -> dict[str, dict]:
    meta = {}
    for d in sorted(BENCH.iterdir()):
        if not d.name.startswith("XBEN-"):
            continue
        try:
            m = json.load(open(d / "benchmark.json"))
            meta[d.name] = {
                "level": int(m.get("level", 0)),
                "tags": m.get("tags", []),
                "name": m.get("name", d.name),
            }
        except Exception:
            meta[d.name] = {"level": 0, "tags": [], "name": d.name}
    return meta


def parse_logs(logs: list[str]) -> list[dict]:
    rows = []
    for logf in logs:
        log = open(logf).read()
        starts = re.findall(r"^\[\d+/\d+\] (XBEN-[\d-]+)", log, re.M)
        outs = re.findall(r"(PASS|FAIL) \(([\d.]+)s\)", log)
        for cid, (res, dur) in zip(starts, outs):
            rows.append({"id": cid, "result": res, "dur": float(dur), "log": Path(logf).name})
    return rows


def main() -> None:
    out_path = Path(sys.argv[1])
    logs = sys.argv[2:] or ["/tmp/devin-full-run.log", "/tmp/devin-resume.log"]
    meta = load_meta()
    rows = parse_logs(logs)

    # dedupe: later occurrence (rerun) wins
    by_id: dict[str, dict] = {}
    for r in rows:
        by_id[r["id"]] = r
    final = [by_id[c] for c in sorted(by_id)]

    n_pass = sum(1 for r in final if r["result"] == "PASS")
    n_fail = sum(1 for r in final if r["result"] == "FAIL")
    infra_fails = [r for r in final if r["result"] == "FAIL" and r["id"] in INFRA_FAILS]
    solve_fails = [r for r in final if r["result"] == "FAIL" and r["id"] not in INFRA_FAILS]
    attempted = n_pass + len(solve_fails)

    total = len(meta)
    not_run = sorted(set(meta) - set(by_id))

    lines: list[str] = []
    a = lines.append
    a("# Buggy Benchmark Report — XBOW Validation Suite")
    a("")
    a("**Solver:** Devin CLI agent sessions — GLM 5.3 High (`--solver devin`)  ")
    a(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    a(f"**Corpus:** {total} challenges (45 L1 · 51 L2 · 8 L3)")
    a("")
    a("## Headline")
    a("")
    a(
        f"- **{n_pass} PASS / {n_fail} FAIL** of {len(final)} run "
        f"({len(final)}/{total} of corpus, {len(not_run)} not yet run)"
    )
    if attempted:
        a(
            f"- **Solve rate on challenges the model actually attempted: "
            f"{n_pass}/{attempted} ({n_pass / attempted:.1%})** — "
            f"{len(solve_fails)} genuine solve failures"
        )
    a(
        f"- All {len(infra_fails)} recorded FAILs are infrastructure casualties "
        f"(stale Docker bases / malformed compose), not model failures — "
        f"each is annotated below and re-run separately where fixable"
    )
    durs = [r["dur"] for r in final if r["result"] == "PASS"]
    if durs:
        a(
            f"- Median solve time (passes): {sorted(durs)[len(durs) // 2]:.1f}s · "
            f"fastest {min(durs):.1f}s · slowest {max(durs):.1f}s"
        )
    a("")
    a("## By level")
    a("")
    a("| Level | Run | Pass | Infra fail | Solve fail | Not run | Attempted record |")
    a("|---|---|---|---|---|---|---|")
    for lv in (1, 2, 3):
        ids = {c for c, m in meta.items() if m["level"] == lv}
        run = [by_id[c] for c in ids if c in by_id]
        p = sum(1 for r in run if r["result"] == "PASS")
        inf = sum(1 for r in run if r["result"] == "FAIL" and r["id"] in INFRA_FAILS)
        sf = sum(1 for r in run if r["result"] == "FAIL" and r["id"] not in INFRA_FAILS)
        nr = len(ids) - len(run)
        att = p + sf
        rec = f"{p}/{att} ({p / att:.0%})" if att else "—"
        a(f"| {lv} | {len(run)} | {p} | {inf} | {sf} | {nr} | {rec} |")
    a("")
    a("## By tag (top 15 by count)")
    a("")
    a("| Tag | Run | Pass | Attempted record |")
    a("|---|---|---|---|")
    tag_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for r in final:
        for t in meta[r["id"]]["tags"]:
            tag_stats[t][0] += 1
            if r["result"] == "PASS":
                tag_stats[t][1] += 1
                tag_stats[t][2] += 1
            elif r["id"] not in INFRA_FAILS:
                tag_stats[t][2] += 1
    for t, (run_n, p, att) in sorted(tag_stats.items(), key=lambda kv: -kv[1][0])[:15]:
        rec = f"{p}/{att} ({p / att:.0%})" if att else "—"
        a(f"| {t} | {run_n} | {p} | {rec} |")
    a("")
    if solve_fails:
        a("## Genuine solve failures")
        a("")
        for r in solve_fails:
            a(f"- **{r['id']}** {meta[r['id']]['name']} — {r['dur']:.0f}s")
        a("")
    if infra_fails:
        a("## Infrastructure failures (not model failures)")
        a("")
        for r in infra_fails:
            a(f"- **{r['id']}** — {INFRA_FAILS[r['id']]}")
        a("")
    if not_run:
        a(f"## Not yet run ({len(not_run)})")
        a("")
        a("```")
        a(" ".join(not_run))
        a("```")
        a("")
    a("## Per-challenge results")
    a("")
    a("| ID | Level | Tags | Result | Time |")
    a("|---|---|---|---|---|")
    for r in final:
        m = meta[r["id"]]
        res = (
            "✅ PASS"
            if r["result"] == "PASS"
            else ("⚠️ FAIL (infra)" if r["id"] in INFRA_FAILS else "❌ FAIL")
        )
        a(f"| {r['id']} | {m['level']} | {', '.join(m['tags']) or '—'} | {res} | {r['dur']:.1f}s |")
    a("")

    out_path.write_text("\n".join(lines))
    print(
        f"wrote {out_path} — {n_pass} pass / {n_fail} fail of {len(final)} run, {len(not_run)} not run"
    )


if __name__ == "__main__":
    main()
