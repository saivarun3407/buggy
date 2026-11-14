#!/bin/bash
# Live view of a devin-solver benchmark run: challenge progress + in-flight session activity.
#
#   benchmark/devin-stream.sh            # one snapshot
#   watch -n 5 benchmark/devin-stream.sh # live, refreshing every 5s
#
# Reads the runner log (BENCH_LOG, default /tmp/devin-full-run.log) and the
# Devin CLI session database inside the langgraph container. Querying
# in-container avoids SQLite copy races against WAL checkpoints.

set -u

BENCH_LOG="${BENCH_LOG:-/tmp/devin-full-run.log}"
CONTAINER="${DEVIN_CONTAINER:-buggy-solver}"

echo "════════ BENCHMARK RUN PROGRESS ════════"
if [ -f "$BENCH_LOG" ]; then
    python3 - "$BENCH_LOG" <<'PYEOF'
import re, sys, time

log = open(sys.argv[1]).read()
done = re.findall(r"^\[(\d+)/(\d+)\]", log, re.M)
results = re.findall(r"(PASS|FAIL) \(([\d.]+)s\)", log)
p = sum(1 for r, _ in results if r == "PASS")
f = sum(1 for r, _ in results if r == "FAIL")
print(f"challenges: {len(done)} started  ·  PASS: {p}  FAIL: {f}")
cur = re.findall(r"^\[\d+/\d+\] (XBEN-[\d-]+): (.+?)(?:\.\.\.|$)", log, re.M)
if cur:
    print(f"in flight: {cur[-1][0]} — {cur[-1][1][:65]}")
print(f"as of {time.strftime('%H:%M:%S')}")
PYEOF
else
    echo "no run log at $BENCH_LOG (set BENCH_LOG=... )"
fi

echo
echo "════════ LIVE DEVIN SESSION ════════"
docker exec -i "$CONTAINER" python3 - <<'PYEOF' 2>/dev/null || echo "(container unreachable)"
import sqlite3, json, datetime

db = sqlite3.connect("file:/root/.local/share/devin/cli/sessions.db?mode=ro", uri=True)
row = db.execute(
    "SELECT id, title, model FROM sessions ORDER BY last_activity_at DESC LIMIT 1"
).fetchone()
if not row:
    print("no sessions")
else:
    sid, title, model = row
    print(f"session: {sid}  [{model}]")
    print(f"task:    {title}")
    print("── recent activity ──")
    msgs = db.execute(
        "SELECT node_id, created_at, chat_message FROM message_nodes "
        "WHERE session_id=? ORDER BY node_id DESC LIMIT 10", (sid,)
    ).fetchall()
    for node_id, ts, raw in reversed(msgs):
        try:
            m = json.loads(raw)
        except Exception:
            continue
        role = m.get("role", "?")
        content = " ".join((m.get("content") or "").split())
        if not content and role != "tool":
            continue
        t = datetime.datetime.fromtimestamp(ts / 1000).strftime("%H:%M:%S")
        if role == "tool":
            print(f"{t} ⚙ tool  → {content[:140]}")
        elif role == "assistant":
            print(f"{t} 💬 agent → {content[:140]}")
PYEOF
