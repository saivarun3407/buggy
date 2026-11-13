#!/bin/bash
# Batched XBOW run: process the suite in chunks so the Docker VM disk (60 GB)
# never has to hold every challenge image at once. Between chunks: tear down
# containers and prune images + build cache to reclaim space.
#
# Usage:
#   benchmark/batch-run.sh                 # all 104, chunks of 25
#   CHUNK=20 benchmark/batch-run.sh        # chunks of 20
#   benchmark/batch-run.sh 1 50            # only challenges 1..50 (1-based)
set -u

ROOT="/Users/Shared/t3-scratch/buggy-research/buggy"
BENCH="$ROOT/benchmark/xbow-validation-benchmarks/benchmarks"
STATE="/tmp/xbow-batch-state"
LOG="$STATE/batch.log"
CHUNK="${CHUNK:-25}"              # challenges per chunk
PARALLEL="${PARALLEL:-3}"        # concurrent challenges in flight (sliding window)
MIN_FREE_KB=$((6 * 1024 * 1024)) # abort a chunk if host free disk < 6 GB
RANGE_START="${1:-1}"
RANGE_END="${2:-}"

mkdir -p "$STATE"
: >"$LOG"
log() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$LOG"; }

# --- preflight: VM up + benchmark services reachable -------------------------
if ! docker info >/dev/null 2>&1; then
  log "FATAL: docker not reachable. Run 'colima start' first."
  exit 2
fi
for probe in "http://127.0.0.1:2024/ok" "http://127.0.0.1:9100/v1/health"; do
  if ! curl -fsS --max-time 5 "$probe" >/dev/null 2>&1; then
    log "FATAL: benchmark service down ($probe). Start the Buggy stack first."
    exit 2
  fi
done

# --- gather + slice challenge ids --------------------------------------------
mapfile -t ALL < <(find "$BENCH" -mindepth 2 -maxdepth 2 -name benchmark.json \
                   | awk -F/ '{print $(NF-1)}' | sort)
total="${#ALL[@]}"
[[ -z "$RANGE_END" ]] && RANGE_END="$total"
log "SUITE $total challenges; running index $RANGE_START..$RANGE_END in chunks of $CHUNK"

reclaim() {
  docker container prune -f  >/dev/null 2>&1 || true
  docker image prune -af     >/dev/null 2>&1 || true
  docker builder prune -af   >/dev/null 2>&1 || true
}

build_one() {
  local id="$1" dir="$BENCH/$1"
  [[ -f "$dir/benchmark.json" ]] || { log "  build-skip $id (no benchmark.json)"; return 1; }
  ( cd "$dir" && make build ) >"$STATE/build-$id.log" 2>&1
}

chunk_no=0
i=$((RANGE_START - 1))
while (( i < RANGE_END )); do
  chunk_no=$((chunk_no + 1))
  ids=(); n=0
  while (( n < CHUNK && i < RANGE_END )); do ids+=("${ALL[$i]}"); i=$((i+1)); n=$((n+1)); done

  free_kb=$(df -k /System/Volumes/Data | awk 'NR==2{print $4}')
  if (( free_kb < MIN_FREE_KB )); then
    log "ABORT: host free disk ${free_kb}KB below ${MIN_FREE_KB}KB before chunk $chunk_no."
    exit 1
  fi

  log "── CHUNK $chunk_no: ${#ids[@]} challenges, parallel=$PARALLEL (${ids[*]})"

  # build this chunk; collect the ones that build
  ok=()
  for id in "${ids[@]}"; do
    if build_one "$id"; then ok+=("$id"); log "  build-ok $id"
    else log "  build-FAIL $id"; fi
  done

  if (( ${#ok[@]} == 0 )); then
    log "  chunk $chunk_no: nothing built, skipping agent run"
  else
    csv=$(IFS=,; echo "${ok[*]}")
    log "  AGENT RUN chunk $chunk_no ids=$csv"
    ( cd "$ROOT" && env -u MOONSHOT_API_KEY -u KIMI_API_KEY PYTHONUNBUFFERED=1 \
        .venv/bin/python -m benchmark.runner --ids "$csv" --parallel "$PARALLEL" --timeout 1800 ) 2>&1 | tee -a "$LOG"
  fi

  log "  reclaim after chunk $chunk_no …"
  reclaim
  log "  chunk $chunk_no done; host free now $(df -h /System/Volumes/Data | awk 'NR==2{print $4}')"
done

log "ALL CHUNKS DONE. Reports under $ROOT/benchmark/results/"
