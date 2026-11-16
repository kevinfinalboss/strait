#!/usr/bin/env bash
# Measures the overhead strait adds compared to hitting the backend directly.
# Requires oha (cargo install oha) and jq.
#
# Usage: demo/bench.sh
# Tune with CONNECTIONS (default 50) and DURATION (default 10s).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/demo/.logs/bench"
CONNECTIONS=${CONNECTIONS:-50}
DURATION=${DURATION:-10s}
BACKEND="127.0.0.1:9301"
STRAIT_ADDR="127.0.0.1:18090"
OHA=${OHA:-$(command -v oha || echo "$HOME/.cargo/bin/oha")}

for tool in "$OHA" jq; do
    command -v "$tool" >/dev/null || {
        echo "missing $tool (install oha with: cargo install oha)" >&2
        exit 1
    }
done

mkdir -p "$OUT"
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

wait_for_port() {
    for _ in $(seq 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.05
    done
    echo "port $1 did not open" >&2
    return 1
}

# CPU time used so far by process `pid`, in clock ticks (user + system).
cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$1/stat"
}

# Prints one markdown table row for a run of oha against `url`, including the CPU
# time process `pid` spent per request. CPU per request is far less sensitive to
# other load on the machine than requests per second.
measure() {
    local label=$1 url=$2 name=$3 pid=$4
    shift 4

    # Lingering TIME_WAIT sockets from a previous run can exhaust ephemeral ports.
    while (($(ss -tan state time-wait | wc -l) > 2000)); do
        sleep 1
    done

    local before after
    before=$(cpu_ticks "$pid")
    "$OHA" -c "$CONNECTIONS" -z "$DURATION" --no-tui --output-format json "$@" "$url" \
        >"$OUT/$name.json"
    after=$(cpu_ticks "$pid")

    jq -r --arg label "$label" --argjson ticks $((after - before)) --argjson hz "$(getconf CLK_TCK)" '
        def ms: . * 1000 | . * 100 | round / 100 | tostring + " ms";
        (.statusCodeDistribution["200"] // 0) as $ok
        | "| \($label) | \(.summary.requestsPerSec | round) | \(.latencyPercentiles.p50 | ms) | \(.latencyPercentiles.p99 | ms) | \(if $ok > 0 then ($ticks / $hz * 1e6 / $ok * 10 | round / 10 | tostring) + " µs" else "-" end) | \(.summary.successRate * 100 | round)% |"
    ' "$OUT/$name.json"
}

echo "building strait and the bench backend (release)..."
cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml" --bin strait --example bench_backend

"$ROOT/target/release/examples/bench_backend" "$BACKEND" >/dev/null &
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")
RUST_LOG=warn "$ROOT/target/release/strait" --listen "$STRAIT_ADDR" --backend "$BACKEND" >"$OUT/strait.log" 2>&1 &
STRAIT_PID=$!
PIDS+=("$STRAIT_PID")
wait_for_port "${BACKEND##*:}"
wait_for_port "${STRAIT_ADDR##*:}"

cpu=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || uname -m)
echo
echo "$CONNECTIONS connections for $DURATION each, on $cpu ($(nproc) threads)"
echo
echo "CPU/request is the backend's own CPU time for direct runs and strait's for runs through strait."
echo
echo "| Run | Requests/s | p50 | p99 | CPU/request | Success |"
echo "|---|---|---|---|---|---|"
measure "keep-alive, direct" "http://$BACKEND/" keepalive-direct "$BACKEND_PID"
measure "keep-alive, via strait" "http://$STRAIT_ADDR/" keepalive-strait "$STRAIT_PID"
measure "new connection per request, direct" "http://$BACKEND/" close-direct "$BACKEND_PID" --disable-keepalive
measure "new connection per request, via strait" "http://$STRAIT_ADDR/" close-strait "$STRAIT_PID" --disable-keepalive
echo
echo "raw oha results: $OUT"
