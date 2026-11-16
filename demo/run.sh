#!/usr/bin/env bash
# Runs strait in front of local demo backends and drives traffic through it.
# Usage: demo/run.sh [balance|least-conn|failover|affinity|all]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/demo"
LOGS="$DEMO/.logs"
STRAIT="$ROOT/target/release/strait"
LISTEN="127.0.0.1:18080"
BACKENDS=(a:9101 b:9102 c:9103)

mkdir -p "$LOGS"

cleanup() {
    for pidfile in "$LOGS"/*.pid; do
        [[ -e "$pidfile" ]] || continue
        kill "$(cat "$pidfile")" 2>/dev/null || true
        rm -f "$pidfile"
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

start_backend() {
    local name=$1 port=$2 delay=${3:-0}
    python3 "$DEMO/backend.py" --name "$name" --port "$port" --delay "$delay" \
        >"$LOGS/backend-$name.log" 2>&1 &
    echo $! >"$LOGS/backend-$name.pid"
    wait_for_port "$port"
}

stop_backend() {
    local pidfile="$LOGS/backend-$1.pid"
    kill "$(cat "$pidfile")" 2>/dev/null || true
    rm -f "$pidfile"
}

start_backends() {
    local slow=${1:-}
    for backend in "${BACKENDS[@]}"; do
        local name=${backend%%:*} port=${backend##*:} delay=0
        [[ "$name" == "$slow" ]] && delay=0.05
        start_backend "$name" "$port" "$delay"
    done
}

start_strait() {
    local args=()
    for backend in "${BACKENDS[@]}"; do
        args+=(-b "127.0.0.1:${backend##*:}")
    done
    "$STRAIT" --listen "$LISTEN" "${args[@]}" --health-interval 300ms "$@" \
        >"$LOGS/strait.log" 2>&1 &
    echo $! >"$LOGS/strait.pid"
    wait_for_port "${LISTEN##*:}"
}

stop_all() {
    cleanup
}

header() {
    printf '\n\033[1m== %s\033[0m\n%s\n' "$1" "$2"
}

scenario_balance() {
    header "balance" "Round-robin across three healthy backends. Expect about a third each and no errors."
    start_backends
    start_strait --strategy round-robin
    python3 "$DEMO/load.py" --target "$LISTEN" --clients 20 --duration 4
    stop_all
}

scenario_least_conn() {
    header "least-conn" "Backend c answers 50ms slower. Round-robin keeps sending it a third of the traffic and the slow replica caps throughput; least-conn sends it only what it can handle, so total requests per second go up."
    for strategy in round-robin least-conn; do
        printf '\n\033[1m-- %s\033[0m\n' "$strategy"
        start_backends c
        start_strait --strategy "$strategy"
        python3 "$DEMO/load.py" --target "$LISTEN" --clients 20 --duration 4
        stop_all
    done
}

scenario_failover() {
    header "failover" "Backend b is stopped at second 2 and started again at second 5. Only requests already in flight on b fail; new connections are retried on a and c until the health check takes b out, and b gets traffic again once it is back."
    start_backends
    start_strait --strategy round-robin
    (
        sleep 2
        stop_backend b
        sleep 3
        start_backend b 9102
    ) &
    local timer=$!
    python3 "$DEMO/load.py" --target "$LISTEN" --clients 20 --duration 8
    wait "$timer"
    printf '\nhealth events from strait:\n'
    sed 's/\x1b\[[0-9;]*m//g' "$LOGS/strait.log" | grep 'strait::health' | cut -c29- || true
    stop_all
}

scenario_affinity() {
    header "affinity" "40 client IPs with ip-hash. Expect every IP to stay on one backend. Backend c is stopped halfway: only its clients move."
    start_backends
    start_strait --strategy ip-hash
    (
        sleep 3
        stop_backend c
    ) &
    local timer=$!
    python3 "$DEMO/load.py" --target "$LISTEN" --clients 40 --sources 40 --duration 6
    wait "$timer"
    stop_all
}

main() {
    local scenario=${1:-all}

    echo "building strait (release)..."
    cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"

    case "$scenario" in
        balance) scenario_balance ;;
        least-conn) scenario_least_conn ;;
        failover) scenario_failover ;;
        affinity) scenario_affinity ;;
        all)
            scenario_balance
            scenario_least_conn
            scenario_failover
            scenario_affinity
            ;;
        *)
            echo "usage: $0 [balance|least-conn|failover|affinity|all]" >&2
            exit 1
            ;;
    esac
}

main "$@"
