#!/usr/bin/env bash
# Runs strait in a local kind cluster in front of a Deployment that scales up and
# down under load, to show backends following the Service's ready pods.
#
# Usage: demo/kubernetes.sh [up|scale|down]   (default: up, then scale)
# Needs docker, kind, kubectl and helm.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$ROOT/demo/kubernetes"
CLUSTER=${CLUSTER:-strait}
LOCAL_PORT=18080

up() {
    if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
        kind create cluster --name "$CLUSTER" --wait 120s
    fi
    kubectl config use-context "kind-$CLUSTER" >/dev/null

    echo "building and loading the strait image..."
    docker build -q -t strait:dev "$ROOT" >/dev/null
    kind load docker-image strait:dev --name "$CLUSTER" >/dev/null

    kubectl apply -f "$DEMO/web.yaml" >/dev/null
    kubectl rollout status deploy/web --timeout=120s >/dev/null

    helm upgrade --install strait "$ROOT/deploy/helm/strait" -f "$DEMO/values.yaml" --wait >/dev/null
    # The image tag stays "dev", so restart to pick up a rebuilt image.
    kubectl rollout restart deploy/strait >/dev/null
    kubectl rollout status deploy/strait --timeout=120s >/dev/null
    echo "strait is running in kind-$CLUSTER in front of Service web"
}

scale() {
    kubectl scale deploy/web --replicas=3 >/dev/null
    kubectl rollout status deploy/web --timeout=120s >/dev/null

    kubectl port-forward svc/strait "$LOCAL_PORT:8080" >/dev/null 2>&1 &
    local forward=$!
    trap 'kill $forward 2>/dev/null || true' RETURN
    for _ in $(seq 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$LOCAL_PORT") 2>/dev/null && break
        sleep 0.1
    done

    printf '\n\033[1m== scale\033[0m\n%s\n' \
        "Deployment web goes 3 -> 5 replicas at second 5, down to 1 at second 15 and back to 3 at second 25. strait follows the Service's ready pods with no restart."
    (
        sleep 5
        kubectl scale deploy/web --replicas=5 >/dev/null
        sleep 10
        kubectl scale deploy/web --replicas=1 >/dev/null
        sleep 10
        kubectl scale deploy/web --replicas=3 >/dev/null
    ) &
    local timer=$!

    python3 "$ROOT/demo/load.py" --target "127.0.0.1:$LOCAL_PORT" --clients 10 --duration 35 \
        --backend-pattern 'Hostname: (\S+)'
    wait "$timer"

    printf '\nendpoint updates from strait:\n'
    kubectl logs deploy/strait --since=60s | sed 's/\x1b\[[0-9;]*m//g' | grep 'endpoints updated' | cut -c29- || true
}

down() {
    kind delete cluster --name "$CLUSTER"
}

case "${1:-all}" in
    up) up ;;
    scale) scale ;;
    down) down ;;
    all)
        up
        scale
        ;;
    *)
        echo "usage: $0 [up|scale|down]" >&2
        exit 1
        ;;
esac
