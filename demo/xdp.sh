#!/usr/bin/env bash
# XDP data plane demo: a client, a router, strait with XDP and two backends,
# each in its own network namespace, wired with veth pairs.
#
#   client 10.10.1.2 ── router ── 10.10.2.2 lb (strait, XDP on l0)
#                         ├────── 10.10.3.2 b1 ─┐ VIP 10.10.0.10 on lo,
#                         └────── 10.10.4.2 b2 ─┘ IP-in-IP tunnel
#
# The router sends VIP traffic to the load balancer. XDP picks a backend with
# Maglev, wraps the packet in IP-in-IP and sends it back to the router, which
# forwards it to the backend. The backend unwraps it and answers the client
# directly: replies never pass through the load balancer.
#
# Needs root (sudo) for namespaces and XDP. Usage:
#   demo/xdp.sh            build, set up, run the demo, tear down
#   demo/xdp.sh up         set up and leave everything running
#   demo/xdp.sh down       tear down
# MODE=native|generic|auto (default auto) picks the XDP attach mode.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOGS="$ROOT/demo/.logs/xdp"
STRAIT="$ROOT/target/release/strait"
MODE=${MODE:-auto}
VIP=10.10.0.10
NS=(st-client st-router st-lb st-b1 st-b2)

run() { sudo ip netns exec "$@"; }

down() {
    for ns in "${NS[@]}"; do
        # Killing every process in the namespace stops strait and the backends.
        if ip netns list | grep -qw "$ns"; then
            sudo ip netns pids "$ns" | xargs -r sudo kill 2>/dev/null || true
            sudo ip netns del "$ns"
        fi
    done
}

# veth pair `a` in namespace `na` with address `ipa`, `b` in `nb` with `ipb`.
link() {
    local na=$1 a=$2 ipa=$3 nb=$4 b=$5 ipb=$6 mtu=${7:-1500}
    sudo ip link add "$a" netns "$na" type veth peer name "$b" netns "$nb"
    run "$na" ip addr add "$ipa" dev "$a"
    run "$nb" ip addr add "$ipb" dev "$b"
    run "$na" ip link set "$a" mtu "$mtu" up
    run "$nb" ip link set "$b" mtu "$mtu" up
}

no_rp_filter() {
    run "$1" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0
}

backend() {
    local ns=$1 ip=$2 name=$3
    no_rp_filter "$ns"
    run "$ns" ip link set lo up
    run "$ns" ip route add default via "${ip%.*}.1"
    # The VIP is local, so the kernel accepts the inner packet and the reply
    # leaves with the VIP as its source.
    run "$ns" ip addr add "$VIP/32" dev lo
    # A tunnel with no remote accepts IP-in-IP from any source.
    run "$ns" ip tunnel add ipip0 mode ipip local "$ip"
    run "$ns" ip link set ipip0 up
    run "$ns" sysctl -qw net.ipv4.conf.ipip0.rp_filter=0

    mkdir -p "$LOGS/$name"
    echo "$name" >"$LOGS/$name/index.html"
    run "$ns" python3 -m http.server 80 --bind 0.0.0.0 --directory "$LOGS/$name" \
        >"$LOGS/$name.log" 2>&1 &
}

up() {
    down
    sudo modprobe ipip
    mkdir -p "$LOGS"
    for ns in "${NS[@]}"; do sudo ip netns add "$ns"; done

    # Encapsulated packets are 20 bytes larger, so links behind the load
    # balancer get a larger MTU than the client's. Native XDP on veth needs a
    # frame to fit in one page, hence 3000 rather than 9000 on the lb link.
    link st-client c0 10.10.1.2/24 st-router r-c 10.10.1.1/24
    link st-lb l0 10.10.2.2/24 st-router r-l 10.10.2.1/24 3000
    link st-b1 eth0 10.10.3.2/24 st-router r-b1 10.10.3.1/24 9000
    link st-b2 eth0 10.10.4.2/24 st-router r-b2 10.10.4.1/24 9000

    run st-client ip link set lo up
    run st-client ip route add default via 10.10.1.1
    run st-router sysctl -qw net.ipv4.ip_forward=1
    no_rp_filter st-router
    run st-router ip route add "$VIP/32" via 10.10.2.2
    run st-lb ip link set lo up
    run st-lb ip route add default via 10.10.2.1
    backend st-b1 10.10.3.2 b1
    backend st-b2 10.10.4.2 b2

    local gateway
    gateway=$(run st-router cat /sys/class/net/r-l/address)
    cat >"$LOGS/strait.yaml" <<EOF
metrics:
  listen: 10.10.2.2:9090
xdp:
  interface: l0
  source: 10.10.2.2
  gateway_mac: "$gateway"
  mode: $MODE
listeners:
  - name: web
    listen: $VIP:80
    dataplane: xdp
    backends: [10.10.3.2:80, 10.10.4.2:80]
    health_check:
      interval: 500ms
EOF
    run st-lb "$STRAIT" --config "$LOGS/strait.yaml" >"$LOGS/strait.log" 2>&1 &
    for _ in $(seq 50); do
        grep -q "XDP backends updated" "$LOGS/strait.log" 2>/dev/null && break
        sleep 0.1
    done
    if ! grep -q "XDP backends updated" "$LOGS/strait.log"; then
        echo "strait did not start; log:" >&2
        cat "$LOGS/strait.log" >&2
        exit 1
    fi
}

# Prints the backend that answered each of `count` requests, one per line.
requests() {
    for _ in $(seq "$1"); do
        run st-client curl -s --max-time 2 "http://$VIP/" || echo "(failed)"
    done
}

xdp_metric() {
    run st-lb curl -s http://10.10.2.2:9090/metrics | grep "^strait_xdp_$1" || true
}

demo() {
    echo "== 20 requests to the VIP; each new connection is a new flow"
    requests 20 | sort | uniq -c

    echo
    echo "== b1 goes down; the health check takes it out of every table"
    sudo ip netns pids st-b1 | xargs -r sudo kill
    sleep 2
    requests 10 | sort | uniq -c

    echo
    echo "== the load balancer never sees a reply: it only counts client packets"
    xdp_metric packets
    xdp_metric no_backend
}

case ${1:-} in
    up) up ;;
    down) down ;;
    "")
        cargo build --release --quiet --features xdp --manifest-path "$ROOT/Cargo.toml" 2>/dev/null
        trap down EXIT
        up
        demo
        ;;
    *)
        echo "usage: $0 [up|down]" >&2
        exit 2
        ;;
esac
