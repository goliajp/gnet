#!/usr/bin/env bash
# v0.13 cross-NAT punch test — Linux netns topology.
# See docs/measurements/v0.13-cross-nat-hit-rate.md for context.
#
# Five namespaces glued by one host bridge. Two NAT routers
# (mock-a-nat, mock-b-nat) wrap two inner peer namespaces; a third
# namespace (mock-c) on the bridge plays rendezvous coordinator.
# tc netem adds 25 ms egress on each NAT-outer veth so the round-trip
# between any two NAT'd peers is ~100 ms — the design envelope of the
# DCUtR simultaneous-open timing.
#
# Modes (set via NAT_MODE env): "default" → plain MASQUERADE; "random-fully"
# → MASQUERADE --random-fully (true per-flow symmetric NAT). Teardown is
# idempotent so the same script can be re-run between trials.

set -euo pipefail

NAT_MODE="${NAT_MODE:-default}"           # default | random-fully
BRIDGE=br-mocknat

cleanup() {
    # Delete in reverse-dependency order; ignore-missing for idempotency.
    for ns in mock-a-inner mock-b-inner mock-a-nat mock-b-nat mock-c; do
        ip netns delete "$ns" 2>/dev/null || true
    done
    # Host-side veth ends survive ns-delete (master'd to bridge), so wipe
    # them explicitly. Same for the bridge itself.
    for veth in veth-c-h veth-ao-h veth-bo-h; do
        ip link delete "$veth" 2>/dev/null || true
    done
    ip link delete "$BRIDGE" 2>/dev/null || true
}

if [[ "${1:-}" == "down" ]]; then
    cleanup
    echo "topology torn down"
    exit 0
fi

cleanup    # always start from a clean slate

# ── host bridge ────────────────────────────────────────────────────────
ip link add "$BRIDGE" type bridge
ip addr add 10.99.0.1/24 dev "$BRIDGE"
ip link set "$BRIDGE" up

# ── namespaces ─────────────────────────────────────────────────────────
for ns in mock-c mock-a-nat mock-b-nat mock-a-inner mock-b-inner; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
done

# Helper: create veth pair joining (host-side iface in $BRIDGE) ↔ (ns iface)
mk_veth_to_bridge() {
    local host="$1" peer_ns="$2" peer_if="$3" peer_ip="$4"
    ip link add "$host" type veth peer name "$peer_if" netns "$peer_ns"
    ip link set "$host" master "$BRIDGE"
    ip link set "$host" up
    ip netns exec "$peer_ns" ip link set "$peer_if" up
    ip netns exec "$peer_ns" ip addr add "$peer_ip" dev "$peer_if"
}

# Helper: veth between two namespaces
mk_veth_ns_to_ns() {
    local a_ns="$1" a_if="$2" a_ip="$3" b_ns="$4" b_if="$5" b_ip="$6"
    ip link add "$a_if" netns "$a_ns" type veth peer name "$b_if" netns "$b_ns"
    ip netns exec "$a_ns" ip link set "$a_if" up
    ip netns exec "$a_ns" ip addr add "$a_ip" dev "$a_if"
    ip netns exec "$b_ns" ip link set "$b_if" up
    ip netns exec "$b_ns" ip addr add "$b_ip" dev "$b_if"
}

# ── mock-c: directly on bridge (no NAT) ────────────────────────────────
mk_veth_to_bridge veth-c-h mock-c veth-c 10.99.0.30/24
ip netns exec mock-c ip route add default via 10.99.0.1

# ── NAT routers + inner namespaces ─────────────────────────────────────
mk_veth_to_bridge veth-ao-h mock-a-nat veth-ao 10.99.0.10/24
mk_veth_ns_to_ns  mock-a-nat veth-ai 192.168.10.1/24  mock-a-inner veth-ain 192.168.10.2/24
ip netns exec mock-a-nat sysctl -wq net.ipv4.ip_forward=1
ip netns exec mock-a-inner ip route add default via 192.168.10.1

mk_veth_to_bridge veth-bo-h mock-b-nat veth-bo 10.99.0.20/24
mk_veth_ns_to_ns  mock-b-nat veth-bi 192.168.20.1/24  mock-b-inner veth-bin 192.168.20.2/24
ip netns exec mock-b-nat sysctl -wq net.ipv4.ip_forward=1
ip netns exec mock-b-inner ip route add default via 192.168.20.1

# ── NAT rules ──────────────────────────────────────────────────────────
masq_flags=""
if [[ "$NAT_MODE" == "random-fully" ]]; then
    masq_flags="--random-fully"
fi

ip netns exec mock-a-nat iptables -t nat -A POSTROUTING -o veth-ao -j MASQUERADE $masq_flags
ip netns exec mock-b-nat iptables -t nat -A POSTROUTING -o veth-bo -j MASQUERADE $masq_flags

# ── simulate WAN RTT ───────────────────────────────────────────────────
# In raw netns, RTT is sub-ms — too fast for DCUtR's simultaneous-open
# timing (the origin's `dial_at = sync_send + RTT/2` puts its fan-out
# ahead of the target's fan-out by less than one packet flight, so its
# slot-0 hits the peer's NAT before the peer's conntrack opens). Adding
# 25ms egress on each NAT-outer interface → ~100ms round-trip between
# any two NAT'd peers, well within the design envelope of the protocol.
ip netns exec mock-a-nat tc qdisc add dev veth-ao root netem delay 25ms
ip netns exec mock-b-nat tc qdisc add dev veth-bo root netem delay 25ms

# ── connectivity sanity check ──────────────────────────────────────────
echo "── connectivity check (NAT_MODE=$NAT_MODE) ──"
ip netns exec mock-a-inner ping -c1 -W1 192.168.10.1 >/dev/null && echo "  ok  mock-a-inner → mock-a-nat (192.168.10.1)"
ip netns exec mock-a-inner ping -c1 -W1 10.99.0.1    >/dev/null && echo "  ok  mock-a-inner → host bridge (10.99.0.1)"
ip netns exec mock-a-inner ping -c1 -W1 10.99.0.30   >/dev/null && echo "  ok  mock-a-inner → mock-c (10.99.0.30)"
ip netns exec mock-b-inner ping -c1 -W1 192.168.20.1 >/dev/null && echo "  ok  mock-b-inner → mock-b-nat (192.168.20.1)"
ip netns exec mock-b-inner ping -c1 -W1 10.99.0.1    >/dev/null && echo "  ok  mock-b-inner → host bridge (10.99.0.1)"
ip netns exec mock-b-inner ping -c1 -W1 10.99.0.30   >/dev/null && echo "  ok  mock-b-inner → mock-c (10.99.0.30)"
echo "topology up — NAT_MODE=$NAT_MODE"
