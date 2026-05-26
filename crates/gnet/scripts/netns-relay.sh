#!/bin/bash
# Relay-fallback test (Linux, root): two nodes each behind their own SYMMETRIC
# NAT, with NO direct endpoint for each other — they only know a mutually
# reachable public coordinator. Symmetric NAT assigns a fresh random source port
# per destination, so the reflexive endpoint A learns via the coordinator is
# useless to B (and vice versa): the hole punch necessarily fails. After
# PUNCH_ATTEMPTS give-ups each side trips to relay fallback and tunnels its
# end-to-end-encrypted traffic through the coordinator, which forwards by
# destination key without ever decrypting it.
#
# This is the symmetric-NAT counterpart to netns-punch-sync.sh: same topology
# and same configs (the coordinator doubles as the relay), the only difference
# is the NAT flavour — full-cone there (punch succeeds), symmetric here (punch
# fails → relay). No netem is needed: relay does not depend on RTT timing.
#
# Topology (all public legs + the coordinator on one public bridge):
#   ns-a — br-pa — ns-nata — br-pub — ns-natb — br-pb — ns-b
#                              |
#                          ns-coord (public, no NAT; also the relay)
#
#   sudo bash crates/gnet/scripts/netns-relay.sh
set -u

cargo build -p gnet 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnet"
TMP=$(mktemp -d)
A_PUB=192.168.60.10;   A_PORT=50001
B_PUB=192.168.60.20;   B_PORT=50002
COORD_PUB=192.168.60.30

# Every host-side device this script creates (see netns-punch.sh for why each
# must be listed: a lost netns-move race can strand veth ends in the host ns,
# and a leftover makes the next `ip link add` fail with "File exists").
DEVS="ns-nata-pub ns-nata-pri ns-natb-pub ns-natb-pri ns-a-eth ns-b-eth \
      ns-coord-pub br-ns-natap br-ns-natar br-ns-natbp br-ns-natbr \
      br-ns-a br-ns-b br-ns-coord br-pub br-pa br-pb"
NSS="ns-a ns-nata ns-b ns-natb ns-coord"

cleanup() {
    kill "${pid_a:-}" "${pid_b:-}" "${pid_coord:-}" 2>/dev/null
    for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
    for br in br-pub br-pa br-pb; do
        iptables -D FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
    done
    for l in $DEVS; do ip link del "$l" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

# Pre-clean residue from an interrupted run and wait for the kernel to release
# the bridge name before recreating (device teardown is asynchronous).
for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
for l in $DEVS; do ip link del "$l" 2>/dev/null; done
for _ in $(seq 1 100); do ip link show br-pub >/dev/null 2>&1 || break; sleep 0.05; done

a_out=$("$BIN" keygen); b_out=$("$BIN" keygen); c_out=$("$BIN" keygen)
a_priv=$(echo "$a_out" | awk '/^private/{print $2}')
a_pub=$(echo "$a_out"  | awk '/^public/{print $2}')
a_mlk=$(echo "$a_out"  | awk '/^mlkem-public/{print $2}')
b_priv=$(echo "$b_out" | awk '/^private/{print $2}')
b_pub=$(echo "$b_out"  | awk '/^public/{print $2}')
b_mlk=$(echo "$b_out"  | awk '/^mlkem-public/{print $2}')
c_priv=$(echo "$c_out" | awk '/^private/{print $2}')
c_pub=$(echo "$c_out"  | awk '/^public/{print $2}')
c_mlk=$(echo "$c_out"  | awk '/^mlkem-public/{print $2}')

for br in br-pub br-pa br-pb; do
    ip link add "$br" type bridge
    ip link set "$br" up
    iptables -I FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
done

# one NAT gateway + one client behind it. SYMMETRIC NAT: SNAT to a random source
# port per flow (--random-fully, no fixed --to-source port), so the same client
# reaches different destinations from different public ports — the reflexive
# endpoint learned via the coordinator does not match the port a direct peer
# would see, and the punch fails. No netem: relay needs no RTT alignment.
make_side() {
    local ns_nat=$1 ns_cli=$2 br_priv=$3 pubip=$4 privnet=$5 cliip=$6
    ip netns add "$ns_nat"; ip netns add "$ns_cli"
    ip link add "${ns_nat}-pub" type veth peer name "br-${ns_nat}p"
    ip link set "${ns_nat}-pub" netns "$ns_nat"
    ip link set "br-${ns_nat}p" master br-pub; ip link set "br-${ns_nat}p" up
    ip -n "$ns_nat" addr add "$pubip/24" dev "${ns_nat}-pub"
    ip -n "$ns_nat" link set "${ns_nat}-pub" up
    ip link add "${ns_nat}-pri" type veth peer name "br-${ns_nat}r"
    ip link set "${ns_nat}-pri" netns "$ns_nat"
    ip link set "br-${ns_nat}r" master "$br_priv"; ip link set "br-${ns_nat}r" up
    ip -n "$ns_nat" addr add "$privnet.254/24" dev "${ns_nat}-pri"
    ip -n "$ns_nat" link set "${ns_nat}-pri" up
    ip -n "$ns_nat" link set lo up
    ip netns exec "$ns_nat" sysctl -wq net.ipv4.ip_forward=1
    ip netns exec "$ns_nat" iptables -t nat -A POSTROUTING -o "${ns_nat}-pub" \
        -s "$cliip" -p udp -j SNAT --to-source "$pubip" --random-fully
    ip link add "${ns_cli}-eth" type veth peer name "br-${ns_cli}"
    ip link set "${ns_cli}-eth" netns "$ns_cli"
    ip link set "br-${ns_cli}" master "$br_priv"; ip link set "br-${ns_cli}" up
    ip -n "$ns_cli" addr add "$cliip/24" dev "${ns_cli}-eth"
    ip -n "$ns_cli" link set "${ns_cli}-eth" up
    ip -n "$ns_cli" link set lo up
    ip -n "$ns_cli" route add default via "$privnet.254"
}
make_side ns-nata ns-a br-pa "$A_PUB" 10.1.0 10.1.0.1
make_side ns-natb ns-b br-pb "$B_PUB" 10.2.0 10.2.0.1

# coordinator / relay: a plain public node on br-pub, no NAT (same /24 as the NAT
# public legs, so it reaches A_PUB/B_PUB directly at layer 2). It mediates the
# (doomed) punch AND forwards the relayed traffic that follows.
ip netns add ns-coord
ip link add ns-coord-pub type veth peer name br-ns-coord
ip link set ns-coord-pub netns ns-coord
ip link set br-ns-coord master br-pub; ip link set br-ns-coord up
ip -n ns-coord addr add "$COORD_PUB/24" dev ns-coord-pub
ip -n ns-coord link set ns-coord-pub up
ip -n ns-coord link set lo up

# A and B know the coordinator's endpoint but NOT each other's. Identical to the
# punch-sync config — the coordinator doubles as the relay once the punch fails.
cat > "$TMP/a.conf" <<EOF
private $a_priv
address 10.88.0.1
listen 0.0.0.0:7777
keepalive 1
peer $c_pub $c_mlk 10.88.0.3 $COORD_PUB:7777
peer $b_pub $b_mlk 10.88.0.2
EOF
cat > "$TMP/b.conf" <<EOF
private $b_priv
address 10.88.0.2
listen 0.0.0.0:7777
keepalive 1
peer $c_pub $c_mlk 10.88.0.3 $COORD_PUB:7777
peer $a_pub $a_mlk 10.88.0.1
EOF
cat > "$TMP/coord.conf" <<EOF
private $c_priv
address 10.88.0.3
listen 0.0.0.0:7777
keepalive 1
peer $a_pub $a_mlk 10.88.0.1
peer $b_pub $b_mlk 10.88.0.2
EOF

ip netns exec ns-coord "$BIN" up "$TMP/coord.conf" >"$TMP/coord.log" 2>&1 & pid_coord=$!
ip netns exec ns-a "$BIN" up "$TMP/a.conf" >"$TMP/a.log" 2>&1 & pid_a=$!
ip netns exec ns-b "$BIN" up "$TMP/b.conf" >"$TMP/b.log" 2>&1 & pid_b=$!
sleep 2

# fail fast (and distinctly) if any node never bound — a harness/setup race, not
# a relay failure.
if ! grep -q "node up" "$TMP/coord.log" || ! grep -q "node up" "$TMP/a.log" \
   || ! grep -q "node up" "$TMP/b.log"; then
    echo "=== result: FAIL (node failed to start) ==="
    for n in coord a b; do echo "=== node $n log ==="; cat "$TMP/$n.log"; done
    exit 1
fi

# phase 1 — A and B each reach the coordinator. This opens each NAT mapping to
# the coordinator, lets it learn their reflexive endpoints (needed to relay back
# to them), and lets A/B discover their OWN reflexive endpoints via the probe.
ip netns exec ns-a ping -c3 -i0.5 -W2 10.88.0.3 >/dev/null 2>&1 &
ip netns exec ns-b ping -c3 -i0.5 -W2 10.88.0.3 >/dev/null 2>&1 &
sleep 3

# phase 2 — A pings B. B has no endpoint, so this triggers the coordinator-
# mediated punch, which fails under symmetric NAT. After PUNCH_ATTEMPTS (3)
# give-ups (~5s each → ~15s) A trips to relay fallback and the handshake +
# traffic flow through the coordinator. Keep both sides pinging across the whole
# window so each give-up re-initiates and the counter advances.
ip netns exec ns-a ping -c60 -i0.5 -W2 10.88.0.2 >/dev/null 2>&1 &
ip netns exec ns-b ping -c60 -i0.5 -W2 10.88.0.1 >/dev/null 2>&1 &
sleep 28

echo "=== overlay ping across two symmetric NATs (relay fallback via coordinator) ==="
rc=0
ip netns exec ns-a ping -c5 -W2 10.88.0.2 || rc=1

# confirm the path is the relay, not a (impossible) direct punch: both sides must
# have tripped to relay fallback.
if grep -q "tripped to relay" "$TMP/a.log" && grep -q "tripped to relay" "$TMP/b.log"; then
    echo "relay fallback engaged on both sides (punch gave up, as expected)"
else
    echo "WARNING: expected both sides to trip to relay fallback"
    rc=1
fi

echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
if [ $rc != 0 ]; then
    for n in coord a b; do echo "=== node $n log ==="; cat "$TMP/$n.log"; done
    for ns in ns-natb ns-nata; do
        echo "=== $ns conntrack ==="
        ip netns exec "$ns" cat /proc/net/nf_conntrack 2>/dev/null | grep -i udp \
            || echo "(no udp conntrack entries)"
    done
fi
exit $rc
