#!/bin/bash
# Coordinator-synchronized hole-punch test (Linux, root): two nodes each behind
# their own NAT, with NO direct endpoint for each other — they only know a
# mutually-reachable public coordinator. A's overlay traffic to B triggers a
# DCUtR-style rendezvous through the coordinator: endpoints are exchanged, the
# coordinator-path RTT is measured, and both sides dial in sync (origin after
# RTT/2, target on the sync) so their first packets cross at the path midpoint.
#
# Like netns-punch.sh this keeps a netem delay on each NAT public leg: a hole
# punch needs RTT > 0 so each side's outbound flow commits before the peer's
# packet arrives (a ~zero-RTT same-host race has a sub-millisecond window no
# userspace timer can hit). What CP2 adds over CP1 is that A and B never know
# each other's endpoint — the coordinator discovers and exchanges them, and the
# RTT/2 sync aligns the two dials to within the netem window, so the punch is
# reliable rather than a lucky race.
#
# Topology (all public legs + the coordinator on one public bridge):
#   ns-a — br-pa — ns-nata — br-pub — ns-natb — br-pb — ns-b
#                              |
#                          ns-coord (public, no NAT)
#
#   sudo bash crates/gnetcli/scripts/netns-punch-sync.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
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

# one NAT gateway + one client behind it (full-cone: fixed-port SNAT). No netem.
make_side() {
    local ns_nat=$1 ns_cli=$2 br_priv=$3 pubip=$4 port=$5 privnet=$6 cliip=$7
    ip netns add "$ns_nat"; ip netns add "$ns_cli"
    ip link add "${ns_nat}-pub" type veth peer name "br-${ns_nat}p"
    ip link set "${ns_nat}-pub" netns "$ns_nat"
    ip link set "br-${ns_nat}p" master br-pub; ip link set "br-${ns_nat}p" up
    ip -n "$ns_nat" addr add "$pubip/24" dev "${ns_nat}-pub"
    ip -n "$ns_nat" link set "${ns_nat}-pub" up
    # netem RTT on the public leg so each side's outbound SNAT flow commits
    # before the peer's inbound packet arrives (see netns-punch.sh / RFC CP1).
    ip netns exec "$ns_nat" tc qdisc add dev "${ns_nat}-pub" root netem delay 20ms
    ip link add "${ns_nat}-pri" type veth peer name "br-${ns_nat}r"
    ip link set "${ns_nat}-pri" netns "$ns_nat"
    ip link set "br-${ns_nat}r" master "$br_priv"; ip link set "br-${ns_nat}r" up
    ip -n "$ns_nat" addr add "$privnet.254/24" dev "${ns_nat}-pri"
    ip -n "$ns_nat" link set "${ns_nat}-pri" up
    ip -n "$ns_nat" link set lo up
    ip netns exec "$ns_nat" sysctl -wq net.ipv4.ip_forward=1
    ip netns exec "$ns_nat" iptables -t nat -A POSTROUTING -o "${ns_nat}-pub" \
        -s "$cliip" -p udp -j SNAT --to-source "$pubip:$port"
    ip link add "${ns_cli}-eth" type veth peer name "br-${ns_cli}"
    ip link set "${ns_cli}-eth" netns "$ns_cli"
    ip link set "br-${ns_cli}" master "$br_priv"; ip link set "br-${ns_cli}" up
    ip -n "$ns_cli" addr add "$cliip/24" dev "${ns_cli}-eth"
    ip -n "$ns_cli" link set "${ns_cli}-eth" up
    ip -n "$ns_cli" link set lo up
    ip -n "$ns_cli" route add default via "$privnet.254"
}
make_side ns-nata ns-a br-pa "$A_PUB" "$A_PORT" 10.1.0 10.1.0.1
make_side ns-natb ns-b br-pb "$B_PUB" "$B_PORT" 10.2.0 10.2.0.1

# coordinator: a plain public node on br-pub, no NAT (same /24 as the NAT public
# legs, so it reaches A_PUB/B_PUB directly at layer 2).
ip netns add ns-coord
ip link add ns-coord-pub type veth peer name br-ns-coord
ip link set ns-coord-pub netns ns-coord
ip link set br-ns-coord master br-pub; ip link set br-ns-coord up
ip -n ns-coord addr add "$COORD_PUB/24" dev ns-coord-pub
ip -n ns-coord link set ns-coord-pub up
ip -n ns-coord link set lo up

# A and B know the coordinator's endpoint but NOT each other's — the punch must
# discover and exchange the reflexive endpoints. The coordinator knows neither
# A nor B by endpoint; it learns them when they first reach out.
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
# a punch failure.
if ! grep -q "node up" "$TMP/coord.log" || ! grep -q "node up" "$TMP/a.log" \
   || ! grep -q "node up" "$TMP/b.log"; then
    echo "=== result: FAIL (node failed to start) ==="
    for n in coord a b; do echo "=== node $n log ==="; cat "$TMP/$n.log"; done
    exit 1
fi

# phase 1 — A and B each reach the coordinator. This opens each NAT mapping,
# lets the coordinator learn their reflexive endpoints (needed to relay), and
# lets A/B discover their OWN reflexive endpoints via the maintenance probe.
ip netns exec ns-a ping -c3 -i0.5 -W2 10.88.0.3 >/dev/null 2>&1 &
ip netns exec ns-b ping -c3 -i0.5 -W2 10.88.0.3 >/dev/null 2>&1 &
sleep 3

# phase 2 — A pings B. B has no endpoint, so this triggers the coordinator-
# mediated synchronized punch. B pings A too (bidirectional → exercises the
# glare path where both sides are origins).
ip netns exec ns-a ping -c10 -i0.5 -W2 10.88.0.2 >/dev/null 2>&1 &
ip netns exec ns-b ping -c10 -i0.5 -W2 10.88.0.1 >/dev/null 2>&1 &
sleep 6

echo "=== overlay ping across two NATs (synchronized punch via coordinator) ==="
rc=0
ip netns exec ns-a ping -c5 -W2 10.88.0.2 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
if [ $rc != 0 ]; then
    for n in coord a b; do echo "=== node $n log ==="; cat "$TMP/$n.log"; done
    # lx64 has no conntrack CLI; read the namespace conntrack tables directly.
    for ns in ns-natb ns-nata; do
        echo "=== $ns conntrack ==="
        ip netns exec "$ns" cat /proc/net/nf_conntrack 2>/dev/null | grep -i udp \
            || echo "(no udp conntrack entries)"
    done
fi
exit $rc
