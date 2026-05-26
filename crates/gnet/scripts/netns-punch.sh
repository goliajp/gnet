#!/bin/bash
# Hole-punch core test (Linux, root): two nodes each behind their own NAT, with
# no public endpoint, connect directly when each is configured with the other's
# reflexive (public) endpoint. Both initiate, so each NAT opens its mapping
# outbound and the peer's init arrives on the freshly-opened port — the classic
# simultaneous open. This verifies the transport can punch with no new code;
# only the endpoint *discovery/exchange* is automated separately.
#
# Topology (all NATs on one public bridge; each client on its own private one):
#   ns-a — br-pa — ns-nata — br-pub — ns-natb — br-pb — ns-b
#
#   sudo bash crates/gnet/scripts/netns-punch.sh
set -u

cargo build -p gnet 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnet"
TMP=$(mktemp -d)
A_PUB=192.168.60.10; A_PORT=50001
B_PUB=192.168.60.20; B_PORT=50002

# Every device this script creates, host-side. The veth ns ends (ns-*-pub etc.)
# normally ride into their namespace, but a `ip link set ... netns` that lost a
# teardown race in a previous run can strand one in the host ns; the bridge-side
# peers (br-ns-*) and bridges stay host-side by design. List them all so cleanup
# and pre-clean can delete whatever leaked.
DEVS="ns-nata-pub ns-nata-pri ns-natb-pub ns-natb-pri ns-a-eth ns-b-eth \
      br-ns-natap br-ns-natar br-ns-natbp br-ns-natbr br-ns-a br-ns-b \
      br-pub br-pa br-pb"
NSS="ns-a ns-nata ns-b ns-natb"

cleanup() {
    kill "${pid_a:-}" "${pid_b:-}" 2>/dev/null
    for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
    for br in br-pub br-pa br-pb; do
        iptables -D FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
    done
    # delete host-side veth ends (and any stranded by a lost netns-move race)
    # explicitly: `ip netns del` won't reap a veth left in the host ns, and a
    # leftover makes the next `ip link add` fail with "File exists", leaving a
    # node to start with its address unconfigured (bind → EADDRNOTAVAIL).
    for l in $DEVS; do ip link del "$l" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

# Pre-clean residue from an interrupted run and wait for the kernel to release
# the bridge name before recreating: device teardown is asynchronous, so a rapid
# re-run otherwise races into "File exists" and a node starts unconfigured. Same
# fix as netns-glare.sh.
for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
for l in $DEVS; do ip link del "$l" 2>/dev/null; done
for _ in $(seq 1 100); do ip link show br-pub >/dev/null 2>&1 || break; sleep 0.05; done

a_out=$("$BIN" keygen); b_out=$("$BIN" keygen)
a_priv=$(echo "$a_out" | awk '/^private/{print $2}')
a_pub=$(echo "$a_out"  | awk '/^public/{print $2}')
a_mlk=$(echo "$a_out"  | awk '/^mlkem-public/{print $2}')
b_priv=$(echo "$b_out" | awk '/^private/{print $2}')
b_pub=$(echo "$b_out"  | awk '/^public/{print $2}')
b_mlk=$(echo "$b_out"  | awk '/^mlkem-public/{print $2}')

for br in br-pub br-pa br-pb; do
    ip link add "$br" type bridge
    ip link set "$br" up
    iptables -I FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
done

# one NAT gateway + one client behind it
make_side() {
    local ns_nat=$1 ns_cli=$2 br_priv=$3 pubip=$4 port=$5 privnet=$6 cliip=$7
    ip netns add "$ns_nat"; ip netns add "$ns_cli"
    # NAT public leg on br-pub
    ip link add "${ns_nat}-pub" type veth peer name "br-${ns_nat}p"
    ip link set "${ns_nat}-pub" netns "$ns_nat"
    ip link set "br-${ns_nat}p" master br-pub; ip link set "br-${ns_nat}p" up
    ip -n "$ns_nat" addr add "$pubip/24" dev "${ns_nat}-pub"
    ip -n "$ns_nat" link set "${ns_nat}-pub" up
    # netem RTT on the public leg: with ~20ms each way, each side's outbound
    # SNAT flow commits before the peer's inbound packet arrives — the real-
    # network timing a zero-RTT same-host netns otherwise lacks, which is what
    # makes the conntrack tuple-collision deadlock disappear (RFC 20260525 CP1).
    ip netns exec "$ns_nat" tc qdisc add dev "${ns_nat}-pub" root netem delay 20ms
    # NAT private leg on br_priv
    ip link add "${ns_nat}-pri" type veth peer name "br-${ns_nat}r"
    ip link set "${ns_nat}-pri" netns "$ns_nat"
    ip link set "br-${ns_nat}r" master "$br_priv"; ip link set "br-${ns_nat}r" up
    ip -n "$ns_nat" addr add "$privnet.254/24" dev "${ns_nat}-pri"
    ip -n "$ns_nat" link set "${ns_nat}-pri" up
    ip -n "$ns_nat" link set lo up
    ip netns exec "$ns_nat" sysctl -wq net.ipv4.ip_forward=1
    ip netns exec "$ns_nat" iptables -t nat -A POSTROUTING -o "${ns_nat}-pub" \
        -s "$cliip" -p udp -j SNAT --to-source "$pubip:$port"
    # client behind the NAT
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

# each side knows ONLY the other's reflexive (public) endpoint — no direct path
cat > "$TMP/a.conf" <<EOF
private $a_priv
address 10.88.0.1
listen 0.0.0.0:7777
keepalive 1
peer $b_pub $b_mlk 10.88.0.2 $B_PUB:$B_PORT
EOF
cat > "$TMP/b.conf" <<EOF
private $b_priv
address 10.88.0.2
listen 0.0.0.0:7777
keepalive 1
peer $a_pub $a_mlk 10.88.0.1 $A_PUB:$A_PORT
EOF

ip netns exec ns-a "$BIN" up "$TMP/a.conf" >"$TMP/a.log" 2>&1 & pid_a=$!
ip netns exec ns-b "$BIN" up "$TMP/b.conf" >"$TMP/b.log" 2>&1 & pid_b=$!
sleep 2

# fail fast (and distinctly) if a node never bound — a harness/setup race, not a
# punch failure, and must not be mistaken for punch flakiness.
if ! grep -q "node up" "$TMP/a.log" || ! grep -q "node up" "$TMP/b.log"; then
    echo "=== result: FAIL (node failed to start) ==="
    echo "=== node A log ==="; cat "$TMP/a.log"
    echo "=== node B log ==="; cat "$TMP/b.log"
    exit 1
fi

# kick off the simultaneous open: the first ICMP on each side triggers an init
# (opening that NAT's outbound mapping), and from there the maintenance thread
# retransmits msg1 on a timer until the two inits cross a freshly-opened port.
# The steady ping + keepalive holds both NAT mappings open meanwhile.
ip netns exec ns-a ping -c10 -i 0.5 -W2 10.88.0.2 >/dev/null 2>&1 &
ip netns exec ns-b ping -c10 -i 0.5 -W2 10.88.0.1 >/dev/null 2>&1 &
sleep 6

echo "=== overlay ping across two NATs (hole punched) ==="
rc=0
ip netns exec ns-a ping -c5 -W2 10.88.0.2 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
if [ $rc != 0 ]; then
    echo "=== node A log ==="; cat "$TMP/a.log"
    echo "=== node B log ==="; cat "$TMP/b.log"
    # lx64 has no conntrack CLI; read the namespace's conntrack table directly.
    echo "=== ns-natb conntrack (B's NAT) ==="
    ip netns exec ns-natb cat /proc/net/nf_conntrack 2>/dev/null | grep -i udp \
        || echo "(no udp conntrack entries)"
fi
exit $rc
