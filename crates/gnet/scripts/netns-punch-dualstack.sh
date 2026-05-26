#!/bin/bash
# Hole-punch test, dual-stack edition (Linux, root). Same two-NAT
# topology as netns-punch.sh — each node behind its own NAT cone with
# no public endpoint, simultaneous open against each other's reflexive
# IP — but with BOTH v4 and v6 overlay addresses. After the punch
# succeeds, ping AND ping6 over the freshly-opened tunnel.
#
# Proves the dual-stack code (address6 directive + peer <v4>,<v6>) is
# compatible with the existing hole-punch path: each side learns the
# other's underlay endpoint via simultaneous open, then the overlay
# carries both ICMPv4 and ICMPv6 over the encrypted transport.
#
# Topology (all NATs on one public bridge; each client on its own private one):
#   ns-a — br-pa — ns-nata — br-pub — ns-natb — br-pb — ns-b
#
#   sudo bash crates/gnet/scripts/netns-punch-dualstack.sh
set -u

cargo build -p gnet 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnet"
TMP=$(mktemp -d)
A_PUB=192.168.61.10; A_PORT=51001
B_PUB=192.168.61.20; B_PORT=51002

DEVS="ns-nata-pub ns-nata-pri ns-natb-pub ns-natb-pri ns-a-eth ns-b-eth \
      br-ns-natap br-ns-natar br-ns-natbp br-ns-natbr br-ns-a br-ns-b \
      br-pubd br-pad br-pbd"
NSS="ns-a ns-nata ns-b ns-natb"

cleanup() {
    kill "${pid_a:-}" "${pid_b:-}" 2>/dev/null
    for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
    for br in br-pubd br-pad br-pbd; do
        iptables -D FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
    done
    for l in $DEVS; do ip link del "$l" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

for ns in $NSS; do ip netns del "$ns" 2>/dev/null; done
for l in $DEVS; do ip link del "$l" 2>/dev/null; done
for _ in $(seq 1 100); do ip link show br-pubd >/dev/null 2>&1 || break; sleep 0.05; done

a_out=$("$BIN" keygen); b_out=$("$BIN" keygen)
a_priv=$(echo "$a_out" | awk '/^private/{print $2}')
a_pub=$(echo "$a_out"  | awk '/^public/{print $2}')
a_mlk=$(echo "$a_out"  | awk '/^mlkem-public/{print $2}')
b_priv=$(echo "$b_out" | awk '/^private/{print $2}')
b_pub=$(echo "$b_out"  | awk '/^public/{print $2}')
b_mlk=$(echo "$b_out"  | awk '/^mlkem-public/{print $2}')

for br in br-pubd br-pad br-pbd; do
    ip link add "$br" type bridge
    ip link set "$br" up
    iptables -I FORWARD -i "$br" -o "$br" -j ACCEPT 2>/dev/null
done

make_side() {
    local ns_nat=$1 ns_cli=$2 br_priv=$3 pubip=$4 port=$5 privnet=$6 cliip=$7
    ip netns add "$ns_nat"; ip netns add "$ns_cli"
    ip link add "${ns_nat}-pub" type veth peer name "br-${ns_nat}p"
    ip link set "${ns_nat}-pub" netns "$ns_nat"
    ip link set "br-${ns_nat}p" master br-pubd; ip link set "br-${ns_nat}p" up
    ip -n "$ns_nat" addr add "$pubip/24" dev "${ns_nat}-pub"
    ip -n "$ns_nat" link set "${ns_nat}-pub" up
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
make_side ns-nata ns-a br-pad "$A_PUB" "$A_PORT" 10.1.0 10.1.0.1
make_side ns-natb ns-b br-pbd "$B_PUB" "$B_PORT" 10.2.0 10.2.0.1

cat > "$TMP/a.conf" <<EOF
private $a_priv
address  10.88.0.1
address6 fd00:88::1
listen 0.0.0.0:7777
keepalive 1
peer $b_pub $b_mlk 10.88.0.2,fd00:88::2 $B_PUB:$B_PORT
EOF
cat > "$TMP/b.conf" <<EOF
private $b_priv
address  10.88.0.2
address6 fd00:88::2
listen 0.0.0.0:7777
keepalive 1
peer $a_pub $a_mlk 10.88.0.1,fd00:88::1 $A_PUB:$A_PORT
EOF

ip netns exec ns-a "$BIN" up "$TMP/a.conf" >"$TMP/a.log" 2>&1 & pid_a=$!
ip netns exec ns-b "$BIN" up "$TMP/b.conf" >"$TMP/b.log" 2>&1 & pid_b=$!
sleep 2

if ! grep -q "node up" "$TMP/a.log" || ! grep -q "node up" "$TMP/b.log"; then
    echo "=== result: FAIL (node failed to start) ==="
    echo "=== node A log ==="; cat "$TMP/a.log"
    echo "=== node B log ==="; cat "$TMP/b.log"
    exit 1
fi

# simultaneous open: both sides ping each other to trigger inits crossing
# at freshly-opened NAT ports. Steady ping + keepalive holds mappings open.
ip netns exec ns-a ping  -c10 -i 0.5 -W2 10.88.0.2     >/dev/null 2>&1 &
ip netns exec ns-b ping  -c10 -i 0.5 -W2 10.88.0.1     >/dev/null 2>&1 &
ip netns exec ns-a ping6 -c10 -i 0.5 -W2 fd00:88::2    >/dev/null 2>&1 &
ip netns exec ns-b ping6 -c10 -i 0.5 -W2 fd00:88::1    >/dev/null 2>&1 &
sleep 6

# Now the punch should be done and the tunnel up. Final assertion ping:
# need at least 2 echo replies in 3 to count as PASS (allow first-packet
# loss during late establishment).
PASS=0; FAIL=0
final_ping() {
    local desc=$1 ns=$2 target=$3 family=$4
    local cmd
    if [[ $family == 6 ]]; then cmd="ping6"; else cmd="ping"; fi
    local got
    got=$(ip netns exec "$ns" $cmd -c3 -i 0.3 -W2 "$target" 2>&1 | grep -oE '[0-9]+ received' | head -1 | awk '{print $1}')
    got=${got:-0}
    if [[ "$got" -ge 2 ]]; then
        echo "  PASS $desc: $got/3 received"; PASS=$((PASS+1))
    else
        echo "  FAIL $desc: $got/3 received"; FAIL=$((FAIL+1))
    fi
}
final_ping "ns-a -> ns-b v4 (post-punch)" ns-a 10.88.0.2     4
final_ping "ns-b -> ns-a v4 (post-punch)" ns-b 10.88.0.1     4
final_ping "ns-a -> ns-b v6 (post-punch)" ns-a fd00:88::2    6
final_ping "ns-b -> ns-a v6 (post-punch)" ns-b fd00:88::1    6

echo
echo "=== summary: $PASS PASS / $FAIL FAIL (need 4/0 for dual-stack punch L2) ==="
echo "=== node A log tail ==="; tail -5 "$TMP/a.log"
echo "=== node B log tail ==="; tail -5 "$TMP/b.log"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
