#!/bin/bash
# Dual-stack overlay end-to-end test (Linux, root). Two namespaces on a
# shared IPv4 underlay bridge, each running `gnet up` with BOTH a v4
# (10.42.42.X/24) AND v6 (fd8d:f090:2ebb::X/64) overlay address on the
# same TUN. Ping AND ping6 over the overlay in both directions.
#
# Proves the v0.1 dual-stack pipeline end-to-end at the data plane:
#   - `address` + `address6` directives parse and apply both families
#   - `peer ... <v4>,<v6>` syntax populates both vip slots
#   - daemon routing (`by_vip`) matches incoming overlay packets in
#     either family to the right peer
#   - encrypted Noise+ML-KEM transport carries both ICMPv4 and ICMPv6
#
#   sudo bash crates/gnet/scripts/netns-dualstack.sh
set -u

cargo build -p gnet 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnet"
TMP=$(mktemp -d)
declare -A priv pub mlk pid

cleanup() {
    for i in 1 2; do
        [[ -n "${pid[$i]:-}" ]] && kill "${pid[$i]}" 2>/dev/null || true
        ip netns del "ns$i" 2>/dev/null || true
    done
    iptables -D FORWARD -i br-ds -o br-ds -j ACCEPT 2>/dev/null || true
    ip link del br-ds 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

for i in 1 2; do
    out=$("$BIN" keygen)
    priv[$i]=$(echo "$out" | awk '/^private/{print $2}')
    pub[$i]=$(echo "$out" | awk '/^public/{print $2}')
    mlk[$i]=$(echo "$out" | awk '/^mlkem-public/{print $2}')
done

# IPv4 underlay bridge shared by both nodes
ip link add br-ds type bridge
ip addr add 10.7.0.1/24 dev br-ds
ip link set br-ds up
iptables -A FORWARD -i br-ds -o br-ds -j ACCEPT 2>/dev/null || true

for i in 1 2; do
    ip netns add ns$i
    ip link add veth-ds$i type veth peer name vbr-ds$i
    ip link set vbr-ds$i master br-ds up
    ip link set veth-ds$i netns ns$i
    ip -n ns$i addr add 10.7.0.$((i+1))/24 dev veth-ds$i
    ip -n ns$i link set lo up
    ip -n ns$i link set veth-ds$i up
done

cat > "$TMP/n1.conf" <<EOF
private ${priv[1]}
address  10.42.42.1
address6 fd8d:f090:2ebb::1
listen 0.0.0.0:51820
peer ${pub[2]} ${mlk[2]} 10.42.42.2,fd8d:f090:2ebb::2 10.7.0.3:51820
EOF
cat > "$TMP/n2.conf" <<EOF
private ${priv[2]}
address  10.42.42.2
address6 fd8d:f090:2ebb::2
listen 0.0.0.0:51820
peer ${pub[1]} ${mlk[1]} 10.42.42.1,fd8d:f090:2ebb::1 10.7.0.2:51820
EOF

ip netns exec ns1 "$BIN" up "$TMP/n1.conf" > "$TMP/n1.log" 2>&1 &
pid[1]=$!
ip netns exec ns2 "$BIN" up "$TMP/n2.conf" > "$TMP/n2.log" 2>&1 &
pid[2]=$!
sleep 3

PASS=0; FAIL=0
run_ping() {
    local desc=$1 ns=$2 target=$3 family=$4
    local cmd
    if [[ $family == 6 ]]; then cmd="ping6"; else cmd="ping"; fi
    echo "--- $desc ---"
    if ip netns exec "$ns" $cmd -c3 -W2 "$target"; then
        echo "  >> PASS: $desc"; PASS=$((PASS+1))
    else
        echo "  >> FAIL: $desc"; FAIL=$((FAIL+1))
    fi
}

run_ping "ns1 -> ns2 (v4 overlay)" ns1 10.42.42.2 4
run_ping "ns1 -> ns2 (v6 overlay)" ns1 fd8d:f090:2ebb::2 6
run_ping "ns2 -> ns1 (v4 overlay)" ns2 10.42.42.1 4
run_ping "ns2 -> ns1 (v6 overlay)" ns2 fd8d:f090:2ebb::1 6

echo
echo "=== summary: $PASS PASS / $FAIL FAIL (need 4/0 for L2 dual-stack) ==="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
