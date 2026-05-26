#!/bin/bash
# Anti-replay reorder test (Linux, root): two network namespaces on a shared
# underlay bridge, with netem reordering the underlay UDP packets. A flood of
# overlay pings at a tight interval forces genuine reordering; the transport's
# sliding-window anti-replay must still authenticate the out-of-order packets,
# so loss stays at 0%. Without the window (strict in-order nonce) a reordered
# packet fails to decrypt and the session wedges — loss would be severe.
#
#   sudo bash crates/gnet/scripts/netns-reorder.sh
set -u

cargo build -p gnet 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnet"
TMP=$(mktemp -d)

cleanup() {
    for i in 1 2; do
        kill "${pid[$i]:-}" 2>/dev/null
        ip netns del "ns$i" 2>/dev/null
    done
    iptables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    ip link del br-gnet 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

for i in 1 2; do
    out=$("$BIN" keygen)
    priv[$i]=$(echo "$out" | awk '/^private/{print $2}')
    pub[$i]=$(echo "$out" | awk '/^public/{print $2}')
    mlk[$i]=$(echo "$out" | awk '/^mlkem-public/{print $2}')
done

# underlay bridge with one veth per namespace (192.168.51.0/24)
ip link add br-gnet type bridge
ip link set br-gnet up
iptables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
for i in 1 2; do
    ip netns add "ns$i"
    ip link add "veth$i" type veth peer name "br$i"
    ip link set "veth$i" netns "ns$i"
    ip link set "br$i" master br-gnet
    ip link set "br$i" up
    ip -n "ns$i" addr add "192.168.51.$i/24" dev "veth$i"
    ip -n "ns$i" link set "veth$i" up
    ip -n "ns$i" link set lo up
done

# reorder the underlay in both namespaces: delay 30ms ± 15ms with 40% of
# packets sent ahead of schedule (no loss% — pure reordering).
for i in 1 2; do
    ip netns exec "ns$i" tc qdisc add dev "veth$i" root \
        netem delay 30ms 15ms reorder 40% 50%
done

for i in 1 2; do
    {
        echo "private ${priv[$i]}"
        echo "address 10.99.0.$i"
        echo "listen 192.168.51.$i:7777"
        j=$((3 - i))
        echo "peer ${pub[$j]} ${mlk[$j]} 10.99.0.$j 192.168.51.$j:7777"
    } > "$TMP/node$i.conf"
done

for i in 1 2; do
    ip netns exec "ns$i" "$BIN" up "$TMP/node$i.conf" &
    pid[$i]=$!
done
sleep 2

# warmup: prime the session (first packet triggers the handshake and is dropped)
ip netns exec ns1 ping -c1 -W2 10.99.0.2 >/dev/null 2>&1
sleep 1

echo "=== reordered overlay flood (netem reorder on the underlay) ==="
# 100 packets at 10ms spacing: the 30ms delay genuinely reorders them.
out=$(ip netns exec ns1 ping -c 100 -i 0.01 -W2 10.99.0.2)
echo "$out" | tail -3
loss=$(echo "$out" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
echo "=== loss under reorder: ${loss}% ==="
# pure reorder (no netem loss) must round-trip fully with anti-replay.
[ "${loss:-100}" -eq 0 ] && { echo "=== result: PASS ==="; exit 0; } || { echo "=== result: FAIL ==="; exit 1; }
