#!/bin/bash
# Reproducible multi-peer end-to-end test (Linux, root): three network
# namespaces on a shared underlay bridge, each running `gnetcli up` with the
# other two configured as static peers, then ping across the overlay. Proves
# the multi-peer data plane — per-destination routing, on-demand Noise_IK
# handshakes, and many concurrent sessions — with zero external deps.
#
#   sudo bash crates/gnetcli/scripts/netns-gnet.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
TMP=$(mktemp -d)

cleanup() {
    for i in 1 2 3; do
        kill "${pid[$i]:-}" 2>/dev/null
        ip netns del "ns$i" 2>/dev/null
    done
    # remove our targeted bridge FORWARD rule (added below); leave global
    # policy untouched.
    iptables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    ip link del br-gnet 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# generate keypairs (X25519 + derived ML-KEM public for the PQ hybrid)
for i in 1 2 3; do
    out=$("$BIN" keygen)
    priv[$i]=$(echo "$out" | awk '/^private/{print $2}')
    pub[$i]=$(echo "$out" | awk '/^public/{print $2}')
    mlk[$i]=$(echo "$out" | awk '/^mlkem-public/{print $2}')
done

# underlay: a bridge with one veth per namespace (192.168.50.0/24)
ip link add br-gnet type bridge
ip link set br-gnet up
# allow traffic switched within our test bridge — needed where br_netfilter
# routes bridged frames through iptables with a default-DROP FORWARD policy
# (e.g. docker hosts). Targeted to br-gnet only; removed on cleanup.
iptables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
for i in 1 2 3; do
    ip netns add "ns$i"
    ip link add "veth$i" type veth peer name "br$i"
    ip link set "veth$i" netns "ns$i"
    ip link set "br$i" master br-gnet
    ip link set "br$i" up
    ip -n "ns$i" addr add "192.168.50.$i/24" dev "veth$i"
    ip -n "ns$i" link set "veth$i" up
    ip -n "ns$i" link set lo up
done

# write a config per node: own identity + the other two as peers. a 1s
# persistent keepalive exercises the empty-transport-packet path live (each
# established peer gets an encrypted 0-length datagram per second, which the
# receiver decrypts and drops rather than forwarding to the TUN).
for i in 1 2 3; do
    {
        echo "private ${priv[$i]}"
        echo "address 10.88.0.$i"
        echo "listen 192.168.50.$i:7777"
        echo "keepalive 1"
        for j in 1 2 3; do
            [ "$j" = "$i" ] && continue
            echo "peer ${pub[$j]} ${mlk[$j]} 10.88.0.$j 192.168.50.$j:7777"
        done
    } > "$TMP/node$i.conf"
done

# start the three nodes
for i in 1 2 3; do
    ip netns exec "ns$i" "$BIN" up "$TMP/node$i.conf" &
    pid[$i]=$!
done
sleep 2

# warmup: the first packet to each peer triggers an on-demand Noise_IK
# handshake and is dropped (as in WireGuard), so prime every session first.
for pair in "ns1 10.88.0.2" "ns1 10.88.0.3" "ns2 10.88.0.3" "ns3 10.88.0.1"; do
    set -- $pair
    ip netns exec "$1" ping -c1 -W2 "$2" >/dev/null 2>&1
done
sleep 1

echo "=== full-gnet overlay ping (sessions established) ==="
rc=0
ip netns exec ns1 ping -c3 -W2 10.88.0.2 || rc=1   # 1 -> 2
ip netns exec ns1 ping -c3 -W2 10.88.0.3 || rc=1   # 1 -> 3
ip netns exec ns2 ping -c3 -W2 10.88.0.3 || rc=1   # 2 -> 3
ip netns exec ns3 ping -c3 -W2 10.88.0.1 || rc=1   # 3 -> 1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
exit $rc
