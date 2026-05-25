#!/bin/bash
# IPv6 overlay end-to-end test (Linux, root): three namespaces on a shared
# IPv4 underlay bridge, each running `meshcli up` with an IPv6 overlay address
# (fd00:88::/64) on the TUN, then ping6 across the overlay. Proves the overlay
# is dual-stack — IPv6 dst-IP routing, /64 TUN configuration, and IPv6 ICMP
# over the (IPv4) encrypted transport — with zero external deps.
#
#   sudo bash crates/meshcli/scripts/netns-mesh-v6.sh
set -u

cargo build -p meshcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/meshcli"
TMP=$(mktemp -d)

cleanup() {
    for i in 1 2 3; do
        kill "${pid[$i]:-}" 2>/dev/null
        ip netns del "ns$i" 2>/dev/null
    done
    iptables -D FORWARD -i br-mesh -o br-mesh -j ACCEPT 2>/dev/null
    ip link del br-mesh 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

for i in 1 2 3; do
    out=$("$BIN" keygen)
    priv[$i]=$(echo "$out" | awk '/^private/{print $2}')
    pub[$i]=$(echo "$out" | awk '/^public/{print $2}')
    mlk[$i]=$(echo "$out" | awk '/^mlkem-public/{print $2}')
done

# IPv4 underlay bridge (the encrypted transport rides over IPv4 here)
ip link add br-mesh type bridge
ip link set br-mesh up
iptables -I FORWARD -i br-mesh -o br-mesh -j ACCEPT 2>/dev/null
for i in 1 2 3; do
    ip netns add "ns$i"
    # the overlay TUN is point-to-point; skip IPv6 DAD so the /64 address is
    # usable immediately instead of sitting tentative.
    ip netns exec "ns$i" sysctl -wq net.ipv6.conf.default.accept_dad=0
    ip netns exec "ns$i" sysctl -wq net.ipv6.conf.all.accept_dad=0
    ip link add "veth$i" type veth peer name "br$i"
    ip link set "veth$i" netns "ns$i"
    ip link set "br$i" master br-mesh
    ip link set "br$i" up
    ip -n "ns$i" addr add "192.168.50.$i/24" dev "veth$i"
    ip -n "ns$i" link set "veth$i" up
    ip -n "ns$i" link set lo up
done

# per-node config: IPv6 overlay address, IPv4 underlay endpoints
for i in 1 2 3; do
    {
        echo "private ${priv[$i]}"
        echo "address fd00:88::$i"
        echo "listen 192.168.50.$i:7777"
        echo "keepalive 1"
        for j in 1 2 3; do
            [ "$j" = "$i" ] && continue
            echo "peer ${pub[$j]} ${mlk[$j]} fd00:88::$j 192.168.50.$j:7777"
        done
    } > "$TMP/node$i.conf"
done

for i in 1 2 3; do
    ip netns exec "ns$i" "$BIN" up "$TMP/node$i.conf" &
    pid[$i]=$!
done
sleep 2

# warmup: first packet to each peer triggers an on-demand handshake (dropped)
for pair in "ns1 fd00:88::2" "ns1 fd00:88::3" "ns2 fd00:88::3" "ns3 fd00:88::1"; do
    set -- $pair
    ip netns exec "$1" ping -6 -c1 -W2 "$2" >/dev/null 2>&1
done
sleep 1

echo "=== full-mesh IPv6 overlay ping (sessions established) ==="
rc=0
ip netns exec ns1 ping -6 -c3 -W2 fd00:88::2 || rc=1
ip netns exec ns1 ping -6 -c3 -W2 fd00:88::3 || rc=1
ip netns exec ns2 ping -6 -c3 -W2 fd00:88::3 || rc=1
ip netns exec ns3 ping -6 -c3 -W2 fd00:88::1 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
exit $rc
