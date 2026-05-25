#!/bin/bash
# IPv6 underlay end-to-end test (Linux, root): three namespaces whose nodes
# reach each other over an IPv6 underlay (fd00:50::/64) — `listen` and peer
# `endpoint` are [v6]:port — carrying an IPv4 overlay (10.88.0.0/24). Proves
# the transport is address-family-agnostic: nothing in the data path or config
# assumes IPv4 for the underlay. Zero external deps.
#
#   sudo bash crates/gnetcli/scripts/netns-underlay-v6.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
TMP=$(mktemp -d)

cleanup() {
    for i in 1 2 3; do
        kill "${pid[$i]:-}" 2>/dev/null
        ip netns del "ns$i" 2>/dev/null
    done
    ip6tables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    ip link del br-gnet 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

for i in 1 2 3; do
    out=$("$BIN" keygen)
    priv[$i]=$(echo "$out" | awk '/^private/{print $2}')
    pub[$i]=$(echo "$out" | awk '/^public/{print $2}')
    mlk[$i]=$(echo "$out" | awk '/^mlkem-public/{print $2}')
done

ip link add br-gnet type bridge
ip link set br-gnet up
# allow bridged forwarding for both families (br_netfilter + default DROP hosts)
ip6tables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
iptables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
for i in 1 2 3; do
    ip netns add "ns$i"
    # underlay is IPv6; skip DAD so the address is usable immediately
    ip netns exec "ns$i" sysctl -wq net.ipv6.conf.default.accept_dad=0
    ip netns exec "ns$i" sysctl -wq net.ipv6.conf.all.accept_dad=0
    ip link add "veth$i" type veth peer name "br$i"
    ip link set "veth$i" netns "ns$i"
    ip link set "br$i" master br-gnet
    ip link set "br$i" up
    ip -n "ns$i" addr add "fd00:50::$i/64" dev "veth$i"
    ip -n "ns$i" link set "veth$i" up
    ip -n "ns$i" link set lo up
done

# per-node config: IPv4 overlay over an IPv6 underlay ([v6]:port endpoints)
for i in 1 2 3; do
    {
        echo "private ${priv[$i]}"
        echo "address 10.88.0.$i"
        echo "listen [fd00:50::$i]:7777"
        echo "keepalive 1"
        for j in 1 2 3; do
            [ "$j" = "$i" ] && continue
            echo "peer ${pub[$j]} ${mlk[$j]} 10.88.0.$j [fd00:50::$j]:7777"
        done
    } > "$TMP/node$i.conf"
done

for i in 1 2 3; do
    ip netns exec "ns$i" "$BIN" up "$TMP/node$i.conf" &
    pid[$i]=$!
done
sleep 2

for pair in "ns1 10.88.0.2" "ns1 10.88.0.3" "ns2 10.88.0.3" "ns3 10.88.0.1"; do
    set -- $pair
    ip netns exec "$1" ping -c1 -W2 "$2" >/dev/null 2>&1
done
sleep 1

echo "=== full-gnet overlay ping over IPv6 underlay (sessions established) ==="
rc=0
ip netns exec ns1 ping -c3 -W2 10.88.0.2 || rc=1
ip netns exec ns1 ping -c3 -W2 10.88.0.3 || rc=1
ip netns exec ns2 ping -c3 -W2 10.88.0.3 || rc=1
ip netns exec ns3 ping -c3 -W2 10.88.0.1 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
exit $rc
