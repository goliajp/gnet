#!/bin/bash
# Reflexive-endpoint discovery test (Linux, root): a node behind a NAT learns
# its own public (reflexive) endpoint by probing a reachable peer, which echoes
# the source address it observes (STUN-like). The NAT'd node must log the
# NAT's public address:port, not its private one. This is the first building
# block of hole punching. Uses a fixed-port SNAT (no conntrack tooling needed).
#
#   sudo bash crates/gnetcli/scripts/netns-reflexive.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
TMP=$(mktemp -d)
NAT_PUB=192.168.52.254
NAT_PORT=45000

cleanup() {
    kill "${pid_pub:-}" "${pid_cli:-}" 2>/dev/null
    for ns in ns-pub ns-nat ns-cli; do ip netns del "$ns" 2>/dev/null; done
    iptables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i br-priv -o br-priv -j ACCEPT 2>/dev/null
    ip link del br-gnet 2>/dev/null
    ip link del br-priv 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

pub_out=$("$BIN" keygen); cli_out=$("$BIN" keygen)
pub_priv=$(echo "$pub_out" | awk '/^private/{print $2}')
pub_pub=$(echo "$pub_out"  | awk '/^public/{print $2}')
pub_mlk=$(echo "$pub_out"  | awk '/^mlkem-public/{print $2}')
cli_priv=$(echo "$cli_out" | awk '/^private/{print $2}')
cli_pub=$(echo "$cli_out"  | awk '/^public/{print $2}')
cli_mlk=$(echo "$cli_out"  | awk '/^mlkem-public/{print $2}')

ip link add br-gnet type bridge; ip link set br-gnet up
ip link add br-priv type bridge; ip link set br-priv up
iptables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
iptables -I FORWARD -i br-priv -o br-priv -j ACCEPT 2>/dev/null

ip netns add ns-pub
ip netns add ns-nat
ip netns add ns-cli

# ns-pub (B): public node
ip link add veth-pub type veth peer name br-pub
ip link set veth-pub netns ns-pub
ip link set br-pub master br-gnet; ip link set br-pub up
ip -n ns-pub addr add 192.168.52.1/24 dev veth-pub
ip -n ns-pub link set veth-pub up
ip -n ns-pub link set lo up

# ns-nat: NAT gateway, SNATs the client to a fixed public port
ip link add nat-pub type veth peer name br-natpub
ip link set nat-pub netns ns-nat
ip link set br-natpub master br-gnet; ip link set br-natpub up
ip -n ns-nat addr add $NAT_PUB/24 dev nat-pub
ip -n ns-nat link set nat-pub up
ip link add nat-priv type veth peer name br-natpriv
ip link set nat-priv netns ns-nat
ip link set br-natpriv master br-priv; ip link set br-natpriv up
ip -n ns-nat addr add 10.77.0.254/24 dev nat-priv
ip -n ns-nat link set nat-priv up
ip -n ns-nat link set lo up
ip netns exec ns-nat sysctl -wq net.ipv4.ip_forward=1
ip netns exec ns-nat iptables -t nat -A POSTROUTING -o nat-pub -s 10.77.0.1 \
    -p udp -j SNAT --to-source "$NAT_PUB:$NAT_PORT"

# ns-cli (A): behind the NAT
ip link add veth-cli type veth peer name br-cli
ip link set veth-cli netns ns-cli
ip link set br-cli master br-priv; ip link set br-cli up
ip -n ns-cli addr add 10.77.0.1/24 dev veth-cli
ip -n ns-cli link set veth-cli up
ip -n ns-cli link set lo up
ip -n ns-cli route add default via 10.77.0.254

cat > "$TMP/pub.conf" <<EOF
private $pub_priv
address 10.88.0.1
listen 192.168.52.1:7777
peer $cli_pub $cli_mlk 10.88.0.2
EOF
cat > "$TMP/cli.conf" <<EOF
private $cli_priv
address 10.88.0.2
listen 0.0.0.0:7777
peer $pub_pub $pub_mlk 10.88.0.1 192.168.52.1:7777
EOF

ip netns exec ns-pub "$BIN" up "$TMP/pub.conf" >/dev/null 2>&1 & pid_pub=$!
ip netns exec ns-cli "$BIN" up "$TMP/cli.conf" >"$TMP/cli.log" 2>&1 & pid_cli=$!

# the client probes on its first maintenance tick; give probe + reply + log time
sleep 4

echo "=== client log (reflexive discovery) ==="
grep -i "reflexive" "$TMP/cli.log" || true
want="discovered reflexive endpoint: $NAT_PUB:$NAT_PORT"
if grep -qF "$want" "$TMP/cli.log"; then
    echo "=== result: PASS (learned public endpoint $NAT_PUB:$NAT_PORT) ==="
    exit 0
else
    echo "=== result: FAIL (expected '$want') ==="
    exit 1
fi
