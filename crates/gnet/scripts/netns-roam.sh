#!/bin/bash
# Endpoint-roaming test (Linux, root): a peer's source address changes
# mid-session (as a NAT rebind or device move would do), and the other side
# must follow it. The public node demuxes transport by session index (not by
# source address) and updates the peer endpoint from any authenticated packet,
# so the link survives the move. Without roaming, the node keeps sending to the
# old address and the link dies after the switch.
#
# No NAT/conntrack needed: the client binds 0.0.0.0 and we flip which local
# source IP it uses (.10 -> .11), removing the old one so replies to the stale
# endpoint cannot reach it — making roaming the sole discriminator.
#
#   sudo bash crates/gnetcli/scripts/netns-roam.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
TMP=$(mktemp -d)

cleanup() {
    kill "${pid_pub:-}" "${pid_cli:-}" 2>/dev/null
    for ns in ns-pub ns-cli; do ip netns del "$ns" 2>/dev/null; done
    iptables -D FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null
    ip link del br-gnet 2>/dev/null
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
iptables -I FORWARD -i br-gnet -o br-gnet -j ACCEPT 2>/dev/null

# ns-pub (A): the public node
ip netns add ns-pub
ip link add veth-pub type veth peer name br-pub
ip link set veth-pub netns ns-pub
ip link set br-pub master br-gnet; ip link set br-pub up
ip -n ns-pub addr add 192.168.52.1/24 dev veth-pub
ip -n ns-pub link set veth-pub up
ip -n ns-pub link set lo up

# ns-cli (B): two candidate source IPs (.10 active, .11 for the move)
ip netns add ns-cli
ip link add veth-cli type veth peer name br-cli
ip link set veth-cli netns ns-cli
ip link set br-cli master br-gnet; ip link set br-cli up
ip -n ns-cli addr add 192.168.52.10/24 dev veth-cli
ip -n ns-cli link set veth-cli up
ip -n ns-cli link set lo up
# pin the source used to reach A
ip -n ns-cli route add 192.168.52.1/32 dev veth-cli src 192.168.52.10

# A learns B's endpoint from B's handshake (no endpoint in A's config).
cat > "$TMP/pub.conf" <<EOF
private $pub_priv
address 10.88.1.1
listen 192.168.52.1:7777
keepalive 1
peer $cli_pub $cli_mlk 10.88.1.2
EOF
# B binds 0.0.0.0 (so it keeps receiving as its source IP changes) and
# initiates to A.
cat > "$TMP/cli.conf" <<EOF
private $cli_priv
address 10.88.1.2
listen 0.0.0.0:7777
keepalive 1
peer $pub_pub $pub_mlk 10.88.1.1 192.168.52.1:7777
EOF

ip netns exec ns-pub "$BIN" up "$TMP/pub.conf" & pid_pub=$!
ip netns exec ns-cli "$BIN" up "$TMP/cli.conf" & pid_cli=$!
sleep 2

echo "=== before move (client source 192.168.52.10) ==="
ip netns exec ns-cli ping -c1 -W2 10.88.1.1 >/dev/null 2>&1   # warmup/handshake
sleep 1
pre=$(ip netns exec ns-cli ping -c3 -W2 10.88.1.1)
echo "$pre" | tail -2
pre_loss=$(echo "$pre" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')

echo "=== client moves: source 192.168.52.10 -> 192.168.52.11 (old IP removed) ==="
ip -n ns-cli addr add 192.168.52.11/24 dev veth-cli
ip -n ns-cli route change 192.168.52.1/32 dev veth-cli src 192.168.52.11
ip -n ns-cli addr del 192.168.52.10/24 dev veth-cli   # stale endpoint now unreachable
sleep 2   # client's 1s keepalive arrives from .11, so A roams

echo "=== after move (must roam to 192.168.52.11) ==="
post=$(ip netns exec ns-cli ping -c5 -W2 10.88.1.1)
echo "$post" | tail -2
post_loss=$(echo "$post" | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')

echo "=== loss before=${pre_loss}%  after-move=${post_loss}% ==="
if [ "${pre_loss:-100}" -eq 0 ] && [ "${post_loss:-100}" -eq 0 ]; then
    echo "=== result: PASS (peer roamed to the new source address) ==="
    exit 0
else
    echo "=== result: FAIL ==="
    exit 1
fi
