#!/bin/bash
# Reproducible end-to-end test (Linux, root): two network namespaces, each
# running a `gnetcli tunnel` endpoint over its own TUN, ping each other
# through the encrypted gnet. Proves the full data path — Noise_IK handshake
# + TUN + ChaCha20-Poly1305 transport + UDP — with zero external deps.
#
#   sudo bash crates/gnetcli/scripts/netns-ping.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"

a_out=$("$BIN" keygen); b_out=$("$BIN" keygen)
a_priv=$(echo "$a_out" | awk '/^private/{print $2}')
a_pub=$(echo "$a_out" | awk '/^public/{print $2}')
b_priv=$(echo "$b_out" | awk '/^private/{print $2}')

cleanup() {
    kill "${listen_pid:-}" "${connect_pid:-}" 2>/dev/null
    ip netns del ns1 2>/dev/null
    ip netns del ns2 2>/dev/null
}
trap cleanup EXIT

ip netns add ns1; ip netns add ns2
ip link add veth1 type veth peer name veth2
ip link set veth1 netns ns1; ip link set veth2 netns ns2
ip -n ns1 addr add 192.168.99.1/24 dev veth1; ip -n ns1 link set veth1 up; ip -n ns1 link set lo up
ip -n ns2 addr add 192.168.99.2/24 dev veth2; ip -n ns2 link set veth2 up; ip -n ns2 link set lo up

ip netns exec ns1 "$BIN" tunnel-listen 192.168.99.1:7777 "$a_priv" 10.88.0.1 10.88.0.2 &
listen_pid=$!
sleep 1
ip netns exec ns2 "$BIN" tunnel-connect 192.168.99.1:7777 "$b_priv" "$a_pub" 10.88.0.2 10.88.0.1 &
connect_pid=$!
sleep 2

echo "=== ping through the gnet tunnel: ns2 (10.88.0.2) -> ns1 (10.88.0.1) ==="
rc=0
ip netns exec ns2 ping -c3 -W2 10.88.0.1 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
exit $rc
