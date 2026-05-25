#!/bin/bash
# Handshake-glare test (Linux, root): two directly-connected nodes (no NAT)
# initiate to each other at the same time — the simultaneous open that hole
# punching also requires. Without glare resolution each side overwrites its
# Initiating session with a responder session and `complete_initiation` then
# skips the reply, leaving two mismatched sessions and a dead overlay. With it,
# the higher-key side keeps initiating and the lower-key side responds, so both
# converge on one session. This isolates the handshake from any NAT behaviour:
# run it in a loop to confirm the simultaneous open is deterministic, not flaky.
#
#   sudo bash crates/gnetcli/scripts/netns-glare.sh
set -u

cargo build -p gnetcli 2>&1 | tail -1 || exit 1
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/gnetcli"
TMP=$(mktemp -d)

cleanup() {
    kill "${pid_a:-}" "${pid_b:-}" 2>/dev/null
    for ns in ns-a ns-b; do ip netns del "$ns" 2>/dev/null; done
    iptables -D FORWARD -i br-glare -o br-glare -j ACCEPT 2>/dev/null
    # delete host-side devices explicitly: a `ip link set ... netns` that lost a
    # teardown race in a previous run can strand a veth in the host namespace,
    # and `ip netns del` won't reap it — leaving the next `ip link add` to fail
    # with "File exists". Listing the veth host ends here clears that leak.
    for l in veth-a veth-b br-a br-b br-glare; do ip link del "$l" 2>/dev/null; done
    rm -rf "$TMP"
}
trap cleanup EXIT

# Pre-clean any residue from an interrupted run and wait for the kernel to
# release the bridge name before recreating: device teardown is asynchronous,
# so a rapid re-run otherwise races into "File exists" and a node starts with
# its address unconfigured (bind → EADDRNOTAVAIL).
ip netns del ns-a 2>/dev/null; ip netns del ns-b 2>/dev/null
for l in veth-a veth-b br-a br-b br-glare; do ip link del "$l" 2>/dev/null; done
for _ in $(seq 1 100); do ip link show br-glare >/dev/null 2>&1 || break; sleep 0.05; done

a_out=$("$BIN" keygen); b_out=$("$BIN" keygen)
a_priv=$(echo "$a_out" | awk '/^private/{print $2}')
a_pub=$(echo "$a_out"  | awk '/^public/{print $2}')
a_mlk=$(echo "$a_out"  | awk '/^mlkem-public/{print $2}')
b_priv=$(echo "$b_out" | awk '/^private/{print $2}')
b_pub=$(echo "$b_out"  | awk '/^public/{print $2}')
b_mlk=$(echo "$b_out"  | awk '/^mlkem-public/{print $2}')

# underlay: one bridge, one veth per namespace (192.168.70.0/24, no NAT)
ip link add br-glare type bridge
ip link set br-glare up
iptables -I FORWARD -i br-glare -o br-glare -j ACCEPT 2>/dev/null
i=1
for n in a b; do
    ip netns add "ns-$n"
    ip link add "veth-$n" type veth peer name "br-$n"
    ip link set "veth-$n" netns "ns-$n"
    ip link set "br-$n" master br-glare; ip link set "br-$n" up
    ip -n "ns-$n" addr add "192.168.70.$i/24" dev "veth-$n"
    ip -n "ns-$n" link set "veth-$n" up
    ip -n "ns-$n" link set lo up
    i=$((i + 1))
done

cat > "$TMP/a.conf" <<EOF
private $a_priv
address 10.88.0.1
listen 192.168.70.1:7777
peer $b_pub $b_mlk 10.88.0.2 192.168.70.2:7777
EOF
cat > "$TMP/b.conf" <<EOF
private $b_priv
address 10.88.0.2
listen 192.168.70.2:7777
peer $a_pub $a_mlk 10.88.0.1 192.168.70.1:7777
EOF

ip netns exec ns-a "$BIN" up "$TMP/a.conf" >"$TMP/a.log" 2>&1 & pid_a=$!
ip netns exec ns-b "$BIN" up "$TMP/b.conf" >"$TMP/b.log" 2>&1 & pid_b=$!
sleep 2

# fail fast (and distinctly) if a node never bound — that is a harness/setup
# problem, not a handshake one, and must not be mistaken for glare flakiness.
if ! grep -q "node up" "$TMP/a.log" || ! grep -q "node up" "$TMP/b.log"; then
    echo "=== result: FAIL (node failed to start) ==="
    echo "=== node A log ==="; cat "$TMP/a.log"
    echo "=== node B log ==="; cat "$TMP/b.log"
    exit 1
fi

# simultaneous open: both fire their first overlay packet at once, so each side
# initiates while the other is also initiating (the glare window). Wait only on
# the two pings — a bare `wait` would also block on the long-lived node procs.
ip netns exec ns-a ping -c1 -W2 10.88.0.2 >/dev/null 2>&1 & pa=$!
ip netns exec ns-b ping -c1 -W2 10.88.0.1 >/dev/null 2>&1 & pb=$!
wait "$pa" "$pb"
sleep 2

echo "=== overlay ping after simultaneous open (no NAT) ==="
rc=0
ip netns exec ns-a ping -c5 -W2 10.88.0.2 || rc=1
echo "=== result: $([ $rc = 0 ] && echo PASS || echo FAIL) ==="
if [ $rc != 0 ]; then
    echo "=== node A log ==="; cat "$TMP/a.log"
    echo "=== node B log ==="; cat "$TMP/b.log"
fi
exit $rc
