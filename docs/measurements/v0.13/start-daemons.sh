#!/usr/bin/env bash
# Launch three `gnet up` daemons (mock-c, mock-a, mock-b) in their netns,
# stopping any prior instance first. Configs are expected under $DIR.
#
# Env:
#   GNET  — path to the gnet binary (default: cargo target/release/gnet)
#   DIR   — directory containing mock-{c,a,b}.conf + writing mock-{c,a,b}.log
#           + mock-{c,a,b}.pid (default: $PWD)

set -euo pipefail
GNET="${GNET:-./target/release/gnet}"
DIR="${DIR:-$PWD}"

stop_existing() {
    for p in mock-c mock-a mock-b; do
        if [[ -f "$DIR/$p.pid" ]]; then
            local pid; pid=$(cat "$DIR/$p.pid" 2>/dev/null || true)
            if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
            rm -f "$DIR/$p.pid"
        fi
    done
    # belt-and-suspenders: kill any orphan daemon
    pkill -f "release/gnet up" 2>/dev/null || true
    sleep 0.5
}

start() {
    local ns="$1" conf="$2" name="$3"
    : > "$DIR/$name.log"
    setsid ip netns exec "$ns" "$GNET" up "$DIR/$conf" </dev/null \
        >> "$DIR/$name.log" 2>&1 &
    echo $! > "$DIR/$name.pid"
    echo "started $name (pid=$(cat $DIR/$name.pid)) in ns=$ns conf=$conf"
}

stop_existing
start mock-c       mock-c.conf mock-c
start mock-a-inner mock-a.conf mock-a
start mock-b-inner mock-b.conf mock-b

sleep 2
echo
echo "── status ──"
for p in mock-c mock-a mock-b; do
    pid=$(cat "$DIR/$p.pid")
    if kill -0 "$pid" 2>/dev/null; then
        echo "  $p: alive (pid $pid)"
    else
        echo "  $p: DEAD — last log lines:"
        tail -5 "$DIR/$p.log" | sed "s/^/      /"
    fi
done
