#!/usr/bin/env bash
# v0.13 cross-NAT hit-rate measurement harness — one mode, N trials.
#
# Per trial:
#   1. tear down topology (resets NAT conntrack)
#   2. bring up topology w/ NAT_MODE
#   3. start 3 daemons fresh
#   4. pre-warm mock-c via overlay pings from mock-a/mock-b inner
#   5. trigger punch by pinging mock-a → mock-b overlay
#   6. wait up to 15s for "v013-test: PUNCH-SUCCESS" in mock-a.log
#   7. record outcome (HIT_SLOT0 | HIT_CORRECTED | MISS)
#   8. stop daemons
#
# Output: $DIR/results-<MODE>.tsv with columns: trial<TAB>outcome<TAB>detail
#
# Env:
#   NAT_MODE — default | random-fully (default: "default")
#   DIR      — work dir w/ configs, logs, results (default: $PWD)
#   GNET     — path to gnet binary (default: ./target/release/gnet)
#   TOPO     — path to setup-topology.sh (default: ./setup-topology.sh)
#   STARTER  — path to start-daemons.sh (default: ./start-daemons.sh)

set -euo pipefail

NAT_MODE="${NAT_MODE:-default}"
N="${1:-30}"
DIR="${DIR:-$PWD}"
TOPO="${TOPO:-$DIR/setup-topology.sh}"
STARTER="${STARTER:-$DIR/start-daemons.sh}"
export GNET="${GNET:-./target/release/gnet}"
export DIR

OUT="$DIR/results-$NAT_MODE.tsv"

echo "── v0.13 trials: NAT_MODE=$NAT_MODE N=$N ──"
echo "results -> $OUT"
printf "trial\toutcome\tdetail\n" > "$OUT"

NAT_MODE="$NAT_MODE" bash "$TOPO" down >/dev/null 2>&1 || true

hit_zero=0
hit_corrected=0
miss=0

for trial in $(seq 1 "$N"); do
    NAT_MODE="$NAT_MODE" bash "$TOPO" >/dev/null
    bash "$STARTER" >/dev/null

    sleep 1

    # pre-warm: mock-a, mock-b each ping mock-c to establish direct sessions
    ip netns exec mock-a-inner ping -c 2 -W 1 -i 0.3 10.42.0.3 >/dev/null 2>&1 || true
    ip netns exec mock-b-inner ping -c 2 -W 1 -i 0.3 10.42.0.3 >/dev/null 2>&1 || true
    sleep 0.5

    # punch trigger: mock-a → mock-b
    ip netns exec mock-a-inner ping -c 1 -W 1 10.42.0.2 >/dev/null 2>&1 || true

    outcome=""
    detail=""
    for w in $(seq 1 30); do
        sleep 0.5
        if grep -q "PUNCH-SUCCESS (slot-0 hit)" "$DIR/mock-a.log" 2>/dev/null; then
            outcome="HIT_SLOT0"
            detail=$(grep -m1 "PUNCH-SUCCESS (slot-0 hit)" "$DIR/mock-a.log" | sed 's/.*endpoint stays at //')
            break
        fi
        if grep -q "PUNCH-SUCCESS (corrected)" "$DIR/mock-a.log" 2>/dev/null; then
            outcome="HIT_CORRECTED"
            detail=$(grep -m1 "PUNCH-SUCCESS (corrected)" "$DIR/mock-a.log" | sed 's/.*v013-test: //')
            break
        fi
    done
    if [[ -z "$outcome" ]]; then
        outcome="MISS"
        n_dials=$(grep -E "dial_fanout|start_punch" "$DIR/mock-a.log" | wc -l)
        detail="dial_events=$n_dials"
    fi

    printf "%d\t%s\t%s\n" "$trial" "$outcome" "$detail" >> "$OUT"
    case "$outcome" in
        HIT_SLOT0)     hit_zero=$((hit_zero+1)) ;;
        HIT_CORRECTED) hit_corrected=$((hit_corrected+1)) ;;
        MISS)          miss=$((miss+1)) ;;
    esac

    # archive raw logs for first 3 + any misses (debug aid)
    if [[ $trial -le 3 || "$outcome" == "MISS" ]]; then
        mkdir -p "$DIR/logs-$NAT_MODE"
        for who in a b c; do
            cp "$DIR/mock-$who.log" "$DIR/logs-$NAT_MODE/trial${trial}-mock-$who.log" 2>/dev/null || true
        done
    fi

    printf "  trial %2d/%d -> %-13s  (slot0=%d corrected=%d miss=%d)\n" \
        "$trial" "$N" "$outcome" "$hit_zero" "$hit_corrected" "$miss"

    pkill -f "release/gnet up" 2>/dev/null || true
    sleep 0.3
    NAT_MODE="$NAT_MODE" bash "$TOPO" down >/dev/null 2>&1 || true
done

total=$((hit_zero + hit_corrected))
echo
echo "── summary: NAT_MODE=$NAT_MODE ──"
echo "  total hits      = $total / $N"
echo "  slot-0 hits     = $hit_zero"
echo "  corrected hits  = $hit_corrected"
echo "  misses          = $miss"
printf "  hit-rate        = %.1f%%\n" "$(echo "scale=4; $total * 100 / $N" | bc)"
echo
echo "rows persisted: $OUT"
