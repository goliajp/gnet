#!/bin/bash
# Run every netns end-to-end test in sequence and print a pass/fail matrix.
#
# Each netns-*.sh builds gnet, stands up its own namespaces, runs its check,
# and tears the namespaces down via its own `cleanup` trap. This runner judges
# each by exit code (0 = PASS) and, on failure, prints the tail of its output so
# a regression is visible in one place. Ordered cheap → expensive so a basic
# breakage shows before the slow punch/relay tests.
#
# Linux + root (the scripts create namespaces and iptables rules):
#
#   sudo bash crates/gnet/scripts/netns-all.sh
set -u
cd "$(dirname "$0")" || exit 1

# cheap → expensive; punch/relay take ~15-30s each (they wait out NAT timing).
SCRIPTS=(netns-ping netns-gnet netns-gnet-v6 netns-underlay-v6 netns-reflexive \
         netns-glare netns-reorder netns-roam netns-punch netns-punch-sync netns-relay)

# fold in any netns-*.sh not in the ordered list above (new tests run last).
for f in netns-*.sh; do
    [ "$f" = "netns-all.sh" ] && continue
    s="${f%.sh}"
    case " ${SCRIPTS[*]} " in *" $s "*) ;; *) SCRIPTS+=("$s") ;; esac
done

declare -A result
pass=0
fail=0
for s in "${SCRIPTS[@]}"; do
    [ -f "$s.sh" ] || { result[$s]=MISSING; continue; }
    printf 'running %-22s ... ' "$s"
    out=$(bash "$s.sh" 2>&1)
    rc=$?
    if [ "$rc" -eq 0 ]; then
        result[$s]=PASS
        pass=$((pass + 1))
        echo PASS
    else
        result[$s]=FAIL
        fail=$((fail + 1))
        echo "FAIL (rc=$rc)"
        echo "  --- $s.sh tail ---"
        echo "$out" | tail -12 | sed 's/^/  /'
        echo "  ---"
    fi
done

echo
echo "=== netns e2e matrix ==="
for s in "${SCRIPTS[@]}"; do
    printf '  %-22s %s\n' "$s" "${result[$s]:-?}"
done
echo "total: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
