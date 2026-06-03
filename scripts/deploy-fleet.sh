#!/usr/bin/env bash
# Deploy the current `develop` HEAD to internal fleet hosts.
#
# Scope: build + install + restart the `gnet` daemon on each named SSH
# host. Does NOT touch the coordinator (gnet-discover) or the relay-server
# — those have their own deploy targets (TODO when needed). Strictly
# separate from product CI (.github/workflows/ci.yml) and from Docker
# image publish (scripts/docker-publish.sh).
#
# Usage:
#   scripts/deploy-fleet.sh <host> [<host> …]
#   scripts/deploy-fleet.sh all                # shorthand for the default set
#   scripts/deploy-fleet.sh --rollback <host>  # restore /usr/local/bin/gnet.bak + restart
#
# Defaults:
#   ALL_HOSTS=${ALL_HOSTS:-"t01 t02 lx64"}
#
# Per-host posture (autodetected: if remote `whoami` == root → no sudo;
# otherwise prefix sudo). Each host gets:
#   1. rsync source (excludes target/ and .git)
#   2. cargo build --release -p gnet
#   3. cp /usr/local/bin/gnet → /usr/local/bin/gnet.bak  (atomic backup)
#   4. install new binary + new systemd unit
#   5. systemctl daemon-reload + restart gnet@main
#   6. `gnet doctor` verifies green/red post-restart
#
# Rollback is the same `cp .bak → in-place + restart`. Idempotent and
# scoped per-host so a single bad host doesn't block the others.

set -euo pipefail

ALL_HOSTS=${ALL_HOSTS:-"t01 t02 lx64"}
REMOTE_BUILD_DIR=/tmp/gnet-build

usage() {
    cat <<EOF >&2
Usage: $0 <host> [<host> …] | all | --rollback <host>

Hosts default-set: ${ALL_HOSTS}
Override with the ALL_HOSTS env var.

Examples:
  $0 t01
  $0 t01 t02
  $0 all
  $0 --rollback t02
EOF
    exit 2
}

# Wrap a remote command so it runs as root regardless of whether the
# ssh user is root or a sudoer.
remote_sudo() {
    local host=$1 ; shift
    local cmd=$*
    # autodetect: if remote user is already root, skip sudo (the host may
    # not even have sudo installed — lx64 in our fleet doesn't).
    local user
    user=$(ssh -o BatchMode=yes "$host" whoami)
    if [ "$user" = "root" ]; then
        ssh "$host" "$cmd"
    else
        ssh "$host" "sudo bash -c \"$cmd\""
    fi
}

rollback_host() {
    local host=$1
    echo "==> [rollback] $host"
    remote_sudo "$host" "test -f /usr/local/bin/gnet.bak || { echo 'no .bak on '$host' — aborting'; exit 1; }"
    remote_sudo "$host" "cp /usr/local/bin/gnet.bak /usr/local/bin/gnet && systemctl restart gnet@main && systemctl is-active gnet@main"
    echo "==> [rollback] $host done"
}

deploy_host() {
    local host=$1
    echo "==> [deploy] $host"

    # 1. sync source (excluding heavy/ephemeral dirs)
    rsync -az --delete \
        --exclude target \
        --exclude .git \
        --exclude '**/fuzz/corpus' \
        --exclude '**/fuzz/artifacts' \
        -e ssh ./ "$host:$REMOTE_BUILD_DIR/"

    # 2. build (release) — remote toolchain is "always latest stable"
    ssh "$host" "cd $REMOTE_BUILD_DIR && cargo build --release -p gnet" \
        | tail -3

    # 3-5. install + restart, atomically per host. Backup is unconditional
    #      so the rollback path is always available.
    remote_sudo "$host" "
        cp /usr/local/bin/gnet /usr/local/bin/gnet.bak 2>/dev/null || true
        install -m 0755 $REMOTE_BUILD_DIR/target/release/gnet /usr/local/bin/gnet
        install -m 0644 $REMOTE_BUILD_DIR/crates/gnet/contrib/systemd/gnet@.service /etc/systemd/system/gnet@.service
        systemctl daemon-reload
        systemctl restart gnet@main
        sleep 2
        systemctl is-active gnet@main
    "

    # 6. verify
    echo "--- [verify] gnet doctor on $host ---"
    if remote_sudo "$host" "gnet doctor"; then
        echo "==> [deploy] $host green"
    else
        echo "!! [deploy] $host doctor RED — investigate; rollback with:"
        echo "   $0 --rollback $host"
        return 1
    fi
}

main() {
    if [ $# -eq 0 ]; then
        usage
    fi

    if [ "$1" = "--rollback" ]; then
        shift
        if [ $# -eq 0 ]; then usage; fi
        for host in "$@"; do rollback_host "$host"; done
        return 0
    fi

    # expand `all` to ALL_HOSTS
    local hosts=()
    for arg in "$@"; do
        if [ "$arg" = "all" ]; then
            # shellcheck disable=SC2206
            hosts+=(${ALL_HOSTS})
        else
            hosts+=("$arg")
        fi
    done

    local failed=()
    for host in "${hosts[@]}"; do
        if ! deploy_host "$host"; then
            failed+=("$host")
        fi
    done

    if [ ${#failed[@]} -gt 0 ]; then
        echo
        echo "!! deploy completed with failures on: ${failed[*]}"
        return 1
    fi
    echo
    echo "✓ deploy green on: ${hosts[*]}"
}

main "$@"
