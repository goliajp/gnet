#!/bin/sh
# gnet container entrypoint.
#
# Selects one of the four binaries by either:
#   - GNET_ROLE env var (daemon|dispatcher|relay|console), or
#   - first positional arg if it matches a role keyword
#
# Default = daemon, so v1.0-style invocations like
#   docker run goliakk/gnet up /etc/gnet/main.conf
# keep working unchanged on v1.1+.
#
# Everything after the role selector is passed through to the chosen
# binary verbatim, so per-role flags (`--listen 0.0.0.0:65433`,
# `up /etc/gnet/main.conf`, etc.) work as before.

set -e

role="${GNET_ROLE:-}"

# Positional override — only consumes $1 when it's an exact role
# keyword, so daemon flags ("up", "doctor", "keygen", "status") still
# pass through cleanly without us shadowing them.
if [ -z "$role" ] && [ $# -gt 0 ]; then
    case "$1" in
        daemon|dispatcher|relay|console)
            role="$1"
            shift
            ;;
    esac
fi

case "${role:-daemon}" in
    daemon)
        exec /usr/local/bin/gnet "$@"
        ;;
    dispatcher)
        exec /usr/local/bin/gnet-discover "$@"
        ;;
    relay)
        exec /usr/local/bin/gnet-relay-server "$@"
        ;;
    console)
        exec /usr/local/bin/gnet-console "$@"
        ;;
    *)
        echo "gnet: unknown GNET_ROLE='$role' (want daemon|dispatcher|relay|console)" >&2
        exit 64
        ;;
esac
