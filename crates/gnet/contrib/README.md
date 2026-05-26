# gnet — daemon contrib

Init-system glue for running `gnet up <config>` as a long-lived OS-managed
daemon. Each subdirectory targets a specific platform and is self-documenting:
each unit file has the install / status / stop commands in its header comment.

| Platform | File | Manager |
|---|---|---|
| macOS | [`launchd/com.gnet.gnet.plist`](launchd/com.gnet.gnet.plist) | `launchctl bootstrap / bootout` |
| Linux | [`systemd/gnet@.service`](systemd/gnet@.service) | `systemctl enable --now gnet@<instance>` |

## Why no PID file, no cleanup script, no signal handler

`gnet up` opens the TUN device as an `OwnedFd`. On exit (clean SIGTERM,
crash, or SIGKILL) the kernel reclaims the fd, which destroys the interface:

- Linux: `/dev/net/tun` opens are non-persistent by default (`IFF_TUN`
  without `IFF_PERSIST`); fd close → interface gone.
- macOS: `utun` is implemented as a `PF_SYSTEM` socket; socket close →
  interface gone.

That means the init system's default lifecycle (`SIGTERM → wait → SIGKILL`)
is enough — there is no in-process cleanup the daemon needs to run, so
adding a signal handler would only widen the surface without raising the
ceiling. Routes added via `ip route` / `route add` are attached to the
interface and disappear with it.

## Conventions

- Binary: `/usr/local/bin/gnet`
- Config dir: `/etc/gnet/` (Linux) · `/usr/local/etc/gnet/` (macOS)
- Log dir: `/var/log/gnet/` (macOS only; Linux uses journald)
- Config mode: `0600 root:root` — config carries the device private key

## After install

Verify the interface comes up:

```bash
# Linux
sudo systemctl start gnet@main
ip link show | grep tun       # expect: tun0 ... state UNKNOWN
sudo systemctl stop gnet@main
ip link show | grep tun       # expect: empty

# macOS
sudo launchctl bootstrap system /Library/LaunchDaemons/com.gnet.gnet.plist
ifconfig | grep -E '^utun'    # expect: utunN appears
sudo launchctl bootout system/com.gnet.gnet
ifconfig | grep -E '^utun'    # expect: utunN gone
```
