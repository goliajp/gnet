# macOS deploy — launchd

The `gnet` overlay daemon runs as a macOS LaunchDaemon. Unlike the
Linux + systemd path (instance-templated `gnet@<i>`), the macOS deploy
runs a single-instance plist at `com.gnet.gnet` — multi-instance is
possible by duplicating the plist with a different `Label` + conf
path. macOS does not host the `gnet-discover` coordinator or
`gnet-relay-server` in the reference deploy; those live on Linux.

The plist is at
[`crates/gnet/contrib/launchd/com.gnet.gnet.plist`](../../crates/gnet/contrib/launchd/com.gnet.gnet.plist).

## Prerequisites

- macOS 14+ (arm64 or x86_64). The reference build is arm64 (Apple
  Silicon).
- Admin / `sudo` access (TUN device creation requires root).
- A built `gnet` binary
  (`cargo build --release -p gnet --target aarch64-apple-darwin`).

## Install

```bash
# directories — match the macOS-side default conf path used by
# `gnet status` / `gnet doctor`
sudo install -d -m 0755 -o root -g wheel /usr/local/etc/gnet /var/log/gnet

# conf (mode 0600, root-owned — carries the private key)
sudo install -m 0600 -o root -g wheel  /path/to/main.conf \
                                       /usr/local/etc/gnet/main.conf

# binary + plist
sudo install -m 0755 -o root -g wheel  target/release/gnet \
                                       /usr/local/bin/gnet
sudo install -m 0644 -o root -g wheel  crates/gnet/contrib/launchd/com.gnet.gnet.plist \
                                       /Library/LaunchDaemons/com.gnet.gnet.plist

# load + start
sudo launchctl bootstrap system /Library/LaunchDaemons/com.gnet.gnet.plist
```

`launchctl bootstrap` is the modern equivalent of `launchctl load` —
it both registers and starts the daemon in one shot.

## Verify

```bash
# service state
sudo launchctl print system/com.gnet.gnet | head -30

# the utunN device the daemon opened (Apple labels them sequentially)
ifconfig | grep -A2 utun

# tail the log (plist sets StandardErrorPath = /var/log/gnet/stderr.log)
sudo tail -f /var/log/gnet/stderr.log

# operator CLI
sudo gnet status
sudo gnet doctor
```

A clean startup line in the log looks like:

```
event=node_up tun=utun7 v4=10.42.42.5 v6=fd8d:f090:2ebb::5 peers=0
event=admin_socket_up path=/usr/local/var/run/gnet/admin.sock
```

Note the macOS admin socket path differs from Linux:

| OS | admin socket | conf path |
|---|---|---|
| Linux | `/var/run/gnet/admin.sock` (→ `/run/gnet/...`) | `/etc/gnet/main.conf` |
| macOS | `/usr/local/var/run/gnet/admin.sock` | `/usr/local/etc/gnet/main.conf` |

Both are derived by `gnet::node::admin_socket_path()` /
`status::default_conf_path()`. The CLI uses the right one for the
host's OS automatically.

## Operate

| Task | Command |
|---|---|
| Stop | `sudo launchctl kickstart -k system/com.gnet.gnet` (restart) |
| Disable | `sudo launchctl bootout system/com.gnet.gnet` |
| Re-enable | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.gnet.gnet.plist` |
| Tail logs | `sudo tail -f /var/log/gnet/stderr.log` |
| Health check | `sudo gnet doctor` |
| Live status | `sudo gnet status` |

The plist sets `KeepAlive { SuccessfulExit = false }`, so the daemon
restarts on crash but a clean `bootout` stays bootouted. `ThrottleInterval
= 10` holds off restarts so a crash-loop can't hammer the OS.

## Uninstall

```bash
sudo launchctl bootout system/com.gnet.gnet
sudo rm /Library/LaunchDaemons/com.gnet.gnet.plist
sudo rm /usr/local/etc/gnet/main.conf      # optional — keeps the device's identity
sudo rm /usr/local/bin/gnet
```

The `utunN` device is owned by the daemon process's fd (no
`IFF_PERSIST` equivalent on macOS — the kernel destroys it on process
exit). No PID file, no cleanup hook.

## Conf shape

Same as Linux — see
[`crates/gnet-config/src/lib.rs`](../../crates/gnet-config/src/lib.rs).
The conf file format is OS-agnostic; only the default install path
differs.

A coordinator-driven minimal conf:

```text
private  <64-hex>                  # from `gnet keygen`
address  10.42.42.5                # overlay v4 — utunN's IP
listen   0.0.0.0:65432             # UDP bind
coordinator http://coord.example:65432
device_token <token>
# alias mini                       # optional; written by `gnet join`
```

## Network requirements

- Outbound UDP to the configured `coordinator` host:port (HTTP) and to
  every peer's reflexive endpoint (UDP overlay).
- macOS firewall: if "stealth mode" is on (System Settings → Network →
  Firewall), incoming UDP on the `listen` port is dropped — disable
  stealth mode or use the coordinator + relay path.
- `pf` (Packet Filter) is off by default; no rules needed unless your
  org image enables it.

## /etc/hosts splice

On macOS the daemon writes the `gnet-<alias>` block into `/etc/hosts`
the same way as Linux (atomic tmp + rename when possible, direct
write-all fallback on a sandboxed system). Disable with `manage_hosts
false` in the conf if you have a local resolver that handles the
overlay names differently.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `launchctl bootstrap` returns 5: "Input/output error" | the plist file path is wrong, or the binary at the path the plist references doesn't exist |
| Daemon up but no `utunN` device | `gnet` not running as root — check the plist has `UserName = root` or no UserName key (default is root for system-domain launchd jobs) |
| `gnet status` prints `daemon: (no gnet up process found)` | daemon crashed shortly after start — check `/var/log/gnet/stderr.log` for the panic |
| Peer reach fails with relay-fallback events | macOS firewall stealth-mode dropping inbound UDP; relay path still works |
| `event=admin_socket_unavailable` | parent dir `/usr/local/var/run/gnet/` not writable — should not happen with the default install since the daemon's `create_dir_all` runs as root |
