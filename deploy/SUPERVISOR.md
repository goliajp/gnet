# Daemon supervisor units

`/local/restart` (v1.1 §17.9) and the control-channel `restart` op
(v1.2-plan §18.A3.1) both work by having the daemon exit cleanly and
trusting the host's supervisor to bring it back. No supervisor → no
auto-recovery; the daemon stays down until you re-launch it.

## macOS — launchd

Copy [`launchd/jp.golia.gnet.plist`](launchd/jp.golia.gnet.plist) to
`/Library/LaunchDaemons/jp.golia.gnet.plist`, then:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/jp.golia.gnet.plist
sudo launchctl enable system/jp.golia.gnet
```

The plist's `KeepAlive=true` restarts the daemon on any exit; the
`ThrottleInterval=2` second guard keeps a crash loop from spinning.

## Linux — systemd

Copy [`systemd/gnet.service`](systemd/gnet.service) to
`/etc/systemd/system/gnet.service`, then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now gnet.service
```

`Restart=always` brings the daemon back on the clean exit(0) that the
restart paths schedule; `RestartSec=2` matches launchd's throttle.

## Docker / Compose

For the unified `goliakk/gnet:1.x` image, the supervisor IS the
container runtime — set `restart: always` (or `restart:
unless-stopped`) on the service in your compose file. The bundled
`self-host/docker-compose.yml` and `deploy/saas/` configs already do
this.

## Without a supervisor

If you run `gnet up` directly in a shell session, `restart` ops will
cleanly exit the process and stay down. That is the correct behaviour
for dev — re-launch when you want it back.
