---
name: Bug report
about: Something gnet does that it shouldn't, or doesn't that it should
title: ''
labels: bug
assignees: ''
---

> ⚠️ **Security bug?** Don't file here. See [SECURITY.md](../../SECURITY.md)
> for the disclosure address. The threat-model line is "any finding that
> doesn't require root on the host" — when in doubt, email instead.

## What happened

<!-- One or two sentences. The thing you observed, in plain language. -->

## What should have happened

<!-- One sentence. What you expected instead. -->

## Reproduction

<!-- Either the exact commands, or a small test that demonstrates it.
"`gnet status` on host X shows peer Y as established but I can't ping
its overlay IP" is enough to start. -->

## Environment

- gnet version: <!-- `gnet --help` shows the git tag; or paste the commit SHA -->
- OS + kernel: <!-- `uname -a` -->
- Deploy posture: <!-- systemd + the linux-systemd.md unit / launchd + the macOS plist / one-shot CLI / custom -->
- Coordinator + relay topology: <!-- single coord, primary+standby, N relays -->

## Logs / output

<!-- Paste the relevant `journalctl -u gnet@main` window, the `gnet
status` block, or the `gnet doctor` output. Trim to the relevant
event= lines — full unbounded logs are noise. -->

```
<paste here>
```

## Anything else

<!-- Workarounds you tried, related issues, hunches about the cause —
all optional. -->
