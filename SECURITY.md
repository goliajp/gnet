# Security

This file describes how to report a security issue in `gnet` and what to
expect in return.

## Scope

In scope:

- The data-plane crates: `gnet-crypto`, `gnet-noise`, `gnet-wire`,
  `gnet-relay`, `gnet-punch`, `gnet-tun`, `gnet-rand`, `gnet-hex`,
  `gnet-config`.
- The daemon binaries: `gnet`, `gnet-discover`, `gnet-relay-server`.
- The systemd / launchd unit files and the documented deploy procedure
  in [`docs/deploy/`](docs/deploy/).

Out of scope:

- Findings that require an attacker who already has root on the host the
  daemon runs on.
- Findings that depend on running the daemon outside the documented
  deploy posture (no sandbox, no `CAP_NET_ADMIN`, etc.).
- Bugs in third-party tools the daemon shells out to (`curl`,
  `iproute2`).

## Reporting

Email **security@golia.jp** with:

- a short description of the issue and the threat model it breaks,
- a minimal reproduction (test program, packet capture, or step list),
- the affected version (`gnet --help` reports the workspace version, or
  the `gnet-v*` git tag on the deploy),
- whether you want public credit when the fix lands.

**Please do not file public GitHub issues for unpatched security
findings.** Email the address above instead.

You will get an acknowledgement within **3 business days**. We will
follow up with a triage verdict (accepted / not-a-bug / duplicate)
within **10 business days**.

## Embargo

If the issue is accepted as a security bug:

- We aim to ship a fix within **30 days** for high-severity issues and
  **90 days** for medium/low. Fix lands first, then a public commit on
  the develop branch with the SECURITY-tagged commit message.
- We coordinate disclosure with you: the embargo lifts when the fix is
  deployed on the internal fleet AND the patched binary is available to
  any downstream operators we know of. Public advisory is published at
  that point.
- We will credit you in the advisory unless you ask us not to.

## What's in the threat model

The data plane assumes:

- An attacker can observe, drop, reorder, replay, or inject arbitrary
  UDP traffic on the underlay.
- An attacker can run a coordinator at a URL the daemon talks to (so
  the coordinator is trusted for *roster*, not for *content* — peer
  static keys exchanged via the coordinator are TOFU-equivalent, and
  the Noise_IK handshake is what authenticates the actual peer).
- An attacker can run a relay server (the `gnet-relay` envelope hides
  the payload from the relay; the relay only sees source/destination
  static keys).

The data plane does not defend against:

- Compromise of the device static private key (X25519 + ML-KEM-768),
  including via root on the host or via leaked `private` directive in
  `main.conf`. Use the `rotate-key` subcommand at the first sign.
- Compromise of the coordinator's signing key (if/when one exists in a
  later version) — that would let an attacker substitute peer static
  keys in `/peers` responses, which the daemon currently TOFUs.
- Side-channels outside the constant-time hot paths audited in the
  v1.0.0 CT review (e.g. timing of `/etc/hosts` file writes or systemd
  journal emission) — see
  [CT-REVIEW.md](crates/gnet-crypto/CT-REVIEW.md) for the scoped
  audit.

## Cryptographic primitives

All primitives are hand-rolled and KAT-validated against the official
RFC / NIST vectors frozen in each crate's test fixtures (v1.0.0 KAT
audit; see [KAT.md](crates/gnet-crypto/KAT.md)). The crypto stack:

| primitive | spec | crate |
|---|---|---|
| ChaCha20-Poly1305 (AEAD) | RFC 8439 | `gnet-crypto::aead` |
| X25519 (DH) | RFC 7748 | `gnet-crypto::x25519` |
| BLAKE2s (hash, MAC) | RFC 7693 | `gnet-crypto::blake2s` |
| HKDF-BLAKE2s (KDF) | RFC 5869 | `gnet-crypto::hkdf` |
| SHA-3 / SHAKE | FIPS 202 | `gnet-crypto::sha3` |
| ML-KEM-768 (post-quantum KEM) | FIPS 203 | `gnet-crypto::mlkem` |
| Noise_IK handshake | Noise spec rev. 34 | `gnet-noise` |

## Versions

The latest **`gnet-v1.x.y` release on the `develop` branch** is the
supported line. Within a 1.x minor, the most recent patch is what
backports land on. Older 1.x minors get critical security fixes for
the duration documented in the release notes; pre-1.0 tags
(`gnet-v0.5` through `gnet-v0.20`) are unsupported and unlikely to
receive backports.
