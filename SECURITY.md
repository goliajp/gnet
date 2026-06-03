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
  the `v*` git tag on the deploy),
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

The latest **`v1.x.y` release on the `develop` branch** is the
supported line. Within a 1.x minor, the most recent patch is what
backports land on. Older 1.x minors get critical security fixes for
the duration documented in the release notes; pre-1.0 tags
(`gnet-v0.5` through `gnet-v0.20`) are unsupported and unlikely to
receive backports.

---

## ASVS L1 — v1.1 control-plane walkthrough

The sections above cover the v1.0 data-plane threat model. v1.1
introduces three HTTP control-plane binaries — `gnet-discover` (the
dispatcher), `gnet-relay-server` (the relay's lite admin), and
`gnet-console` (the SaaS console). This section walks those binaries
against [OWASP ASVS L1](https://owasp.org/www-project-application-security-verification-standard/),
the baseline tier appropriate for an admin app that authenticates
humans and orchestrates infrastructure. The walkthrough was authored
as part of plan §17 step 12 (hardening sweep); status reflects the
develop branch as of the §17.12 commit chain.

### V2 — Authentication

| Control | Status | Notes |
|---|---|---|
| Password ≥ 12 chars | **met** | enforced at `MIN_PASSWORD_LEN` in console (`crates/gnet-console/src/routes/auth.rs`) and dispatcher admin setup |
| Password storage: memory-hard hash, salted | **met** | Argon2id, m=64 MiB, t=3, p=4 (`crates/gnet-console/src/auth.rs::ARGON2_*`); matches OWASP Argon2id recommendations |
| Account enumeration prevented at login | **met** | both binaries collapse "user not found" and "wrong password" to a single `BadCreds` 401 |
| Brute-force throttle | **met** | per-account counter in Valkey, 5 attempts / 60s, 429 + `Retry-After` (`ratelimit.rs` in both binaries) |
| Login session ID is fresh per login | **met** | every successful login mints a new `gnet_sess` value (32 random bytes hex); no fixation surface |
| Logout revokes the server-side session | **met** | dispatcher + console both `DEL` the Valkey row on `/api/auth/logout` |
| OAuth state CSRF nonce | **met** | the `oauth_state` HttpOnly cookie carries the same 32-byte nonce stored in Valkey under a 5-min TTL; callback rejects on mismatch |
| Email verification before admin access | **partially met** | console requires `verified_at IS NOT NULL` on email login. Auto-verify (`auto_verify_email=true`) skips the mail loop when `MAILRS_SMTP_HOST` is unset — used for self-host. SaaS deployments must configure mailrs (see `deploy/saas/.env.local.example`). |
| OAuth ID-token signature verify | **met** | Apple ES256 verify via `jsonwebtoken` with cached JWKS (`crates/gnet-console/src/oauth/apple.rs`); Google + GitHub use bearer access-token introspection over HTTPS |

### V3 — Session management

| Control | Status | Notes |
|---|---|---|
| Cookie `HttpOnly` on session | **met** | every session-cookie build sets `.http_only(true)` |
| Cookie `SameSite=Lax` | **met** | both binaries; OAuth callback flow requires Lax (not Strict) for the redirect to carry the cookie |
| Cookie `Secure` on HTTPS | **met** | console default `true` via `GNET_CONSOLE_SECURE_COOKIES`; dispatcher default `false` (self-host plain HTTP) with `GNET_DISCOVER_SECURE_COOKIES=1` to enable when behind TLS proxy |
| Session ID not in URL | **met** | session lives in cookies only; no path/query carriage |
| Session timeout / max-age | **met** | `SESSION_TTL_SECS` enforced both as cookie `max-age` and as the Valkey EX value — no zombie sessions past the TTL even if the cookie is forged |
| Session ID storage | **met** | server side: SHA3-256 hash of the raw bearer indexes Valkey; the plaintext bearer lives only in the HttpOnly cookie (`crates/gnet-console/src/session.rs`, dispatcher mirror) |

### V4 — Access control

| Control | Status | Notes |
|---|---|---|
| Default-deny on mutating endpoints | **met** | dispatcher admin routes are wrapped in `require_login`; CSRF guard applies to every non-GET (`csrf.rs`) |
| CSRF on cookie sessions | **met** | double-submit (`gnet_csrf` cookie ↔ `X-Csrf-Token` header); GET/HEAD/OPTIONS + pre-auth + bearer-auth paths exempt |
| Forced browsing of admin endpoints | **met** | both binaries 401 unauthenticated callers; the SPA shell is open (it has no privileged content) but every API call behind it is gated |
| Tenant boundary | **partially met** | dispatcher writes scope on `network_id` from the session; console federation tokens scope on `(user_id, network_id)`. Cross-tenant admin is N/A in v1.1 (single network per dispatcher) |

### V5 — Validation, sanitization, encoding

| Control | Status | Notes |
|---|---|---|
| Email format validation | **met** | `looks_like_email` filter on register + login (`crates/gnet-console/src/auth.rs`) |
| Alias shape validation | **met** | dispatcher rename: 3..32 chars of `[a-z0-9_-]`; 400 on bad shape, 409 on uniqueness conflict (§17.7) |
| JSON body size limit | **partially met** | axum default is 2 MiB; admin payloads are tiny so this is two orders of magnitude over real traffic. Explicit per-route limits are a v1.2 hardening pass |
| SQL injection | **met** | all DB access uses sqlx parameterised queries; no string interpolation |
| Output encoding | **N/A** | API returns JSON, browser renders SPA — no server-side HTML rendering of user content |

### V7 — Error handling and logging

| Control | Status | Notes |
|---|---|---|
| No stack traces to clients | **met** | `IntoResponse` impls collapse internal errors to the error message string + 5xx; full error trees go to `tracing::error!` not the response |
| Secrets not in logs | **met** | search of the source for `tracing::*token` / `*password` returns zero hits; PHC strings, bearer tokens, and federation tokens never enter the trace path |
| Structured event log | **met** | dispatcher writes per-write events to `audit_log` (PG); daemon emits `event=…` lines for admin / wire actions |

### V8 — Data at rest

| Control | Status | Notes |
|---|---|---|
| Password hashes only | **met** | no plaintext passwords stored anywhere; `email_credentials.password_hash` carries the Argon2id PHC string |
| Bearer token storage | **met** | dispatcher stores `device_token_hash` (SHA3-256), never the plaintext; console stores `federation_trust.token_hash` likewise; auth compares hashes |
| Encryption-at-rest of the PG volume | **N/A** | deferred to the operator's deployment (filesystem encryption / cloud KMS) |

### V9 — Communication

| Control | Status | Notes |
|---|---|---|
| TLS on public surfaces | **met (deployment-side)** | SaaS console terminates TLS at Caddy on t01; HSTS header added in `headers.rs` when `GNET_CONSOLE_SECURE_COOKIES=1` |
| HSTS | **met (opt-in)** | `max-age=63072000; includeSubDomains` added by `headers.rs`. Default off on self-host (plain HTTP) |
| Cookie `Secure` flag | **met (opt-in)** | gated on the same env as HSTS, default on for console / off for dispatcher (matches default deployment posture) |
| Subresource integrity for SPA | **N/A** | the SPA is embedded into the binary via `include_dir!` (plan §3.4) — no CDN, no third-party scripts, no SRI surface |

### V11 — Business logic

| Control | Status | Notes |
|---|---|---|
| Idempotency on critical writes | **partially met** | `device.rename` is naturally idempotent (PUT to same alias is a no-op); federation register is idempotent on `(console_origin, token_hash)`; explicit idempotency keys are a v1.2 follow-up |
| Anti-automation | **met** | login rate-limit is the only credential gate; v1.2 considers CAPTCHA on signup once mail loops are mandatory |

### V12 — Files and resources

| Control | Status | Notes |
|---|---|---|
| No user file uploads | **met** | v1.1 has no upload endpoints |
| SPA path traversal | **met** | `spa::serve` strips the leading `/` and resolves via `include_dir::Dir::get_file`, which compares relative paths against an in-binary tree — no filesystem access |

### V13 — API

| Control | Status | Notes |
|---|---|---|
| All APIs identify themselves | **met** | every binary serves `GET /api/host-role` returning `{"role":"<dispatcher|relay|console>","version":"<ver>"}` (plan §3.4); the SPA hits this to pick its tabs |
| CSRF on mutating API | **met** | see V4 |
| Defensive headers | **met** | `routes/headers.rs` (parallel copy in both control-plane binaries): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, conditional HSTS |
| Content-Security-Policy | **deferred** | needs the SPA's exact bundle shape to be useful without breaking it; v1.2 follow-up after the SPA stabilises across roles |

### V14 — Config

| Control | Status | Notes |
|---|---|---|
| Secrets in env, not in source | **met** | every credential reaches the binary via env (`GNET_*_DATABASE_URL`, `GNET_*_FEDERATION_SECRET`, OAuth `*_CLIENT_SECRET`, admin tokens). Templates ship as `.env.example` files (`self-host/.env.example`, `deploy/saas/.env.local.example`) with empty values; real values come from the operator or the devops secret store |
| Dependency hygiene | **met** | daemon (`gnet`) zero-deps invariant verified in CI (`cargo tree -p gnet` = 10 workspace crates); control-plane crates walled off so their deps never reach the daemon |
| Minimum mode on token files | **met** | daemon `/local` admin token file rejected at startup unless mode is exactly `0o400` (`crates/gnet/src/node/local_admin.rs::TOKEN_FILE_MODE`) |
| Hardened systemd units | **met** | `deploy/saas/systemd/gnet-console.service` + `crates/gnet-relay-server/deploy/gnet-relay-server.service` ship with `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, dedicated dynamic users, modest `MemoryMax` |

### Deferred to v1.2

The following are conscious omissions in v1.1, not findings:

- **Content-Security-Policy** — needs the SPA's stable asset shape and a per-role policy (relay's "Settings"-only SPA looks very different from the console's full network UI). Authoring a CSP that wins more than it costs requires the v1.2 native-app integration to be done.
- **Explicit per-route body limits** — currently relying on axum's 2 MiB default. Real admin bodies are < 8 KiB; tightening to a per-route `RequestBodyLimitLayer` is a small but mechanical pass.
- **Per-IP brute-force throttle** — the per-account form lands the dominant share of the mitigation. Per-IP needs a trust model for `X-Forwarded-For` behind Caddy that doesn't exist yet.
- **CAPTCHA / signup throttle** — needs mailrs to be mandatory first (otherwise signup is auto-verify and CAPTCHA is the only friction).
- **Audit-log integrity** — `audit_log` rows are append-only by convention, not by PG constraint. Tamper-evidence (hash chain) is plausibly worth doing for v1.2.
