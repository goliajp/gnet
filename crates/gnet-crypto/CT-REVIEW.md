# gnet-crypto — constant-time review (v0.23 Track B)

> **Frozen as of v0.23.** Each CT-sensitive hot path is cataloged below
> with the mechanism that keeps it constant-time and the assumptions that
> mechanism rests on. New CT-sensitive code paths get appended here when
> added.

## Scope

The CT review covers code paths where the *secret input* (a private key,
a derived shared secret, a MAC key, a plaintext to be authenticated)
flows into branch conditions, memory addresses, or comparisons whose
timing the attacker can observe via network RTT or the system event log.

In scope:

- ChaCha20 stream cipher (key-dependent state evolution)
- Poly1305 MAC (`r`-dependent state evolution)
- ChaCha20-Poly1305 AEAD (tag compare)
- X25519 scalar multiplication (scalar-dependent ladder)
- X25519 base-point comb (scalar-window-dependent table lookup)
- ML-KEM-768 Decaps (Fujisaki-Okamoto re-encrypt check)
- BLAKE2s / SHA-3 (message-dependent permutation — both are CT by
  construction; no secret-dependent control flow in either)
- HKDF-BLAKE2s (HMAC over a secret PRK)

Out of scope:

- The Noise handshake state machine (built on the primitives above; CT
  inherits from them).
- The discovery / coordinator HTTP path (talks plaintext to the
  coordinator, not secret-bearing).
- The TUN device read / write loop (operates on already-decrypted
  plaintext that the application is about to hand to the kernel
  anyway).
- The `gnet-relay-server` forwarder (never decrypts; sees only
  source/destination static keys, both of which are public).

## Findings

### Fixed in v0.23 — `ml_kem::decaps` mask derivation

**Location:** `src/mlkem/mod.rs`, the FO-transform implicit-rejection
key select.

**Before:**

```rust
let ok = ct_eq(ct, &ct2);
let mask = if ok { 0u8 } else { 0xff };
```

**Issue:** the `if ok` form may compile to a conditional jump on some
backends (depending on optimisation level and target). If it does, the
attacker can distinguish a real ciphertext from an FO-rejected one by
the timing of the FO select — leaking which branch was taken, which is
exactly what the rejection key is supposed to hide. This was the
canonical "bool-boundary" CT slip.

**After:**

```rust
let mask = (ct_eq(ct, &ct2) as u8).wrapping_sub(1); // ok → 0; not-ok → 0xff
```

The conversion is unconditional cmp+sete+sub on every backend gnet
supports (x86_64, aarch64); no `cmov`, no branch. Wire-format unchanged,
ACVP tests still pass.

## CT mechanism inventory (no findings — for the record)

### ChaCha20-Poly1305 AEAD tag compare

**Location:** `src/aead.rs`, `ct_eq` + `open_in_place`.

**Mechanism:** classic ORed-XOR accumulator over the whole 16-byte tag,
then a single `diff == 0`. No early return on mismatch. The bool boundary
into `if ct_eq(...)` is acceptable here because the consumer is
`open_in_place` which then *publicly* returns `Result<(), AuthError>` —
the attacker is allowed to know the auth verdict, so the timing of the
follow-up decrypt isn't a CT issue (and the decrypt itself is skipped on
auth failure to save work, which is also a public outcome).

### X25519 Montgomery ladder

**Location:** `src/x25519/scalar.rs`, the per-bit `cswap` calls.

**Mechanism:** `cswap` (in `src/x25519/field.rs`) uses a 64-bit mask
derived from `0u64.wrapping_sub(swap & 1)` and XOR-mixes both field
elements unconditionally. No branch on `swap`. The ladder iterates a
fixed 255 times regardless of scalar value.

### X25519 base-point comb (signed-window table lookup)

**Location:** `src/x25519/edwards.rs`, `ct_select_cached` +
`ct_negate_cached`.

**Mechanism:** for each window the inner loop walks all N table entries
and merges via `mask & (out ^ src)` where `mask = ct_eq_u8(abs_d, k+1)`.
`ct_eq_u8` is branch-free (`(diff | diff.wrapping_neg()) >> 63` then
`wrapping_sub(1)`). The negate step uses an unconditional XOR-swap
gated by `neg_mask`. No memory access is skipped — all N entries are
touched on every call, so cache-timing on the lookup is invariant.

### ML-KEM keygen / encaps / decaps

**Location:** `src/mlkem/*`.

**Mechanism:**

- KeyGen: deterministic over the public seeds `d` and `z`; no
  conditional flow on key material.
- Encaps: takes a public `ek` and a randomness input `m`; no secret
  intermediates branched on.
- Decaps: as fixed above. FO check uses CT byte-mask. Both candidate
  keys (real and rejection) are materialised regardless of the verdict,
  so cache footprint is invariant.

The underlying polynomial NTT (`src/mlkem/ntt/`) and Keccak permutation
(`src/sha3/`) are message-driven but not branch-on-message — every
multiplication / addition / squeezeing step runs unconditionally to
fixed length.

### Poly1305

**Location:** `src/poly1305/mod.rs`.

**Mechanism:** `r` clamping is a constant byte-mask. Field arithmetic
(`fmul5`, `reduce_products`, `carry`) is unconditional. The bulk path
uses SIMD lanes that process exactly two full blocks per iteration with
no length-dependent control flow; the tail path (`absorb_tail`) handles
sub-block remainder with a public-length branch (the remainder length is
derived from the input length, which is itself public — the message body
content is not).

### ChaCha20

**Location:** `src/chacha20/*`.

**Mechanism:** quarter-round is pure 32-bit add/xor/rotate, no table
lookups. The SIMD dispatchers (`avx2`, `neon`, `sse2`) are selected at
build time / runtime via `cfg!`/cpuid — public choice, no secret. The
keystream apply XORs full blocks unconditionally, with the tail handled
by a public-length loop.

### BLAKE2s / SHA-3 / SHAKE

CT by construction: both permutations are straight-line
add/xor/rotate. No secret-dependent indexing, no key-dependent rounds.
The hash-state buffering uses public input length to decide when to
absorb a block.

### HKDF-BLAKE2s

**Location:** `src/hkdf.rs`.

**Mechanism:** HMAC over BLAKE2s. The PRK is secret, but the HMAC
construction is straight-line (pad XOR, hash, hash again). HKDF-Expand
loops `ceil(L / HASH_LEN)` times with the iteration count derived from
the public output length `L`; nothing branches on PRK content.

## Caveats / non-CT-protected paths (deliberately)

- **Public-input length branches.** Wherever the public input length
  determines a loop bound or a tail-handling branch, that branch is on
  public data and is acceptable.
- **Boundary-of-decryption branches.** Once `open_in_place` returns
  `AuthError`, the caller is allowed to skip downstream work — at that
  point the secret has not been revealed and the timing leak is the
  public verdict itself.
- **Debug logging.** A panic in debug builds (`debug_assert!`) is
  release-build dead code; we keep them for development sanity. None of
  the release-path crypto code panics.
- **Allocator behaviour.** Where ML-KEM / Poly1305 use `Vec<_>`, the
  allocation size is determined by public input length only. We don't
  branch allocator choice on secret content.

## Out-of-scope concerns (deferred or won't-fix for v1.0)

- **Speculative-execution side channels** (Spectre-style). The CT
  techniques above guard against direct timing leaks of secret-dependent
  branches; they do not pretend to defend against branch-prediction
  speculation that could leak via cache. Mitigation would require
  `LFENCE` / `DSB SY` insertion which we don't currently do.
- **Power-analysis side channels.** Out of scope — we run on
  general-purpose CPUs in datacenters and laptops, not smart cards.
- **System-call-level side channels.** The daemon's `gnet status` /
  admin socket can be probed for whether a session is established or
  not — this is by design (operator observability) and unrelated to
  cryptographic CT.

## Review workflow for adding code

When adding crypto code that touches a secret, before merging:

1. Identify every branch (`if`, `match`, `?`, early `return`) whose
   condition depends on the secret. Eliminate them with mask ops.
2. Identify every memory access whose index depends on the secret. Walk
   the full range with CT select, never index directly.
3. Cross the result through a `cargo +nightly fuzz run` of any harness
   that touches the new path (or add a new harness — see
   `docs/fuzzing.md`).
4. Append a row to this file with the path's CT mechanism.

When a CT finding is fixed, add an entry under "Findings" above with
before/after and the wire-compat verdict (ours should always be "wire
unchanged" — CT fixes never change protocol output, only its timing).
