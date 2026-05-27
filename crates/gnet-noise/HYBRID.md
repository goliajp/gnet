# Hybrid post-quantum handshake — design rationale

`Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s`, implemented in
[`src/hybrid.rs`](src/hybrid.rs). This is the post-quantum hardened
companion to the classical `Noise_IK` handshake the rest of this crate
ships — the transport keys end up depending on **both** an X25519 ECDH
**and** an ML-KEM-768 encapsulation, so the session is secure as long
as *either* primitive holds. A future cryptanalytic break of X25519
(quantum or classical) does not retroactively unlock past traffic, and
neither does a break of ML-KEM.

This document exists because there is **no published cross-implementation
test vector** for Noise + ML-KEM at the time of writing: the IETF
post-quantum drafts (`draft-ietf-pquip-*`) and Noise Framework PQ
extension proposals are still in flight. A self-contained construction
in this ecological niche risks looking ad-hoc, so every design choice
below is anchored to existing peer-reviewed work or NIST/IETF
documents. Frozen byte-exact KAT vectors live in
[`src/hybrid.rs`](src/hybrid.rs) (`frozen_hybrid_handshake_kat`) to lock
the wire format against accidental drift.

---

## 1. Construction

### 1.1 Setup

Both sides initialise a `SymmetricState` keyed by the protocol name and
absorb three pre-message tokens:

```text
sym = SymmetricState(b"Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s")
sym.mix_hash(prologue = empty)
sym.mix_hash(responder_x25519_static_pub)   // pre-message 1
sym.mix_hash(responder_mlkem_ek)            // pre-message 2
```

### 1.2 Message 1 — initiator → responder

```text
Wire layout (1207 bytes for the KAT's 23-byte payload):
    e_pub                        (32)
    enc_static  = AEAD(s_pub)    (32 + 16 tag)
    mlkem_ct    plaintext        (mlkem::CT_LEN = 1088)
    enc_payload = AEAD(payload)  (|payload| + 16 tag)

Symmetric state transitions:
    sym.mix_hash(e_pub)
    sym.mix_key(DH(e_priv, rs))                        # es
    sym.encrypt_and_hash(s_pub) -> enc_static          # writes s
    sym.mix_key(DH(s_priv, rs))                        # ss
    (mlkem_ss, mlkem_ct) = ML-KEM-768.encaps(
        rs_mlkem_ek, caller_supplied_encaps_randomness)
    sym.mix_hash(mlkem_ct)                             # ct bound to transcript
    sym.mix_key(mlkem_ss)                              # KEM ss folded into chain
    sym.encrypt_and_hash(payload) -> enc_payload
```

### 1.3 Message 2 — responder → initiator

**Identical to classical `Noise_IK`**, on the chain key that already
includes the ML-KEM contribution from message 1.

```text
Wire layout:
    re_pub                       (32)
    enc_payload = AEAD(payload)  (|payload| + 16 tag)

Symmetric state transitions:
    sym.mix_hash(re_pub)
    sym.mix_key(DH(re_priv, ie))                       # ee
    sym.mix_key(DH(re_priv, is))                       # se
    sym.encrypt_and_hash(payload) -> enc_payload

split() -> (transport.send, transport.recv)
```

The split's two cipher keys derive from `BLAKE2s(chain_key, …)`, and the
chain key already absorbed both classical (`es`, `ss`, `ee`, `se`) and
post-quantum (`mlkem_ss`) secrets, so the transport AEAD key is a
combiner output over all five.

---

## 2. Design choices and their anchors

### 2.1 Why ML-KEM `ek` as a pre-message

The responder's classical static X25519 key is already a pre-message
(it is the `IK` in `Noise_IK` — initiator knows responder's identity
in advance). Treating the responder's ML-KEM `ek` the same way
mirrors that identity-binding for the post-quantum primitive: both
identifiers are bound to the transcript hash **before** any handshake
key material is generated.

**Anchor**: this matches the construction in *Post-quantum WireGuard*
(Hülsing, Ning, Schwabe, Weber, IEEE S&P 2021), §IV-A "PQ-WG hybrid
protocol", where the responder's Kyber public key plays the same
pre-message role as the responder's static X25519 key.

Practical consequence: an adversary who substitutes a different
`mlkem_ek` for the responder breaks the initiator's transcript hash
(`mix_hash(rs_mlkem_ek)` diverges), which makes `encrypt_and_hash(s_pub)`
in message 1 fail to authenticate on the responder side. Identity
substitution is detected without needing a separate signature.

### 2.2 Why the ML-KEM ciphertext travels in the clear (`mix_hash` only, no AEAD)

KEM ciphertexts carry no confidential plaintext: the ML-KEM ciphertext
itself reveals nothing useful about the shared secret to a passive
observer (that's the IND-CCA security property the KEM provides). So
we save an AEAD pass — `mlkem_ct` is written as bare bytes and
`mix_hash(mlkem_ct)` binds it into the transcript. A tampered
ciphertext is rejected at `encrypt_and_hash(payload)` because both
sides' chain keys diverge through `mix_key(mlkem_ss)`.

**Anchor**: this is the canonical pattern for IND-CCA KEM use in
hybrid AKE. See *Hybrid Key Encapsulation Mechanisms and
Authenticated Key Exchange* (Bindel, Brendel, Fischlin, Goncalves,
Stebila, PQCrypto 2019) §3 "KEM combiners", and PQ-WireGuard §IV-A
which makes the same choice (Kyber ciphertext in plaintext, MAC'd by
the transcript).

### 2.3 Why `mix_key(mlkem_ss)` after the classical DH triplet, before the payload AEAD

The order matters. We folde the post-quantum secret into the chain
**after** the classical triplet `es, ss` and **before** the payload
AEAD encryption. This gives:

- **Hybrid security for the payload**: the message-1 payload AEAD key
  is derived from a chain that already includes `mlkem_ss`, so a
  break of X25519 alone does not unlock the message-1 payload.
- **Hybrid security for the session keys**: message 2's `ee` and `se`
  build on the same chain, so the final transport keys are an
  HKDF-combiner over (`es`, `ss`, `mlkem_ss`, `ee`, `se`) in order.

**Anchor**: NIST SP 800-56C Rev. 2, *Recommendation for Key-Derivation
Methods in Key-Establishment Schemes*, §2 "Concatenation /
combiner". HKDF-style chained extraction over multiple input secrets
is the recommended construction for hybrid PQ/classical KDFs. We get
that for free via Noise's `mix_key`, which is HKDF-Extract under the
hood.

### 2.4 Why message 2 is unchanged from classical `Noise_IK`

A single KEM encapsulation in message 1 already injects PQ entropy
into the chain. The classical `e, ee, se` in message 2 provides
forward secrecy (compromise of long-term `s_priv` later does not
unlock past traffic, because `ee` uses ephemerals that were destroyed
after use). Adding a second KEM round to message 2 buys nothing — the
transport keys are already hybrid-secure.

**Anchor**: PQ-WireGuard ships exactly one KEM round in their hybrid
construction (Hülsing et al. §IV-A, message 1 only). The
forward-secrecy argument is in the same section's security analysis.

### 2.5 Domain separation in the protocol name

`Noise_pqIKhybrid_25519MLKEM768_ChaChaPoly_BLAKE2s` differs from
`Noise_IK_25519_ChaChaPoly_BLAKE2s` (this crate's classical pattern).
The protocol name is the initial chain key seed
(`BLAKE2s(protocol_name)`), so a downgrade attack from hybrid to
classical changes the chain key from the very first byte — every
subsequent `mix_key` / `encrypt_and_hash` diverges, and the handshake
fails at message 1 authentication.

The name includes all primitive identifiers (`25519MLKEM768`,
`ChaChaPoly`, `BLAKE2s`) so a future variant that swaps a primitive
gets a distinct domain automatically.

**Anchor**: Noise Protocol Framework specification, revision 34,
§8 "Protocol names" — the protocol name is the **only** mechanism
preventing cross-protocol confusion in Noise, and full primitive
identification is explicitly recommended.

### 2.6 ML-KEM-768 (not Kyber-512 or ML-KEM-1024)

NIST classifies ML-KEM-768 as Category 3 (≈ AES-192 brute-force
resistance), targeting roughly the same defended-model security
margin as X25519's classical ~128-bit and Curve25519's defenses
against the strongest known classical attacks. Category 1
(ML-KEM-512) under-provides margin if MLWE cryptanalysis improves;
Category 5 (ML-KEM-1024) doubles the ciphertext size for negligible
practical gain in our threat model.

**Anchor**: NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation
Mechanism Standard*, §1 "Introduction" and Table 2 "Parameter sets".

### 2.7 Caller-injected randomness, RNG-free crate

`HybridInitiator::new` and `HybridResponder::new` accept ephemerals
and ML-KEM encapsulation `m` from the caller. The crate contains no
`gnet-rand` (or any RNG) import. Three reasons:

1. **Auditable entropy sourcing**: the daemon owns its RNG and
   logs/proves its source. The crypto layer cannot accidentally
   weaken it.
2. **Deterministic testing**: KATs and differential tests need
   reproducible runs. Injection makes this trivial.
3. **Layering discipline**: see [memory `feedback-gnet-0dep-self-research`]
   and the architectural comment at the top of `lib.rs`.

The pattern follows FIPS 203's randomness-injected `ML-KEM.KeyGen(d, z)`
and `ML-KEM.Encaps(ek, m)` APIs verbatim — we inherit the property
that fresh randomness is the caller's responsibility, exposed at the
API boundary.

---

## 3. What this construction does **not** claim

- **It is not a published standard.** Until IETF pquip or Noise
  Framework ratifies a Noise + ML-KEM variant, our protocol name is
  best understood as a private implementation choice that happens to
  follow the PQ-WireGuard recipe.
- **It has no cross-implementation test vector.** Self-consistency is
  verified (roundtrip / wrong-key fail / tamper-detect), plus a
  byte-exact frozen KAT pinning **our** transcript against future
  drift. No external authority validates "this is the right
  construction".
- **The classical halves are individually authoritative.** ML-KEM-768
  passes FIPS 203 ACVP KAT vectors
  (see `gnet-crypto/tests/mlkem_acvp.rs`). X25519, ChaCha20-Poly1305,
  BLAKE2s, HKDF all pass their respective RFC vectors. The
  *combination* is what currently lacks an external authority.

---

## 4. Migration plan when a standard lands

When IETF pquip / Noise Framework / another respected body publishes a
specification for hybrid Noise:

1. **If our construction matches**: add the standard's test vectors
   to the KAT. The protocol name probably needs a small adjustment
   to match the standardised name; that's a coordinated breaking
   change with a bump (`Noise_pqIKhybrid_…_v2`).
2. **If our construction differs**: implement the standard alongside.
   Run both in parallel for one release cycle. Deprecate our private
   variant in the next.

Either way, the frozen self-KAT serves as a forensic record of "what
exactly was on the wire during the pre-standard period", which is
useful for retrospective audits.

---

## 5. References

- Hülsing, A., Ning, K.-C., Schwabe, P., Weber, F., Zimmermann, P. R.:
  **Post-quantum WireGuard.** IEEE Symposium on Security and Privacy,
  2021. ([eprint](https://eprint.iacr.org/2020/379))
- Bindel, N., Brendel, J., Fischlin, M., Goncalves, B., Stebila, D.:
  **Hybrid Key Encapsulation Mechanisms and Authenticated Key
  Exchange.** PQCrypto 2019. ([eprint](https://eprint.iacr.org/2018/903))
- Trevor Perrin: **The Noise Protocol Framework, revision 34**, 2018.
- NIST FIPS 203: **Module-Lattice-Based Key-Encapsulation Mechanism
  Standard**, 2024.
- NIST SP 800-56C Rev. 2: **Recommendation for Key-Derivation Methods
  in Key-Establishment Schemes**, 2020.
- IETF pquip WG: **Post-Quantum Use In Protocols** working group
  drafts (in progress as of 2026-05).
