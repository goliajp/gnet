# gnet-crypto — known-answer test inventory

> **Frozen as of v0.23 (Track B audit).** Each primitive lists the
> published spec, the exact section / table the vector comes from, and the
> test function that locks the vector in. New vectors get appended here
> when added; existing entries do not move.

The intent of this file is twofold:

1. **Trust.** A reader can check `cargo test --release` against the cited
   specs and see that the daemon's wire-compatibility claims hold against
   the standards body, not just against the implementation's own
   self-tests.
2. **Regression fence.** Once a vector is cited here it is a contract — a
   primitive change that breaks it is a wire-level break and must come
   with an explicit acknowledgement (rev the file, name the standard,
   etc.).

## Primitive coverage

### ChaCha20 (RFC 8439)

| section | what | test |
|---|---|---|
| §2.1.1 | quarter-round on a 4-tuple | `chacha20::tests::quarter_round_rfc8439_2_1_1` |
| §2.3.2 | full block function keystream | `chacha20::tests::block_rfc8439_2_3_2` |
| §2.4.2 | end-to-end encryption, 114-byte plaintext (2 blocks) | `chacha20::tests::encrypt_rfc8439_2_4_2` |

### Poly1305 (RFC 8439)

| section | what | test |
|---|---|---|
| §2.5.2 | worked example, 34-byte message (partial block) | `poly1305::tests::mac_rfc8439_2_5_2` |
| §A.3 #1 | all-zero key + message → all-zero tag | `poly1305::tests::mac_rfc8439_a3_1_zero` |
| §A.3 #2 | `r = 0` over the IETF-Contribution boilerplate message → tag = `s` | `poly1305::tests::mac_rfc8439_a3_2_r_zero` |

### ChaCha20-Poly1305 AEAD (RFC 8439)

| section | what | test |
|---|---|---|
| §2.8.2 | worked AEAD example — sunscreen plaintext + AAD | `aead::tests::aead_rfc8439_2_8_2` |

> **Known gap:** §A.5 (the long AEAD decryption vector) is not yet
> frozen. The underlying ChaCha20 stream and Poly1305 MAC components
> are each frozen against their own RFC vectors above, and the
> end-to-end `mac_tag_matches_materialized_reference` property test
> exercises the AEAD glue across many length boundaries. §A.5
> appendix vector inclusion is a small future commit, not a v1.0 gate.

### X25519 (RFC 7748)

| section | what | test |
|---|---|---|
| §5.2 vector 1 | scalar-mult, single shot | `x25519::tests::rfc7748_5_2_vector1` |
| §5.2 vector 2 | scalar-mult, second canonical shot | `x25519::tests::rfc7748_5_2_vector2` |
| §5.2 iterated 1 | k=u=9 then one round | `x25519::tests::rfc7748_5_2_iterated_one` |
| §5.2 iterated 1000 | 1000-round chained k/u | `x25519::tests::rfc7748_5_2_iterated_1000` |
| §6.1 | full ECDH — Alice/Bob public keys + shared secret | `x25519::tests::rfc7748_6_1_ecdh` |
| §6.1 (base-table) | Alice public via signed-comb basepoint mult | `x25519::base::tests::rfc7748_alice_public_key_via_basepoint_comb` |
| §6.1 (base-table) | Bob public via signed-comb basepoint mult | `x25519::base::tests::rfc7748_bob_public_key_via_basepoint_comb` |
| §6.1 (edwards) | basepoint via Edwards form ↔ Montgomery agreement | `x25519::edwards::tests::edwards_basepoint_matches_montgomery_for_known_vector` |

### BLAKE2s (RFC 7693)

| section | what | test |
|---|---|---|
| §B | BLAKE2s-256("abc") | `blake2s::tests::blake2s_abc` |
| §A reference | BLAKE2s-256 of the empty input | `blake2s::tests::blake2s_empty` |
| §A keyed | keyed BLAKE2s-256, key=00..1f, empty message | `blake2s::tests::blake2s_keyed_empty` |

### SHA-3 / SHAKE (NIST FIPS 202)

| algorithm | what | test |
|---|---|---|
| SHA3-256 | empty message | `sha3::tests::sha3_256_empty` |
| SHA3-256 | "abc" | `sha3::tests::sha3_256_abc` |
| SHA3-512 | empty message | `sha3::tests::sha3_512_empty` |
| SHA3-512 | "abc" | `sha3::tests::sha3_512_abc` |
| SHAKE128 | empty message, 32-byte output | `sha3::tests::shake128_empty_32` |
| SHAKE256 | empty message, 32-byte output | `sha3::tests::shake256_empty_32` |

### ML-KEM-768 (NIST FIPS 203)

Driven by the NIST ACVP-Server JSON test vectors (gen-val/json-files/
ML-KEM-keyGen-FIPS203 + ML-KEM-encapDecap-FIPS203, internalProjection),
flattened into a zero-dep line format. Test vectors live at
`tests/mlkem_acvp_768.txt`; harness at `tests/mlkem_acvp.rs`.

| operation | what | test |
|---|---|---|
| keyGen | (d, z) → (ek, dk) matches reference | `tests/mlkem_acvp.rs::keygen_matches_acvp` |
| encaps | (ek, m) → (k, c) matches reference | `tests/mlkem_acvp.rs::encaps_matches_acvp` |
| decaps | (dk, c) → k matches reference (incl. implicit-reject) | `tests/mlkem_acvp.rs::decaps_matches_acvp` |

## Known gaps — deliberately not closed in v0.23

These constructions have no IETF/NIST-published vectors at the parameters
we use, so we cannot freeze "the spec's" vector. Coverage relies on the
property tests + the cross-validation that each underlying primitive
*does* have a frozen RFC vector.

- **HKDF-BLAKE2s.** RFC 5869 publishes vectors for SHA-256 / SHA-1 only.
  The Noise spec defines HKDF over BLAKE2s but does not ship test
  vectors. Coverage:
  - HMAC-BLAKE2s construction property-tested in
    `hkdf::tests::hmac_matches_textbook_definition` +
    `hkdf::tests::hmac_long_key_is_prehashed`.
  - HKDF-Expand prefix / determinism / info-sensitivity property-tested
    in the remaining `hkdf::tests::*`.
  - The underlying BLAKE2s primitive has its RFC vector frozen (above).
- **Noise_IK end-to-end handshake.** The Noise framework spec (rev 34)
  defines the IK pattern but does not ship per-implementation test
  vectors comparable to RFC test vectors. Cross-validation is
  implementation-to-implementation (cacophony, noise-c) and is **not in
  the v1.0 scope** — gnet's handshake is exercised end-to-end by the
  Noise crate's property tests and the daemon's integration tests, but
  no third-party fixture is frozen here.
- **Hybrid (Noise_IK + ML-KEM-768) handshake.** Not a published
  construction. gnet's hybrid is documented in
  `crates/gnet-noise/HYBRID.md`. Wire-format regression coverage lives in
  the noise crate's `tests/transport.rs`; no third-party vector exists.

## Adding a vector

1. Find the spec section / table. Cite it.
2. Add the test under `crates/gnet-crypto/src/<primitive>/...` (small
   single-shot vectors) or `crates/gnet-crypto/tests/<name>.rs` (large
   vector tables — keep them out of the inline test module so
   `cargo test --release` doesn't re-build the whole file just for the
   fixture).
3. Append a row to the table above. Once committed, the vector is a
   contract — changing it requires explicit acknowledgement.
