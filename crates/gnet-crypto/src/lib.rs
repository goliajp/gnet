//! `gnet-crypto` — zero-dependency, pure-Rust cryptographic core for the
//! gnet overlay. **No external crates, by design.** Every primitive is
//! validated against its published known-answer test vectors and written
//! constant-time where secrets are involved.
//!
//! Built bottom-up. Current surface:
//! - [`chacha20`] — ChaCha20 stream cipher (RFC 8439)
//! - [`poly1305`] — Poly1305 one-time MAC (RFC 8439)
//! - [`aead`] — ChaCha20-Poly1305 AEAD (RFC 8439)
//! - [`x25519`] — X25519 Diffie-Hellman on Curve25519 (RFC 7748)
//! - [`blake2s`] — BLAKE2s hash / keyed MAC (RFC 7693)
//! - [`hkdf`] — HKDF (RFC 5869) over HMAC-BLAKE2s
//! - [`sha3`] — SHA-3 / SHAKE (FIPS 202), for the ML-KEM hybrid
//!
//! Planned, same KAT-driven discipline: the ML-KEM post-quantum KEM
//! (FIPS 203) for the hybrid handshake.
//!
//! # Example
//!
//! ```
//! use gnet_crypto::{aead, x25519};
//!
//! let base = {
//!     let mut b = [0u8; 32];
//!     b[0] = 9;
//!     b
//! };
//! let alice_sk = [0x11u8; 32];
//! let bob_sk = [0x22u8; 32];
//!
//! // X25519 key agreement
//! let shared = x25519::x25519(&alice_sk, &x25519::x25519(&bob_sk, &base));
//! assert_eq!(shared, x25519::x25519(&bob_sk, &x25519::x25519(&alice_sk, &base)));
//!
//! // ChaCha20-Poly1305 AEAD with the shared secret
//! let (ct, tag) = aead::seal(&shared, &[0u8; 12], b"ad", b"hi");
//! assert_eq!(
//!     aead::open(&shared, &[0u8; 12], b"ad", &ct, &tag).unwrap(),
//!     b"hi".to_vec()
//! );
//! ```

// `unsafe` is permitted only in clearly-marked SIMD acceleration paths
// (each with a `// SAFETY:` note and guarded by KAT + differential tests
// against the portable scalar reference). All field / MAC / hash arithmetic
// and the portable fallbacks stay safe.

pub mod aead;
pub mod blake2s;
pub mod chacha20;
pub mod hkdf;
pub mod mlkem;
pub mod poly1305;
pub mod sha3;
pub mod x25519;
