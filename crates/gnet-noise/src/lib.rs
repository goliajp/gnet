//! `mesh-noise` — the Noise_IK handshake (the pattern WireGuard uses) for
//! the mesh overlay. No external dependencies: built entirely on the
//! in-house [`gnet_crypto`] primitives.
//!
//! Cipher suite: `Noise_IK_25519_ChaChaPoly_BLAKE2s`.
//!
//! Built bottom-up:
//! - [`cipher_state`] — an AEAD key plus a nonce counter (Noise §5.1)
//! - [`symmetric_state`] — chaining key + transcript hash + cipher (§5.2)
//! - [`handshake`] — the Noise_IK initiator / responder state machines
//!
//! Ephemeral keys are injected by the caller (no RNG dependency here).
//!
//! # Example
//!
//! ```
//! use gnet_noise::handshake::{Initiator, Responder};
//! use gnet_crypto::x25519;
//!
//! let base = {
//!     let mut b = [0u8; 32];
//!     b[0] = 9;
//!     b
//! };
//! let responder_static = [0x22u8; 32];
//! let responder_static_pub = x25519::x25519(&responder_static, &base);
//!
//! // ephemerals are injected (this crate has no RNG)
//! let mut initiator = Initiator::new([0x11u8; 32], responder_static_pub, [0x33u8; 32]);
//! let mut responder = Responder::new(responder_static, [0x44u8; 32]);
//!
//! let msg1 = initiator.write_message_1(b"hello");
//! responder.read_message_1(&msg1).unwrap();
//! let (msg2, mut responder_tp) = responder.write_message_2(b"world").unwrap();
//! let (mut initiator_tp, _payload) = initiator.read_message_2(&msg2).unwrap();
//!
//! let ct = initiator_tp.send.encrypt_with_ad(b"", b"ping");
//! assert_eq!(responder_tp.recv.decrypt_with_ad(b"", &ct).unwrap(), b"ping".to_vec());
//! ```

pub mod cipher_state;
pub mod handshake;
pub mod hybrid;
pub mod replay;
pub mod symmetric_state;
