//! Fuzz `HybridResponder::read_message_1` against arbitrary byte inputs.
//!
//! The hybrid Noise_IK + ML-KEM-768 responder is the first untrusted
//! crypto-touching code on a fresh peer's connection. Garbage msg1 must
//! return `None` cleanly — no panic, no OOB read on a short or
//! length-fuzzed payload (the message carries `e || ek || ct || s_enc
//! || aead-tag` segments behind length-implicit boundaries; tweaking a
//! length-implicit boundary should never crash).
//!
//! A deterministic responder is built fresh per fuzz iteration from a
//! fixed seed so the fuzzer's mutator drives the input bytes, not the
//! responder state. We don't care about reuse — this is purely a
//! decoder/crypto-input fuzz, not a session fuzz.
//!
//! Run with:
//!     cd crates/gnet-noise && cargo +nightly fuzz run noise_read_message_1

#![no_main]

use gnet_crypto::mlkem;
use gnet_noise::hybrid::HybridResponder;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // deterministic key pair — never trust the fuzzer's input to drive
    // our identity; the fuzz is on the input message bytes.
    let static_priv = [7u8; 32];
    let ephemeral_priv = [11u8; 32];
    let d = [13u8; 32];
    let z = [17u8; 32];
    let (mlkem_ek, mlkem_dk) = mlkem::keygen(&d, &z);
    let mut resp = HybridResponder::new(static_priv, &mlkem_ek, &mlkem_dk, ephemeral_priv);
    let _ = resp.read_message_1(data);
});
