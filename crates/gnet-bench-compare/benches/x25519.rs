//! X25519 scalar multiplication: gnet's hand-rolled impl vs. `x25519-dalek`,
//! the de-facto SOTA Rust implementation (RustCrypto / dalek-cryptography).
//!
//! Both expose the same primitive: given a 32-byte scalar (private key) and
//! 32-byte point (peer's public key), compute the shared secret. Every Noise
//! handshake does 1–3 of these; reflexive endpoint discovery does zero, AEAD
//! does zero, so this is purely a handshake-rate cost.
//!
//! Run: `cargo bench -p gnet-bench-compare --bench x25519`.

use gnet_bench_compare::{bench, bench_vs, opaque, section};
use gnet_rand::random_32;

fn main() {
    section("X25519 scalar multiplication (one ECDH operation)");

    // Curve25519 basepoint u = 9 (RFC 7748 §4.1).
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let alice_sk: [u8; 32] = random_32();
    let bob_sk: [u8; 32] = random_32();
    let alice_pk = gnet_crypto::x25519::x25519(&alice_sk, &basepoint);
    let bob_pk = gnet_crypto::x25519::x25519(&bob_sk, &basepoint);

    // BASELINE: gnet's hand-rolled X25519.
    let gnet_ns = bench("gnet-crypto::x25519", 10_000, || {
        let ss = gnet_crypto::x25519::x25519(opaque(&alice_sk), opaque(&bob_pk));
        opaque(ss);
    });

    // COMPETITOR: dalek's x25519-dalek (the Rust gold standard).
    use x25519_dalek::{PublicKey, StaticSecret};
    let dalek_alice = StaticSecret::from(alice_sk);
    let dalek_bob_pub = PublicKey::from(bob_pk);
    bench_vs("x25519-dalek::diffie_hellman", gnet_ns, 10_000, || {
        let ss = opaque(&dalek_alice).diffie_hellman(opaque(&dalek_bob_pub));
        opaque(ss);
    });

    // Sanity: both impls produce the same shared secret on the same input.
    let gnet_ss = gnet_crypto::x25519::x25519(&alice_sk, &bob_pk);
    let dalek_ss = StaticSecret::from(alice_sk).diffie_hellman(&PublicKey::from(bob_pk));
    assert_eq!(gnet_ss, *dalek_ss.as_bytes(), "x25519 output must agree");
    println!("\n  (sanity ✓ — gnet-crypto and x25519-dalek produce identical shared secrets)");
    let _ = alice_pk;
}
