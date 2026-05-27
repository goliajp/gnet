//! ChaCha20-Poly1305 AEAD seal+open: gnet's hand-rolled impl vs. RustCrypto's
//! `chacha20poly1305` crate (the SOTA pure-Rust impl). Both are constant-time
//! and IETF-spec; the comparison is "how much faster (or slower) is our
//! 0-dep stone than the established library?"
//!
//! AEAD seal is the per-packet hot path: every Transport datagram is sealed
//! once by the sender and opened once by the receiver. At an MTU of 1400 B,
//! a multi-Gbps link calls into this path hundreds of thousands of times per
//! second per session — a 2× regression here would visibly cap throughput.
//!
//! Run: `cargo bench -p gnet-bench-compare --bench chacha20poly1305`.

use chacha20poly1305::{
    AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce,
    aead::Aead,
};
use gnet_bench_compare::{bench, bench_vs, opaque, section};
use gnet_rand::random_32;

const MTU_PAYLOAD: usize = 1400;

fn main() {
    section("ChaCha20-Poly1305 AEAD (seal in-place, 1400 B Transport payload)");

    let key: [u8; 32] = random_32();
    let nonce_bytes = [0u8; 12]; // gnet uses counter-driven nonces; this is a fixed sample.
    let aad = [0u8; 16]; // gnet's Transport AEAD passes empty AAD; competitor side same.
    let plaintext = vec![0xABu8; MTU_PAYLOAD];
    let tag_len = 16;

    // BASELINE: gnet-crypto seal_in_place. Signature: buf is plaintext (encrypted
    // in place); the 16-byte tag is returned separately.
    let mut gnet_buf = vec![0u8; MTU_PAYLOAD];
    let gnet_seal_ns = bench("gnet-crypto::aead::seal_in_place (1400 B)", 5_000, || {
        gnet_buf.copy_from_slice(&plaintext);
        let tag = gnet_crypto::aead::seal_in_place(
            opaque(&key),
            opaque(&nonce_bytes),
            opaque(&aad[..]),
            &mut gnet_buf,
        );
        opaque((tag, &gnet_buf));
    });

    // COMPETITOR: chacha20poly1305 in-place.
    let cipher = ChaCha20Poly1305::new(opaque(&key.into()));
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut comp_buf = plaintext.clone();
    bench_vs(
        "chacha20poly1305::encrypt_in_place (1400 B)",
        gnet_seal_ns,
        5_000,
        || {
            comp_buf.clear();
            comp_buf.extend_from_slice(&plaintext);
            cipher
                .encrypt_in_place(opaque(nonce), opaque(&aad[..]), opaque(&mut comp_buf))
                .expect("encrypt");
            opaque(&comp_buf);
        },
    );

    // For completeness: the allocating `encrypt()` API (returns owned Vec).
    bench_vs(
        "chacha20poly1305::encrypt (allocating)",
        gnet_seal_ns,
        5_000,
        || {
            let ct = cipher
                .encrypt(opaque(nonce), opaque(&plaintext[..]))
                .expect("encrypt");
            opaque(ct);
        },
    );

    section("ChaCha20-Poly1305 AEAD (open / decrypt, 1400 B)");

    // Prepare a fresh sealed message for the open benches.
    let mut sealed = plaintext.clone();
    let sealed_tag = gnet_crypto::aead::seal_in_place(&key, &nonce_bytes, &aad, &mut sealed);

    let mut gnet_open_buf = sealed.clone();
    let gnet_open_ns = bench("gnet-crypto::aead::open_in_place (1400 B)", 5_000, || {
        gnet_open_buf.copy_from_slice(&sealed);
        let _ = gnet_crypto::aead::open_in_place(
            opaque(&key),
            opaque(&nonce_bytes),
            opaque(&aad[..]),
            &mut gnet_open_buf,
            opaque(&sealed_tag),
        );
    });
    let _ = tag_len;

    // For competitor open, we need a competitor-sealed message.
    let mut comp_sealed = plaintext.clone();
    cipher
        .encrypt_in_place(nonce, &aad, &mut comp_sealed)
        .expect("seal for open bench");
    let mut comp_open_buf = comp_sealed.clone();
    bench_vs(
        "chacha20poly1305::decrypt_in_place (1400 B)",
        gnet_open_ns,
        5_000,
        || {
            comp_open_buf.clear();
            comp_open_buf.extend_from_slice(&comp_sealed);
            cipher
                .decrypt_in_place(opaque(nonce), opaque(&aad[..]), opaque(&mut comp_open_buf))
                .expect("decrypt");
            opaque(&comp_open_buf);
        },
    );

    println!();
    println!("  (note: both impls are constant-time pure-Rust ChaCha20-Poly1305. The");
    println!("   competitor uses LLVM auto-vectorisation; gnet-crypto is a scalar");
    println!("   reference impl — perf gap is expected, not a regression.)");
}
