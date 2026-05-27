//! Hex encode/decode: gnet-hex's hand-rolled lowercase impl vs. the `hex`
//! crate (the de-facto Rust standard for hex codecs).
//!
//! Same input shape as `gnet-hex`'s own bench: 32-byte X25519 pubkey is the
//! per-join hot path; the 1184-byte ML-KEM ek is the per-join cold path
//! (one encode + one decode each).
//!
//! Run: `cargo bench -p gnet-bench-compare --bench hex`.

use gnet_bench_compare::{bench, bench_vs, opaque, section};

fn main() {
    section("Hex encode 32 B (X25519 pubkey)");

    let key32 = [0xABu8; 32];
    let hex32 = gnet_hex::encode(&key32);

    let gnet_enc_ns = bench("gnet-hex::encode (32 B)", 1_000_000, || {
        let s = gnet_hex::encode(opaque(&key32));
        opaque(s);
    });
    bench_vs("hex::encode (32 B)", gnet_enc_ns, 1_000_000, || {
        let s = hex::encode(opaque(&key32));
        opaque(s);
    });

    section("Hex decode 64 chars → 32 B");

    let gnet_dec_ns = bench("gnet-hex::decode_32", 1_000_000, || {
        let b = gnet_hex::decode_32(opaque(&hex32));
        opaque(b);
    });
    bench_vs("hex::decode_to_slice (32 B target)", gnet_dec_ns, 1_000_000, || {
        let mut out = [0u8; 32];
        hex::decode_to_slice(opaque(&hex32), opaque(&mut out)).expect("decode");
        opaque(out);
    });

    section("Hex encode 1184 B (ML-KEM-768 ek)");

    let ek = vec![0xCDu8; 1184];
    let ek_hex = gnet_hex::encode(&ek);

    let gnet_enc_ek_ns = bench("gnet-hex::encode (1184 B)", 10_000, || {
        let s = gnet_hex::encode(opaque(&ek));
        opaque(s);
    });
    bench_vs("hex::encode (1184 B)", gnet_enc_ek_ns, 10_000, || {
        let s = hex::encode(opaque(&ek));
        opaque(s);
    });

    section("Hex decode 2368 chars → 1184 B");

    let gnet_dec_ek_ns = bench("gnet-hex::decode (1184 B)", 10_000, || {
        let b = gnet_hex::decode(opaque(&ek_hex));
        opaque(b);
    });
    bench_vs("hex::decode (1184 B)", gnet_dec_ek_ns, 10_000, || {
        let b = hex::decode(opaque(&ek_hex)).expect("decode");
        opaque(b);
    });
}
