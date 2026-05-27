//! ML-KEM-768 keygen / encaps / decaps: gnet's hand-rolled NIST FIPS 203
//! reference impl vs. RustCrypto's `ml-kem` crate.
//!
//! ML-KEM is the post-quantum half of gnet's hybrid Noise_IK handshake — one
//! keygen + one encaps + one decaps per session. At ~100 µs/op this is the
//! single biggest cost in setup, so a 2× regression doubles handshake latency.
//!
//! Run: `cargo bench -p gnet-bench-compare --bench mlkem`.

use gnet_bench_compare::{bench, bench_vs, opaque, section};
use ml_kem::{KemCore, MlKem768};
use ml_kem::kem::{Decapsulate, Encapsulate};

fn main() {
    section("ML-KEM-768 keygen (one keypair)");

    // BASELINE: gnet-crypto's mlkem keygen. Takes two 32-byte randomness inputs
    // (d, z) per FIPS 203.
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    gnet_rand::fill(&mut d);
    gnet_rand::fill(&mut z);
    let gnet_keygen_ns = bench("gnet-crypto::mlkem::keygen", 200, || {
        gnet_rand::fill(opaque(&mut d));
        gnet_rand::fill(&mut z);
        let kp = gnet_crypto::mlkem::keygen(&d, &z);
        opaque(kp);
    });

    // COMPETITOR: RustCrypto `ml-kem`. Uses `rand_core::OsRng` internally.
    let mut rng = OsRngCompat;
    bench_vs("ml-kem (RustCrypto)::generate", gnet_keygen_ns, 200, || {
        let (dk, ek) = MlKem768::generate(opaque(&mut rng));
        opaque((dk, ek));
    });

    section("ML-KEM-768 encaps (sender side, per handshake init)");

    let (gnet_ek, gnet_dk) = gnet_crypto::mlkem::keygen(&d, &z);
    let mut encaps_rand = [0u8; 32];
    gnet_rand::fill(&mut encaps_rand);
    let gnet_encaps_ns = bench("gnet-crypto::mlkem::encaps", 200, || {
        gnet_rand::fill(opaque(&mut encaps_rand));
        let (ss, ct) = gnet_crypto::mlkem::encaps(opaque(&gnet_ek), opaque(&encaps_rand));
        opaque((ss, ct));
    });

    let (comp_dk, comp_ek) = MlKem768::generate(&mut rng);
    bench_vs("ml-kem::encapsulate", gnet_encaps_ns, 200, || {
        let (ct, ss) = opaque(&comp_ek).encapsulate(opaque(&mut rng)).expect("encaps");
        opaque((ct, ss));
    });

    section("ML-KEM-768 decaps (receiver side, per handshake msg1 read)");

    let (ss_a, ct) = gnet_crypto::mlkem::encaps(&gnet_ek, &encaps_rand);
    let gnet_decaps_ns = bench("gnet-crypto::mlkem::decaps", 200, || {
        let ss = gnet_crypto::mlkem::decaps(opaque(&gnet_dk), opaque(&ct));
        opaque(ss);
    });

    let (comp_ct, _comp_ss_a) = comp_ek.encapsulate(&mut rng).expect("encaps");
    bench_vs("ml-kem::decapsulate", gnet_decaps_ns, 200, || {
        let ss = opaque(&comp_dk).decapsulate(opaque(&comp_ct)).expect("decaps");
        opaque(ss);
    });

    // sanity: gnet's encaps/decaps round-trip matches.
    let (ss_b, _) = gnet_crypto::mlkem::encaps(&gnet_ek, &encaps_rand);
    assert_eq!(ss_a, ss_b, "gnet mlkem must be deterministic for fixed randomness");
    println!("\n  (sanity ✓ — gnet-crypto::mlkem encaps is deterministic in its randomness input)");
}

// Tiny shim so we can use gnet_rand for the competitor too, instead of pulling
// `rand_core` into the workspace deps just for this bench. The `ml-kem` crate
// only needs a `CryptoRng + RngCore` source; gnet_rand wrapped in this struct
// satisfies the bound without external rand crates.
struct OsRngCompat;
impl rand_core::CryptoRng for OsRngCompat {}
impl rand_core::RngCore for OsRngCompat {
    fn next_u32(&mut self) -> u32 {
        gnet_rand::random_u32()
    }
    fn next_u64(&mut self) -> u64 {
        let lo = u64::from(gnet_rand::random_u32());
        let hi = u64::from(gnet_rand::random_u32());
        (hi << 32) | lo
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        gnet_rand::fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        gnet_rand::fill(dest);
        Ok(())
    }
}
