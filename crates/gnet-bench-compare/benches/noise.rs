//! Noise_IK full handshake: gnet-noise's hand-rolled impl vs. `snow`, the
//! de-facto SOTA Rust Noise framework.
//!
//! Compares the *classical* Noise_IK only (X25519 / ChaCha20-Poly1305 /
//! BLAKE2s) — gnet-noise's hybrid (Noise_IK ⊕ ML-KEM) is unique to the gnet
//! stack and has no peer to compare against, so it gets its own row at the
//! end as a "what the hybrid layer adds on top" datapoint.
//!
//! Run: `cargo bench -p gnet-bench-compare --bench noise`.

use gnet_bench_compare::{bench, bench_vs, opaque, section};
use gnet_rand::random_32;
use snow::{Builder, params::NoiseParams};

const NOISE_IK_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

fn main() {
    section("Noise_IK full handshake (msg1+msg2, one initiator + one responder)");

    let ini_sk = random_32();
    let resp_sk = random_32();
    let mut basepoint = [0u8; 32];
    basepoint[0] = 9;
    let resp_pk = gnet_crypto::x25519::x25519(&resp_sk, &basepoint);

    // BASELINE: gnet-noise classical Noise_IK (msg1 write + msg2 read).
    let gnet_classic_ns = bench("gnet-noise::IK classic (msg1 + msg2)", 500, || {
        use gnet_noise::handshake::{Initiator, Responder};
        let mut ini = Initiator::new(opaque(ini_sk), opaque(resp_pk), random_32());
        let msg1 = ini.write_message_1(b"");
        let mut resp = Responder::new(opaque(resp_sk), random_32());
        resp.read_message_1(&msg1).expect("read msg1");
        let (msg2, _resp_t) = resp.write_message_2(b"").expect("write msg2");
        let (_ini_t, _) = ini.read_message_2(&msg2).expect("read msg2");
        opaque(msg2);
    });

    // COMPETITOR: snow Noise_IK.
    let params: NoiseParams = NOISE_IK_PARAMS.parse().expect("snow params");
    bench_vs("snow::IK (msg1 + msg2)", gnet_classic_ns, 500, || {
        let mut ini = Builder::new(opaque(params.clone()))
            .local_private_key(opaque(&ini_sk))
            .expect("local sk")
            .remote_public_key(opaque(&resp_pk))
            .expect("remote pk")
            .build_initiator()
            .expect("build initiator");
        let mut msg1 = vec![0u8; 1024];
        let n1 = ini.write_message(b"", &mut msg1).expect("write msg1");
        let mut resp = Builder::new(params.clone())
            .local_private_key(&resp_sk)
            .expect("resp local sk")
            .build_responder()
            .expect("build responder");
        let mut p1 = vec![0u8; 1024];
        resp.read_message(&msg1[..n1], &mut p1).expect("read msg1");
        let mut msg2 = vec![0u8; 1024];
        let n2 = resp.write_message(b"", &mut msg2).expect("write msg2");
        let mut p2 = vec![0u8; 1024];
        ini.read_message(&msg2[..n2], &mut p2).expect("read msg2");
        let _ = ini.into_transport_mode();
        let _ = resp.into_transport_mode();
        opaque(n2);
    });

    section("gnet hybrid (Noise_IK ⊕ ML-KEM-768) — for reference, no peer to compare");

    // Pre-build the responder ML-KEM keypair so the handshake bench reflects
    // only handshake cost, not key generation.
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    gnet_rand::fill(&mut d);
    gnet_rand::fill(&mut z);
    let (resp_mlkem_ek, resp_mlkem_dk) = gnet_crypto::mlkem::keygen(&d, &z);
    bench("gnet-noise::hybrid (msg1 + msg2)", 200, || {
        use gnet_noise::hybrid::{HybridInitiator, HybridResponder};
        let mut ini = HybridInitiator::new(
            opaque(ini_sk),
            opaque(resp_pk),
            opaque(&resp_mlkem_ek[..]),
            random_32(),
            random_32(),
        );
        let msg1 = ini.write_message_1(b"");
        let mut resp =
            HybridResponder::new(opaque(resp_sk), &resp_mlkem_ek, &resp_mlkem_dk, random_32());
        resp.read_message_1(&msg1).expect("read msg1");
        let (msg2, _resp_t) = resp.write_message_2(b"").expect("write msg2");
        let (_ini_t, _) = ini.read_message_2(&msg2).expect("read msg2");
        opaque(msg2);
    });

    println!();
    println!("  (note: gnet's hybrid handshake adds an ML-KEM-768 encapsulation +");
    println!("   decapsulation to classic Noise_IK — that's the post-quantum cost.)");
}
