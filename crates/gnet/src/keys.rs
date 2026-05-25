//! Static keypair generation for mesh endpoints: the X25519 identity key plus
//! a deterministically-derived ML-KEM-768 key pair for the post-quantum hybrid
//! handshake. Deriving ML-KEM from the X25519 private key keeps the secret a
//! single 32-byte value; only the (public) ML-KEM encapsulation key needs to
//! be shared with peers.

use gnet_crypto::{mlkem, sha3, x25519};

/// Curve25519 base point (`u = 9`).
const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// Domain separator for ML-KEM seed derivation.
const MLKEM_DERIVE_DOMAIN: &[u8] = b"mesh-mlkem768-v1";

/// Generate a fresh static keypair `(private, public)` using OS entropy.
pub fn generate_static() -> ([u8; 32], [u8; 32]) {
    let private = gnet_rand::random_32();
    let public = x25519::x25519(&private, &BASE_POINT);
    (private, public)
}

/// Derive the public key for a static private key.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    x25519::x25519(private, &BASE_POINT)
}

/// Deterministically derive a node's ML-KEM-768 key pair `(ek, dk)` from its
/// X25519 private key. The 64-byte ML-KEM seed `(d ‖ z)` is `SHAKE256(priv ‖
/// domain)`, so the same private key always yields the same key pair and peers
/// can be configured with the (public) `ek` alone.
pub fn derive_mlkem(private: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut seed_in = Vec::with_capacity(32 + MLKEM_DERIVE_DOMAIN.len());
    seed_in.extend_from_slice(private);
    seed_in.extend_from_slice(MLKEM_DERIVE_DOMAIN);
    let mut seed = [0u8; 64];
    sha3::shake256(&seed_in, &mut seed);
    let d: [u8; 32] = seed[..32].try_into().expect("32");
    let z: [u8; 32] = seed[32..].try_into().expect("32");
    mlkem::keygen(&d, &z)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_matches_derivation() {
        let (sk, pk) = generate_static();
        assert_eq!(public_key(&sk), pk);
    }

    #[test]
    fn fresh_keys_differ() {
        let (sk1, _) = generate_static();
        let (sk2, _) = generate_static();
        assert_ne!(sk1, sk2);
    }

    #[test]
    fn mlkem_derivation_is_deterministic_and_usable() {
        let priv1 = [0x42u8; 32];
        let (ek, dk) = derive_mlkem(&priv1);
        // deterministic
        assert_eq!(derive_mlkem(&priv1), (ek.clone(), dk.clone()));
        assert_eq!(ek.len(), mlkem::EK_LEN);
        assert_eq!(dk.len(), mlkem::DK_LEN);
        // a different private key yields a different ek
        let (ek2, _) = derive_mlkem(&[0x43u8; 32]);
        assert_ne!(ek, ek2);
        // the pair works: encaps to ek, decaps with dk recovers the secret
        let (ss, ct) = mlkem::encaps(&ek, &[7u8; 32]);
        assert_eq!(mlkem::decaps(&dk, &ct), ss);
    }
}
