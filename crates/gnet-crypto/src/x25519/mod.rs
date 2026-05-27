//! X25519 Diffie-Hellman on Curve25519 — RFC 7748.
//!
//! Field GF(2^255 - 19) in five 51-bit limbs (radix 2^51) with `u128`
//! products, scalar multiplication via a constant-time Montgomery ladder
//! (conditional swaps are mask-driven, no secret-dependent branches), and
//! field inversion by Fermat's little theorem (`x^(p-2)`). 0-dependency.

mod base;
mod base_table;
mod edwards;
mod field;
mod field2255;
mod scalar;

pub use base::{x25519_base, x25519_base_pair};
pub use scalar::x25519;

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            let hi = char::from(b[2 * i]).to_digit(16).unwrap() as u8;
            let lo = char::from(b[2 * i + 1]).to_digit(16).unwrap() as u8;
            *o = (hi << 4) | lo;
        }
        out
    }

    fn base() -> [u8; 32] {
        let mut u = [0u8; 32];
        u[0] = 9;
        u
    }

    /// RFC 7748 §5.2 — scalar-mult test vector 1.
    #[test]
    fn rfc7748_5_2_vector1() {
        let k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let r = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519(&k, &u), r);
    }

    /// RFC 7748 §5.2 — scalar-mult test vector 2.
    #[test]
    fn rfc7748_5_2_vector2() {
        let k = hex32("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        let u = hex32("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        let r = hex32("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        assert_eq!(x25519(&k, &u), r);
    }

    /// RFC 7748 §5.2 — iterated test, after one round (`k = u = 9`).
    #[test]
    fn rfc7748_5_2_iterated_one() {
        let u = base();
        let k = base();
        let r = hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
        assert_eq!(x25519(&k, &u), r);
    }

    /// RFC 7748 §5.2 — iterated test, after 1000 rounds (`k`/`u` chained).
    #[test]
    fn rfc7748_5_2_iterated_1000() {
        let mut k = base();
        let mut u = base();
        for _ in 0..1000 {
            let next = x25519(&k, &u);
            u = k;
            k = next;
        }
        assert_eq!(
            k,
            hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    /// RFC 7748 §6.1 — full ECDH: public keys and the shared secret.
    #[test]
    fn rfc7748_6_1_ecdh() {
        let a_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b_priv = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let a_pub = x25519(&a_priv, &base());
        let b_pub = x25519(&b_priv, &base());
        assert_eq!(
            a_pub,
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b_pub,
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );
        let shared_a = x25519(&a_priv, &b_pub);
        let shared_b = x25519(&b_priv, &a_pub);
        assert_eq!(shared_a, shared_b);
        assert_eq!(
            shared_a,
            hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
    }
}
