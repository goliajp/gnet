//! X25519 Diffie-Hellman on Curve25519 — RFC 7748.
//!
//! Field GF(2^255 - 19) in five 51-bit limbs (radix 2^51) with `u128`
//! products, scalar multiplication via a constant-time Montgomery ladder
//! (conditional swaps are mask-driven, no secret-dependent branches), and
//! field inversion by Fermat's little theorem (`x^(p-2)`). 0-dependency.

/// 51-bit field element (radix 2^51), five limbs.
type Fe = [u64; 5];

const MASK51: u64 = 0x0007_ffff_ffff_ffff;
const TWO54M152: u64 = (1u64 << 54) - 152;
const TWO54M8: u64 = (1u64 << 54) - 8;
const FE_ZERO: Fe = [0; 5];
const FE_ONE: Fe = [1, 0, 0, 0, 0];

fn load_le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Field add (limbs grow; the next multiply re-reduces).
fn fadd(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ]
}

/// Field subtract `a - b`, biased by a multiple of `2p` to stay positive.
fn fsub(a: &Fe, b: &Fe) -> Fe {
    [
        a[0] + TWO54M152 - b[0],
        a[1] + TWO54M8 - b[1],
        a[2] + TWO54M8 - b[2],
        a[3] + TWO54M8 - b[3],
        a[4] + TWO54M8 - b[4],
    ]
}

/// Field multiply with 2^255-19 reduction (curve25519-donna-c64 schedule).
fn fmul(a: &Fe, b: &Fe) -> Fe {
    let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
    let (r0, r1, r2, r3, r4) = (a[0], a[1], a[2], a[3], a[4]);
    let (s0, s1, s2, s3, s4) = (b[0], b[1], b[2], b[3], b[4]);

    let mut t0 = m(r0, s0);
    let mut t1 = m(r0, s1) + m(r1, s0);
    let mut t2 = m(r0, s2) + m(r2, s0) + m(r1, s1);
    let mut t3 = m(r0, s3) + m(r3, s0) + m(r1, s2) + m(r2, s1);
    let mut t4 = m(r0, s4) + m(r4, s0) + m(r3, s1) + m(r1, s3) + m(r2, s2);

    let (e1, e2, e3, e4) = (r1 * 19, r2 * 19, r3 * 19, r4 * 19);
    t0 += m(e4, s1) + m(e1, s4) + m(e2, s3) + m(e3, s2);
    t1 += m(e4, s2) + m(e2, s4) + m(e3, s3);
    t2 += m(e4, s3) + m(e3, s4);
    t3 += m(e4, s4);

    let mut o0 = (t0 as u64) & MASK51;
    let mut c = (t0 >> 51) as u64;
    t1 += u128::from(c);
    let mut o1 = (t1 as u64) & MASK51;
    c = (t1 >> 51) as u64;
    t2 += u128::from(c);
    let mut o2 = (t2 as u64) & MASK51;
    c = (t2 >> 51) as u64;
    t3 += u128::from(c);
    let o3 = (t3 as u64) & MASK51;
    c = (t3 >> 51) as u64;
    t4 += u128::from(c);
    let o4 = (t4 as u64) & MASK51;
    c = (t4 >> 51) as u64;
    o0 += c * 19;
    c = o0 >> 51;
    o0 &= MASK51;
    o1 += c;
    c = o1 >> 51;
    o1 &= MASK51;
    o2 += c;
    [o0, o1, o2, o3, o4]
}

/// Field square (curve25519-donna-c64 schedule). Faster than `fmul(a, a)`:
/// the off-diagonal cross terms are computed once and doubled.
fn fsqr(a: &Fe) -> Fe {
    let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
    let (r0, r1, r2, r3, r4) = (a[0], a[1], a[2], a[3], a[4]);
    let d0 = r0 * 2;
    let d1 = r1 * 2;
    let d2 = r2 * 2 * 19;
    let d419 = r4 * 19;
    let d4 = d419 * 2;

    let t0 = m(r0, r0) + m(d4, r1) + m(d2, r3);
    let mut t1 = m(d0, r1) + m(d4, r2) + m(r3, r3 * 19);
    let mut t2 = m(d0, r2) + m(r1, r1) + m(d4, r3);
    let mut t3 = m(d0, r3) + m(d1, r2) + m(r4, d419);
    let mut t4 = m(d0, r4) + m(d1, r3) + m(r2, r2);

    let mut o0 = (t0 as u64) & MASK51;
    let mut c = (t0 >> 51) as u64;
    t1 += u128::from(c);
    let mut o1 = (t1 as u64) & MASK51;
    c = (t1 >> 51) as u64;
    t2 += u128::from(c);
    let mut o2 = (t2 as u64) & MASK51;
    c = (t2 >> 51) as u64;
    t3 += u128::from(c);
    let o3 = (t3 as u64) & MASK51;
    c = (t3 >> 51) as u64;
    t4 += u128::from(c);
    let o4 = (t4 as u64) & MASK51;
    c = (t4 >> 51) as u64;
    o0 += c * 19;
    c = o0 >> 51;
    o0 &= MASK51;
    o1 += c;
    c = o1 >> 51;
    o1 &= MASK51;
    o2 += c;
    [o0, o1, o2, o3, o4]
}

/// Repeated squaring: `a^(2^n)`.
fn fsqr_n(mut a: Fe, n: usize) -> Fe {
    for _ in 0..n {
        a = fsqr(&a);
    }
    a
}

/// Field multiply by the small constant 121665 (= a24).
fn fmul121665(a: &Fe) -> Fe {
    let s = 121665u128;
    let mut acc = u128::from(a[0]) * s;
    let o0 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[1]) * s;
    let o1 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[2]) * s;
    let o2 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[3]) * s;
    let o3 = (acc as u64) & MASK51;
    acc >>= 51;
    acc += u128::from(a[4]) * s;
    let o4 = (acc as u64) & MASK51;
    acc >>= 51;
    [o0 + (acc as u64) * 19, o1, o2, o3, o4]
}

/// Constant-time conditional swap of `a` and `b` when `swap` is 1.
fn cswap(swap: u64, a: &mut Fe, b: &mut Fe) {
    let mask = 0u64.wrapping_sub(swap & 1);
    for (x, y) in a.iter_mut().zip(b.iter_mut()) {
        let t = mask & (*x ^ *y);
        *x ^= t;
        *y ^= t;
    }
}

/// Field inverse `z^(p-2)` via Fermat (curve25519-donna addition chain).
fn finvert(z: &Fe) -> Fe {
    let z2 = fsqr(z);
    let z8 = fsqr_n(z2, 2);
    let z9 = fmul(&z8, z);
    let z11 = fmul(&z9, &z2);
    let z22 = fsqr(&z11);
    let z2_5_0 = fmul(&z22, &z9);
    let z2_10_0 = fmul(&fsqr_n(z2_5_0, 5), &z2_5_0);
    let z2_20_0 = fmul(&fsqr_n(z2_10_0, 10), &z2_10_0);
    let z2_40_0 = fmul(&fsqr_n(z2_20_0, 20), &z2_20_0);
    let z2_50_0 = fmul(&fsqr_n(z2_40_0, 10), &z2_10_0);
    let z2_100_0 = fmul(&fsqr_n(z2_50_0, 50), &z2_50_0);
    let z2_200_0 = fmul(&fsqr_n(z2_100_0, 100), &z2_100_0);
    let z2_250_0 = fmul(&fsqr_n(z2_200_0, 50), &z2_50_0);
    fmul(&fsqr_n(z2_250_0, 5), &z11)
}

/// Decode a u-coordinate (RFC 7748): little-endian, high bit masked.
fn unpack(b: &[u8; 32]) -> Fe {
    [
        load_le64(&b[0..8]) & MASK51,
        (load_le64(&b[6..14]) >> 3) & MASK51,
        (load_le64(&b[12..20]) >> 6) & MASK51,
        (load_le64(&b[19..27]) >> 1) & MASK51,
        (load_le64(&b[24..32]) >> 12) & MASK51,
    ]
}

/// Reduce fully mod p and serialize to 32 little-endian bytes.
fn pack(input: &Fe) -> [u8; 32] {
    let mut t = *input;
    for _ in 0..2 {
        t[1] += t[0] >> 51;
        t[0] &= MASK51;
        t[2] += t[1] >> 51;
        t[1] &= MASK51;
        t[3] += t[2] >> 51;
        t[2] &= MASK51;
        t[4] += t[3] >> 51;
        t[3] &= MASK51;
        t[0] += 19 * (t[4] >> 51);
        t[4] &= MASK51;
    }
    // add 19, carry: now offset so a conditional subtraction of p is exact
    t[0] += 19;
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t[2] += t[1] >> 51;
    t[1] &= MASK51;
    t[3] += t[2] >> 51;
    t[2] &= MASK51;
    t[4] += t[3] >> 51;
    t[3] &= MASK51;
    t[0] += 19 * (t[4] >> 51);
    t[4] &= MASK51;
    // add 2^255 - 19, carry, drop the top bit
    t[0] += (1u64 << 51) - 19;
    t[1] += (1u64 << 51) - 1;
    t[2] += (1u64 << 51) - 1;
    t[3] += (1u64 << 51) - 1;
    t[4] += (1u64 << 51) - 1;
    t[1] += t[0] >> 51;
    t[0] &= MASK51;
    t[2] += t[1] >> 51;
    t[1] &= MASK51;
    t[3] += t[2] >> 51;
    t[2] &= MASK51;
    t[4] += t[3] >> 51;
    t[3] &= MASK51;
    t[4] &= MASK51;

    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&(t[0] | (t[1] << 51)).to_le_bytes());
    out[8..16].copy_from_slice(&((t[1] >> 13) | (t[2] << 38)).to_le_bytes());
    out[16..24].copy_from_slice(&((t[2] >> 26) | (t[3] << 25)).to_le_bytes());
    out[24..32].copy_from_slice(&((t[3] >> 39) | (t[4] << 12)).to_le_bytes());
    out
}

/// Clamp the scalar per RFC 7748 §5 (decodeScalar25519).
fn clamp(s: &mut [u8; 32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

/// X25519: scalar multiplication of base/u-coordinate `point` by `scalar`.
/// Both inputs and the output are 32-byte little-endian. RFC 7748 §5.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut s = *scalar;
    clamp(&mut s);
    let x1 = unpack(point);

    let mut x2 = FE_ONE;
    let mut z2 = FE_ZERO;
    let mut x3 = x1;
    let mut z3 = FE_ONE;
    let mut swap = 0u64;

    for t in (0..=254).rev() {
        let bit = u64::from((s[t >> 3] >> (t & 7)) & 1);
        swap ^= bit;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = bit;

        let a = fadd(&x2, &z2);
        let aa = fsqr(&a);
        let b = fsub(&x2, &z2);
        let bb = fsqr(&b);
        let e = fsub(&aa, &bb);
        let c = fadd(&x3, &z3);
        let d = fsub(&x3, &z3);
        let da = fmul(&d, &a);
        let cb = fmul(&c, &b);
        x3 = fsqr(&fadd(&da, &cb));
        z3 = fmul(&x1, &fsqr(&fsub(&da, &cb)));
        x2 = fmul(&aa, &bb);
        z2 = fmul(&e, &fadd(&aa, &fmul121665(&e)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);

    pack(&fmul(&x2, &finvert(&z2)))
}

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
