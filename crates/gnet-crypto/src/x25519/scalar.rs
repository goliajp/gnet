//! Montgomery-ladder X25519 (RFC 7748 §5).
//!
//! Constant-time scalar mult of an arbitrary u-coordinate. Conditional swaps
//! are mask-driven; no secret-dependent branches. Field inversion uses
//! Fermat's little theorem. Stays as the general `x25519(scalar, point)`
//! routine; for the fixed-base case (`scalar · 9`) see `base::x25519_base`
//! which uses an Edwards comb table and is ~4× faster.

use super::field::{
    FE_ONE, FE_ZERO, Fe, cswap, fadd, finvert, fmul, fmul121665, fsqr, fsub, pack, unpack,
};

/// Clamp the scalar per RFC 7748 §5 (decodeScalar25519).
pub(super) fn clamp(s: &mut [u8; 32]) {
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

/// X25519: scalar multiplication of base/u-coordinate `point` by `scalar`.
/// Both inputs and the output are 32-byte little-endian. RFC 7748 §5.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let mut s = *scalar;
    clamp(&mut s);
    let x1: Fe = unpack(point);

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
