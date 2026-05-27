//! Fe2255 ↔ 32-byte LE serialization (`pack` / `unpack`).
//!
//! Both directions decompose the 255-bit field element across the same
//! alternating 26/25-bit limb layout used by the rest of the module
//! (see [`super::mod`] for the bit map). `pack` finishes with the
//! standard 3-step canonical reduction (carry pass → +19 wrap → +p
//! mask) that brings any in-bounds Fe2255 down to its unique
//! representative in `[0, p)` before serializing.

use super::{Fe2255, MASK25, MASK26, reduce};

// ───── pack / unpack ───────────────────────────────────────────────────

/// Decode 32 little-endian bytes into a reduced `Fe2255`. The input is
/// taken `mod 2^255` (the top bit of byte 31 is dropped, matching
/// RFC 7748's u-coordinate decoding rule).
///
/// Byte ↔ limb layout (mirror of [`pack`]):
///
/// ```text
///   limb 0  bits 0..26    → bytes[0..3] low 2 of byte 3
///   limb 1  bits 26..51   → bits 2..8 of byte 3 | bytes[4..6] | low 3 of byte 6
///   limb 2  bits 51..77   → bits 3..8 of byte 6 | bytes[7..9] | low 5 of byte 9
///   limb 3  bits 77..102  → bits 5..8 of byte 9 | bytes[10..12] | low 6 of byte 12
///   limb 4  bits 102..128 → bits 6..8 of byte 12 | bytes[13..15]
///   limb 5  bits 128..153 → bytes[16..19] | low 1 of byte 19
///   limb 6  bits 153..179 → bits 1..8 of byte 19 | bytes[20..21] | low 3 of byte 22
///   limb 7  bits 179..204 → bits 3..8 of byte 22 | bytes[23..24] | low 4 of byte 25
///   limb 8  bits 204..230 → bits 4..8 of byte 25 | bytes[26..27] | low 6 of byte 28
///   limb 9  bits 230..255 → bits 6..8 of byte 28 | bytes[29..31] (top bit masked)
/// ```
pub(in super::super) const fn unpack(b: &[u8; 32]) -> Fe2255 {
    let l0 = (b[0] as i32)
        | ((b[1] as i32) << 8)
        | ((b[2] as i32) << 16)
        | (((b[3] as i32) & 0x03) << 24);
    let l1 = (((b[3] as i32) >> 2) & 0x3f)
        | ((b[4] as i32) << 6)
        | ((b[5] as i32) << 14)
        | (((b[6] as i32) & 0x07) << 22);
    let l2 = (((b[6] as i32) >> 3) & 0x1f)
        | ((b[7] as i32) << 5)
        | ((b[8] as i32) << 13)
        | (((b[9] as i32) & 0x1f) << 21);
    let l3 = (((b[9] as i32) >> 5) & 0x07)
        | ((b[10] as i32) << 3)
        | ((b[11] as i32) << 11)
        | (((b[12] as i32) & 0x3f) << 19);
    let l4 = (((b[12] as i32) >> 6) & 0x03)
        | ((b[13] as i32) << 2)
        | ((b[14] as i32) << 10)
        | ((b[15] as i32) << 18);
    let l5 = (b[16] as i32)
        | ((b[17] as i32) << 8)
        | ((b[18] as i32) << 16)
        | (((b[19] as i32) & 0x01) << 24);
    let l6 = (((b[19] as i32) >> 1) & 0x7f)
        | ((b[20] as i32) << 7)
        | ((b[21] as i32) << 15)
        | (((b[22] as i32) & 0x07) << 23);
    let l7 = (((b[22] as i32) >> 3) & 0x1f)
        | ((b[23] as i32) << 5)
        | ((b[24] as i32) << 13)
        | (((b[25] as i32) & 0x0f) << 21);
    let l8 = (((b[25] as i32) >> 4) & 0x0f)
        | ((b[26] as i32) << 4)
        | ((b[27] as i32) << 12)
        | (((b[28] as i32) & 0x3f) << 20);
    let l9 = (((b[28] as i32) >> 6) & 0x03)
        | ((b[29] as i32) << 2)
        | ((b[30] as i32) << 10)
        | (((b[31] as i32) & 0x7f) << 18);
    [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9]
}

/// Encode a `Fe2255` (any form — reducing internally) as 32 LE bytes,
/// fully reduced mod `p`.
pub(in super::super) const fn pack(input: &Fe2255) -> [u8; 32] {
    let mut a = reduce(input);

    // Final reduction: if a >= p, subtract p. Bias to make canonical.
    // Compute a + 19 and check carry: if the top limb carries, original was
    // >= p − 19 ≥ p (since limbs are positive after reduce); we subtract p.
    //
    // Simpler implementation: use the same "add 19, conditional carry"
    // pattern as the radix-2^51 pack, adapted to 10 limbs.
    //
    // Add 19, propagate carries.
    a[0] += 19;
    a[1] += a[0] >> 26;
    a[0] &= MASK26;
    a[2] += a[1] >> 25;
    a[1] &= MASK25;
    a[3] += a[2] >> 26;
    a[2] &= MASK26;
    a[4] += a[3] >> 25;
    a[3] &= MASK25;
    a[5] += a[4] >> 26;
    a[4] &= MASK26;
    a[6] += a[5] >> 25;
    a[5] &= MASK25;
    a[7] += a[6] >> 26;
    a[6] &= MASK26;
    a[8] += a[7] >> 25;
    a[7] &= MASK25;
    a[9] += a[8] >> 26;
    a[8] &= MASK26;
    // Top wrap: if limb 9 overflowed its 25-bit window, fold the overflow
    // back via × 19 into limb 0. This is the critical step that brings
    // values in (p, 2^255) down by p — without it pack returns
    // non-canonical p + 1, p + 2, …
    a[0] += 19 * (a[9] >> 25);
    a[9] &= MASK25;

    // Now add (2^255 − 19) — clear top bit on success.
    a[0] += (1 << 26) - 19;
    a[1] += (1 << 25) - 1;
    a[2] += (1 << 26) - 1;
    a[3] += (1 << 25) - 1;
    a[4] += (1 << 26) - 1;
    a[5] += (1 << 25) - 1;
    a[6] += (1 << 26) - 1;
    a[7] += (1 << 25) - 1;
    a[8] += (1 << 26) - 1;
    a[9] += (1 << 25) - 1;
    a[1] += a[0] >> 26;
    a[0] &= MASK26;
    a[2] += a[1] >> 25;
    a[1] &= MASK25;
    a[3] += a[2] >> 26;
    a[2] &= MASK26;
    a[4] += a[3] >> 25;
    a[3] &= MASK25;
    a[5] += a[4] >> 26;
    a[4] &= MASK26;
    a[6] += a[5] >> 25;
    a[5] &= MASK25;
    a[7] += a[6] >> 26;
    a[6] &= MASK26;
    a[8] += a[7] >> 25;
    a[7] &= MASK25;
    a[9] += a[8] >> 26;
    a[8] &= MASK26;
    a[9] &= MASK25;

    // Pack into bytes: bit layout (after the reductions above):
    //   limb 0: bits 0..26   (offset 0)
    //   limb 1: bits 26..51  (offset 26)
    //   limb 2: bits 51..77  (offset 51)
    //   ...
    let l0 = a[0] as u64;
    let l1 = a[1] as u64;
    let l2 = a[2] as u64;
    let l3 = a[3] as u64;
    let l4 = a[4] as u64;
    let l5 = a[5] as u64;
    let l6 = a[6] as u64;
    let l7 = a[7] as u64;
    let l8 = a[8] as u64;
    let l9 = a[9] as u64;

    let mut out = [0u8; 32];
    // Write 256-bit value as 32 bytes LE. Bit position of each limb is
    // its WEIGHTS[] value; we OR-write each limb into the byte array.
    // To stay const fn we do explicit shifts.

    // Limb 0 occupies bits 0..26 → bytes 0..4 (with bits 24..26 spilling into byte 3 high bits).
    out[0] = l0 as u8;
    out[1] = (l0 >> 8) as u8;
    out[2] = (l0 >> 16) as u8;
    out[3] = (l0 >> 24) as u8 & 0x03; // bottom 2 bits of byte 3 are from l0 bits 24..26
    // Limb 1 occupies bits 26..51 → bytes 3..7 (starting at bit 2 of byte 3).
    out[3] |= ((l1 as u8) & 0x3f) << 2; // l1 bits 0..6 → byte 3 bits 2..8
    out[4] = (l1 >> 6) as u8;
    out[5] = (l1 >> 14) as u8;
    out[6] = (l1 >> 22) as u8 & 0x07; // l1 bits 22..25
    // Limb 2 occupies bits 51..77.
    out[6] |= ((l2 as u8) & 0x1f) << 3; // l2 bits 0..5 → byte 6 bits 3..8
    out[7] = (l2 >> 5) as u8;
    out[8] = (l2 >> 13) as u8;
    out[9] = (l2 >> 21) as u8 & 0x1f; // l2 bits 21..26
    // Limb 3 occupies bits 77..102.
    out[9] |= ((l3 as u8) & 0x07) << 5;
    out[10] = (l3 >> 3) as u8;
    out[11] = (l3 >> 11) as u8;
    out[12] = (l3 >> 19) as u8 & 0x3f;
    // Limb 4 occupies bits 102..128.
    out[12] |= ((l4 as u8) & 0x03) << 6;
    out[13] = (l4 >> 2) as u8;
    out[14] = (l4 >> 10) as u8;
    out[15] = (l4 >> 18) as u8;
    // Limb 5 occupies bits 128..153.
    out[16] = l5 as u8;
    out[17] = (l5 >> 8) as u8;
    out[18] = (l5 >> 16) as u8;
    out[19] = (l5 >> 24) as u8 & 0x01;
    // Limb 6 occupies bits 153..179.
    out[19] |= ((l6 as u8) & 0x7f) << 1;
    out[20] = (l6 >> 7) as u8;
    out[21] = (l6 >> 15) as u8;
    out[22] = (l6 >> 23) as u8 & 0x07;
    // Limb 7 occupies bits 179..204.
    out[22] |= ((l7 as u8) & 0x1f) << 3;
    out[23] = (l7 >> 5) as u8;
    out[24] = (l7 >> 13) as u8;
    out[25] = (l7 >> 21) as u8 & 0x0f;
    // Limb 8 occupies bits 204..230.
    out[25] |= ((l8 as u8) & 0x0f) << 4;
    out[26] = (l8 >> 4) as u8;
    out[27] = (l8 >> 12) as u8;
    out[28] = (l8 >> 20) as u8 & 0x3f;
    // Limb 9 occupies bits 230..255.
    out[28] |= ((l9 as u8) & 0x03) << 6;
    out[29] = (l9 >> 2) as u8;
    out[30] = (l9 >> 10) as u8;
    out[31] = ((l9 >> 18) as u8) & 0x7f;

    out
}
