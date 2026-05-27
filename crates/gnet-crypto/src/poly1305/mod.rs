//! Poly1305 one-time message authentication code — RFC 8439 §2.5.
//!
//! Constant-time by construction: 26-bit-limb arithmetic (à la
//! poly1305-donna) with no data-dependent branches or table lookups. The
//! final conditional subtraction of `p = 2^130 - 5` is mask-selected.
//!
//! The field multiply (`fmul5`) and post-multiply reduction
//! (`reduce_products`) are factored out so the portable scalar path and the
//! x86_64 AVX2 path (private `avx2` module) share one verified arithmetic
//! core. AVX2 evaluates four blocks per group in parallel via precomputed
//! key powers `r .. r^4`; the tail and all other targets use the per-block
//! path.

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "aarch64")]
mod neon;

/// 26-bit limb mask.
const MASK: u64 = 0x3ff_ffff;

/// Read four little-endian bytes as a `u64`.
fn load_le32(b: &[u8]) -> u64 {
    u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Load and clamp `r` from the low 16 key bytes (RFC 8439 §2.5.1); the clamp
/// is folded into the limb-split masks.
fn clamp_r(r_bytes: &[u8; 16]) -> [u64; 5] {
    let t0 = load_le32(&r_bytes[0..4]);
    let t1 = load_le32(&r_bytes[4..8]);
    let t2 = load_le32(&r_bytes[8..12]);
    let t3 = load_le32(&r_bytes[12..16]);
    [
        t0 & 0x3ff_ffff,
        ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03,
        ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff,
        ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff,
        (t3 >> 8) & 0x00f_ffff,
    ]
}

/// The `r·5` wraparound helpers `[b1·5, b2·5, b3·5, b4·5]`.
fn mul5(b: &[u64; 5]) -> [u64; 4] {
    [b[1] * 5, b[2] * 5, b[3] * 5, b[4] * 5]
}

/// The five unreduced product columns of `a · b mod (2^130 - 5)` in the
/// 26-bit-limb schedule. `b5` is [`mul5`]`(b)`. Each output is a sum of five
/// 52-bit products (< 2^59), reduced later by [`reduce_products`]. Shared by
/// the scalar and SIMD paths so both exercise the identical arithmetic.
fn products(a: &[u64; 5], b: &[u64; 5], b5: &[u64; 4]) -> [u64; 5] {
    [
        a[0] * b[0] + a[1] * b5[3] + a[2] * b5[2] + a[3] * b5[1] + a[4] * b5[0],
        a[0] * b[1] + a[1] * b[0] + a[2] * b5[3] + a[3] * b5[2] + a[4] * b5[1],
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b5[3] + a[4] * b5[2],
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b5[3],
        a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
    ]
}

/// Carry-propagate the unreduced product columns into five 26-bit limbs,
/// folding the 2^130 overflow back via the `·5` wraparound.
fn reduce_products(d: [u64; 5]) -> [u64; 5] {
    let mut c = d[0] >> 26;
    let o0 = d[0] & MASK;
    let d1 = d[1] + c;
    c = d1 >> 26;
    let o1 = d1 & MASK;
    let d2 = d[2] + c;
    c = d2 >> 26;
    let o2 = d2 & MASK;
    let d3 = d[3] + c;
    c = d3 >> 26;
    let o3 = d3 & MASK;
    let d4 = d[4] + c;
    c = d4 >> 26;
    let o4 = d4 & MASK;
    let mut o0 = o0 + c * 5;
    c = o0 >> 26;
    o0 &= MASK;
    let o1 = o1 + c;
    [o0, o1, o2, o3, o4]
}

/// Field multiply `a · b mod (2^130 - 5)`, returning five 26-bit limbs.
fn fmul5(a: &[u64; 5], b: &[u64; 5], b5: &[u64; 4]) -> [u64; 5] {
    reduce_products(products(a, b, b5))
}

/// Poly1305 evaluation state: clamped key `r` (with `r·5` helpers `rs`) and
/// the running 130-bit accumulator `h`, each held in five 26-bit limbs.
struct State {
    r: [u64; 5],
    rs: [u64; 4],
    h: [u64; 5],
}

impl State {
    /// State seeded with a clamped `r` and a zero accumulator.
    fn new(r: [u64; 5]) -> Self {
        Self {
            r,
            rs: mul5(&r),
            h: [0; 5],
        }
    }

    /// State seeded with a clamped `r` and an initial accumulator (used to
    /// continue from the SIMD bulk result through the message tail).
    fn from_acc(r: [u64; 5], h: [u64; 5]) -> Self {
        Self { r, rs: mul5(&r), h }
    }

    /// Absorb one 16-byte block, then multiply the accumulator by `r` mod `p`.
    /// `hibit` is `1 << 24` for a full block (the implicit 2^128 bit) or `0`
    /// for the final partial block whose pad byte already sits in `blk`.
    fn block(&mut self, blk: &[u8; 16], hibit: u64) {
        let t0 = load_le32(&blk[0..4]);
        let t1 = load_le32(&blk[4..8]);
        let t2 = load_le32(&blk[8..12]);
        let t3 = load_le32(&blk[12..16]);
        let h = [
            self.h[0] + (t0 & MASK),
            self.h[1] + (((t0 >> 26) | (t1 << 6)) & MASK),
            self.h[2] + (((t1 >> 20) | (t2 << 12)) & MASK),
            self.h[3] + (((t2 >> 14) | (t3 << 18)) & MASK),
            self.h[4] + ((t3 >> 8) | hibit),
        ];
        self.h = fmul5(&h, &self.r, &self.rs);
    }

    /// Fully propagate carries so every limb is < 2^26.
    fn carry(&mut self) {
        let mut c = self.h[1] >> 26;
        self.h[1] &= MASK;
        self.h[2] += c;
        c = self.h[2] >> 26;
        self.h[2] &= MASK;
        self.h[3] += c;
        c = self.h[3] >> 26;
        self.h[3] &= MASK;
        self.h[4] += c;
        c = self.h[4] >> 26;
        self.h[4] &= MASK;
        self.h[0] += c * 5;
        c = self.h[0] >> 26;
        self.h[0] &= MASK;
        self.h[1] += c;
    }

    /// Constant-time reduce mod `p`: returns `h - p` if `h >= p`, else `h`.
    fn reduce(&self) -> [u64; 5] {
        let h = self.h;
        let mut g0 = h[0] + 5;
        let mut c = g0 >> 26;
        g0 &= MASK;
        let mut g1 = h[1] + c;
        c = g1 >> 26;
        g1 &= MASK;
        let mut g2 = h[2] + c;
        c = g2 >> 26;
        g2 &= MASK;
        let mut g3 = h[3] + c;
        c = g3 >> 26;
        g3 &= MASK;
        let mut g4 = h[4] + c;
        let select = ((g4 >> 26) & 1).wrapping_neg();
        g4 &= MASK;
        [
            (h[0] & !select) | (g0 & select),
            (h[1] & !select) | (g1 & select),
            (h[2] & !select) | (g2 & select),
            (h[3] & !select) | (g3 & select),
            (h[4] & !select) | (g4 & select),
        ]
    }

    /// Finalize: full carry, reduce mod `p`, then `(h + s) mod 2^128`.
    fn finalize(mut self, pad: &[u8; 16]) -> [u8; 16] {
        self.carry();
        emit(self.reduce(), pad)
    }
}

/// Collapse the 26-bit limbs into four 32-bit words, add the `s` pad
/// (mod 2^128), and serialize the 16-byte tag little-endian.
fn emit(h: [u64; 5], pad: &[u8; 16]) -> [u8; 16] {
    let f = [
        (h[0] | (h[1] << 26)) & 0xffff_ffff,
        ((h[1] >> 6) | (h[2] << 20)) & 0xffff_ffff,
        ((h[2] >> 12) | (h[3] << 14)) & 0xffff_ffff,
        ((h[3] >> 18) | (h[4] << 8)) & 0xffff_ffff,
    ];
    let mut tag = [0u8; 16];
    let mut carry = 0u64;
    for (i, word) in tag.chunks_exact_mut(4).enumerate() {
        let sum = f[i] + load_le32(&pad[4 * i..4 * i + 4]) + carry;
        carry = sum >> 32;
        word.copy_from_slice(&(sum as u32).to_le_bytes());
    }
    tag
}

/// Process `msg` through `st` block by block (full blocks, then a final
/// partial block with the `1` pad byte), then finalize the tag.
fn absorb_tail(mut st: State, msg: &[u8], pad: &[u8; 16]) -> [u8; 16] {
    let mut chunks = msg.chunks_exact(16);
    for blk in chunks.by_ref() {
        st.block(blk.try_into().expect("chunks_exact(16)"), 1 << 24);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut buf = [0u8; 16];
        buf[..rem.len()].copy_from_slice(rem);
        buf[rem.len()] = 1;
        st.block(&buf, 0);
    }
    st.finalize(pad)
}

/// Run the SIMD bulk over whole four-block (64-byte) groups of `full` (which
/// must be 16-aligned), advancing `acc`. Returns the updated accumulator and
/// the byte count consumed (a multiple of 64); the caller absorbs the rest
/// per-block. On targets without a SIMD path (or x86 without AVX2) it consumes
/// nothing and the caller takes the scalar path.
fn simd_bulk(r: &[u64; 5], acc: [u64; 5], full: &[u8]) -> ([u64; 5], usize) {
    let groups = full.len() / 64;
    if groups == 0 {
        return (acc, 0);
    }
    let consumed = groups * 64;

    #[cfg(target_arch = "x86_64")]
    if std::is_x86_feature_detected!("avx2") {
        // SAFETY: AVX2 just detected at runtime.
        return (
            unsafe { avx2::accumulate(r, acc, &full[..consumed]) },
            consumed,
        );
    }

    #[cfg(target_arch = "aarch64")]
    return (neon::accumulate(r, acc, &full[..consumed]), consumed);

    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = consumed;
        (acc, 0)
    }
}

/// Compute the 16-byte Poly1305 tag for `msg` under the 32-byte one-time
/// `key` (`r` ‖ `s`), per RFC 8439 §2.5.1. The bulk runs four blocks at a time
/// on AVX2 (x86_64) / NEON (aarch64); the tail and other targets use the
/// per-block path.
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let r_bytes: [u8; 16] = key[..16].try_into().expect("16-byte half");
    let pad: [u8; 16] = key[16..].try_into().expect("16-byte half");
    let r = clamp_r(&r_bytes);

    let n_full = msg.len() / 16;
    let (acc, consumed) = simd_bulk(&r, [0; 5], &msg[..n_full * 16]);
    absorb_tail(State::from_acc(r, acc), &msg[consumed..], &pad)
}

/// Streaming Poly1305 over the AEAD MAC framing (RFC 8439 §2.8): each region
/// is absorbed as whole 16-byte blocks (every block carrying the 2^128 bit),
/// with a trailing partial chunk zero-padded to a full block. SIMD-accelerated
/// for runs of four or more blocks. Distinct from the one-shot [`poly1305`],
/// whose final block is a *partial* block with a `0x01` pad byte.
pub struct Mac {
    st: State,
    s: [u8; 16],
}

impl Mac {
    /// Initialize from the 32-byte one-time key (`r` ‖ `s`).
    pub fn new(key: &[u8; 32]) -> Self {
        let r_bytes: [u8; 16] = key[..16].try_into().expect("16-byte half");
        let s: [u8; 16] = key[16..].try_into().expect("16-byte half");
        Self {
            st: State::new(clamp_r(&r_bytes)),
            s,
        }
    }

    /// Absorb `data` as full 16-byte blocks; a trailing partial chunk is
    /// zero-padded to a full block (the AEAD region padding of RFC 8439 §2.8).
    pub fn update_padded(&mut self, data: &[u8]) {
        let n_full = data.len() / 16;
        let full = &data[..n_full * 16];
        let (h, consumed) = simd_bulk(&self.st.r, self.st.h, full);
        self.st.h = h;
        for blk in full[consumed..].chunks_exact(16) {
            self.st
                .block(blk.try_into().expect("chunks_exact(16)"), 1 << 24);
        }
        let rem = &data[n_full * 16..];
        if !rem.is_empty() {
            let mut buf = [0u8; 16];
            buf[..rem.len()].copy_from_slice(rem);
            self.st.block(&buf, 1 << 24);
        }
    }

    /// Finalize and return the 16-byte tag.
    pub fn finalize(self) -> [u8; 16] {
        self.st.finalize(&self.s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.5.2 — worked example (34-byte message, partial block).
    #[test]
    fn mac_rfc8439_2_5_2() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(poly1305(&key, msg), expected);
    }

    /// RFC 8439 §A.3 #1 — all-zero key and message yield an all-zero tag.
    #[test]
    fn mac_rfc8439_a3_1_zero() {
        assert_eq!(poly1305(&[0u8; 32], &[0u8; 64]), [0u8; 16]);
    }

    /// RFC 8439 §A.3 #2 — `r = 0`, so the tag is just `s`.
    #[test]
    fn mac_rfc8439_a3_2_r_zero() {
        let mut key = [0u8; 32];
        let s: [u8; 16] = [
            0x36, 0xe5, 0xf6, 0xb5, 0xc5, 0xe0, 0x60, 0x70, 0xf0, 0xef, 0xca, 0x96, 0x22, 0x7a,
            0x86, 0x3e,
        ];
        key[16..].copy_from_slice(&s);
        let msg = b"Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an \"IETF Contribution\". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to";
        assert_eq!(poly1305(&key, msg), s);
    }

    /// Empty message: tag is `s` (the accumulator stays zero).
    #[test]
    fn mac_empty_message() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let s: [u8; 16] = key[16..].try_into().unwrap();
        assert_eq!(poly1305(&key, &[]), s);
    }

    /// Per-block scalar reference (forces the non-SIMD path) for differential
    /// testing of the AVX2 path against identical inputs.
    fn scalar_reference(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
        let r_bytes: [u8; 16] = key[..16].try_into().unwrap();
        let pad: [u8; 16] = key[16..].try_into().unwrap();
        absorb_tail(State::new(clamp_r(&r_bytes)), msg, &pad)
    }

    /// `poly1305` (which uses AVX2 when available) must match the per-block
    /// scalar reference across all group/block boundary cases.
    #[test]
    fn dispatch_matches_scalar_reference() {
        for len in [
            0usize, 1, 15, 16, 17, 31, 63, 64, 65, 79, 80, 127, 128, 129, 191, 192, 193, 255, 256,
            257, 1000, 1024, 4096,
        ] {
            let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7) ^ 0x1f);
            let msg: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(13)).collect();
            assert_eq!(
                poly1305(&key, &msg),
                scalar_reference(&key, &msg),
                "mismatch at len {len}"
            );
        }
    }
}
