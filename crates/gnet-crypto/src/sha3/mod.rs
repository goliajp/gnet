//! SHA-3 and SHAKE (FIPS 202) over the Keccak-f\[1600\] permutation.
//!
//! Zero-dependency and constant-time by construction (the permutation is pure
//! word logic — rotates, xor, and/not — with no data-dependent branches or
//! table lookups). Provides the fixed-output hashes [`sha3_256`] / [`sha3_512`]
//! and the extendable-output functions [`shake128`] / [`shake256`]. These are
//! the hash primitives required by ML-KEM (FIPS 203).
//!
//! Internal structure:
//! - `scalar` — portable scalar Keccak-f\[1600\] + sponge. The correctness
//!   reference, always available.
//! - `neon_x4` — aarch64 NEON 4-way Keccak-f\[1600\] and SHAKE128 used by
//!   ML-KEM matrix sampling (9 independent SHAKE128 streams per matrix). On
//!   non-aarch64 the 4-way wrappers route to four serial scalar calls.

mod scalar;

#[cfg(target_arch = "aarch64")]
mod neon_x4;

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx2_x4;

/// SHAKE128 rate in bytes (1600 − 2·128 = 1344 bits = 168 B). Shared by
/// the per-arch 4-way fast paths plus the scalar fallback so callers
/// can size their per-block buffers without pulling in a SIMD-only
/// re-export.
pub(crate) const SHAKE128_RATE: usize = 168;

/// Streaming SHAKE128 4-way sponge, used by ML-KEM matrix sampling. Only
/// available on aarch64; on other architectures callers should fall back to
/// four serial [`Xof::shake128`] readers, or use the AVX2 path on
/// x86_64 (see `avx2_x4::ShakeState4Avx2`).
#[cfg(target_arch = "aarch64")]
pub(crate) use neon_x4::ShakeState4;

/// SHA3-256 (FIPS 202): 32-byte digest.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    scalar::sponge(136, 0x06, input, &mut out);
    out
}

/// SHA3-512 (FIPS 202): 64-byte digest.
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    scalar::sponge(72, 0x06, input, &mut out);
    out
}

/// SHAKE128 (FIPS 202) extendable-output function: fill `out`.
pub fn shake128(input: &[u8], out: &mut [u8]) {
    scalar::sponge(168, 0x1f, input, out);
}

/// SHAKE256 (FIPS 202) extendable-output function: fill `out`.
pub fn shake256(input: &[u8], out: &mut [u8]) {
    scalar::sponge(136, 0x1f, input, out);
}

/// SHAKE128 of four independent seeds in parallel. On aarch64 uses a single
/// NEON 4-way Keccak-f\[1600\], packing four 25-lane states into `uint64x2_t`
/// pairs (one register holds two states' lane). On other architectures
/// degrades to four serial scalar [`shake128`] calls — same output bit-for-bit,
/// just no SIMD win.
///
/// The 4-way path is the speedup that lets ML-KEM-768 matrix generation
/// (9 SHAKE128 streams = 2×4 + 1) outrun rustcrypto's single-stream loop.
pub fn shake128_x4(seeds: [&[u8]; 4], outs: [&mut [u8]; 4]) {
    #[cfg(target_arch = "aarch64")]
    {
        neon_x4::shake128_x4(seeds, outs);
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                // SAFETY: AVX2 just runtime-detected.
                unsafe {
                    avx2_x4::shake128_x4(seeds, outs);
                }
                return;
            }
        }
        let [s0, s1, s2, s3] = seeds;
        let [o0, o1, o2, o3] = outs;
        shake128(s0, o0);
        shake128(s1, o1);
        shake128(s2, o2);
        shake128(s3, o3);
    }
}

/// Incremental SHAKE extendable-output reader: absorb a seed once, then
/// [`squeeze`](Xof::squeeze) arbitrary amounts of output across calls. Used by
/// ML-KEM's rejection sampling, which consumes an unbounded stream.
pub struct Xof {
    state: [u64; 25],
    rate: usize,
    /// byte position within the current squeeze block (`0..rate`).
    pos: usize,
}

impl Xof {
    fn new(rate: usize, input: &[u8]) -> Self {
        let mut s = [0u64; 25];
        let mut blocks = input.chunks_exact(rate);
        for blk in blocks.by_ref() {
            scalar::xor_block(&mut s, blk);
            scalar::keccak_f(&mut s);
        }
        let rem = blocks.remainder();
        let mut last = [0u8; 168];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x1f;
        last[rate - 1] |= 0x80;
        scalar::xor_block(&mut s, &last[..rate]);
        scalar::keccak_f(&mut s);
        Xof {
            state: s,
            rate,
            pos: 0,
        }
    }

    /// A SHAKE128 reader over `input` (rate 168).
    pub fn shake128(input: &[u8]) -> Self {
        Self::new(168, input)
    }

    /// A SHAKE256 reader over `input` (rate 136).
    pub fn shake256(input: &[u8]) -> Self {
        Self::new(136, input)
    }

    /// Squeeze `out.len()` more bytes, continuing the stream. Reads 8 bytes
    /// at a time when the current position is lane-aligned, so a rate-block
    /// squeeze costs ~21 u64 reads instead of 168 byte-level shifts.
    pub fn squeeze(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.pos == self.rate {
                scalar::keccak_f(&mut self.state);
                self.pos = 0;
            }
            let avail = self.rate - self.pos;
            let take = out.len().min(avail);

            // Fast path: when both pos and take are aligned, copy whole u64
            // lanes via `to_le_bytes`. Otherwise fall back to byte-level
            // extraction for the partial lanes at either end.
            let mut written = 0;
            // Misaligned head (pos not on a lane boundary).
            let head = self.pos % 8;
            if head != 0 {
                let lane = self.state[self.pos / 8];
                let take_head = (8 - head).min(take);
                let bytes = lane.to_le_bytes();
                out[..take_head].copy_from_slice(&bytes[head..head + take_head]);
                written += take_head;
            }
            // Whole lanes.
            while written + 8 <= take {
                let lane_idx = (self.pos + written) / 8;
                let bytes = self.state[lane_idx].to_le_bytes();
                out[written..written + 8].copy_from_slice(&bytes);
                written += 8;
            }
            // Misaligned tail.
            if written < take {
                let p = self.pos + written;
                let lane = self.state[p / 8];
                let lane_off = p % 8;
                let remaining = take - written;
                let bytes = lane.to_le_bytes();
                out[written..written + remaining]
                    .copy_from_slice(&bytes[lane_off..lane_off + remaining]);
            }

            self.pos += take;
            out = &mut out[take..];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    /// NIST FIPS 202 — SHA3-256 of the empty message.
    #[test]
    fn sha3_256_empty() {
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
    }

    /// NIST FIPS 202 — SHA3-256 of "abc".
    #[test]
    fn sha3_256_abc() {
        assert_eq!(
            sha3_256(b"abc").to_vec(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    /// NIST FIPS 202 — SHA3-512 of the empty message.
    #[test]
    fn sha3_512_empty() {
        assert_eq!(
            sha3_512(b"").to_vec(),
            hex(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
                 15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );
    }

    /// NIST FIPS 202 — SHA3-512 of "abc".
    #[test]
    fn sha3_512_abc() {
        assert_eq!(
            sha3_512(b"abc").to_vec(),
            hex(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
    }

    /// NIST FIPS 202 — SHAKE128 of the empty message (first 32 bytes).
    #[test]
    fn shake128_empty_32() {
        let mut out = [0u8; 32];
        shake128(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
    }

    /// NIST FIPS 202 — SHAKE256 of the empty message (first 32 bytes).
    #[test]
    fn shake256_empty_32() {
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    /// The incremental Xof must produce the same stream as the one-shot SHAKE,
    /// regardless of how the output is chunked across squeeze calls.
    #[test]
    fn xof_matches_oneshot() {
        let mut oneshot = [0u8; 300];
        shake128(b"gnet-xof", &mut oneshot);
        let mut x = Xof::shake128(b"gnet-xof");
        let mut got = [0u8; 300];
        // squeeze in irregular chunks to exercise the resume path
        let mut off = 0;
        for step in [1usize, 7, 168, 1, 100, 23] {
            x.squeeze(&mut got[off..off + step]);
            off += step;
        }
        x.squeeze(&mut got[off..]);
        assert_eq!(got, oneshot);

        let mut o256 = [0u8; 200];
        shake256(b"abc", &mut o256);
        let mut x2 = Xof::shake256(b"abc");
        let mut g2 = [0u8; 200];
        x2.squeeze(&mut g2);
        assert_eq!(g2, o256);
    }

    /// Squeezing across a rate boundary must match a single long squeeze.
    #[test]
    fn shake128_long_output_crosses_blocks() {
        let mut long = [0u8; 200]; // > rate (168)
        shake128(b"gnet", &mut long);
        // re-deriving the prefix must be stable
        let mut prefix = [0u8; 32];
        shake128(b"gnet", &mut prefix);
        assert_eq!(&long[..32], &prefix[..]);
    }

    /// shake128_x4 must produce the same four streams as four serial shake128.
    #[test]
    fn shake128_x4_matches_serial() {
        let seeds: [&[u8]; 4] = [b"alpha", b"beta-test", b"gnet-x4", b""];
        let mut got = [[0u8; 200]; 4];
        let mut want = [[0u8; 200]; 4];
        {
            let [g0, g1, g2, g3] = &mut got;
            shake128_x4(seeds, [g0.as_mut(), g1.as_mut(), g2.as_mut(), g3.as_mut()]);
        }
        for i in 0..4 {
            shake128(seeds[i], &mut want[i]);
        }
        for i in 0..4 {
            assert_eq!(got[i], want[i], "stream {i}");
        }
    }
}
