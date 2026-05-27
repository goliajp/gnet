//! SHA-3 and SHAKE (FIPS 202) over the Keccak-f[1600] permutation.
//!
//! Zero-dependency and constant-time by construction (the permutation is pure
//! word logic — rotates, xor, and/not — with no data-dependent branches or
//! table lookups). Provides the fixed-output hashes [`sha3_256`] / [`sha3_512`]
//! and the extendable-output functions [`shake128`] / [`shake256`]. These are
//! the hash primitives required by ML-KEM (FIPS 203).

/// Keccak-f[1600] round constants (ι step).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Lane rotation offsets (ρ step), in the order of the ρ/π walk.
const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation indices (π step), in the order of the ρ/π walk.
const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation: 24 rounds of θ, ρ, π, χ, ι on the 25-lane
/// (5×5×64-bit) state.
fn keccak_f(s: &mut [u64; 25]) {
    for &rc in &RC {
        // θ
        let mut bc = [0u64; 5];
        for i in 0..5 {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            for j in (0..25).step_by(5) {
                s[j + i] ^= t;
            }
        }
        // ρ and π
        let mut t = s[1];
        for i in 0..24 {
            let j = PILN[i];
            let tmp = s[j];
            s[j] = t.rotate_left(ROTC[i]);
            t = tmp;
        }
        // χ
        for j in (0..25).step_by(5) {
            let row = [s[j], s[j + 1], s[j + 2], s[j + 3], s[j + 4]];
            for i in 0..5 {
                s[j + i] ^= (!row[(i + 1) % 5]) & row[(i + 2) % 5];
            }
        }
        // ι
        s[0] ^= rc;
    }
}

/// XOR `block` (length `rate`, a multiple of 8) into the state lanes (LE).
fn xor_block(s: &mut [u64; 25], block: &[u8]) {
    for (lane, chunk) in s.iter_mut().zip(block.chunks_exact(8)) {
        *lane ^= u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8)"));
    }
}

/// Keccak sponge: absorb `input` at byte-`rate` with domain-separation byte
/// `domain` (`0x06` SHA-3, `0x1f` SHAKE), then squeeze `out.len()` bytes.
fn sponge(rate: usize, domain: u8, input: &[u8], out: &mut [u8]) {
    debug_assert!(rate.is_multiple_of(8) && rate <= 168);
    let mut s = [0u64; 25];

    // absorb full rate-sized blocks
    let mut blocks = input.chunks_exact(rate);
    for blk in blocks.by_ref() {
        xor_block(&mut s, blk);
        keccak_f(&mut s);
    }
    // final block: pad10*1 with the domain byte and the 0x80 terminator
    let rem = blocks.remainder();
    let mut last = [0u8; 168];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] = domain;
    last[rate - 1] |= 0x80;
    xor_block(&mut s, &last[..rate]);
    keccak_f(&mut s);

    // squeeze
    let mut off = 0;
    loop {
        let mut block = [0u8; 168];
        for (chunk, lane) in block[..rate].chunks_exact_mut(8).zip(s.iter()) {
            chunk.copy_from_slice(&lane.to_le_bytes());
        }
        let n = rate.min(out.len() - off);
        out[off..off + n].copy_from_slice(&block[..n]);
        off += n;
        if off >= out.len() {
            break;
        }
        keccak_f(&mut s);
    }
}

/// SHA3-256 (FIPS 202): 32-byte digest.
pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    sponge(136, 0x06, input, &mut out);
    out
}

/// SHA3-512 (FIPS 202): 64-byte digest.
pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    sponge(72, 0x06, input, &mut out);
    out
}

/// SHAKE128 (FIPS 202) extendable-output function: fill `out`.
pub fn shake128(input: &[u8], out: &mut [u8]) {
    sponge(168, 0x1f, input, out);
}

/// SHAKE256 (FIPS 202) extendable-output function: fill `out`.
pub fn shake256(input: &[u8], out: &mut [u8]) {
    sponge(136, 0x1f, input, out);
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
            xor_block(&mut s, blk);
            keccak_f(&mut s);
        }
        let rem = blocks.remainder();
        let mut last = [0u8; 168];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x1f;
        last[rate - 1] |= 0x80;
        xor_block(&mut s, &last[..rate]);
        keccak_f(&mut s);
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
                keccak_f(&mut self.state);
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
}
