//! Portable scalar Keccak-f[1600] permutation and sponge. All architectures
//! fall back to this; aarch64 may additionally use the NEON 4-way variant in
//! [`super::neon_x4`] for batched workloads (ML-KEM matrix sampling).

/// Keccak-f[1600] round constants (ι step).
pub(super) const RC: [u64; 24] = [
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
pub(super) const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation indices (π step), in the order of the ρ/π walk.
pub(super) const PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation: 24 rounds of θ, ρ, π, χ, ι on the 25-lane
/// (5×5×64-bit) state.
pub(super) fn keccak_f(s: &mut [u64; 25]) {
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
pub(super) fn xor_block(s: &mut [u64; 25], block: &[u8]) {
    for (lane, chunk) in s.iter_mut().zip(block.chunks_exact(8)) {
        *lane ^= u64::from_le_bytes(chunk.try_into().expect("chunks_exact(8)"));
    }
}

/// Keccak sponge: absorb `input` at byte-`rate` with domain-separation byte
/// `domain` (`0x06` SHA-3, `0x1f` SHAKE), then squeeze `out.len()` bytes.
pub(super) fn sponge(rate: usize, domain: u8, input: &[u8], out: &mut [u8]) {
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
