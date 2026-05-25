//! `gnet-rand` — zero-dependency cryptographically-secure randomness for the
//! gnet overlay, sourced from the operating system.
//!
//! Reads `/dev/urandom` via `std` only (no `unsafe`, no crates.io
//! dependencies). This covers Unix targets (Linux, macOS, the BSDs);
//! Windows support (via a CSP syscall) is a future addition.
//!
//! Use it to generate Noise ephemeral and static private keys.
//!
//! ```
//! let sk = gnet_rand::random_32(); // an X25519 private scalar's worth of entropy
//! assert_ne!(sk, [0u8; 32]); // not all zero, with overwhelming probability
//! ```

use std::fs::File;
use std::io::Read;

/// Fill `buf` with OS entropy, returning an error if the OS RNG cannot be
/// read.
pub fn try_fill(buf: &mut [u8]) -> std::io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buf)
}

/// Fill `buf` with OS entropy.
///
/// # Panics
/// If the OS RNG (`/dev/urandom`) is unavailable — proceeding without secure
/// randomness would be worse than failing loudly.
pub fn fill(buf: &mut [u8]) {
    try_fill(buf).expect("OS RNG (/dev/urandom) unavailable");
}

/// Return 32 fresh random bytes (e.g. an X25519 private key).
pub fn random_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    fill(&mut b);
    b
}

/// Return a fresh random `u32` (e.g. a transport session index).
pub fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    fill(&mut b);
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_fill_succeeds() {
        let mut b = [0u8; 16];
        assert!(try_fill(&mut b).is_ok());
    }

    #[test]
    fn fill_writes_entropy() {
        let mut b = [0u8; 64];
        fill(&mut b);
        // an all-zero 64-byte read is astronomically unlikely
        assert!(b.iter().any(|&x| x != 0));
    }

    #[test]
    fn successive_keys_differ() {
        assert_ne!(random_32(), random_32());
    }

    #[test]
    fn random_u32_varies() {
        // a collision between two fresh u32s is ~1 in 4 billion
        assert_ne!(random_u32(), random_u32());
    }
}
