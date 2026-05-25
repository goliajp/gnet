//! Minimal zero-dependency lowercase-hex encode/decode for the gnet overlay —
//! handling X25519 / ML-KEM keys on the CLI and in config files.
//!
//! Part of a from-scratch, 0-external-dependency overlay; `[dependencies]` is
//! empty. Lowercase output; decode trims surrounding whitespace and requires an
//! even-length input.
//!
//! ```
//! let key = [0xABu8; 32];
//! let hex = gnet_hex::encode(&key);
//! assert_eq!(hex, "ab".repeat(32));
//! assert_eq!(gnet_hex::decode_32(&hex), Some(key));
//! ```

#![forbid(unsafe_code)]

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as a lowercase hex string.
pub fn encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode an even-length hex string into bytes; `None` if malformed.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        let hi = char::from(bytes[2 * i]).to_digit(16)?;
        let lo = char::from(bytes[2 * i + 1]).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Decode a 64-char hex string into exactly 32 bytes; `None` if malformed.
pub fn decode_32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        let hi = char::from(bytes[2 * i]).to_digit(16)?;
        let lo = char::from(bytes[2 * i + 1]).to_digit(16)?;
        *o = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_32() {
        let k: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        assert_eq!(decode_32(&encode(&k)), Some(k));
    }

    #[test]
    fn encode_known() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn decode_rejects_bad_length() {
        assert_eq!(decode_32("abcd"), None);
    }

    #[test]
    fn decode_rejects_non_hex() {
        let bad = "z".repeat(64);
        assert_eq!(decode_32(&bad), None);
    }

    /// Randomized encode→decode roundtrip via the sibling 0-dep RNG (proptest
    /// stand-in): lossless for arbitrary byte lengths, and `decode_32` agrees
    /// with `decode` for 32-byte inputs.
    #[test]
    fn randomized_roundtrip() {
        for _ in 0..2000 {
            let n = (gnet_rand::random_u32() % 64) as usize;
            let mut bytes = vec![0u8; n];
            for chunk in bytes.chunks_mut(4) {
                let r = gnet_rand::random_u32().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            let enc = encode(&bytes);
            assert_eq!(enc.len(), n * 2);
            assert_eq!(decode(&enc), Some(bytes));
        }
        for _ in 0..500 {
            let k = gnet_rand::random_32();
            let enc = encode(&k);
            assert_eq!(decode_32(&enc), Some(k));
            assert_eq!(decode(&enc).as_deref(), Some(&k[..]));
        }
    }
}
