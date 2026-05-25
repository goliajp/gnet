//! Relay envelope framing for the gnet overlay.
//!
//! When two peers cannot hole-punch a direct path (symmetric NAT, CGNAT,
//! hairpin) they fall back to relaying traffic through a mutually reachable
//! node. This crate is the *wire envelope* for that path and nothing else: it
//! wraps an opaque, already-encrypted inner datagram with a routing header
//! `src_pubkey ‖ dst_pubkey ‖ inner`, and parses it back. The relay reads only
//! the routing prefix to forward by destination key — it never sees plaintext,
//! because the inner bytes stay end-to-end encrypted (the relay is not a
//! handshake party for the inner session).
//!
//! # Design
//!
//! - **Zero dependencies.** `[dependencies]` is empty; the envelope is a
//!   hand-written prefix over an opaque byte slice.
//! - **Zero allocation on the hot path.** [`encode_into`] writes into a
//!   caller-supplied buffer and [`decode`] borrows; both are allocation-free,
//!   matching the per-packet discipline of the rest of the overlay. A
//!   convenience [`encode`] returning an owned `Vec` exists for cold paths and
//!   tests.
//! - **No length field.** The inner datagram runs to the end of the UDP
//!   payload, exactly as an unrelayed datagram does — the transport layer
//!   already delimits it.
//! - **Symmetric routing keys.** Carrying both `src` and `dst` lets the relay
//!   rewrite nothing: the receiver learns who to relay back to from `src`, and
//!   the relay routes on `dst`. See [`dst_key`] for the forward-only fast path.
//!
//! ```
//! let src = [1u8; gnet_relay::KEY_LEN];
//! let dst = [2u8; gnet_relay::KEY_LEN];
//! let inner: &[u8] = b"end-to-end ciphertext";
//! let envelope = gnet_relay::encode(&src, &dst, inner);
//! let (gsrc, gdst, ginner) = gnet_relay::decode(&envelope).unwrap();
//! assert_eq!(gsrc, &src);
//! assert_eq!(gdst, &dst);
//! assert_eq!(ginner, inner);
//! ```

#![forbid(unsafe_code)]

/// Length of a static public key (X25519) in the routing header.
pub const KEY_LEN: usize = 32;

/// Bytes the routing header occupies before the opaque inner datagram:
/// `src_pubkey(32) ‖ dst_pubkey(32)`.
pub const HEADER_LEN: usize = KEY_LEN * 2;

/// Write a relay envelope `src ‖ dst ‖ inner` into `out`, returning the total
/// number of bytes written, or `None` if `out` is too small to hold it.
///
/// Allocation-free: this is the hot path for wrapping a transport datagram for
/// relay, called once per relayed packet.
pub fn encode_into(
    out: &mut [u8],
    src: &[u8; KEY_LEN],
    dst: &[u8; KEY_LEN],
    inner: &[u8],
) -> Option<usize> {
    let total = HEADER_LEN + inner.len();
    let slot = out.get_mut(..total)?;
    slot[..KEY_LEN].copy_from_slice(src);
    slot[KEY_LEN..HEADER_LEN].copy_from_slice(dst);
    slot[HEADER_LEN..].copy_from_slice(inner);
    Some(total)
}

/// Build a relay envelope as an owned buffer. Cold path / convenience; the data
/// plane should prefer [`encode_into`] to stay allocation-free.
pub fn encode(src: &[u8; KEY_LEN], dst: &[u8; KEY_LEN], inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + inner.len());
    out.extend_from_slice(src);
    out.extend_from_slice(dst);
    out.extend_from_slice(inner);
    out
}

/// Parse a relay envelope, borrowing the routing keys and the opaque inner
/// datagram, or `None` if `b` is shorter than the routing header. The inner
/// slice may be empty — a header-only envelope is structurally valid.
pub fn decode(b: &[u8]) -> Option<(&[u8; KEY_LEN], &[u8; KEY_LEN], &[u8])> {
    let (header, inner) = b.split_at_checked(HEADER_LEN)?;
    let src: &[u8; KEY_LEN] = header[..KEY_LEN].try_into().ok()?;
    let dst: &[u8; KEY_LEN] = header[KEY_LEN..].try_into().ok()?;
    Some((src, dst, inner))
}

/// Read just the destination key — the only field a relay needs to forward —
/// without borrowing the rest. `None` if `b` is too short to carry a header.
pub fn dst_key(b: &[u8]) -> Option<&[u8; KEY_LEN]> {
    b.get(KEY_LEN..HEADER_LEN)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_into_and_decode() {
        let src = [7u8; KEY_LEN];
        let dst = [9u8; KEY_LEN];
        let inner = b"opaque end-to-end ciphertext";
        let mut buf = [0u8; 256];
        let n = encode_into(&mut buf, &src, &dst, inner).expect("fits");
        assert_eq!(n, HEADER_LEN + inner.len());
        let (gsrc, gdst, ginner) = decode(&buf[..n]).expect("decode");
        assert_eq!(gsrc, &src);
        assert_eq!(gdst, &dst);
        assert_eq!(ginner, inner);
    }

    #[test]
    fn owned_encode_matches_encode_into() {
        let src = [1u8; KEY_LEN];
        let dst = [2u8; KEY_LEN];
        let inner = b"payload";
        let owned = encode(&src, &dst, inner);
        let mut buf = [0u8; 128];
        let n = encode_into(&mut buf, &src, &dst, inner).unwrap();
        assert_eq!(owned, &buf[..n]);
    }

    #[test]
    fn empty_inner_is_valid() {
        let src = [3u8; KEY_LEN];
        let dst = [4u8; KEY_LEN];
        let owned = encode(&src, &dst, &[]);
        assert_eq!(owned.len(), HEADER_LEN);
        let (_, gdst, inner) = decode(&owned).expect("header-only decodes");
        assert_eq!(gdst, &dst);
        assert!(inner.is_empty());
    }

    #[test]
    fn dst_key_matches_decode() {
        let src = [5u8; KEY_LEN];
        let dst = [6u8; KEY_LEN];
        let owned = encode(&src, &dst, b"x");
        assert_eq!(dst_key(&owned), Some(&dst));
    }

    #[test]
    fn decode_rejects_short() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0u8; HEADER_LEN - 1]).is_none());
        assert!(dst_key(&[0u8; KEY_LEN]).is_none());
        // exactly the header is the smallest valid envelope
        assert!(decode(&[0u8; HEADER_LEN]).is_some());
    }

    #[test]
    fn encode_into_rejects_small_buffer() {
        let src = [0u8; KEY_LEN];
        let dst = [0u8; KEY_LEN];
        let inner = b"too big for the buffer";
        let mut buf = [0u8; HEADER_LEN]; // no room for inner
        assert!(encode_into(&mut buf, &src, &dst, inner).is_none());
    }

    /// Randomized roundtrip across many lengths using the sibling 0-dep RNG —
    /// our `proptest` stand-in (no external test crates, per the overlay's
    /// zero-dependency rule). Asserts encode→decode is lossless and the relay
    /// fast-path `dst_key` agrees with full `decode` for every sample.
    #[test]
    fn randomized_roundtrip_is_lossless() {
        let mut buf = [0u8; 2048];
        for _ in 0..2000 {
            let src = gnet_rand::random_32();
            let dst = gnet_rand::random_32();
            let len = (gnet_rand::random_u32() as usize) % (buf.len() - HEADER_LEN + 1);
            // fill an inner payload of pseudo-random bytes
            let mut inner = [0u8; 2048 - HEADER_LEN];
            for chunk in inner[..len].chunks_mut(4) {
                let r = gnet_rand::random_u32().to_le_bytes();
                chunk.copy_from_slice(&r[..chunk.len()]);
            }
            let n = encode_into(&mut buf, &src, &dst, &inner[..len]).expect("fits");
            let (gsrc, gdst, ginner) = decode(&buf[..n]).expect("decode");
            assert_eq!(gsrc, &src);
            assert_eq!(gdst, &dst);
            assert_eq!(ginner, &inner[..len]);
            assert_eq!(dst_key(&buf[..n]), Some(&dst));
        }
    }
}
