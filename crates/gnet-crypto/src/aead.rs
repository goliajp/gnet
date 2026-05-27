//! ChaCha20-Poly1305 AEAD — RFC 8439 §2.8.
//!
//! Builds on the KAT-verified [`chacha20`] and [`poly1305`] primitives,
//! where the AEAD's authentication tag is compared in constant time on
//! `open`.

use crate::{chacha20, poly1305};

/// AEAD key length (bytes).
pub const KEY_LEN: usize = 32;
/// AEAD nonce length (bytes).
pub const NONCE_LEN: usize = 12;
/// Authentication tag length (bytes).
pub const TAG_LEN: usize = 16;

/// Derive the Poly1305 one-time key (RFC 8439 §2.6): the first 32 bytes of
/// the ChaCha20 keystream block at counter 0.
fn poly_key(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let ks = chacha20::block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&ks[..32]);
    otk
}

/// Compute the Poly1305 tag over the RFC 8439 §2.8 framing
/// `aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ le64(len aad) ‖ le64(len ct)`
/// without materializing it: the streaming [`poly1305::Mac`] absorbs `aad` and
/// `ct` directly (zero-padding each region to a block boundary) and a final
/// 16-byte length block, so `ct` is MAC'd in place rather than copied.
fn mac_tag(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut mac = poly1305::Mac::new(otk);
    mac.update_padded(aad);
    mac.update_padded(ct);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    mac.update_padded(&lengths);
    mac.finalize()
}

/// Constant-time equality over the 16-byte tag.
fn ct_eq(a: &[u8; TAG_LEN], b: &[u8; TAG_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authentication failure from [`open_in_place`]: the tag did not verify, and
/// the buffer is left untouched (still ciphertext).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthError;

/// In-place AEAD seal (RFC 8439 §2.8): encrypt `buf` in place and return the
/// tag authenticating it together with `aad`. No allocation — the MAC runs
/// over the ciphertext where it now sits (cache-warm from the cipher pass).
pub fn seal_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; TAG_LEN] {
    let otk = poly_key(key, nonce);
    chacha20::apply_keystream(key, 1, nonce, buf);
    mac_tag(&otk, aad, buf)
}

/// In-place AEAD open (RFC 8439 §2.8): verify `tag` over `aad`+`buf` with a
/// constant-time compare, then decrypt `buf` in place. On failure `buf` is
/// left untouched (still ciphertext) and decryption is skipped. No allocation.
pub fn open_in_place(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), AuthError> {
    let otk = poly_key(key, nonce);
    let expected = mac_tag(&otk, aad, buf);
    if ct_eq(&expected, tag) {
        chacha20::apply_keystream(key, 1, nonce, buf);
        Ok(())
    } else {
        Err(AuthError)
    }
}

/// AEAD seal (RFC 8439 §2.8): encrypt `plaintext` and authenticate it together
/// with `aad`. Returns `(ciphertext, tag)`. Convenience wrapper over
/// [`seal_in_place`] for callers that want an owned buffer.
pub fn seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = plaintext.to_vec();
    let tag = seal_in_place(key, nonce, aad, &mut ct);
    (ct, tag)
}

/// AEAD open (RFC 8439 §2.8): verify `tag` over `aad`+`ciphertext`, then
/// decrypt. Returns the plaintext, or `None` if authentication fails.
/// Convenience wrapper over [`open_in_place`] for callers that want an owned
/// buffer.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Option<Vec<u8>> {
    let mut buf = ciphertext.to_vec();
    match open_in_place(key, nonce, aad, &mut buf, tag) {
        Ok(()) => Some(buf),
        Err(AuthError) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8439 §2.8.2 — worked AEAD example.
    #[test]
    fn aead_rfc8439_2_8_2() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let (ct, tag) = seal(&key, &nonce, &aad, plaintext);
        assert_eq!(ct, expected_ct);
        assert_eq!(tag, expected_tag);

        let pt = open(&key, &nonce, &aad, &ct, &tag);
        assert_eq!(pt.as_deref(), Some(&plaintext[..]));
    }

    /// Reference MAC that materializes the full RFC 8439 §2.8 buffer and runs
    /// the one-shot `poly1305`, for differential testing of the streaming
    /// `mac_tag`.
    fn mac_tag_reference(otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
        let mut data = Vec::new();
        let pad16 = |d: &mut Vec<u8>| {
            let rem = d.len() % 16;
            if rem != 0 {
                d.resize(d.len() + (16 - rem), 0);
            }
        };
        data.extend_from_slice(aad);
        pad16(&mut data);
        data.extend_from_slice(ct);
        pad16(&mut data);
        data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
        poly1305::poly1305(otk, &data)
    }

    /// The streaming `mac_tag` must equal the materialized reference across all
    /// aad/ct length boundary cases (block- and group-aligned and not).
    #[test]
    fn mac_tag_matches_materialized_reference() {
        let otk: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(11) ^ 0x55);
        let lens = [
            0usize, 1, 15, 16, 17, 31, 63, 64, 65, 79, 255, 256, 257, 1000, 4096,
        ];
        for &al in &lens {
            for &cl in &lens {
                let aad: Vec<u8> = (0..al).map(|i| (i as u8).wrapping_mul(3)).collect();
                let ct: Vec<u8> = (0..cl).map(|i| (i as u8).wrapping_mul(7) ^ 0x9a).collect();
                assert_eq!(
                    mac_tag(&otk, &aad, &ct),
                    mac_tag_reference(&otk, &aad, &ct),
                    "mismatch at aad={al} ct={cl}"
                );
            }
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"gnet-overlay-header";
        let pt = b"the quick brown fox";
        let (ct, tag) = seal(&key, &nonce, aad, pt);
        assert_eq!(open(&key, &nonce, aad, &ct, &tag).as_deref(), Some(&pt[..]));
    }

    #[test]
    fn open_rejects_tampered_ciphertext() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let (mut ct, tag) = seal(&key, &nonce, b"aad", b"secret payload");
        ct[0] ^= 0x01;
        assert!(open(&key, &nonce, b"aad", &ct, &tag).is_none());
    }

    #[test]
    fn open_rejects_tampered_tag() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let (ct, mut tag) = seal(&key, &nonce, b"aad", b"secret payload");
        tag[15] ^= 0x80;
        assert!(open(&key, &nonce, b"aad", &ct, &tag).is_none());
    }

    #[test]
    fn open_rejects_wrong_aad() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let (ct, tag) = seal(&key, &nonce, b"aad-one", b"secret payload");
        assert!(open(&key, &nonce, b"aad-two", &ct, &tag).is_none());
    }

    /// In-place seal/open must round-trip and agree with the owned-buffer API.
    #[test]
    fn in_place_roundtrip_matches_owned() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let aad = b"gnet-overlay-header";
        for len in [0usize, 1, 15, 16, 63, 64, 65, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(5) ^ 0x3c).collect();
            let mut buf = pt.clone();
            let tag = seal_in_place(&key, &nonce, aad, &mut buf);

            let (owned_ct, owned_tag) = seal(&key, &nonce, aad, &pt);
            assert_eq!(buf, owned_ct, "ciphertext mismatch at len {len}");
            assert_eq!(tag, owned_tag, "tag mismatch at len {len}");

            assert_eq!(open_in_place(&key, &nonce, aad, &mut buf, &tag), Ok(()));
            assert_eq!(buf, pt, "decrypt mismatch at len {len}");
        }
    }

    /// A tampered ciphertext fails open_in_place and leaves the buffer intact.
    #[test]
    fn open_in_place_rejects_tamper_and_preserves_buf() {
        let key = [0x11u8; 32];
        let nonce = [0x22u8; 12];
        let mut buf = b"secret payload".to_vec();
        let tag = seal_in_place(&key, &nonce, b"aad", &mut buf);
        let ciphertext = buf.clone();
        buf[0] ^= 0x01;
        let tampered = buf.clone();
        assert_eq!(
            open_in_place(&key, &nonce, b"aad", &mut buf, &tag),
            Err(AuthError)
        );
        // buffer is untouched on failure (no partial decryption)
        assert_eq!(buf, tampered);
        // and the untampered ciphertext still opens
        let mut ok = ciphertext;
        assert_eq!(open_in_place(&key, &nonce, b"aad", &mut ok, &tag), Ok(()));
        assert_eq!(ok, b"secret payload");
    }
}
