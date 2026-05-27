//! Seal a small plaintext with ChaCha20-Poly1305 AEAD, then open it back —
//! the most common `gnet-crypto` end-to-end demo. Mirrors the transport
//! path the rest of the overlay uses on every encrypted datagram, just
//! without the wire framing on top.
//!
//! ```sh
//! cargo run -p gnet-crypto --example aead_roundtrip
//! ```

use gnet_crypto::aead;

fn main() {
    let key: [u8; aead::KEY_LEN] = [0x11; aead::KEY_LEN];
    let nonce: [u8; aead::NONCE_LEN] = [0x22; aead::NONCE_LEN];
    let aad: &[u8] = b"associated-data-stays-cleartext";
    let plaintext: &[u8] = b"transport payload demo";

    let (ciphertext, tag) = aead::seal(&key, &nonce, aad, plaintext);
    println!(
        "sealed: {} bytes ciphertext + {}-byte tag",
        ciphertext.len(),
        tag.len()
    );

    let opened = aead::open(&key, &nonce, aad, &ciphertext, &tag).expect("auth ok");
    assert_eq!(opened, plaintext);
    println!("opened: {:?}", core::str::from_utf8(&opened).unwrap());

    // Tampering with the AAD makes the open fail — the auth tag covers it.
    let bad = aead::open(&key, &nonce, b"different-aad", &ciphertext, &tag);
    assert!(bad.is_none(), "auth must reject mismatched AAD");
    println!("tamper detection ok: open() refused with a different AAD");
}
