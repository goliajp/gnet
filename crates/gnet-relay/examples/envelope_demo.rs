//! Wrap an opaque end-to-end-encrypted datagram in a relay envelope, then
//! parse it back from the relay's perspective. The inner bytes are
//! whatever the underlying session produced (here a placeholder); the
//! envelope only owns the `src ‖ dst` routing prefix.
//!
//! ```sh
//! cargo run -p gnet-relay --example envelope_demo
//! ```

fn main() {
    // Source + destination peer pubkeys (X25519-sized, 32 bytes each).
    let src = [0xAA; gnet_relay::KEY_LEN];
    let dst = [0xBB; gnet_relay::KEY_LEN];

    // The inner datagram — already end-to-end encrypted by the underlying
    // transport. The relay never touches the plaintext.
    let inner = b"opaque-ciphertext-bytes" as &[u8];

    // Encode into an owned Vec (cold path; the hot path uses encode_into
    // to write directly into a pre-sized buffer).
    let envelope = gnet_relay::encode(&src, &dst, inner);
    println!(
        "envelope: {} bytes ({}-byte header + {}-byte inner)",
        envelope.len(),
        gnet_relay::HEADER_LEN,
        inner.len()
    );

    // Forward-only relay fast path: peek the destination key without
    // borrowing the full decoded triple.
    let routed_to = gnet_relay::dst_key(&envelope).expect("envelope has dst");
    assert_eq!(routed_to, &dst);
    println!("dst_key matches: relay forwards to {}", hex(routed_to));

    // Receiver side: full decode borrows the src + dst + inner slice.
    let (decoded_src, decoded_dst, decoded_inner) =
        gnet_relay::decode(&envelope).expect("envelope parses");
    assert_eq!(decoded_src, &src);
    assert_eq!(decoded_dst, &dst);
    assert_eq!(decoded_inner, inner);
    println!("decode roundtrip ok");
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
