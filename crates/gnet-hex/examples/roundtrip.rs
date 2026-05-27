//! Hex encode a 32-byte key (X25519-sized) and decode it back — the smallest
//! possible `gnet-hex` end-to-end demo.
//!
//! ```sh
//! cargo run -p gnet-hex --example roundtrip
//! ```

fn main() {
    // A pretend X25519 public key.
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);

    let hex = gnet_hex::encode(&key);
    println!("encoded ({} chars): {hex}", hex.len());

    let decoded = gnet_hex::decode_32(&hex).expect("decode_32 roundtrip");
    assert_eq!(decoded, key);
    println!("decode_32 roundtrip ok");

    // The variable-length variant trims surrounding whitespace.
    let with_ws = format!("  {hex}\n");
    let decoded = gnet_hex::decode(&with_ws).expect("decode trims whitespace");
    assert_eq!(decoded.as_slice(), &key);
    println!("decode (whitespace-tolerant) roundtrip ok");
}
