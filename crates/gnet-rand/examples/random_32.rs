//! Print 32 bytes of fresh OS entropy as lowercase hex — the smallest possible
//! `gnet-rand` end-to-end demo.
//!
//! ```sh
//! cargo run -p gnet-rand --example random_32
//! ```

fn main() {
    let bytes = gnet_rand::random_32();
    print!("random_32 = ");
    for b in bytes {
        print!("{b:02x}");
    }
    println!();

    // A four-byte u32 is the common case for indices / txids.
    println!("random_u32 = 0x{:08x}", gnet_rand::random_u32());

    // For variable-length buffers, fill in place.
    let mut wide = [0u8; 64];
    gnet_rand::fill(&mut wide);
    print!("random 64B = ");
    for b in &wide[..16] {
        print!("{b:02x}");
    }
    println!("…");
}
