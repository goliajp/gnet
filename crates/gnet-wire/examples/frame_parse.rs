//! Frame a handshake datagram and parse it back, then build a transport
//! datagram with the receiver index + counter and read those fields back —
//! the two shapes the rest of the overlay uses on every packet.
//!
//! ```sh
//! cargo run -p gnet-wire --example frame_parse
//! ```

use gnet_wire::{Kind, TRANSPORT_HEADER, counter, frame, index, parse, put_counter, put_index};

fn main() {
    // Handshake-style: an opaque ciphertext body framed with a 1-byte tag.
    let body = b"pretend msg1 bytes" as &[u8];
    let dg = frame(Kind::HandshakeInit, body);
    println!("framed {} bytes (tag + body)", dg.len());

    let (kind, parsed) = parse(&dg).expect("valid frame");
    assert_eq!(kind, Kind::HandshakeInit);
    assert_eq!(parsed, body);
    println!("parse roundtrip ok");

    // Transport-style: tag + receiver index + counter, ahead of the
    // in-place-encrypted payload. The gnet daemon writes the index and
    // counter directly into the same buffer the AEAD encrypts into.
    let mut tx = vec![0u8; TRANSPORT_HEADER + 32];
    tx[0] = Kind::Transport as u8;
    put_index(&mut tx, 0xDEAD_BEEF);
    put_counter(&mut tx, 0x0102_0304_0506_0708);
    println!("transport tag={:#x} index={:#x} counter={:#x}",
        tx[0], index(&tx).unwrap(), counter(&tx).unwrap());
}
