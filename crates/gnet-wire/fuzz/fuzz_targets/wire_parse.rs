//! Fuzz `gnet_wire::parse` against arbitrary byte inputs.
//!
//! The daemon's UDP downlink runs every incoming datagram through `parse`
//! before any crypto, so this is the first line of untrusted-input
//! exposure. Any panic / OOB read found here is a real DoS vector.
//!
//! Also exercises the smaller demux helpers (`index`, `counter`) the
//! daemon uses on transport datagrams — they have their own
//! length-prefix invariants and benefit from random length probing.
//!
//! Run with:
//!     cd crates/gnet-wire && cargo +nightly fuzz run wire_parse

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gnet_wire::parse(data);
    let _ = gnet_wire::index(data);
    let _ = gnet_wire::counter(data);
    let _ = gnet_wire::decode_addr(data);
});
