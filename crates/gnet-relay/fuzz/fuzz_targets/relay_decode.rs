//! Fuzz `gnet_relay::decode` against arbitrary byte inputs.
//!
//! The relay envelope decoder runs on every incoming RelayData datagram
//! both in `gnet-relay-server` (when forwarding) and in the gnet daemon
//! (when a peer answers via a relay). It precedes any per-peer state
//! lookup, so a panic here is a remote-DoS vector on the relay server
//! itself.
//!
//! Also exercises `dst_key` which the relay calls before the full decode
//! to do the routing lookup with a sub-slice borrow.
//!
//! Run with:
//!     cd crates/gnet-relay && cargo +nightly fuzz run relay_decode

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gnet_relay::decode(data);
    let _ = gnet_relay::dst_key(data);
});
