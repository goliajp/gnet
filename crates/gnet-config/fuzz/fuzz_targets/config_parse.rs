//! Fuzz `gnet_config::parse` against arbitrary text.
//!
//! `parse` runs at daemon startup (via `gnet up`) and at `gnet status` /
//! `gnet doctor`, on a file the operator wrote — the input is somewhat
//! trusted, but a panic on a typo'd conf is a deploy-time foot-gun that
//! the daemon should never emit (it should always be `Err(String)`).
//!
//! Conf is line-oriented ASCII / UTF-8. We try the input as a string if
//! it's valid UTF-8; otherwise skip (parser only sees valid UTF-8 from
//! `read_to_string`).
//!
//! Run with:
//!     cd crates/gnet-config && cargo +nightly fuzz run config_parse

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = gnet_config::parse(text);
    }
});
