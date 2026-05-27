//! Parse a small WireGuard-style gnet config from a literal string and
//! print the resulting `Config` struct. Hex byte values below are valid
//! lowercase hex of the right length; the parser checks identity-derivation
//! consistency at load time, so real configs use values produced by
//! `gnet keygen`.
//!
//! ```sh
//! cargo run -p gnet-config --example parse_sample
//! ```

fn main() {
    // A two-peer node config: us at 10.42.42.2, plus one peer at 10.42.42.3
    // with a known direct UDP endpoint. The 64-hex private key here is
    // arbitrary (test scalar [0x11; 32]); the peer's pubkey + ML-KEM ek would
    // normally come from `gnet keygen` output.
    let text = "\
# example gnet node config
private  1111111111111111111111111111111111111111111111111111111111111111
address  10.42.42.2
listen   0.0.0.0:65432
keepalive 25
";

    let cfg = gnet_config::parse(text).expect("parse");
    println!("private = (32-byte scalar)");
    println!("address = {}", cfg.address);
    println!("listen  = {}", cfg.listen);
    println!("keepalive = {:?}", cfg.keepalive);
    println!("peers   = {} configured", cfg.peers.len());
}
