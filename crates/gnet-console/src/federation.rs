//! Deterministic federation-token derivation.
//!
//! The console never stores the plaintext token — neither in PG nor in
//! Valkey. It derives it on demand from a master kept in env via:
//!
//!   token_bytes = SHA3-256(LABEL || master || nul || user_id ||
//!                          nul || network_label || nul || endpoint)
//!   token       = hex(token_bytes)
//!
//! A leaked PG dump on its own gets you nothing — without
//! `GNET_CONSOLE_FEDERATION_SECRET` the input is missing 256 bits. The
//! dispatcher only ever stores `SHA3-256(token_bytes)`, so a leaked
//! dispatcher dump tells you that *something* federated but not what
//! the token was.
//!
//! When the user proxies a request through the console to one of their
//! dispatchers, the console re-derives the token and sends it as the
//! Bearer. The dispatcher hashes the bearer and matches against its
//! `federation_trust` row — the same value lands on both sides without
//! ever sitting in console storage.

use uuid::Uuid;

const LABEL: &[u8] = b"gnet-console federation v1\0";

pub fn derive_token(
    master: &[u8; 32],
    user_id: Uuid,
    network_label: &str,
    dispatcher_endpoint: &str,
) -> String {
    let mut buf = Vec::with_capacity(
        LABEL.len() + 32 + 1 + 16 + 1 + network_label.len() + 1 + dispatcher_endpoint.len(),
    );
    buf.extend_from_slice(LABEL);
    buf.extend_from_slice(master);
    buf.push(0);
    buf.extend_from_slice(user_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(network_label.as_bytes());
    buf.push(0);
    buf.extend_from_slice(dispatcher_endpoint.as_bytes());
    gnet_hex::encode(&gnet_crypto::sha3::sha3_256(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_inputs_matter() {
        let m = [7u8; 32];
        let u = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let t1 = derive_token(&m, u, "main", "http://h:1");
        let t2 = derive_token(&m, u, "main", "http://h:1");
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);

        let other_master = derive_token(&[8u8; 32], u, "main", "http://h:1");
        let other_user = derive_token(
            &m,
            Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            "main",
            "http://h:1",
        );
        let other_label = derive_token(&m, u, "other", "http://h:1");
        let other_endpoint = derive_token(&m, u, "main", "http://h:2");

        assert_ne!(t1, other_master);
        assert_ne!(t1, other_user);
        assert_ne!(t1, other_label);
        assert_ne!(t1, other_endpoint);
    }
}
