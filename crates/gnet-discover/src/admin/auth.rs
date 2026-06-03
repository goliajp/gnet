//! Local-admin password + setup-token plumbing.
//!
//! Parameters live in this file only; bump in one place (plan §11). All
//! random bytes come from `gnet_rand` (the daemon's OS-entropy primitive
//! already in the dep tree); all hashes are SHA-3-256 via `gnet-crypto`
//! (the same family the rest of the stack uses).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

// OWASP-style high parameters (plan §11). 64 MiB memory makes password
// verify cost real (~tens of ms on modern hardware); brute-force at this
// cost is impractical even with a leaked PG dump.
pub const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
pub const ARGON2_ITERATIONS: u32 = 3;
pub const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("argon2 params: {0}")]
    Params(argon2::Error),
    #[error("argon2 hash: {0}")]
    Hash(argon2::password_hash::Error),
}

/// Argon2id PHC-string hash of `password`. Salt is freshly drawn from
/// `OsRng`. Output is the standard `$argon2id$v=19$m=…$…` string ready to
/// store in `admin_users.password_hash`.
pub fn hash_password(password: &str) -> Result<String, AuthError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        None,
    )
    .map_err(AuthError::Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let salt = SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(AuthError::Hash)
}

/// PHC string carries its own params; `Argon2::default()` is fine for
/// verify because it only consults the parsed `PasswordHash`. Returns
/// `false` on *any* error — a hash that won't parse is a wrong password.
pub fn verify_password(stored_hash: &str, candidate: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// A 32-byte random secret. The plaintext leaves the binary as hex (64
/// chars) exactly once — printed on stdout for the operator. The DB only
/// ever sees `SHA3_256(raw)`.
pub struct SetupToken {
    raw: [u8; 32],
}

pub fn generate_setup_token() -> SetupToken {
    let mut raw = [0u8; 32];
    gnet_rand::fill(&mut raw);
    SetupToken { raw }
}

impl SetupToken {
    pub fn plaintext_hex(&self) -> String {
        gnet_hex::encode(&self.raw)
    }

    pub fn hash(&self) -> [u8; 32] {
        gnet_crypto::sha3::sha3_256(&self.raw)
    }
}

/// Re-hash an inbound hex token to its stored representation. Returns
/// `None` on hex-format errors — the caller maps that to an "invalid
/// token" 401 (we deliberately do not distinguish "wrong format" from
/// "wrong bytes" to outside callers).
pub fn setup_token_hash_from_hex(token_hex: &str) -> Option<[u8; 32]> {
    let raw = gnet_hex::decode_32(token_hex)?;
    Some(gnet_crypto::sha3::sha3_256(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_token_roundtrip_through_hex() {
        let t = generate_setup_token();
        let hex = t.plaintext_hex();
        assert_eq!(hex.len(), 64);
        let server_hash = setup_token_hash_from_hex(&hex).unwrap();
        assert_eq!(server_hash, t.hash());
    }

    #[test]
    fn setup_token_hex_rejects_garbage() {
        assert!(setup_token_hash_from_hex("not-hex-not-64-chars").is_none());
        // Right length, wrong alphabet.
        let bad = "z".repeat(64);
        assert!(setup_token_hash_from_hex(&bad).is_none());
    }

    #[test]
    fn verify_rejects_garbage_hash() {
        assert!(!verify_password("not-a-phc-string", "whatever"));
        assert!(!verify_password("", ""));
    }
}
