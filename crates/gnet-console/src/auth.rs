//! Argon2id password hashing.
//!
//! Parameters live here in one place; bump in one place. Identical to the
//! dispatcher's `gnet-discover/src/admin/auth.rs` (plan §11): the shared
//! constant gets folded into a `gnet-adminapi` crate once the second
//! consumer (this one) is real, which is now — `§17.5a` is the right
//! moment to extract. For *this* commit we keep a parallel definition so
//! the diff stays scoped to console; the extraction is its own commit.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

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

pub fn verify_password(stored_hash: &str, candidate: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(candidate.as_bytes(), &parsed)
        .is_ok()
}

/// Light email-format check. Not RFC 5322 — that's a rabbit hole. We
/// look for the smallest property the rest of the system actually
/// depends on (an `@`, something either side, no whitespace) and let
/// SMTP delivery be the real validator.
pub fn looks_like_email(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > 254 {
        return false;
    }
    if bytes.iter().any(|b| b.is_ascii_whitespace()) {
        return false;
    }
    let at = match bytes.iter().position(|&b| b == b'@') {
        Some(i) => i,
        None => return false,
    };
    if at == 0 || at == bytes.len() - 1 {
        return false;
    }
    // local part has no second @; domain part has a dot.
    if bytes[at + 1..].iter().any(|&b| b == b'@') {
        return false;
    }
    if !bytes[at + 1..].iter().any(|&b| b == b'.') {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_accepts_simple_addresses() {
        assert!(looks_like_email("a@b.co"));
        assert!(looks_like_email("first.last+tag@sub.example.com"));
    }

    #[test]
    fn email_rejects_bad() {
        assert!(!looks_like_email(""));
        assert!(!looks_like_email("noatsign"));
        assert!(!looks_like_email("@no-local.com"));
        assert!(!looks_like_email("trailing@"));
        assert!(!looks_like_email("double@@example.com"));
        assert!(!looks_like_email("no-dot@example"));
        assert!(!looks_like_email("white space@example.com"));
    }

    #[test]
    fn verify_rejects_garbage() {
        assert!(!verify_password("not-a-phc", "x"));
        assert!(!verify_password("", ""));
    }
}
