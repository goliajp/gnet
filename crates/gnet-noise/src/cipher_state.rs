//! Noise `CipherState` — an AEAD key plus a monotonic nonce counter
//! (Noise Protocol Framework §5.1), instantiated with ChaCha20-Poly1305.

use gnet_crypto::aead;

const TAG_LEN: usize = 16;

/// A Noise cipher state: an optional 32-byte key `k` and a 64-bit nonce
/// counter `n`. An absent key makes `encrypt`/`decrypt` pass-through, as
/// required by the pre-key steps of a handshake.
pub struct CipherState {
    k: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {
    /// Keyed cipher state; the nonce counter starts at 0.
    pub fn new(key: [u8; 32]) -> Self {
        Self { k: Some(key), n: 0 }
    }

    /// Keyless (pass-through) cipher state.
    pub fn empty() -> Self {
        Self { k: None, n: 0 }
    }

    /// Whether a key is set.
    pub fn has_key(&self) -> bool {
        self.k.is_some()
    }

    /// The counter the next encryption will use. Stamp it on a transport frame
    /// so the receiver can decrypt out of order via [`decrypt_in_place_at`].
    ///
    /// [`decrypt_in_place_at`]: Self::decrypt_in_place_at
    pub fn counter(&self) -> u64 {
        self.n
    }

    /// In-place decrypt of `buf[..len]` (`ciphertext ‖ tag`) using an explicit
    /// `counter` as the nonce, bound to `ad`. Unlike [`decrypt_in_place`], this
    /// does not touch the internal counter — the caller owns ordering (e.g. via
    /// a [`ReplayWindow`]). On success the plaintext occupies `buf[..len - 16]`
    /// and that length is returned; on authentication failure returns `None`
    /// and leaves `buf` untouched.
    ///
    /// [`decrypt_in_place`]: Self::decrypt_in_place
    /// [`ReplayWindow`]: crate::replay::ReplayWindow
    pub fn decrypt_in_place_at(
        &self,
        counter: u64,
        ad: &[u8],
        buf: &mut [u8],
        len: usize,
    ) -> Option<usize> {
        match self.k {
            Some(key) => {
                if len < TAG_LEN {
                    return None;
                }
                let ct_len = len - TAG_LEN;
                let tag: [u8; TAG_LEN] = buf[ct_len..len].try_into().ok()?;
                aead::open_in_place(&key, &Self::nonce(counter), ad, &mut buf[..ct_len], &tag)
                    .ok()?;
                Some(ct_len)
            }
            None => Some(len),
        }
    }

    /// Noise nonce encoding for ChaChaPoly: four zero bytes followed by the
    /// little-endian counter (Noise §11.1).
    fn nonce(n: u64) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[4..].copy_from_slice(&n.to_le_bytes());
        iv
    }

    /// AEAD-encrypt `plaintext` bound to associated data `ad`, returning
    /// `ciphertext ‖ tag` and advancing the counter. Pass-through (returns
    /// `plaintext`) when keyless.
    pub fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self.k {
            Some(key) => {
                let (mut out, tag) = aead::seal(&key, &Self::nonce(self.n), ad, plaintext);
                out.extend_from_slice(&tag);
                self.n += 1;
                out
            }
            None => plaintext.to_vec(),
        }
    }

    /// AEAD-decrypt `data` (`ciphertext ‖ tag`) bound to associated data
    /// `ad`, advancing the counter on success. Returns `None` on
    /// authentication failure. Pass-through when keyless.
    pub fn decrypt_with_ad(&mut self, ad: &[u8], data: &[u8]) -> Option<Vec<u8>> {
        match self.k {
            Some(key) => {
                if data.len() < TAG_LEN {
                    return None;
                }
                let (ct, tag) = data.split_at(data.len() - TAG_LEN);
                let tag: [u8; TAG_LEN] = tag.try_into().ok()?;
                let pt = aead::open(&key, &Self::nonce(self.n), ad, ct, &tag)?;
                self.n += 1;
                Some(pt)
            }
            None => Some(data.to_vec()),
        }
    }

    /// In-place encrypt of `buf[..len]` bound to `ad`: the ciphertext replaces
    /// the plaintext and the 16-byte tag is written to `buf[len..len + 16]`,
    /// returning the framed length `len + 16`. `buf` must have room for the
    /// tag. Advances the counter; pass-through (returns `len`) when keyless.
    /// Allocation-free — the per-packet data path uses this.
    pub fn encrypt_in_place(&mut self, ad: &[u8], buf: &mut [u8], len: usize) -> usize {
        match self.k {
            Some(key) => {
                let tag = aead::seal_in_place(&key, &Self::nonce(self.n), ad, &mut buf[..len]);
                buf[len..len + TAG_LEN].copy_from_slice(&tag);
                self.n += 1;
                len + TAG_LEN
            }
            None => len,
        }
    }

    /// In-place decrypt of `buf[..len]` (`ciphertext ‖ tag`) bound to `ad`:
    /// on success the plaintext occupies `buf[..len - 16]` and that length is
    /// returned; on authentication failure returns `None` and leaves `buf`
    /// untouched. Advances the counter on success; pass-through when keyless.
    /// Allocation-free.
    pub fn decrypt_in_place(&mut self, ad: &[u8], buf: &mut [u8], len: usize) -> Option<usize> {
        match self.k {
            Some(key) => {
                if len < TAG_LEN {
                    return None;
                }
                let ct_len = len - TAG_LEN;
                let tag: [u8; TAG_LEN] = buf[ct_len..len].try_into().ok()?;
                aead::open_in_place(&key, &Self::nonce(self.n), ad, &mut buf[..ct_len], &tag)
                    .ok()?;
                self.n += 1;
                Some(ct_len)
            }
            None => Some(len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_advances_nonce() {
        let key = [7u8; 32];
        let mut tx = CipherState::new(key);
        let mut rx = CipherState::new(key);
        let c1 = tx.encrypt_with_ad(b"ad1", b"first");
        let c2 = tx.encrypt_with_ad(b"ad2", b"second");
        assert_eq!(
            rx.decrypt_with_ad(b"ad1", &c1).as_deref(),
            Some(&b"first"[..])
        );
        assert_eq!(
            rx.decrypt_with_ad(b"ad2", &c2).as_deref(),
            Some(&b"second"[..])
        );
    }

    #[test]
    fn wrong_ad_is_rejected() {
        let key = [9u8; 32];
        let mut tx = CipherState::new(key);
        let mut rx = CipherState::new(key);
        let c = tx.encrypt_with_ad(b"ad", b"payload");
        assert!(rx.decrypt_with_ad(b"different", &c).is_none());
    }

    #[test]
    fn nonce_desync_is_rejected() {
        let key = [3u8; 32];
        let mut tx = CipherState::new(key);
        let mut rx = CipherState::new(key);
        let _m0 = tx.encrypt_with_ad(b"", b"m0");
        let c1 = tx.encrypt_with_ad(b"", b"m1"); // encrypted at n = 1
        // rx is still at n = 0, so decrypting the n=1 message fails.
        assert!(rx.decrypt_with_ad(b"", &c1).is_none());
    }

    #[test]
    fn in_place_roundtrip_and_interop() {
        let key = [5u8; 32];
        let mut tx = CipherState::new(key);
        let mut rx = CipherState::new(key);
        let mut rx2 = CipherState::new(key);

        // in-place encrypt, then both in-place and owned decrypt agree
        let mut buf = [0u8; 64];
        let msg = b"per-packet payload";
        buf[..msg.len()].copy_from_slice(msg);
        let framed = tx.encrypt_in_place(b"ad", &mut buf, msg.len());
        assert_eq!(framed, msg.len() + 16);

        let owned = rx.decrypt_with_ad(b"ad", &buf[..framed]);
        assert_eq!(owned.as_deref(), Some(&msg[..]));

        let pt_len = rx2.decrypt_in_place(b"ad", &mut buf, framed).unwrap();
        assert_eq!(&buf[..pt_len], msg);
    }

    #[test]
    fn in_place_decrypt_rejects_tamper() {
        let key = [6u8; 32];
        let mut tx = CipherState::new(key);
        let mut rx = CipherState::new(key);
        let mut buf = [0u8; 64];
        buf[..4].copy_from_slice(b"data");
        let framed = tx.encrypt_in_place(b"", &mut buf, 4);
        buf[0] ^= 0x80;
        assert_eq!(rx.decrypt_in_place(b"", &mut buf, framed), None);
    }

    #[test]
    fn keyless_is_passthrough() {
        let mut cs = CipherState::empty();
        assert!(!cs.has_key());
        let c = cs.encrypt_with_ad(b"ad", b"plain");
        assert_eq!(c, b"plain");
        assert_eq!(
            cs.decrypt_with_ad(b"ad", &c).as_deref(),
            Some(&b"plain"[..])
        );
    }

    #[test]
    fn counter_tracks_encryptions() {
        let mut cs = CipherState::new([1u8; 32]);
        assert_eq!(cs.counter(), 0);
        cs.encrypt_with_ad(b"", b"a");
        assert_eq!(cs.counter(), 1);
        let mut buf = [0u8; 32];
        cs.encrypt_in_place(b"", &mut buf, 0);
        assert_eq!(cs.counter(), 2);
    }

    #[test]
    fn decrypt_at_explicit_counter_out_of_order() {
        // encrypt three packets at counters 0,1,2; decrypt them out of order
        // using the explicit-counter path (which never touches rx's counter).
        let key = [8u8; 32];
        let mut tx = CipherState::new(key);
        let rx = CipherState::new(key);
        let mut frames: Vec<(u64, Vec<u8>)> = Vec::new();
        for msg in [&b"zero"[..], b"one", b"two"] {
            let n = tx.counter();
            let mut buf = vec![0u8; msg.len() + TAG_LEN];
            buf[..msg.len()].copy_from_slice(msg);
            let framed = tx.encrypt_in_place(b"", &mut buf, msg.len());
            frames.push((n, buf[..framed].to_vec()));
        }
        // decrypt counter 2 first, then 0, then 1 — all succeed
        for &i in &[2usize, 0, 1] {
            let (n, frame) = &frames[i];
            let mut buf = frame.clone();
            let len = frame.len();
            let pt = rx.decrypt_in_place_at(*n, b"", &mut buf, len);
            assert!(pt.is_some(), "explicit-counter decrypt of {n} should work");
        }
    }

    #[test]
    fn decrypt_at_wrong_counter_fails() {
        let key = [4u8; 32];
        let mut tx = CipherState::new(key);
        let rx = CipherState::new(key);
        let mut buf = [0u8; 32];
        buf[..3].copy_from_slice(b"abc");
        let framed = tx.encrypt_in_place(b"", &mut buf, 3); // encrypted at counter 0
        // decrypting with the wrong counter (nonce) must fail authentication
        assert_eq!(rx.decrypt_in_place_at(7, b"", &mut buf, framed), None);
    }
}
