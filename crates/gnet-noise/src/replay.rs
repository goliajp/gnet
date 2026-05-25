//! Sliding-window anti-replay for a transport receive direction.
//!
//! A Noise transport numbers every packet with a strictly increasing counter,
//! but a real network reorders and drops packets, so the receiver cannot
//! require them in order. This window accepts each counter at most once and
//! tolerates reordering up to [`WINDOW`] packets behind the highest counter
//! seen — the same approach WireGuard uses (RFC 6479 style). Packets older
//! than the window, or already seen, are rejected.

/// How far behind the highest accepted counter a packet may still be accepted.
pub const WINDOW: u64 = 64;

/// Anti-replay state for one receive direction.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    /// Highest counter accepted so far (bit 0 of `bitmap` tracks it).
    last: u64,
    /// Bitmap of recently-seen counters: bit `i` marks counter `last - i`.
    bitmap: u64,
}

impl ReplayWindow {
    /// A fresh window that has seen nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `counter` if it is fresh, returning `true`; return `false` if it
    /// is a replay or older than the window. Must be called only for counters
    /// whose packet already authenticated (the counter is the AEAD nonce, so a
    /// forged counter fails decryption before reaching here).
    pub fn accept(&mut self, counter: u64) -> bool {
        if counter > self.last {
            // advance the window: shift seen bits down by the gap, then mark
            // the new highest counter at bit 0.
            let shift = counter - self.last;
            self.bitmap = if shift >= WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.last = counter;
            return true;
        }
        // counter <= last: it must fall inside the window and be unseen.
        let diff = self.last - counter;
        if diff >= WINDOW {
            return false; // older than the window
        }
        let mask = 1u64 << diff;
        if self.bitmap & mask != 0 {
            return false; // already seen
        }
        self.bitmap |= mask;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_first_and_in_order() {
        let mut w = ReplayWindow::new();
        for c in 0..10 {
            assert!(w.accept(c), "in-order counter {c} should be accepted");
        }
    }

    #[test]
    fn rejects_immediate_replay() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(!w.accept(5), "the same counter must not be accepted twice");
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(10));
        // earlier packets arriving late, still inside the window
        assert!(w.accept(8));
        assert!(w.accept(9));
        assert!(w.accept(3));
        // but each only once
        assert!(!w.accept(8));
        assert!(!w.accept(10));
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(100));
        // 100 - 64 = 36 is the oldest still in window; anything <= 36 is too old
        assert!(!w.accept(100 - WINDOW), "exactly WINDOW behind is too old");
        assert!(!w.accept(0), "far older is too old");
        assert!(w.accept(100 - WINDOW + 1), "one inside the window is fine");
    }

    #[test]
    fn large_jump_forward_resets_window() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(5));
        assert!(w.accept(5 + 2 * WINDOW)); // jump far ahead
        // old counters are now all out of window
        assert!(!w.accept(5));
        assert!(!w.accept(50));
        // and the new neighbourhood works
        assert!(w.accept(5 + 2 * WINDOW - 1));
    }
}
