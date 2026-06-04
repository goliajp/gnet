//! State the forwarder and the admin HTTP surface share.
//!
//! The forwarder's hot path (UDP `recv_from`) is single-threaded and used
//! to own a plain `HashMap` + `Stats` struct outright. v1.1 §17.8 adds an
//! opt-in admin HTTP read surface that runs on a separate OS thread and
//! needs a concurrent view of the same state — so the table moves behind
//! an `RwLock` and the counters move to `AtomicU64`. Both choices keep
//! the forwarder's per-datagram cost flat (uncontended write-lock acquire
//! and relaxed atomic adds) while letting the admin server snapshot
//! without blocking forwarding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use gnet_relay::KEY_LEN;

pub type PeerKey = [u8; KEY_LEN];

/// Per-peer registry entry: where we last saw them and when. Unchanged
/// shape from the v1.0 forwarder — moving the surrounding map behind a
/// lock doesn't touch the value type.
pub struct PeerEntry {
    pub endpoint: SocketAddr,
    pub last_seen: Instant,
}

pub type SharedPeers = Arc<RwLock<HashMap<PeerKey, PeerEntry>>>;

pub fn new_peers() -> SharedPeers {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Cumulative counters since boot. The forwarder bumps these with
/// `Ordering::Relaxed` (no cross-counter invariants — each field is read
/// independently by the log loop / admin endpoint), and the log loop
/// stores a previous-tick snapshot locally to print per-minute deltas.
#[derive(Default)]
pub struct Stats {
    pub forwarded: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub unknown_dst: AtomicU64,
    pub non_relay: AtomicU64,
    pub self_addressed: AtomicU64,
}

/// Plain-old-data snapshot of the cumulative counters. Convenient for
/// computing deltas (`StatsSnapshot - StatsSnapshot`) and for the admin
/// endpoint's JSON serialisation.
#[derive(Clone, Copy, Default)]
pub struct StatsSnapshot {
    pub forwarded: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub unknown_dst: u64,
    pub non_relay: u64,
    pub self_addressed: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            forwarded: self.forwarded.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            unknown_dst: self.unknown_dst.load(Ordering::Relaxed),
            non_relay: self.non_relay.load(Ordering::Relaxed),
            self_addressed: self.self_addressed.load(Ordering::Relaxed),
        }
    }
}

impl StatsSnapshot {
    /// Per-field delta vs. a previous snapshot. Saturates at 0 in the
    /// unlikely case a counter has been reset (we never reset in v1.1
    /// lite — totals run for the life of the process — but defending
    /// against `u64` overflow is free).
    pub fn delta(&self, prev: StatsSnapshot) -> StatsSnapshot {
        StatsSnapshot {
            forwarded: self.forwarded.saturating_sub(prev.forwarded),
            bytes_in: self.bytes_in.saturating_sub(prev.bytes_in),
            bytes_out: self.bytes_out.saturating_sub(prev.bytes_out),
            unknown_dst: self.unknown_dst.saturating_sub(prev.unknown_dst),
            non_relay: self.non_relay.saturating_sub(prev.non_relay),
            self_addressed: self.self_addressed.saturating_sub(prev.self_addressed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reads_atomic_values() {
        let s = Stats::default();
        s.forwarded.fetch_add(3, Ordering::Relaxed);
        s.bytes_in.fetch_add(1200, Ordering::Relaxed);
        let snap = s.snapshot();
        assert_eq!(snap.forwarded, 3);
        assert_eq!(snap.bytes_in, 1200);
        assert_eq!(snap.bytes_out, 0);
    }

    #[test]
    fn delta_subtracts_per_field_saturating() {
        let prev = StatsSnapshot {
            forwarded: 5,
            bytes_in: 100,
            bytes_out: 200,
            ..Default::default()
        };
        let cur = StatsSnapshot {
            forwarded: 9,
            bytes_in: 100,
            bytes_out: 150, // would underflow without saturation
            ..Default::default()
        };
        let d = cur.delta(prev);
        assert_eq!(d.forwarded, 4);
        assert_eq!(d.bytes_in, 0);
        assert_eq!(d.bytes_out, 0);
    }
}
