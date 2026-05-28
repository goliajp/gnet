//! DCUtR-style synchronized hole-punch rendezvous — the wire codec + the
//! per-peer state machine, zero-I/O.
//!
//! Two peers each behind their own NAT exchange reflexive endpoints through a
//! mutually-reachable coordinator, then dial at the same instant — the origin
//! after RTT/2, the target on receipt of the sync — so their first packets
//! cross at the path midpoint and each NAT sees the peer's packet arrive on a
//! mapping it just opened outbound, defeating the conntrack tuple collision a
//! naive simultaneous race otherwise hits (see RFC 20260525 CP2).
//!
//! This crate owns only the bytes and the state transitions — no sockets, no
//! peer table. The node binary drives it: relaying connect/sync by destination
//! key, measuring the RTT, and turning a due dial into an actual handshake.
//!
//! - [`encode_connect`] / [`decode_connect`] — PunchConnect body
//!   (`origin ‖ target ‖ reflexive-endpoint`).
//! - [`encode_sync`] / [`decode_sync`] — PunchSync body (`origin ‖ target`).
//! - [`PunchState`] — per-peer rendezvous state + its transitions
//!   ([`PunchState::on_reply`], [`PunchState::due_dial`]).
//! - [`candidates_around`] — sequential symmetric-NAT port-prediction
//!   candidates around an observed reflexive endpoint (sequential half of
//!   [`predict::CandidateSet`]; randomized half stays off in phase 2 — the
//!   wire path is sequential-only until the integration is measured).

#![forbid(unsafe_code)]

pub mod predict;

use std::net::SocketAddr;
use std::time::Instant;

use gnet_wire::{decode_addr, encode_addr};
use predict::CandidateSet;

/// Length of a static public key on the wire (X25519).
const PK_LEN: usize = 32;

/// Encode a PunchConnect body: origin pubkey ‖ target pubkey ‖ origin's
/// reflexive endpoint. The coordinator routes by the target key; the target
/// learns who is calling (origin key) and where to dial it (origin endpoint).
pub fn encode_connect(origin: &[u8; 32], target: &[u8; 32], reflexive: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(PK_LEN * 2 + 19);
    out.extend_from_slice(origin);
    out.extend_from_slice(target);
    encode_addr(&mut out, reflexive);
    out
}

/// Decode a PunchConnect body into `(origin, target, reflexive)`, or `None` if
/// it is malformed or truncated.
pub fn decode_connect(b: &[u8]) -> Option<([u8; 32], [u8; 32], SocketAddr)> {
    let origin: [u8; 32] = b.get(..PK_LEN)?.try_into().ok()?;
    let target: [u8; 32] = b.get(PK_LEN..PK_LEN * 2)?.try_into().ok()?;
    let (reflexive, _) = decode_addr(b.get(PK_LEN * 2..)?)?;
    Some((origin, target, reflexive))
}

/// Encode a PunchSync body: origin pubkey ‖ target pubkey. The endpoints were
/// already exchanged by the connect round, so sync only needs to be routed.
pub fn encode_sync(origin: &[u8; 32], target: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PK_LEN * 2);
    out.extend_from_slice(origin);
    out.extend_from_slice(target);
    out
}

/// Decode a PunchSync body into `(origin, target)`, or `None` if it is not two
/// whole pubkeys.
pub fn decode_sync(b: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    let origin: [u8; 32] = b.get(..PK_LEN)?.try_into().ok()?;
    let target: [u8; 32] = b.get(PK_LEN..PK_LEN * 2)?.try_into().ok()?;
    // reject trailing bytes so a sync frame is exactly two keys
    if b.len() != PK_LEN * 2 {
        return None;
    }
    Some((origin, target))
}

/// Per-peer rendezvous state driving the synchronized dial. The node holds one
/// of these alongside each peer's handshake session: punch runs first (to learn
/// the peer's reflexive endpoint and align the dial), then hands off to the
/// normal handshake once both sides dial.
pub enum PunchState {
    /// No rendezvous in progress.
    Idle,
    /// Origin role: we sent a PunchConnect and await the target's reply.
    /// `sent_at` dates the send so the reply measures the coordinator RTT.
    Connecting {
        /// When the PunchConnect was sent — dates the coordinator RTT measurement.
        sent_at: Instant,
    },
    /// Origin role: RTT measured and PunchSync sent; fan-out dial `candidates`
    /// once `dial_at` (reply time + RTT/2) arrives, so our first packets cross
    /// the target's — which dialed immediately on the sync — at the path
    /// midpoint. The candidate list always leads with the observed reflexive
    /// endpoint (the one the coordinator told us); the remainder is symmetric
    /// `±1..=±R` ports for symmetric-NAT port-prediction (see [`predict`]).
    Syncing {
        /// When to dial: the reply time plus half the measured coordinator RTT.
        dial_at: Instant,
        /// Fan-out candidate endpoints in dial order; `candidates[0]` is the
        /// observed reflexive.
        candidates: Vec<SocketAddr>,
    },
    /// Target role: we replied to a PunchConnect and await the origin's sync.
    /// Fan-out dial `candidates` the instant the sync lands — no wait, since
    /// the origin already scheduled its own dial RTT/2 out. Same shape as the
    /// origin's `Syncing.candidates`.
    Awaiting {
        /// Fan-out candidate endpoints in dial order; `candidates[0]` is the
        /// origin's observed reflexive.
        candidates: Vec<SocketAddr>,
    },
}

impl PunchState {
    /// The candidate endpoints to dial if this is a `Syncing` state whose
    /// deadline has arrived, else `None`. Drives the origin's delayed
    /// fan-out dial.
    pub fn due_dial(&self, now: Instant) -> Option<&[SocketAddr]> {
        match self {
            PunchState::Syncing { dial_at, candidates } if *dial_at <= now => {
                Some(candidates.as_slice())
            }
            _ => None,
        }
    }

    /// Origin transition on the target's connect reply: measure the RTT from
    /// `sent_at`, move to `Syncing` with the dial scheduled at reply + RTT/2,
    /// and remember the candidate list (observed reflexive plus
    /// `sequential_radius` symmetric `±1..=±R` ports — see [`predict`]).
    /// Returns `false` (a no-op) unless we were `Connecting`, so a stray or
    /// duplicate reply is ignored.
    pub fn on_reply(
        &mut self,
        endpoint: SocketAddr,
        now: Instant,
        sequential_radius: u16,
    ) -> bool {
        let PunchState::Connecting { sent_at } = self else {
            return false;
        };
        let dial_at = dial_at_from_rtt(*sent_at, now);
        let candidates = candidates_around(endpoint, sequential_radius);
        *self = PunchState::Syncing {
            dial_at,
            candidates,
        };
        true
    }
}

/// Build the fan-out candidate list around an observed reflexive endpoint:
/// the observed endpoint itself first, then symmetric `±1..=±R` ports. The
/// randomized half of [`predict::CandidateSet`] is intentionally off here —
/// phase 2's wire path is sequential-only, and the random tail is reserved
/// for a follow-on once the sequential fan-out is measured in the field.
pub fn candidates_around(observed: SocketAddr, sequential_radius: u16) -> Vec<SocketAddr> {
    CandidateSet::new(observed, sequential_radius, 0, 0)
        .iter()
        .collect()
}

/// The dial instant after a connect→reply round: `reply_now + RTT/2`, where RTT
/// is the measured coordinator round trip (`reply_now - sent_at`). The sync we
/// send takes ~RTT/2 to reach the target (which then dials at once), so dialing
/// after RTT/2 ourselves lands both first packets at the path midpoint. Clamped
/// against a backwards clock (saturating RTT).
fn dial_at_from_rtt(sent_at: Instant, reply_now: Instant) -> Instant {
    let rtt = reply_now.saturating_duration_since(sent_at);
    reply_now + rtt / 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn connect_roundtrip() {
        let origin = [7u8; 32];
        let target = [9u8; 32];
        for s in ["203.0.113.5:41000", "[2001:db8::9]:7777"] {
            let ep: SocketAddr = s.parse().unwrap();
            let body = encode_connect(&origin, &target, ep);
            let (o, t, e) = decode_connect(&body).expect("decode");
            assert_eq!(o, origin);
            assert_eq!(t, target);
            assert_eq!(e, ep);
        }
    }

    #[test]
    fn sync_roundtrip() {
        let origin = [1u8; 32];
        let target = [2u8; 32];
        let body = encode_sync(&origin, &target);
        assert_eq!(body.len(), PK_LEN * 2);
        let (o, t) = decode_sync(&body).expect("decode");
        assert_eq!(o, origin);
        assert_eq!(t, target);
    }

    #[test]
    fn decode_rejects_truncated() {
        // connect needs 32 + 32 + an addr; two keys alone is not enough
        assert!(decode_connect(&[]).is_none());
        assert!(decode_connect(&[0u8; PK_LEN * 2]).is_none());
        assert!(decode_connect(&[0u8; PK_LEN]).is_none());
        // sync needs exactly two whole keys
        assert!(decode_sync(&[]).is_none());
        assert!(decode_sync(&[0u8; PK_LEN]).is_none());
        assert!(decode_sync(&[0u8; PK_LEN * 2 - 1]).is_none());
    }

    #[test]
    fn due_dial_only_after_deadline() {
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let now = Instant::now();
        let past = PunchState::Syncing {
            dial_at: now - Duration::from_secs(1),
            candidates: vec![ep],
        };
        assert_eq!(past.due_dial(now), Some(&[ep][..]));
        let future = PunchState::Syncing {
            dial_at: now + Duration::from_secs(1),
            candidates: vec![ep],
        };
        assert_eq!(future.due_dial(now), None);
        assert_eq!(PunchState::Idle.due_dial(now), None);
        assert_eq!(PunchState::Connecting { sent_at: now }.due_dial(now), None);
    }

    #[test]
    fn on_reply_moves_connecting_to_syncing() {
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let now = Instant::now();
        let mut st = PunchState::Connecting {
            sent_at: now - Duration::from_millis(40),
        };
        assert!(
            st.on_reply(ep, now, 0),
            "connecting accepts the reply"
        );
        assert_eq!(st.due_dial(now), None);
        match &st {
            PunchState::Syncing { dial_at, candidates } => {
                assert_eq!(candidates.as_slice(), &[ep][..]);
                let delay = dial_at.duration_since(now);
                assert!(delay >= Duration::from_millis(18) && delay <= Duration::from_millis(40));
            }
            _ => panic!("on_reply must yield Syncing"),
        }
        assert!(!st.on_reply(ep, now, 0));
        assert!(!PunchState::Idle.on_reply(ep, now, 0));
    }

    #[test]
    fn on_reply_builds_sequential_fan_out_when_radius_positive() {
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let now = Instant::now();
        let mut st = PunchState::Connecting {
            sent_at: now - Duration::from_millis(20),
        };
        assert!(st.on_reply(ep, now, 3));
        let PunchState::Syncing { candidates, .. } = &st else {
            panic!("on_reply must yield Syncing");
        };
        let ports: Vec<u16> = candidates.iter().map(|a| a.port()).collect();
        // observed, +1, -1, +2, -2, +3, -3
        assert_eq!(ports, vec![41000, 41001, 40999, 41002, 40998, 41003, 40997]);
    }

    #[test]
    fn candidates_around_is_observed_then_alternating_sequential() {
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        let c = candidates_around(ep, 2);
        let ports: Vec<u16> = c.iter().map(|a| a.port()).collect();
        assert_eq!(ports, vec![41000, 41001, 40999, 41002, 40998]);
    }

    #[test]
    fn candidates_around_radius_zero_yields_observed_only() {
        let ep: SocketAddr = "203.0.113.5:41000".parse().unwrap();
        assert_eq!(candidates_around(ep, 0), vec![ep]);
    }

    #[test]
    fn dial_at_is_half_the_measured_rtt() {
        let now = Instant::now();
        let sent_at = now - Duration::from_millis(40);
        let delay = dial_at_from_rtt(sent_at, now).duration_since(now);
        assert!(delay >= Duration::from_millis(18), "at least ~rtt/2");
        assert!(delay <= Duration::from_millis(40), "no more than the rtt");
    }

    #[test]
    fn dial_at_clamps_backwards_clock() {
        let now = Instant::now();
        let sent_at = now + Duration::from_secs(1);
        assert_eq!(dial_at_from_rtt(sent_at, now), now);
    }

    /// Randomized connect/sync roundtrip via the sibling 0-dep RNG (proptest
    /// stand-in): encode→decode is lossless for arbitrary keys + endpoints.
    #[test]
    fn randomized_codec_roundtrip() {
        for _ in 0..2000 {
            let origin = gnet_rand::random_32();
            let target = gnet_rand::random_32();
            let port = (gnet_rand::random_u32() & 0xFFFF) as u16;
            let o = gnet_rand::random_u32().to_le_bytes();
            let ep: SocketAddr = format!("{}.{}.{}.{}:{port}", o[0], o[1], o[2], o[3])
                .parse()
                .unwrap();

            let cbody = encode_connect(&origin, &target, ep);
            let (co, ct, ce) = decode_connect(&cbody).expect("connect decode");
            assert_eq!((co, ct, ce), (origin, target, ep));

            let sbody = encode_sync(&origin, &target);
            let (so, st) = decode_sync(&sbody).expect("sync decode");
            assert_eq!((so, st), (origin, target));
        }
    }
}
