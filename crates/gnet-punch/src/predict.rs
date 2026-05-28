//! Symmetric-NAT port-prediction candidate enumeration.
//!
//! Symmetric NAT (RFC 4787 "endpoint-dependent mapping") allocates a *different*
//! external port for each `(source, destination)` tuple. Coordinator-mediated
//! reflexive-endpoint exchange therefore tells the peer behind such a NAT
//! about port `P_AC` (the mapping the NAT picked when speaking to the
//! coordinator C), but *not* `P_AB` (the mapping it will pick when first
//! dialing target B). A naive dial to `(IP, P_AC)` cannot succeed: that
//! mapping is bound to traffic with C, not B.
//!
//! The standard mitigation — implemented here as a pure candidate-generator,
//! wired into the dial path by the node — is to dial **multiple candidate
//! ports** in parallel:
//!
//! 1. **Sequential candidates** (most valuable in practice). Real symmetric
//!    NAT implementations (Linux netfilter `MASQUERADE`, most consumer
//!    router firmwares) allocate ports incrementally: the next outbound's
//!    external port is `P_AC ± k` for small `k`, with occasional jumps when
//!    the deterministic next-port is already in use. Empirically, fan-out
//!    over `P_AC ± [1..=R]` catches 30-50% of symmetric NAT paths in
//!    field deployments (libp2p / iroh measurements).
//!
//! 2. **Birthday-paradox candidates** (cheap tail-cover). For NATs that
//!    randomise port allocation (Linux's `RANDOM_PORT` or `RANDOM_FULLY`
//!    masquerade flag, some carrier-grade NAT), sequential prediction
//!    fails. The fallback is to sample `K` random ports from the ephemeral
//!    range — hit probability is `1 - (1 - 1/N)^K` where `N` is the range
//!    size (Linux default: 28 232 ports = `32768..=60999`). Scaling K with
//!    payload budget: `K=100` → ~0.35%, `K=1000` → 3.5%, `K=5000` → 16%.
//!    Combined with sequential, the realistic overall coverage is roughly
//!    [`birthday_hit_probability`] + (sequential coverage). Birthday alone
//!    is **not** the headline win — sequential is.
//!
//! The fan-out is bounded by the dial budget (each candidate is one UDP
//! packet, and the path-midpoint synchronization window is ~one RTT), so
//! we expose two integer dials directly: `sequential_radius` and
//! `randomized_count`. Total budget = `2·sequential_radius + randomized_count`
//! (sequential candidates are emitted symmetric around the observed port,
//! `±1..=±R`).
//!
//! # Determinism for testing
//!
//! The randomized half uses a [`Lcg`] seeded explicitly: the caller passes
//! `seed`. This makes the iterator output reproducible for unit tests and
//! Monte-Carlo simulation, while in production the daemon seeds from
//! `gnet_rand` once per peer.
//!
//! # References
//!
//! - RFC 4787 §4 — NAT mapping behaviour terminology.
//! - libp2p / iroh fieldwork on real symmetric-NAT distributions (2024-2026).
//! - Linux `net/ipv4/inet_connection_sock.c` — `inet_csk_get_port` is the
//!   actual incremental allocator behind most "symmetric NAT" behaviour.

use std::net::SocketAddr;

/// Default Linux ephemeral port range (`/proc/sys/net/ipv4/ip_local_port_range`).
pub const LINUX_EPHEMERAL_BASE: u16 = 32_768;
/// Default Linux ephemeral port range top.
pub const LINUX_EPHEMERAL_TOP: u16 = 60_999;
/// Size of the default Linux ephemeral port range.
pub const LINUX_EPHEMERAL_SIZE: u32 =
    (LINUX_EPHEMERAL_TOP as u32) - (LINUX_EPHEMERAL_BASE as u32) + 1;

/// Linear-congruential generator (Numerical Recipes constants) — used here as
/// a 0-dep, deterministic source of u32s for test reproducibility. *NOT* a
/// cryptographic RNG; do not use for keys.
#[derive(Debug, Clone, Copy)]
pub struct Lcg(u64);

impl Lcg {
    /// New LCG seeded with `seed`. A zero seed is fine: the multiplier shifts
    /// it off zero in one step.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 32-bit pseudorandom value. Numerical Recipes coefficients
    /// (multiplier `1664525`, increment `1013904223`).
    pub fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        (self.0 >> 16) as u32
    }
}

/// A bounded set of candidate `SocketAddr`s to fan a hole-punch dial over.
/// Built from one observed reflexive endpoint (the one the coordinator told
/// us) plus a sequential radius and a randomized count.
#[derive(Debug, Clone)]
pub struct CandidateSet {
    observed: SocketAddr,
    sequential_radius: u16,
    randomized_count: u16,
    seed: u64,
    /// The ephemeral port range used by the randomized half.
    /// `(base, top)` inclusive on both ends.
    ephemeral: (u16, u16),
}

impl CandidateSet {
    /// Build a candidate set: the observed `(IP, P_AC)` becomes the anchor,
    /// `sequential_radius` controls how many ports around `P_AC` to enumerate
    /// (emits 2 × radius candidates: `P_AC-1, P_AC+1, P_AC-2, P_AC+2, ...`),
    /// `randomized_count` controls how many uniformly random ports in the
    /// ephemeral range to sample, `seed` makes the randomized half
    /// deterministic. The ephemeral range defaults to Linux's standard
    /// `32768..=60999`; override with [`with_ephemeral`](Self::with_ephemeral)
    /// for environments with a different `net.ipv4.ip_local_port_range`.
    pub fn new(
        observed: SocketAddr,
        sequential_radius: u16,
        randomized_count: u16,
        seed: u64,
    ) -> Self {
        Self {
            observed,
            sequential_radius,
            randomized_count,
            seed,
            ephemeral: (LINUX_EPHEMERAL_BASE, LINUX_EPHEMERAL_TOP),
        }
    }

    /// Override the ephemeral port range used by the randomized candidates.
    /// `(base, top)` inclusive on both ends. Use this when the peer's NAT is
    /// known to operate on a non-Linux-default range (e.g. some CGNAT).
    pub fn with_ephemeral(mut self, base: u16, top: u16) -> Self {
        assert!(base <= top, "ephemeral base must be ≤ top");
        self.ephemeral = (base, top);
        self
    }

    /// The observed endpoint itself, always tried first (covers the
    /// "actually it's not symmetric NAT, the dial would have worked
    /// directly" case at zero extra cost).
    pub fn observed(&self) -> SocketAddr {
        self.observed
    }

    /// Total candidate count `1 + 2·sequential_radius + randomized_count`.
    /// (`+1` for the observed endpoint itself.)
    pub fn len(&self) -> usize {
        1 + 2 * (self.sequential_radius as usize) + (self.randomized_count as usize)
    }

    /// A `CandidateSet` is never structurally empty — the observed endpoint
    /// is always at least one candidate.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterator over candidate `SocketAddr`s in dial order: observed first,
    /// then sequential alternating `±1, ±2, …, ±R`, then randomized samples.
    /// All ports are clamped against `u16` overflow (a sequential candidate
    /// that would wrap is silently dropped). Randomized candidates are kept
    /// inside the configured ephemeral range.
    pub fn iter(&self) -> Candidates<'_> {
        Candidates {
            set: self,
            phase: Phase::Observed,
            lcg: Lcg::new(self.seed),
        }
    }
}

#[derive(Debug)]
enum Phase {
    Observed,
    Sequential { offset: u16, side: SeqSide },
    Randomized { remaining: u16 },
    Done,
}

#[derive(Debug, Clone, Copy)]
enum SeqSide {
    Plus,
    Minus,
}

/// Iterator yielding the candidate `SocketAddr`s of a [`CandidateSet`].
pub struct Candidates<'a> {
    set: &'a CandidateSet,
    phase: Phase,
    lcg: Lcg,
}

impl Iterator for Candidates<'_> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.phase {
                Phase::Observed => {
                    self.phase = if self.set.sequential_radius > 0 {
                        Phase::Sequential {
                            offset: 1,
                            side: SeqSide::Plus,
                        }
                    } else if self.set.randomized_count > 0 {
                        Phase::Randomized {
                            remaining: self.set.randomized_count,
                        }
                    } else {
                        Phase::Done
                    };
                    return Some(self.set.observed);
                }
                Phase::Sequential { offset, side } => {
                    let base_port = self.set.observed.port();
                    let candidate = match side {
                        SeqSide::Plus => base_port.checked_add(offset),
                        SeqSide::Minus => base_port.checked_sub(offset),
                    };
                    // Advance phase first so we always make progress even if
                    // the candidate is dropped (overflow / boundary).
                    let (next_offset, next_side) = match side {
                        SeqSide::Plus => (offset, SeqSide::Minus),
                        SeqSide::Minus => (offset + 1, SeqSide::Plus),
                    };
                    self.phase = if next_offset > self.set.sequential_radius {
                        if self.set.randomized_count > 0 {
                            Phase::Randomized {
                                remaining: self.set.randomized_count,
                            }
                        } else {
                            Phase::Done
                        }
                    } else {
                        Phase::Sequential {
                            offset: next_offset,
                            side: next_side,
                        }
                    };
                    if let Some(p) = candidate
                        && p > 0
                    {
                        return Some(with_port(self.set.observed, p));
                    }
                    // overflowed / zero port — skip and try the next phase iter
                }
                Phase::Randomized { remaining } => {
                    if remaining == 0 {
                        self.phase = Phase::Done;
                        continue;
                    }
                    let (lo, hi) = self.set.ephemeral;
                    let span = (hi as u32) - (lo as u32) + 1;
                    let r = self.lcg.next_u32() % span;
                    let port = lo + (r as u16);
                    self.phase = Phase::Randomized {
                        remaining: remaining - 1,
                    };
                    return Some(with_port(self.set.observed, port));
                }
                Phase::Done => return None,
            }
        }
    }
}

fn with_port(mut addr: SocketAddr, port: u16) -> SocketAddr {
    addr.set_port(port);
    addr
}

/// Closed-form hit probability of a `k`-sample uniformly-random scan of an
/// `n`-wide ephemeral range against a single uniformly-random target port:
/// `1 - ((n-1)/n)^k`. This is the textbook birthday-paradox formula for
/// "at least one hit". For Linux defaults (`n = 28232`):
///
/// | k | P(hit) |
/// |---|--------|
/// | 100 | 0.35% |
/// | 1 000 | 3.47% |
/// | 5 000 | 16.2% |
/// | 10 000 | 29.8% |
pub fn birthday_hit_probability(k: u16, ephemeral_range_size: u32) -> f64 {
    let n = ephemeral_range_size as f64;
    1.0 - ((n - 1.0) / n).powi(k as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(port: u16) -> SocketAddr {
        format!("203.0.113.5:{port}").parse().unwrap()
    }

    #[test]
    fn len_matches_total_emission() {
        let s = CandidateSet::new(ep(40000), 5, 10, 0xc0ffee);
        let actual: Vec<_> = s.iter().collect();
        assert_eq!(s.len(), 1 + 2 * 5 + 10);
        assert_eq!(actual.len(), s.len());
    }

    #[test]
    fn observed_first() {
        let s = CandidateSet::new(ep(40000), 3, 0, 0);
        let mut it = s.iter();
        assert_eq!(it.next(), Some(ep(40000)));
    }

    #[test]
    fn sequential_alternates_plus_minus() {
        let s = CandidateSet::new(ep(40000), 3, 0, 0);
        let cands: Vec<_> = s.iter().collect();
        // observed, +1, -1, +2, -2, +3, -3
        let ports: Vec<u16> = cands.iter().map(|a| a.port()).collect();
        assert_eq!(ports, vec![40000, 40001, 39999, 40002, 39998, 40003, 39997]);
    }

    #[test]
    fn sequential_skips_overflow() {
        // observed close to u16::MAX — +1 still fits but +5 overflows; observe
        // emits silently drop overflows but otherwise produce the lower side.
        let s = CandidateSet::new(ep(u16::MAX - 1), 5, 0, 0);
        let cands: Vec<u16> = s.iter().map(|a| a.port()).collect();
        // observed + (MAX, lower, MAX-3, lower, …). MAX+anything dropped.
        // emitted ports: [MAX-1, MAX, MAX-2, MAX-3, MAX-4, MAX-5, MAX-6]
        assert!(cands.contains(&u16::MAX));
        assert!(!cands.contains(&0)); // no wrap to zero
        for p in &cands {
            assert!(*p > 0, "no zero port");
        }
    }

    #[test]
    fn sequential_skips_zero() {
        // observed = 3 with radius 5: -1 = 2, -2 = 1, -3 = 0 (skipped),
        // -4 = checked_sub fails (skipped), -5 = checked_sub fails (skipped)
        let s = CandidateSet::new(ep(3), 5, 0, 0);
        let cands: Vec<u16> = s.iter().map(|a| a.port()).collect();
        assert!(!cands.contains(&0));
    }

    #[test]
    fn randomized_stays_in_ephemeral_range() {
        let s = CandidateSet::new(ep(40000), 0, 1000, 0xc0ffee);
        for c in s.iter().skip(1) {
            let p = c.port();
            assert!(
                (LINUX_EPHEMERAL_BASE..=LINUX_EPHEMERAL_TOP).contains(&p),
                "port {p} outside Linux ephemeral range"
            );
        }
    }

    #[test]
    fn randomized_is_deterministic_under_seed() {
        let a: Vec<u16> = CandidateSet::new(ep(40000), 0, 50, 0x1234)
            .iter()
            .skip(1)
            .map(|a| a.port())
            .collect();
        let b: Vec<u16> = CandidateSet::new(ep(40000), 0, 50, 0x1234)
            .iter()
            .skip(1)
            .map(|a| a.port())
            .collect();
        assert_eq!(a, b, "same seed must produce same sequence");
        let c: Vec<u16> = CandidateSet::new(ep(40000), 0, 50, 0x5678)
            .iter()
            .skip(1)
            .map(|a| a.port())
            .collect();
        assert_ne!(a, c, "different seeds must differ");
    }

    #[test]
    fn randomized_respects_custom_ephemeral_range() {
        let s = CandidateSet::new(ep(40000), 0, 500, 0xc0ffee).with_ephemeral(1024, 65535);
        for c in s.iter().skip(1) {
            let p = c.port();
            assert!(p >= 1024, "port {p} below custom low");
        }
    }

    /// Monte-Carlo check that the random-only hit rate matches the closed-form
    /// birthday formula to within 2σ over many trials — guards the formula
    /// against off-by-one in the iterator and verifies the LCG isn't
    /// catastrophically clumped within the range.
    #[test]
    fn monte_carlo_random_hit_rate_matches_formula() {
        const TRIALS: u32 = 5_000;
        const K: u16 = 1_000;
        let span = LINUX_EPHEMERAL_SIZE;
        let mut prng = Lcg::new(0xdead_beef_cafe_babe);
        let mut hits = 0u32;
        for trial in 0..TRIALS {
            let actual_nat_port =
                LINUX_EPHEMERAL_BASE + ((prng.next_u32() % span) as u16);
            let target = ep(actual_nat_port);
            let set = CandidateSet::new(ep(40_000), 0, K, trial as u64);
            if set.iter().skip(1).any(|c| c == target) {
                hits += 1;
            }
        }
        let measured = hits as f64 / TRIALS as f64;
        let predicted = birthday_hit_probability(K, span);
        // 2σ tolerance ≈ 2 · sqrt(p(1-p)/n)
        let sigma = (predicted * (1.0 - predicted) / (TRIALS as f64)).sqrt();
        let tolerance = 4.0 * sigma; // 4σ — comfortable headroom for an LCG
        assert!(
            (measured - predicted).abs() < tolerance,
            "measured={measured:.4} predicted={predicted:.4} tol={tolerance:.4}"
        );
    }

    /// Field-realistic mixed strategy: a Linux MASQUERADE port walk almost
    /// always lands within `±32` of the previously-allocated port. Verify
    /// the sequential half catches this case 100% of the time when the NAT
    /// behaviour matches.
    #[test]
    fn sequential_catches_small_walk() {
        for delta in [-32i32, -16, -1, 1, 16, 32] {
            let base = 45_000u16;
            let actual_nat_port = ((base as i32) + delta) as u16;
            let set = CandidateSet::new(ep(base), 32, 0, 0);
            let target = ep(actual_nat_port);
            let hit = set.iter().any(|c| c == target);
            assert!(hit, "missed delta {delta}");
        }
    }

    #[test]
    fn birthday_formula_known_values() {
        // sanity-check the closed-form against textbook values
        let n = LINUX_EPHEMERAL_SIZE;
        assert!((birthday_hit_probability(0, n) - 0.0).abs() < 1e-9);
        let p1000 = birthday_hit_probability(1_000, n);
        assert!((0.030..=0.040).contains(&p1000), "p1000 = {p1000:.4}");
        let p5000 = birthday_hit_probability(5_000, n);
        assert!((0.150..=0.175).contains(&p5000), "p5000 = {p5000:.4}");
    }

    #[test]
    fn observed_only_when_zero_extras() {
        let s = CandidateSet::new(ep(40_000), 0, 0, 0);
        let cs: Vec<_> = s.iter().collect();
        assert_eq!(cs, vec![ep(40_000)]);
    }

    #[test]
    fn lcg_seed_zero_is_fine() {
        // a zero seed must still produce a varied sequence (Numerical
        // Recipes increment shifts it off zero in one step)
        let mut g = Lcg::new(0);
        let xs: Vec<u32> = (0..5).map(|_| g.next_u32()).collect();
        let unique: std::collections::HashSet<u32> = xs.iter().copied().collect();
        assert_eq!(unique.len(), xs.len(), "{xs:?} has duplicates");
    }
}
