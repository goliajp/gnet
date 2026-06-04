//! Background peer discovery — polls the gnet-discover coordinator and
//! hot-adds newly-joined peers / refreshes endpoints on `Node.peers`.
//!
//! When `Config::coordinators` is non-empty, [`spawn`] starts a daemon thread
//! that issues `GET <coordinator>/peers` on a fixed interval (and once
//! immediately at startup). New peers absent from `Node.peers` are pushed in
//! `Session::Idle` so the outbound pump initiates a Noise_IK handshake on the
//! next packet to them. Known peers whose `endpoint` changed are updated in
//! place.
//!
//! Multiple coordinators (primary + warm-standbys, see the A6 failover work)
//! are tried in order, starting from the last one that answered, so a dead
//! primary transparently fails the daemon over to a standby — and it sticks
//! with whichever coordinator is currently up rather than re-probing the dead
//! primary every poll. Both `/peers` polling and `/endpoint-report` target the
//! same chosen coordinator each cycle, keeping reads and writes consistent.
//!
//! Removal of vanished peers is deliberately *not* implemented in v0.2.1: the
//! coordinator does not currently expose a stable "device left" signal, and
//! the cost of carrying a stale peer is just one Idle row, not a security
//! issue. v0.3 work tracks proper peer-leave.
//!
//! JSON parsing is hand-rolled, schema-locked to gnet-discover's `/peers`
//! response — an object `{"peers":[...],"relays":["host:port",...]}` since
//! v0.17, with a bare-`[...]`-array fallback for pre-v0.17 coordinators. The
//! `relays` list is fed into `Node.relay_servers` so a peer tripping to relay
//! fallback prefers a dedicated gnet-relay-server. Kept local rather than
//! reusing `join.rs`'s extractors to keep this module's blast radius
//! contained while the discovery contract is still evolving.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gnet_crypto::mlkem;
use gnet_hex as hex;

use gnet_punch::PunchState;

use super::punch::DIRECT_UPGRADE_BASE;
use super::types::{Node, Peer, Session};

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Hosts-file maintenance handed to the discovery loop. When `manage` is
/// true, every poll that changes the peer set re-splices the gnet-managed
/// block in `path`, so `gnet-<alias>` names track the live coordinator peer
/// set without a re-join. `gnet join` writes the block once at onboard time;
/// this keeps it current as peers come and go — the production gap that left
/// already-joined hosts with a stale block.
pub(super) struct HostsSync {
    pub(super) manage: bool,
    pub(super) path: PathBuf,
    /// Our own alias, for the self entry. `None` (a conf without an `alias`
    /// directive — e.g. a pre-v0.16 join or a hand-written conf) writes peer
    /// entries only; the daemon still resolves other peers by name.
    pub(super) self_alias: Option<String>,
    pub(super) self_v4: IpAddr,
    pub(super) self_v6: Option<IpAddr>,
}

impl HostsSync {
    /// Re-splice the managed hosts block from the current peer set. Best
    /// effort: a write failure (insufficient privilege, read-only FS) is
    /// logged and the daemon keeps running — name resolution is advisory,
    /// the overlay itself is unaffected.
    fn sync(&self, node: &Mutex<Node>) {
        if !self.manage {
            return;
        }
        let mut entries: Vec<crate::hosts::Entry> = Vec::new();
        // our own host first, mirroring `gnet join`'s ordering.
        if let Some(alias) = &self.self_alias {
            entries.push(crate::hosts::Entry {
                alias: alias.clone(),
                v4: Some(self.self_v4.to_string()),
                v6: self.self_v6.map(|ip| ip.to_string()),
            });
        }
        {
            let g = node.lock().expect("node mutex");
            for p in &g.peers {
                // a peer carried over from static conf has an empty alias
                // until the coordinator names it — nothing to write yet.
                if p.alias.is_empty() {
                    continue;
                }
                entries.push(crate::hosts::Entry {
                    alias: p.alias.clone(),
                    v4: Some(p.vip.to_string()),
                    v6: p.vip6.map(|ip| ip.to_string()),
                });
            }
        }
        match crate::hosts::splice_atomic(&self.path, &entries) {
            Ok(()) => eprintln!(
                "event=hosts_synced path={} entries={}",
                self.path.display(),
                entries.len()
            ),
            Err(e) => eprintln!(
                "event=hosts_sync_failed path={} error=\"{e}\"",
                self.path.display()
            ),
        }
    }
}

/// Start the discovery thread. The thread runs for the process lifetime; if
/// the coordinator is unreachable it logs and retries on the next interval.
///
/// When `device_token` is `Some`, the same thread also POSTs the daemon's
/// current reflexive endpoint to `POST /endpoint-report` whenever it changes
/// (or first becomes known), so two NAT-behind-NAT peers can discover each
/// other via the coordinator. A `None` token (legacy join, public peer)
/// silently disables the reporter — peers configured with a static `endpoint`
/// already advertise themselves via the conf at startup.
pub(super) fn spawn(
    node: Arc<Mutex<Node>>,
    coordinators: Vec<String>,
    device_token: Option<String>,
    admin_endpoint: Option<String>,
    hosts: HostsSync,
) {
    let our_pk_hex = {
        let g = node.lock().expect("node mutex");
        hex::encode(&g.public)
    };
    thread::spawn(move || {
        let mut last_reported: Option<SocketAddr> = None;
        // Index into `coordinators` of the one that last answered. Each poll
        // starts here and wraps, so we stay on a working standby instead of
        // hammering a dead primary, but still drift back to the primary once
        // it recovers and answers ahead of the standby in order.
        let mut last_good = 0usize;
        loop {
            match try_in_order(&coordinators, last_good, |c| fetch_peers(c, &our_pk_hex)) {
                Ok(((views, relays), idx)) => {
                    if idx != last_good {
                        eprintln!(
                            "event=coordinator_failover from={} to={}",
                            coordinators[last_good], coordinators[idx]
                        );
                        last_good = idx;
                    }
                    let (added, updated, removed) = apply(&node, &views);
                    // Refresh the advertised relay-server set. Cheap to compare;
                    // logged only on change so a steady deployment stays quiet.
                    let relays_changed = {
                        let mut g = node.lock().expect("node mutex");
                        if g.relay_servers != relays {
                            g.relay_servers = relays;
                            true
                        } else {
                            false
                        }
                    };
                    if relays_changed {
                        let g = node.lock().expect("node mutex");
                        eprintln!(
                            "event=relay_servers_updated count={} relays={:?}",
                            g.relay_servers.len(),
                            g.relay_servers
                        );
                    }
                    if added > 0 || updated > 0 || removed > 0 {
                        eprintln!(
                            "event=discovery_poll added={added} updated={updated} removed={removed} total={}",
                            views.len()
                        );
                        // the peer set changed — refresh the managed hosts
                        // block so newly-joined aliases resolve (and departed
                        // ones disappear) immediately.
                        hosts.sync(&node);
                    }
                }
                Err(e) => eprintln!("event=discovery_poll_failed error=\"{e}\""),
            }

            if let Some(tok) = device_token.as_deref() {
                let current = node.lock().expect("node mutex").reflexive;
                if let Some(ep) = current
                    && last_reported != Some(ep)
                {
                    match try_in_order(&coordinators, last_good, |c| report_endpoint(c, tok, ep)) {
                        Ok(((), idx)) => {
                            eprintln!(
                                "event=endpoint_reported endpoint={ep} coordinator={}",
                                coordinators[idx]
                            );
                            last_good = idx;
                            last_reported = Some(ep);
                        }
                        Err(e) => eprintln!("event=endpoint_report_failed error=\"{e}\""),
                    }
                }
            }

            // Admin snapshot push (plan §17.4). Only fires when both a
            // device_token (auth) and an admin_endpoint (target) are
            // configured. Reuses the same curl shell-out the daemon
            // already uses for /endpoint-report — no new HTTP dep.
            if let (Some(tok), Some(admin)) = (device_token.as_deref(), admin_endpoint.as_deref()) {
                let (reflexive, peer_count) = {
                    let g = node.lock().expect("node mutex");
                    (g.reflexive, g.peers.len())
                };
                match push_snapshot(admin, tok, &our_pk_hex, reflexive, peer_count) {
                    Ok(()) => eprintln!("event=snapshot_pushed admin={admin} peers={peer_count}"),
                    Err(e) => eprintln!("event=snapshot_push_failed error=\"{e}\""),
                }
            }

            thread::sleep(POLL_INTERVAL);
        }
    });
}

/// Try `f` against each coordinator in preference order, starting at `start`
/// (the last-good index) and wrapping, until one succeeds. Returns the result
/// paired with the index that produced it (so the caller can pin `last_good`),
/// or the final error when every coordinator fails. An empty list yields an
/// error — callers gate on a non-empty list before reaching here.
fn try_in_order<T>(
    coordinators: &[String],
    start: usize,
    mut f: impl FnMut(&str) -> io::Result<T>,
) -> io::Result<(T, usize)> {
    let n = coordinators.len();
    let mut last_err: Option<io::Error> = None;
    for off in 0..n {
        let idx = (start + off) % n;
        match f(&coordinators[idx]) {
            Ok(v) => return Ok((v, idx)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("no coordinators configured")))
}

/// POST a small admin snapshot to `<admin_endpoint>/api/internal/snapshot`
/// (plan §17.4 push; v1.2-plan §18.A1 / §5.2 reply.)
///
/// Body shape is the JSON the dispatcher's
/// `admin/routes/internal.rs::SnapshotRequest` expects. We hand-roll the
/// body string because the daemon is zero-deps — no serde_json — and the
/// payload is small + escape-free (the only string fields are the hex
/// pubkey and a SocketAddr's Display, neither of which contains a quote
/// or backslash).
///
/// Reply (v1.2 wire):
/// - `204 No Content` when the dispatcher has no pending ops queued for
///   this device — fast path, identical to the v1.1 wire.
/// - `200 OK` with body `{"ops":[{"op_id":..,"op":..,"args":..}]}` when
///   one or more ops are queued. The daemon parses them, dispatches each
///   through [`dispatch_pending_op`] (stubbed in A1 — every op acks
///   `error: not_implemented_in_a1`; A3 wires the real `/local/*`
///   handlers), then POSTs to `/api/internal/snapshot/ack` per op.
fn push_snapshot(
    admin_endpoint: &str,
    device_token: &str,
    pubkey_hex: &str,
    reflexive: Option<SocketAddr>,
    peer_count: usize,
) -> io::Result<()> {
    let url = format!("{admin_endpoint}/api/internal/snapshot");
    let reflexive_json = match reflexive {
        Some(ep) => format!("\"{ep}\""),
        None => "null".to_string(),
    };
    let body = format!(
        r#"{{"device_pubkey_hex":"{pubkey_hex}","snapshot":{{"version":"{}","reflexive":{reflexive_json},"peer_count":{peer_count}}}}}"#,
        env!("CARGO_PKG_VERSION")
    );
    // `-w '\n%{http_code}'` appends the status code to stdout after the
    // body so we can distinguish 200 (drain ops) from 204 (no work)
    // without a header round-trip.
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg("30")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg(format!("Authorization: Bearer {device_token}"))
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("--data-binary")
        .arg(&body)
        .arg("-w")
        .arg("\n%{http_code}")
        .arg(&url)
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (resp_body, status_code) = split_status_tail(&stdout);
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "curl POST {url} exit={:?} status={status_code} stderr={stderr} body={resp_body}",
            out.status.code()
        )));
    }
    match status_code {
        "204" | "" => Ok(()),
        "200" => {
            for op in parse_pending_ops(resp_body) {
                let result = dispatch_pending_op(&op);
                if let Err(e) =
                    ack_pending_op(admin_endpoint, device_token, pubkey_hex, &op.op_id, &result)
                {
                    eprintln!(
                        "event=snapshot_ack_failed op_id={} op={} error=\"{e}\"",
                        op.op_id, op.op
                    );
                }
            }
            Ok(())
        }
        other => Err(io::Error::other(format!(
            "snapshot push got unexpected HTTP {other} from {url}: body={resp_body}"
        ))),
    }
}

/// Dispatcher → daemon pending op (subset of fields A1 acts on). `args`
/// is intentionally left as the raw JSON substring rather than parsed:
/// the per-op handlers in §18.A3 own knowing which keys their op uses,
/// and A1 doesn't execute any of them — every op acks
/// `error: not_implemented_in_a1` for now.
#[derive(Debug)]
struct PendingOp {
    op_id: String,
    op: String,
    #[allow(dead_code)] // consumed by per-op handlers in §18.A3
    args_raw: String,
}

fn parse_pending_ops(body: &str) -> Vec<PendingOp> {
    let Some(arr) = extract_array_after(body, "ops") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for obj in split_objects(arr) {
        let Some(op_id) = extract_string(obj, "op_id") else {
            eprintln!("event=snapshot_op_malformed missing=op_id raw=\"{obj}\"");
            continue;
        };
        let Some(op) = extract_string(obj, "op") else {
            eprintln!("event=snapshot_op_malformed op_id={op_id} missing=op");
            continue;
        };
        out.push(PendingOp {
            op_id,
            op,
            args_raw: obj.to_string(),
        });
    }
    out
}

/// A1 stub. v1.2-plan §18.A1 explicitly only delivers parse + ack; the
/// real `/local/{alias,join,quit,restart,upgrade}` handlers and
/// rotate-key path land in §18.A3, at which point this function dispatches
/// on `op.op` into the corresponding executor. Until then any op the
/// dispatcher manages to enqueue (none, until §18.A2 flips the operator
/// writes off 501) gets a structured `error: not_implemented_in_a1` ack so
/// the row at least transitions out of the pending state.
fn dispatch_pending_op(op: &PendingOp) -> Result<(), String> {
    eprintln!("event=snapshot_op_received op_id={} op={}", op.op_id, op.op);
    Err("not_implemented_in_a1".to_string())
}

/// POST `/api/internal/snapshot/ack` with the daemon's per-op verdict.
/// Same auth pair as the snapshot push (token + pubkey hex). On `Ok(())`
/// status=ok; on `Err(detail)` status=error and detail is recorded as
/// `last_error`. `detail` is assumed to be short, ASCII-ish, and free
/// of `"` / `\` (callers in A1 produce only fixed-string literals; A3
/// callers must keep that contract or upgrade this to a real escaper).
fn ack_pending_op(
    admin_endpoint: &str,
    device_token: &str,
    pubkey_hex: &str,
    op_id: &str,
    result: &Result<(), String>,
) -> io::Result<()> {
    let url = format!("{admin_endpoint}/api/internal/snapshot/ack");
    let body = match result {
        Ok(()) => format!(
            r#"{{"device_pubkey_hex":"{pubkey_hex}","op_id":"{op_id}","status":"ok"}}"#
        ),
        Err(detail) => format!(
            r#"{{"device_pubkey_hex":"{pubkey_hex}","op_id":"{op_id}","status":"error","detail":"{detail}"}}"#
        ),
    };
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg("30")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg(format!("Authorization: Bearer {device_token}"))
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("--data-binary")
        .arg(&body)
        .arg(&url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "curl POST {url} exit={:?} stderr={stderr} body={stdout}",
            out.status.code()
        )));
    }
    Ok(())
}

/// Split curl `-w '\n%{http_code}'` output into (body, status). Tolerates
/// a missing trailing newline (returns `("",  whole)` only when nothing
/// got emitted, which `--silent --fail-with-body` shouldn't produce for
/// any reachable server, but we'd rather degrade to "treat as no-body" than
/// panic).
fn split_status_tail(stdout: &str) -> (&str, &str) {
    match stdout.rsplit_once('\n') {
        Some((body, code)) => (body, code.trim()),
        None => ("", stdout.trim()),
    }
}

/// POST our reflexive endpoint to `<coordinator>/endpoint-report` with the
/// device token as Bearer auth. Schema-locked to the v0.3 coordinator.
fn report_endpoint(coordinator: &str, device_token: &str, endpoint: SocketAddr) -> io::Result<()> {
    let url = format!("{coordinator}/endpoint-report");
    let body = format!(r#"{{"endpoint":"{endpoint}"}}"#);
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg("30")
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg(format!("Authorization: Bearer {device_token}"))
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("--data-binary")
        .arg(&body)
        .arg(&url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "curl POST {url} exit={:?} stderr={stderr} body={stdout}",
            out.status.code()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PeerView {
    pub alias: String,
    pub x25519_pubkey: [u8; 32],
    pub mlkem_ek: Box<[u8; mlkem::EK_LEN]>,
    pub overlay_v4: IpAddr,
    pub overlay_v6: Option<IpAddr>,
    pub endpoint: Option<SocketAddr>,
    pub relay_eligible: bool,
}

fn fetch_peers(
    coordinator: &str,
    our_pk_hex: &str,
) -> io::Result<(Vec<PeerView>, Vec<SocketAddr>)> {
    let url = format!("{coordinator}/peers");
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("10")
        .arg("--max-time")
        .arg("30")
        .arg("-H")
        .arg(format!("X-Device-Pubkey: {our_pk_hex}"))
        .arg(&url)
        .output()?;
    if !out.status.success() {
        let body = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "curl GET {url} exit={:?} stderr={stderr} body={body}",
            out.status.code()
        )));
    }
    parse_peers_response(&String::from_utf8_lossy(&out.stdout))
}

/// Apply a coordinator-provided peer view to `Node.peers`. Returns
/// `(added, updated, removed)` counts for telemetry. Self is filtered
/// server-side, so any view here is a remote peer.
///
/// After the add/update pass, a reconcile drops coordinator-sourced peers
/// (`pinned == false`) no longer present in `views` — that's peer-leave.
/// `apply` is only called on a *successful* poll, so a coordinator outage
/// (which surfaces as an `Err` upstream, skipping `apply`) never mass-removes
/// the peer table.
///
/// Match order, in priority:
///   1. by pubkey — the common case (endpoint/flag refresh)
///   2. by alias  — key-rotation propagation (alias stays, pubkey moved)
///   3. by overlay_v4 — catches static-conf peers whose alias is empty
///      (conf `peer` lines have no alias field), and where the
///      coordinator-side device for the same overlay IP has rotated keys
///      since the conf was written. Without this, the static-conf row
///      and the coordinator-discovered row coexist sharing an overlay IP
///      — `by_vip` returns the older one, traffic uses the dead pubkey,
///      and the relay sender silently drops because dst pubkey is
///      unknown on the relay's peer table. Production fault, observed
///      mini ↔ lx64 100% loss with stale static `peer` line in mini's
///      conf.
pub(super) fn apply(node: &Mutex<Node>, views: &[PeerView]) -> (usize, usize, usize) {
    let mut g = node.lock().expect("node mutex");
    let mut added = 0usize;
    let mut updated = 0usize;
    for v in views {
        // 1. existing peer with matching pubkey — endpoint/flag refresh
        if let Some(idx) = g.peers.iter().position(|p| p.public == v.x25519_pubkey) {
            let p = &mut g.peers[idx];
            let mut changed = false;
            // backfill alias if it was empty (peer originally from static conf).
            if p.alias != v.alias {
                p.alias = v.alias.clone();
                changed = true;
            }
            if p.endpoint != v.endpoint {
                p.endpoint = v.endpoint;
                changed = true;
            }
            if p.relay_eligible != v.relay_eligible {
                p.relay_eligible = v.relay_eligible;
                changed = true;
            }
            if changed {
                updated += 1;
            }
            continue;
        }
        // 2. alias-keyed lookup — a non-empty alias match with a different
        //    pubkey means key rotation: swap identity in place, reset session.
        if !v.alias.is_empty()
            && let Some(idx) = g.peers.iter().position(|p| p.alias == v.alias)
        {
            let p = &mut g.peers[idx];
            eprintln!("event=peer_keys_rotated alias={}", v.alias);
            p.public = v.x25519_pubkey;
            p.mlkem_ek = v.mlkem_ek.clone();
            p.vip = v.overlay_v4;
            p.vip6 = v.overlay_v6;
            p.endpoint = v.endpoint;
            p.relay_eligible = v.relay_eligible;
            // drop any cached session — old keys won't authenticate inbound
            // transport from the new identity, and we must initiate fresh.
            p.session = Session::Idle;
            p.punch = PunchState::Idle;
            p.punched = false;
            p.punch_failures = 0;
            p.relay = false;
            p.relay_endpoint = None;
            p.rx_index = 0;
            p.tx_index = 0;
            updated += 1;
            continue;
        }
        // 3. overlay_v4 fallback — adopts a static-conf peer (its alias is
        //    empty because conf `peer` lines carry no alias) by overlay IP,
        //    fills in the alias from the coord view, and swaps the pubkey
        //    if it has rotated since the conf was written.
        if let Some(idx) = g
            .peers
            .iter()
            .position(|p| p.alias.is_empty() && p.vip == v.overlay_v4)
        {
            let p = &mut g.peers[idx];
            let pubkey_changed = p.public != v.x25519_pubkey;
            eprintln!(
                "event=peer_adopted vip={} alias={} pubkey_changed={}",
                p.vip, v.alias, pubkey_changed
            );
            p.alias = v.alias.clone();
            p.public = v.x25519_pubkey;
            p.mlkem_ek = v.mlkem_ek.clone();
            p.vip6 = v.overlay_v6;
            p.endpoint = v.endpoint;
            p.relay_eligible = v.relay_eligible;
            if pubkey_changed {
                p.session = Session::Idle;
                p.punch = PunchState::Idle;
                p.punched = false;
                p.punch_failures = 0;
                p.relay = false;
                p.relay_endpoint = None;
                p.rx_index = 0;
                p.tx_index = 0;
            }
            updated += 1;
            continue;
        }
        // 4. genuinely new peer.
        g.peers.push(Peer {
            alias: v.alias.clone(),
            // coordinator-sourced — eligible for peer-leave removal.
            pinned: false,
            public: v.x25519_pubkey,
            mlkem_ek: v.mlkem_ek.clone(),
            vip: v.overlay_v4,
            vip6: v.overlay_v6,
            endpoint: v.endpoint,
            rx_index: 0,
            tx_index: 0,
            session: Session::Idle,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            relay_eligible: v.relay_eligible,
            direct_upgrade_at: Instant::now() + DIRECT_UPGRADE_BASE,
            direct_upgrade_failures: 0,
            last_established_at: None,
        });
        added += 1;
    }
    // peer-leave reconcile — drop coordinator-sourced peers (pinned == false)
    // that are no longer advertised. The add/update pass above has already
    // moved any rotated peer's `public` to its new key, so matching the live
    // set by pubkey keeps rotations and adoptions; only genuinely-vanished
    // coordinator peers fall out. Pinned (static-conf) peers always survive.
    let present: std::collections::HashSet<[u8; 32]> =
        views.iter().map(|v| v.x25519_pubkey).collect();
    let before = g.peers.len();
    g.peers.retain(|p| p.pinned || present.contains(&p.public));
    let removed = before - g.peers.len();
    (added, updated, removed)
}

// ── JSON parsing — schema-locked to /peers response ───────────

/// Parse a `/peers` response into `(peers, relays)`.
///
/// The current coordinator returns an object
/// `{"peers":[...],"relays":["host:port",...]}`. A pre-v0.17 coordinator
/// returns a bare `[...]` array with no relays. We detect the object shape by
/// the presence of a top-level `"peers"` key and fall back to the bare-array
/// parse otherwise, so a node upgraded ahead of its coordinator keeps working
/// through the rollout window (and vice versa — the relays field is optional).
fn parse_peers_response(body: &str) -> io::Result<(Vec<PeerView>, Vec<SocketAddr>)> {
    if find_key(body, "peers").is_some() {
        let peers_arr = extract_array_after(body, "peers")
            .ok_or_else(|| io::Error::other("/peers: missing peers array"))?;
        let mut peers = Vec::new();
        for obj in split_objects(peers_arr) {
            peers.push(parse_peer_object(obj)?);
        }
        let relays = match extract_array_after(body, "relays") {
            Some(arr) => parse_relays(arr)?,
            None => Vec::new(),
        };
        Ok((peers, relays))
    } else {
        // legacy bare array — no relays advertised.
        Ok((parse_peer_array(body)?, Vec::new()))
    }
}

fn parse_peer_array(body: &str) -> io::Result<Vec<PeerView>> {
    let arr = extract_array(body).ok_or_else(|| io::Error::other("expected JSON array"))?;
    let mut out = Vec::new();
    for obj in split_objects(arr) {
        out.push(parse_peer_object(obj)?);
    }
    Ok(out)
}

/// Parse a JSON array of `host:port` strings into socket addresses. IPv6
/// literals carry their own `[...]` brackets inside the quotes; `split_strings`
/// is string-aware so those are not mistaken for array delimiters.
fn parse_relays(arr: &str) -> io::Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for s in split_strings(arr) {
        let addr = s
            .parse::<SocketAddr>()
            .map_err(|_| io::Error::other(format!("/peers: bad relay addr {s:?}")))?;
        out.push(addr);
    }
    Ok(out)
}

fn parse_peer_object(obj: &str) -> io::Result<PeerView> {
    let alias =
        extract_string(obj, "alias").ok_or_else(|| io::Error::other("peer: missing alias"))?;
    let pk_hex = extract_string(obj, "x25519_pubkey")
        .ok_or_else(|| io::Error::other("peer: missing x25519_pubkey"))?;
    let x25519_pubkey =
        hex::decode_32(&pk_hex).ok_or_else(|| io::Error::other("peer: bad x25519_pubkey hex"))?;
    let ek_hex = extract_string(obj, "mlkem_ek")
        .ok_or_else(|| io::Error::other("peer: missing mlkem_ek"))?;
    let mlkem_ek: Box<[u8; mlkem::EK_LEN]> = hex::decode(&ek_hex)
        .and_then(|v| v.into_boxed_slice().try_into().ok())
        .ok_or_else(|| io::Error::other("peer: bad mlkem_ek length"))?;
    let v4_s = extract_string(obj, "overlay_v4")
        .ok_or_else(|| io::Error::other("peer: missing overlay_v4"))?;
    let overlay_v4: IpAddr = v4_s
        .parse()
        .map_err(|_| io::Error::other("peer: bad overlay_v4"))?;
    let overlay_v6 = match extract_string(obj, "overlay_v6") {
        Some(s) if !s.is_empty() => Some(
            s.parse::<IpAddr>()
                .map_err(|_| io::Error::other("peer: bad overlay_v6"))?,
        ),
        _ => None,
    };
    let endpoint = match extract_string(obj, "endpoint") {
        Some(s) if !s.is_empty() => Some(
            s.parse::<SocketAddr>()
                .map_err(|_| io::Error::other("peer: bad endpoint"))?,
        ),
        _ => None,
    };
    // optional field — old coordinators omit it; default to false.
    let relay_eligible = extract_bool(obj, "relay_eligible").unwrap_or(false);
    Ok(PeerView {
        alias,
        x25519_pubkey,
        mlkem_ek,
        overlay_v4,
        overlay_v6,
        endpoint,
        relay_eligible,
    })
}

// Hand-rolled extractors — schema-locked, escape-aware enough for our wire.

fn extract_bool(body: &str, key: &str) -> Option<bool> {
    let key_pos = find_key(body, key)?;
    let after_colon = skip_to_value(body, key_pos)?;
    let s = body.get(after_colon..)?;
    if s.starts_with("true") {
        Some(true)
    } else if s.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn extract_string(body: &str, key: &str) -> Option<String> {
    let key_pos = find_key(body, key)?;
    let after_colon = skip_to_value(body, key_pos)?;
    let s = body.get(after_colon..)?;
    if let Some(rest) = s.strip_prefix("null") {
        // optional fields encoded as null come back as None upstream
        let _ = rest;
        return None;
    }
    if !s.starts_with('"') {
        return None;
    }
    let s = &s[1..];
    let bytes = s.as_bytes();
    let mut end = 0;
    while end < bytes.len() {
        match bytes[end] {
            b'\\' => {
                end += 2;
                continue;
            }
            b'"' => return Some(s[..end].to_string()),
            _ => end += 1,
        }
    }
    None
}

fn extract_array(body: &str) -> Option<&str> {
    let bytes = body.as_bytes();
    let start = bytes.iter().position(|&b| b == b'[')?;
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escape = false;
    let mut i = start + 1;
    while i < bytes.len() {
        let c = bytes[i];
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if in_string {
            match c {
                b'\\' => escape = true,
                b'"' => in_string = false,
                _ => {}
            }
            i += 1;
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&body[start + 1..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Extract the `[...]` array that is the value of `key`, scanning from the
/// key's position so a *later* array (e.g. `"relays"` after `"peers"`) is
/// found rather than the body's first array. Returns the array's inner slice
/// (delimiters excluded), like [`extract_array`].
fn extract_array_after<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let key_pos = find_key(body, key)?;
    let val = skip_to_value(body, key_pos)?;
    extract_array(body.get(val..)?)
}

/// Split a JSON array of strings into the inner text of each quoted element.
/// Escape-aware enough for our wire (`\\`-escaped chars are skipped); brackets
/// and colons inside a string (IPv6 endpoints) are treated as content.
fn split_strings(arr: &str) -> Vec<&str> {
    let bytes = arr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() && bytes[j] != b'"' {
            // skip an escaped char so an escaped quote does not end the string.
            if bytes[j] == b'\\' {
                j += 1;
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        out.push(&arr[start..j]);
        i = j + 1;
    }
    out
}

fn split_objects(arr: &str) -> Vec<&str> {
    let bytes = arr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let start = i;
        let mut depth = 1i32;
        let mut in_string = false;
        let mut escape = false;
        i += 1;
        while i < bytes.len() {
            let c = bytes[i];
            if escape {
                escape = false;
                i += 1;
                continue;
            }
            if in_string {
                match c {
                    b'\\' => escape = true,
                    b'"' => in_string = false,
                    _ => {}
                }
                i += 1;
                continue;
            }
            match c {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        i += 1;
                        out.push(&arr[start..i]);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    out
}

fn find_key(body: &str, key: &str) -> Option<usize> {
    let needle = format!("\"{key}\"");
    let bytes = body.as_bytes();
    let nbytes = needle.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    let mut escape = false;
    while i + nbytes.len() <= bytes.len() {
        let c = bytes[i];
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        if in_string {
            match c {
                b'\\' => {
                    escape = true;
                    i += 1;
                    continue;
                }
                b'"' => {
                    in_string = false;
                    i += 1;
                    continue;
                }
                _ => {
                    i += 1;
                    continue;
                }
            }
        }
        if c == b'"' && bytes[i..i + nbytes.len()] == *nbytes {
            let mut j = i + nbytes.len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b':' {
                return Some(i);
            }
            in_string = true;
            i += 1;
            continue;
        }
        if c == b'"' {
            in_string = true;
        }
        i += 1;
    }
    None
}

fn skip_to_value(body: &str, key_pos: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut i = key_pos + 1;
    let mut escape = false;
    while i < bytes.len() {
        if escape {
            escape = false;
            i += 1;
            continue;
        }
        match bytes[i] {
            b'\\' => escape = true,
            b'"' => {
                i += 1;
                break;
            }
            _ => {}
        }
        i += 1;
    }
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n') {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b':' {
        return None;
    }
    i += 1;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t' || bytes[i] == b'\n') {
        i += 1;
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use std::sync::Arc;

    fn fake_ek() -> Box<[u8; mlkem::EK_LEN]> {
        Box::new([0x42; mlkem::EK_LEN])
    }

    fn fake_pk(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn make_node_with_self_key(private: [u8; 32]) -> Arc<Mutex<Node>> {
        let (mlkem_ek, mlkem_dk) = keys::derive_mlkem(&private);
        Arc::new(Mutex::new(Node {
            private,
            public: keys::public_key(&private),
            mlkem_ek,
            mlkem_dk,
            peers: Vec::new(),
            relay_servers: Vec::new(),
            relay_health: Default::default(),
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
            metrics: Default::default(),
        }))
    }

    #[test]
    fn try_in_order_fails_over_to_second_when_primary_down() {
        let coords = vec!["http://t01".to_string(), "http://t02".to_string()];
        let (val, idx) = try_in_order(&coords, 0, |c| {
            if c == "http://t01" {
                Err(io::Error::other("primary down"))
            } else {
                Ok(c.to_string())
            }
        })
        .unwrap();
        assert_eq!(idx, 1, "failover selects the second coordinator");
        assert_eq!(val, "http://t02");
    }

    #[test]
    fn try_in_order_sticks_to_last_good() {
        // start=1 (a prior failover) → the standby is tried first and answers,
        // so the dead primary is never re-probed this cycle.
        let coords = vec!["http://t01".to_string(), "http://t02".to_string()];
        let mut tried = Vec::new();
        let (_, idx) = try_in_order(&coords, 1, |c| {
            tried.push(c.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(idx, 1);
        assert_eq!(tried, vec!["http://t02"]);
    }

    #[test]
    fn try_in_order_errors_when_all_down() {
        let coords = vec!["http://t01".to_string(), "http://t02".to_string()];
        let r: io::Result<((), usize)> =
            try_in_order(&coords, 0, |_| Err(io::Error::other("down")));
        assert!(r.is_err(), "all coordinators down surfaces an error");
    }

    #[test]
    fn parse_single_peer_object() {
        let ek_hex = hex::encode(&[0x11; mlkem::EK_LEN]);
        let body = format!(
            r#"[{{"alias":"alpha","x25519_pubkey":"{pk}","mlkem_ek":"{ek_hex}","overlay_v4":"10.42.42.7","overlay_v6":"fd8d:f090:2ebb::7","endpoint":"1.2.3.4:51820"}}]"#,
            pk = hex::encode(&[0xab; 32]),
        );
        let views = parse_peer_array(&body).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].alias, "alpha");
        assert_eq!(views[0].x25519_pubkey, [0xab; 32]);
        assert_eq!(views[0].overlay_v4, "10.42.42.7".parse::<IpAddr>().unwrap());
        assert_eq!(
            views[0].overlay_v6,
            Some("fd8d:f090:2ebb::7".parse().unwrap())
        );
        assert_eq!(
            views[0].endpoint,
            Some("1.2.3.4:51820".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn parse_optional_endpoint_null() {
        let ek_hex = hex::encode(&[0x11; mlkem::EK_LEN]);
        let body = format!(
            r#"[{{"alias":"a","x25519_pubkey":"{pk}","mlkem_ek":"{ek_hex}","overlay_v4":"10.0.0.2","overlay_v6":"fd00::2","endpoint":null}}]"#,
            pk = hex::encode(&[0x01; 32]),
        );
        let views = parse_peer_array(&body).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].endpoint, None);
    }

    #[test]
    fn parse_empty_array() {
        let views = parse_peer_array("[]").unwrap();
        assert!(views.is_empty());
    }

    #[test]
    fn parse_response_object_with_relays() {
        // v0.17 coordinator shape: object carrying peers + relays. IPv6 relay
        // endpoints bring their own brackets inside the string — the parser
        // must not mistake them for array delimiters.
        let ek_hex = hex::encode(&[0x11; mlkem::EK_LEN]);
        let body = format!(
            r#"{{"peers":[{{"alias":"alpha","x25519_pubkey":"{pk}","mlkem_ek":"{ek_hex}","overlay_v4":"10.42.42.7","overlay_v6":null,"endpoint":null}}],"relays":["198.51.100.9:65433","[2001:db8::1]:65433"]}}"#,
            pk = hex::encode(&[0xab; 32]),
        );
        let (peers, relays) = parse_peers_response(&body).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].alias, "alpha");
        assert_eq!(
            relays,
            vec![
                "198.51.100.9:65433".parse::<SocketAddr>().unwrap(),
                "[2001:db8::1]:65433".parse::<SocketAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn parse_response_object_empty_relays() {
        let body = r#"{"peers":[],"relays":[]}"#;
        let (peers, relays) = parse_peers_response(body).unwrap();
        assert!(peers.is_empty());
        assert!(relays.is_empty());
    }

    #[test]
    fn parse_response_legacy_bare_array() {
        // pre-v0.17 coordinator returns a bare array and no relays — a node
        // upgraded ahead of its coordinator must still parse it.
        let ek_hex = hex::encode(&[0x11; mlkem::EK_LEN]);
        let body = format!(
            r#"[{{"alias":"beta","x25519_pubkey":"{pk}","mlkem_ek":"{ek_hex}","overlay_v4":"10.42.42.8","overlay_v6":null,"endpoint":null}}]"#,
            pk = hex::encode(&[0xcd; 32]),
        );
        let (peers, relays) = parse_peers_response(&body).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].alias, "beta");
        assert!(relays.is_empty(), "bare array advertises no relays");
    }

    #[test]
    fn apply_removes_vanished_coordinator_peer() {
        // alpha + beta arrive from the coordinator; a later poll drops beta —
        // beta (pinned=false) must be reconciled out, alpha stays.
        let node = make_node_with_self_key([0xcd; 32]);
        let alpha = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xaa),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: None,
            relay_eligible: false,
        };
        let beta = PeerView {
            alias: "beta".into(),
            x25519_pubkey: fake_pk(0xbb),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.3".parse().unwrap(),
            overlay_v6: None,
            endpoint: None,
            relay_eligible: false,
        };
        let (added, _, removed) = apply(&node, &[alpha.clone(), beta]);
        assert_eq!(added, 2);
        assert_eq!(removed, 0);

        // next poll: only alpha present → beta leaves
        let (added, updated, removed) = apply(&node, &[alpha]);
        assert_eq!(added, 0);
        assert_eq!(updated, 0);
        assert_eq!(removed, 1, "vanished coordinator peer is reconciled out");
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1);
        assert_eq!(g.peers[0].alias, "alpha");
    }

    #[test]
    fn reconcile_never_removes_pinned_static_peer() {
        // a static-conf peer (pinned=true) must survive a poll that doesn't
        // mention it — the conf is the operator's explicit intent.
        let node = make_node_with_self_key([0xcd; 32]);
        {
            let mut g = node.lock().unwrap();
            g.peers.push(Peer {
                alias: String::new(),
                pinned: true,
                public: fake_pk(0x11),
                mlkem_ek: fake_ek(),
                vip: "10.42.42.9".parse().unwrap(),
                vip6: None,
                endpoint: Some("1.1.1.1:65432".parse().unwrap()),
                rx_index: 0,
                tx_index: 0,
                session: Session::Idle,
                punch: PunchState::Idle,
                punched: false,
                punch_failures: 0,
                relay: false,
                relay_endpoint: None,
                relay_eligible: false,
                direct_upgrade_at: Instant::now() + DIRECT_UPGRADE_BASE,
                direct_upgrade_failures: 0,
                last_established_at: None,
            });
        }
        // a coordinator poll that lists a different peer entirely
        let other = PeerView {
            alias: "other".into(),
            x25519_pubkey: fake_pk(0xaa),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: None,
            relay_eligible: false,
        };
        let (added, _, removed) = apply(&node, &[other]);
        assert_eq!(added, 1);
        assert_eq!(removed, 0, "pinned static peer is never reconciled out");
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 2, "static peer + the new coordinator peer");
        assert!(
            g.peers
                .iter()
                .any(|p| p.pinned && p.public == fake_pk(0x11))
        );
    }

    #[test]
    fn apply_adds_new_peer() {
        let node = make_node_with_self_key([0xcd; 32]);
        let v = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: Some("fd8d::2".parse().unwrap()),
            endpoint: Some("1.2.3.4:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let (added, updated, _) = apply(&node, &[v]);
        assert_eq!(added, 1);
        assert_eq!(updated, 0);
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1);
        assert_eq!(g.peers[0].public, fake_pk(0xab));
        assert_eq!(g.peers[0].endpoint.unwrap().port(), 51820);
    }

    #[test]
    fn apply_updates_endpoint_on_existing_peer() {
        let node = make_node_with_self_key([0xcd; 32]);
        // pre-seed one peer
        let v0 = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("1.1.1.1:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let _ = apply(&node, &[v0]);

        // same peer, different endpoint
        let v1 = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("2.2.2.2:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let (added, updated, _) = apply(&node, &[v1]);
        assert_eq!(added, 0);
        assert_eq!(updated, 1);
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1);
        assert_eq!(g.peers[0].endpoint.unwrap().to_string(), "2.2.2.2:51820");
    }

    #[test]
    fn apply_is_idempotent_when_view_unchanged() {
        let node = make_node_with_self_key([0xcd; 32]);
        let v = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("1.1.1.1:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let _ = apply(&node, std::slice::from_ref(&v));
        let (added, updated, _) = apply(&node, &[v]);
        assert_eq!(added, 0);
        assert_eq!(updated, 0);
        assert_eq!(node.lock().unwrap().peers.len(), 1);
    }

    #[test]
    fn apply_handles_key_rotation_in_place() {
        // Peer "alpha" exists with pubkey [0xab; 32] and an established
        // session. After coordinator rotates alpha to pubkey [0xee; 32],
        // discovery should not push a second entry — it should swap the
        // pubkey/ek in place and reset session/punch state so the next
        // outbound packet re-handshakes with the new keys.
        let node = make_node_with_self_key([0xcd; 32]);
        let v0 = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("1.1.1.1:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let (added, _, _) = apply(&node, &[v0]);
        assert_eq!(added, 1);

        // simulate an active session + non-zero indices so we can verify
        // that rotation tears them down.
        {
            let mut g = node.lock().unwrap();
            g.peers[0].rx_index = 0x1111_2222;
            g.peers[0].tx_index = 0x3333_4444;
            g.peers[0].relay = true;
            g.peers[0].relay_endpoint = Some("9.9.9.9:65432".parse().unwrap());
        }

        let v1 = PeerView {
            alias: "alpha".into(),
            // ↓ rotated pubkey
            x25519_pubkey: fake_pk(0xee),
            mlkem_ek: Box::new([0x55; mlkem::EK_LEN]),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("2.2.2.2:51820".parse().unwrap()),
            relay_eligible: false,
        };
        let (added, updated, _) = apply(&node, &[v1]);
        assert_eq!(added, 0, "rotation must not push a second peer entry");
        assert_eq!(updated, 1);

        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1, "still one peer slot for alias alpha");
        assert_eq!(g.peers[0].public, fake_pk(0xee), "pubkey swapped");
        assert_eq!(g.peers[0].mlkem_ek[0], 0x55, "ek swapped");
        assert!(matches!(g.peers[0].session, Session::Idle), "session reset");
        assert_eq!(g.peers[0].rx_index, 0, "indices cleared");
        assert_eq!(g.peers[0].tx_index, 0);
        assert!(!g.peers[0].relay, "relay state cleared");
        assert_eq!(g.peers[0].relay_endpoint, None);
        assert_eq!(g.peers[0].endpoint.unwrap().to_string(), "2.2.2.2:51820");
    }

    #[test]
    fn apply_adopts_static_conf_peer_by_overlay_v4() {
        // mini's conf has a static `peer` line with the ORIGINAL lx64 pubkey
        // and alias="" (conf doesn't carry alias). After lx64 rotates, the
        // coordinator returns a different pubkey + alias="lx64" for the same
        // overlay IP. v0.5.2 fix: discovery adopts the static-conf row by
        // overlay_v4, filling in the alias and swapping the rotated pubkey,
        // so no duplicate peer-table row coexists at 10.42.42.5.
        let node = make_node_with_self_key([0xcd; 32]);
        // simulate the static-conf seed (alias empty, original pubkey).
        {
            let mut g = node.lock().unwrap();
            g.peers.push(Peer {
                alias: String::new(),
                pinned: true,          // static-conf seed — must survive reconcile
                public: fake_pk(0xab), // ORIGINAL key
                mlkem_ek: fake_ek(),
                vip: "10.42.42.5".parse().unwrap(),
                vip6: None,
                endpoint: Some("1.1.1.1:65432".parse().unwrap()),
                rx_index: 0,
                tx_index: 0,
                session: Session::Idle,
                punch: PunchState::Idle,
                punched: false,
                punch_failures: 0,
                relay: false,
                relay_endpoint: None,
                relay_eligible: false,
                direct_upgrade_at: Instant::now() + DIRECT_UPGRADE_BASE,
                direct_upgrade_failures: 0,
                last_established_at: None,
            });
        }
        // coord view: rotated pubkey + alias
        let v = PeerView {
            alias: "lx64".into(),
            x25519_pubkey: fake_pk(0xee), // ROTATED key
            mlkem_ek: Box::new([0x77; mlkem::EK_LEN]),
            overlay_v4: "10.42.42.5".parse().unwrap(),
            overlay_v6: None,
            endpoint: Some("2.2.2.2:65432".parse().unwrap()),
            relay_eligible: false,
        };
        let (added, updated, _) = apply(&node, &[v]);
        assert_eq!(added, 0, "static-conf row must be adopted, not duplicated");
        assert_eq!(updated, 1);
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1, "single peer slot at 10.42.42.5");
        assert_eq!(g.peers[0].alias, "lx64");
        assert_eq!(g.peers[0].public, fake_pk(0xee));
        assert_eq!(g.peers[0].mlkem_ek[0], 0x77);
        assert_eq!(g.peers[0].endpoint.unwrap().to_string(), "2.2.2.2:65432");
    }

    #[test]
    fn apply_backfills_alias_for_static_conf_peers() {
        // A peer loaded from static conf has alias=="" — when discovery
        // first sees a /peers row with the matching pubkey it should write
        // the alias in so future rotation matches succeed.
        let node = make_node_with_self_key([0xcd; 32]);
        // simulate a static-conf peer (apply with empty alias view to push
        // it, then verify alias is backfilled on the next poll).
        let static_view = PeerView {
            alias: String::new(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: None,
            relay_eligible: false,
        };
        let _ = apply(&node, &[static_view]);
        assert_eq!(node.lock().unwrap().peers[0].alias, "");

        let with_alias = PeerView {
            alias: "alpha".into(),
            x25519_pubkey: fake_pk(0xab),
            mlkem_ek: fake_ek(),
            overlay_v4: "10.42.42.2".parse().unwrap(),
            overlay_v6: None,
            endpoint: None,
            relay_eligible: false,
        };
        let (added, updated, _) = apply(&node, &[with_alias]);
        assert_eq!(added, 0);
        assert_eq!(updated, 1, "alias backfill counts as one update");
        assert_eq!(node.lock().unwrap().peers[0].alias, "alpha");
    }

    #[test]
    fn hosts_sync_writes_self_and_coordinator_peers() {
        let node = make_node_with_self_key([0x55; 32]);
        // a coordinator-named peer lands via apply()
        apply(
            &node,
            &[PeerView {
                alias: "alpha".into(),
                x25519_pubkey: fake_pk(0xab),
                mlkem_ek: fake_ek(),
                overlay_v4: "10.42.42.2".parse().unwrap(),
                overlay_v6: Some("fd8d::2".parse().unwrap()),
                endpoint: None,
                relay_eligible: false,
            }],
        );

        let dir = std::env::temp_dir().join(format!(
            "gnet-discovery-hosts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        std::fs::write(&path, "127.0.0.1\tlocalhost\n").unwrap();

        let sync = HostsSync {
            manage: true,
            path: path.clone(),
            self_alias: Some("mini".into()),
            self_v4: "10.42.42.4".parse().unwrap(),
            self_v6: Some("fd8d::4".parse().unwrap()),
        };
        sync.sync(&node);

        let out = std::fs::read_to_string(&path).unwrap();
        // self entry (both families) plus the coordinator-named peer
        assert!(out.contains("10.42.42.4\tgnet-mini"));
        assert!(out.contains("fd8d::4\tgnet-mini"));
        assert!(out.contains("10.42.42.2\tgnet-alpha"));
        assert!(out.contains("fd8d::2\tgnet-alpha"));
        // hand-written line preserved outside the managed block
        assert!(out.starts_with("127.0.0.1\tlocalhost\n"));

        // manage:false is a no-op — a fresh path is never created
        let off_path = dir.join("hosts-off");
        HostsSync {
            manage: false,
            path: off_path.clone(),
            self_alias: Some("mini".into()),
            self_v4: "10.42.42.4".parse().unwrap(),
            self_v6: None,
        }
        .sync(&node);
        assert!(!off_path.exists(), "manage:false must not touch the fs");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn hosts_sync_without_self_alias_writes_peers_only() {
        let node = make_node_with_self_key([0x77; 32]);
        apply(
            &node,
            &[PeerView {
                alias: "beta".into(),
                x25519_pubkey: fake_pk(0xcd),
                mlkem_ek: fake_ek(),
                overlay_v4: "10.42.42.3".parse().unwrap(),
                overlay_v6: None,
                endpoint: None,
                relay_eligible: false,
            }],
        );
        let dir = std::env::temp_dir().join(format!(
            "gnet-discovery-hosts-noalias-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts");
        HostsSync {
            manage: true,
            path: path.clone(),
            self_alias: None, // pre-v0.16 conf without an `alias` directive
            self_v4: "10.42.42.9".parse().unwrap(),
            self_v6: None,
        }
        .sync(&node);
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.contains("10.42.42.3\tgnet-beta"), "peer entry written");
        // our own address is absent — no alias means no self entry
        assert!(!out.contains("10.42.42.9"), "no self entry without alias");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── §18.A1 — dispatcher → daemon control-channel wire ──

    #[test]
    fn split_status_tail_splits_body_and_code() {
        let (body, code) = split_status_tail(r#"{"ops":[{"op_id":"abc"}]}\n200"#);
        // rsplit_once on the *literal* \n above doesn't apply — but with a
        // real newline it should. Cover both shapes:
        let _ = (body, code);
        let (body, code) = split_status_tail("{\"ops\":[{\"op_id\":\"abc\"}]}\n200");
        assert_eq!(code, "200");
        assert!(body.contains("op_id"));

        let (body, code) = split_status_tail("\n204");
        assert_eq!(code, "204");
        assert_eq!(body, "");

        // No trailing newline at all: degrade gracefully — whole stdout
        // becomes the status guess; caller's match arm rejects the
        // shape with "unexpected HTTP".
        let (body, code) = split_status_tail("200");
        assert_eq!(body, "");
        assert_eq!(code, "200");
    }

    #[test]
    fn parse_pending_ops_extracts_op_id_and_op() {
        let body = r#"{"ops":[
            {"op_id":"11111111-1111-1111-1111-111111111111","op":"rotate_key","args":{"new_pubkey_hex":"deadbeef"}},
            {"op_id":"22222222-2222-2222-2222-222222222222","op":"restart","args":{}}
        ]}"#;
        let ops = parse_pending_ops(body);
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(ops[0].op, "rotate_key");
        assert_eq!(ops[1].op, "restart");
    }

    #[test]
    fn parse_pending_ops_returns_empty_when_ops_missing() {
        // 204-equivalent (we shouldn't get here for 204, but be robust).
        assert!(parse_pending_ops("").is_empty());
        assert!(parse_pending_ops("{}").is_empty());
        // Malformed object — drop the bad entry, keep the good one.
        let body = r#"{"ops":[{"missing":"op_id"},{"op_id":"33333333-3333-3333-3333-333333333333","op":"restart"}]}"#;
        let ops = parse_pending_ops(body);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op_id, "33333333-3333-3333-3333-333333333333");
    }

    #[test]
    fn dispatch_pending_op_returns_not_implemented_in_a1() {
        // A1 contract: every op gets a structured error ack until §18.A3.
        let op = PendingOp {
            op_id: "0".to_string(),
            op: "restart".to_string(),
            args_raw: "{}".to_string(),
        };
        assert_eq!(dispatch_pending_op(&op), Err("not_implemented_in_a1".to_string()));
    }
}
