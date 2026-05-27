//! Background peer discovery — polls the gnet-discover coordinator and
//! hot-adds newly-joined peers / refreshes endpoints on `Node.peers`.
//!
//! When `Config::coordinator` is set, [`spawn`] starts a daemon thread that
//! issues `GET <coordinator>/peers` on a fixed interval (and once immediately
//! at startup). New peers absent from `Node.peers` are pushed in `Session::Idle`
//! so the outbound pump initiates a Noise_IK handshake on the next packet to
//! them. Known peers whose `endpoint` changed are updated in place.
//!
//! Removal of vanished peers is deliberately *not* implemented in v0.2.1: the
//! coordinator does not currently expose a stable "device left" signal, and
//! the cost of carrying a stale peer is just one Idle row, not a security
//! issue. v0.3 work tracks proper peer-leave.
//!
//! JSON parsing is hand-rolled, schema-locked to gnet-discover's `/peers`
//! response. Kept local rather than reusing `join.rs`'s extractors to keep
//! this module's blast radius contained while the discovery contract is
//! still evolving.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use gnet_crypto::mlkem;
use gnet_hex as hex;

use gnet_punch::PunchState;

use super::types::{Node, Peer, Session};

const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Start the discovery thread. The thread runs for the process lifetime; if
/// the coordinator is unreachable it logs and retries on the next interval.
///
/// When `device_token` is `Some`, the same thread also POSTs the daemon's
/// current reflexive endpoint to `POST /endpoint-report` whenever it changes
/// (or first becomes known), so two NAT-behind-NAT peers can discover each
/// other via the coordinator. A `None` token (legacy join, public peer)
/// silently disables the reporter — peers configured with a static `endpoint`
/// already advertise themselves via the conf at startup.
pub(super) fn spawn(node: Arc<Mutex<Node>>, coordinator: String, device_token: Option<String>) {
    let our_pk_hex = {
        let g = node.lock().expect("node mutex");
        hex::encode(&g.public)
    };
    thread::spawn(move || {
        let mut last_reported: Option<SocketAddr> = None;
        loop {
            match fetch_peers(&coordinator, &our_pk_hex) {
                Ok(views) => {
                    let (added, updated) = apply(&node, &views);
                    if added > 0 || updated > 0 {
                        eprintln!(
                            "discovery: peer view → +{added} new, {updated} endpoint update(s) ({} from coordinator)",
                            views.len()
                        );
                    }
                }
                Err(e) => eprintln!("discovery: poll failed: {e}"),
            }

            if let Some(tok) = device_token.as_deref() {
                let current = node.lock().expect("node mutex").reflexive;
                if let Some(ep) = current
                    && last_reported != Some(ep)
                {
                    match report_endpoint(&coordinator, tok, ep) {
                        Ok(()) => {
                            eprintln!("endpoint-report: {ep} -> coordinator");
                            last_reported = Some(ep);
                        }
                        Err(e) => eprintln!("endpoint-report failed: {e}"),
                    }
                }
            }

            thread::sleep(POLL_INTERVAL);
        }
    });
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

fn fetch_peers(coordinator: &str, our_pk_hex: &str) -> io::Result<Vec<PeerView>> {
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
    parse_peer_array(&String::from_utf8_lossy(&out.stdout))
}

/// Apply a coordinator-provided peer view to `Node.peers`. Returns
/// `(added, updated)` counts for telemetry. Self is filtered server-side, so
/// any view here is a remote peer.
///
/// Match order: pubkey first (the common case — endpoint/flag updates);
/// alias second (key rotation: a peer whose pubkey changed but alias stayed
/// the same). On alias-match with a different pubkey, the peer's identity
/// is swapped in place and its session is reset to `Idle` so the next
/// outbound packet re-handshakes with the new keys.
pub(super) fn apply(node: &Mutex<Node>, views: &[PeerView]) -> (usize, usize) {
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
            eprintln!(
                "discovery: peer alias={} rotated keys (pubkey changed), resetting session",
                v.alias
            );
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
        // 3. genuinely new peer.
        g.peers.push(Peer {
            alias: v.alias.clone(),
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
        });
        added += 1;
    }
    (added, updated)
}

// ── JSON parsing — schema-locked to /peers response ───────────

fn parse_peer_array(body: &str) -> io::Result<Vec<PeerView>> {
    let arr = extract_array(body).ok_or_else(|| io::Error::other("expected JSON array"))?;
    let mut out = Vec::new();
    for obj in split_objects(arr) {
        out.push(parse_peer_object(obj)?);
    }
    Ok(out)
}

fn parse_peer_object(obj: &str) -> io::Result<PeerView> {
    let alias = extract_string(obj, "alias")
        .ok_or_else(|| io::Error::other("peer: missing alias"))?;
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
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
        }))
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
        let (added, updated) = apply(&node, &[v]);
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
        let (added, updated) = apply(&node, &[v1]);
        assert_eq!(added, 0);
        assert_eq!(updated, 1);
        let g = node.lock().unwrap();
        assert_eq!(g.peers.len(), 1);
        assert_eq!(
            g.peers[0].endpoint.unwrap().to_string(),
            "2.2.2.2:51820"
        );
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
        let (added, updated) = apply(&node, &[v]);
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
        let (added, _) = apply(&node, &[v0]);
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
        let (added, updated) = apply(&node, &[v1]);
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
        let (added, updated) = apply(&node, &[with_alias]);
        assert_eq!(added, 0);
        assert_eq!(updated, 1, "alias backfill counts as one update");
        assert_eq!(node.lock().unwrap().peers[0].alias, "alpha");
    }
}
