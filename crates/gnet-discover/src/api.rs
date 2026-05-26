//! Route dispatch + handlers.
//!
//! Endpoints:
//! - `GET  /healthz`            — unauth liveness probe.
//! - `POST   /admin/enrol`            — admin Bearer; creates pending row + returns join token.
//! - `PATCH  /admin/devices/<alias>`  — admin Bearer; mutate device flags (e.g. relay_eligible).
//! - `DELETE /admin/devices/<alias>`  — admin Bearer; removes device + any pending token.
//! - `POST   /join`                   — `x-join-token` header; finalises row, returns
//!   conf JSON including a long-lived `device_token`.
//! - `POST   /endpoint-report`        — device Bearer; updates own underlay endpoint.
//! - `GET    /peers`                  — `x-device-pubkey` header; current peer list.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::auth::{JoinTokenStore, admin_token_matches, mint_token, token_matches};
use crate::config::Config;
use crate::http::{Handler, Request, Response};
use crate::state::{Device, Store};
use crate::time::now_rfc3339;

pub struct AppState {
    pub config: Config,
    pub store: Store,
    pub join_tokens: JoinTokenStore,
}

pub fn handler() -> Handler<AppState> {
    Arc::new(|req: Request, state: Arc<AppState>| {
        Box::pin(async move {
            // dynamic-segment routes first (path-prefix match), then static routes.
            if req.method == "DELETE"
                && let Some(alias) = req.path.strip_prefix("/admin/devices/")
            {
                return admin_delete_device(state, &req, alias).await;
            }
            if req.method == "PATCH"
                && let Some(alias) = req.path.strip_prefix("/admin/devices/")
            {
                return admin_patch_device(state, &req, alias).await;
            }
            match (req.method.as_str(), req.path.as_str()) {
                ("GET", "/healthz") => Response::text(200, "OK", "ok"),
                ("POST", "/admin/enrol") => admin_enrol(state, req).await,
                ("POST", "/join") => join(state, req).await,
                ("POST", "/endpoint-report") => endpoint_report(state, req).await,
                ("GET", "/peers") => peers(state, req).await,
                _ => Response::text(404, "Not Found", "not found"),
            }
        })
    })
}

// ── admin enrol ───────────────────────────────────────────────

#[derive(Deserialize)]
struct EnrolReq {
    alias: String,
}

#[derive(Serialize)]
struct EnrolResp {
    join_token: String,
    overlay_v4: String,
    overlay_v6: String,
}

async fn admin_enrol(state: Arc<AppState>, req: Request) -> Response {
    let Some(provided) = bearer(&req) else {
        return Response::text(401, "Unauthorized", "missing bearer");
    };
    if !admin_token_matches(&state.config.admin_token, provided) {
        return Response::text(401, "Unauthorized", "bad admin token");
    }
    let body: EnrolReq = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(_) => return Response::text(400, "Bad Request", "invalid json"),
    };
    if !valid_alias(&body.alias) {
        return Response::text(400, "Bad Request", "invalid alias");
    }

    // Pending join tokens occupy alias + overlay IP too — without this, two
    // concurrent admin enrols (before either device finishes joining) would
    // each see an empty devices snapshot and hand out duplicate assignments.
    let snapshot = state.store.snapshot().await;
    let pending = state.join_tokens.live_pending().await;

    if snapshot.devices.iter().any(|d| d.alias == body.alias)
        || pending.iter().any(|p| p.alias == body.alias)
    {
        return Response::text(409, "Conflict", "alias already exists");
    }
    let Some(octet) = allocate_v4_octet_with_pending(&snapshot, &pending) else {
        return Response::text(409, "Conflict", "v4 pool exhausted");
    };
    let v4 = format!(
        "{}.{}.{}.{}",
        state.config.overlay_v4_prefix[0],
        state.config.overlay_v4_prefix[1],
        state.config.overlay_v4_prefix[2],
        octet
    );
    let p6 = state.config.overlay_v6_prefix;
    let v6 = format!("{:x}:{:x}:{:x}::{:x}", p6[0], p6[1], p6[2], octet);
    let token = state
        .join_tokens
        .issue(body.alias.clone(), v4.clone(), v6.clone())
        .await;
    Response::json(&EnrolResp {
        join_token: token,
        overlay_v4: v4,
        overlay_v6: v6,
    })
}

fn allocate_v4_octet_with_pending(
    state: &crate::state::State,
    pending: &[crate::auth::PendingEnrol],
) -> Option<u8> {
    let mut used: std::collections::HashSet<u8> = state
        .devices
        .iter()
        .filter_map(|d| d.overlay_v4.rsplit('.').next())
        .filter_map(|s| s.parse().ok())
        .collect();
    for p in pending {
        if let Some(last) = p.overlay_v4.rsplit('.').next()
            && let Ok(n) = last.parse::<u8>()
        {
            used.insert(n);
        }
    }
    (2u8..=254u8).find(|n| !used.contains(n))
}

// ── join ──────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JoinReq {
    x25519_pubkey: String,
    mlkem_ek: String,
    endpoint: Option<String>,
}

#[derive(Serialize)]
struct JoinResp {
    alias: String,
    overlay_v4: String,
    overlay_v6: String,
    /// Long-lived secret the daemon stores in its conf and presents on
    /// `POST /endpoint-report`. Issued fresh on every successful join.
    device_token: String,
    peers: Vec<PeerView>,
}

#[derive(Clone, Serialize)]
struct PeerView {
    alias: String,
    x25519_pubkey: String,
    mlkem_ek: String,
    overlay_v4: String,
    overlay_v6: String,
    endpoint: Option<String>,
    relay_eligible: bool,
}

async fn join(state: Arc<AppState>, req: Request) -> Response {
    let Some(token) = req.header("x-join-token") else {
        return Response::text(401, "Unauthorized", "missing X-Join-Token");
    };
    let body: JoinReq = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(_) => return Response::text(400, "Bad Request", "invalid json"),
    };
    if !is_hex_pubkey(&body.x25519_pubkey) {
        return Response::text(
            400,
            "Bad Request",
            "x25519_pubkey must be 64 lowercase hex chars",
        );
    }
    if !is_lower_hex(&body.mlkem_ek) || body.mlkem_ek.is_empty() {
        return Response::text(
            400,
            "Bad Request",
            "mlkem_ek must be a non-empty lowercase hex string",
        );
    }
    let Some(pending) = state.join_tokens.consume(token).await else {
        return Response::text(401, "Unauthorized", "invalid or expired join token");
    };

    let device_token = mint_token();
    let device = Device {
        alias: pending.alias.clone(),
        x25519_pubkey: body.x25519_pubkey.clone(),
        mlkem_ek: body.mlkem_ek,
        overlay_v4: pending.overlay_v4.clone(),
        overlay_v6: pending.overlay_v6.clone(),
        endpoint: body.endpoint,
        device_token: device_token.clone(),
        relay_eligible: false,
        created_at: now_rfc3339(),
    };
    let alias = device.alias.clone();
    let v4 = device.overlay_v4.clone();
    let v6 = device.overlay_v6.clone();
    let pk = device.x25519_pubkey.clone();

    let persist = state
        .store
        .mutate(move |st| {
            st.devices
                .retain(|d| d.alias != device.alias && d.x25519_pubkey != device.x25519_pubkey);
            st.devices.push(device);
        })
        .await;
    if persist.is_err() {
        return Response::text(500, "Internal Server Error", "persist failed");
    }

    let snapshot = state.store.snapshot().await;
    let peers = snapshot
        .devices
        .iter()
        .filter(|d| d.x25519_pubkey != pk)
        .map(peer_view)
        .collect();
    Response::json(&JoinResp {
        alias,
        overlay_v4: v4,
        overlay_v6: v6,
        device_token,
        peers,
    })
}

// ── admin patch device ────────────────────────────────────────

#[derive(Deserialize)]
struct PatchDeviceReq {
    /// Set true to mark this device as a preferred relay candidate; false to
    /// clear. Omitting the field leaves the flag unchanged.
    relay_eligible: Option<bool>,
}

async fn admin_patch_device(state: Arc<AppState>, req: &Request, alias: &str) -> Response {
    let token_ok = bearer(req)
        .map(|t| admin_token_matches(&state.config.admin_token, t))
        .unwrap_or(false);
    if !token_ok {
        return Response::text(401, "Unauthorized", "bad or missing admin token");
    }
    if !valid_alias(alias) {
        return Response::text(400, "Bad Request", "invalid alias");
    }
    let body: PatchDeviceReq = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(_) => return Response::text(400, "Bad Request", "invalid json"),
    };
    let snapshot = state.store.snapshot().await;
    if !snapshot.devices.iter().any(|d| d.alias == alias) {
        return Response::text(404, "Not Found", "no such device");
    }
    let target = alias.to_string();
    let want_relay = body.relay_eligible;
    let persist = state
        .store
        .mutate(move |st| {
            if let Some(d) = st.devices.iter_mut().find(|d| d.alias == target)
                && let Some(v) = want_relay
            {
                d.relay_eligible = v;
            }
        })
        .await;
    if persist.is_err() {
        return Response::text(500, "Internal Server Error", "persist failed");
    }
    Response::text(200, "OK", "patched")
}

// ── admin delete device ───────────────────────────────────────

async fn admin_delete_device(state: Arc<AppState>, req: &Request, alias: &str) -> Response {
    let Some(provided) = bearer(req) else {
        return Response::text(401, "Unauthorized", "missing bearer");
    };
    if !admin_token_matches(&state.config.admin_token, provided) {
        return Response::text(401, "Unauthorized", "bad admin token");
    }
    if !valid_alias(alias) {
        return Response::text(400, "Bad Request", "invalid alias");
    }

    let snapshot = state.store.snapshot().await;
    if !snapshot.devices.iter().any(|d| d.alias == alias) {
        // also clear any pending token for this alias — caller may want to
        // recycle the slot even if no completed device row exists.
        let _ = state.join_tokens.evict_alias(alias).await;
        return Response::text(404, "Not Found", "no such device");
    }

    let target = alias.to_string();
    let persist = state
        .store
        .mutate(move |st| {
            st.devices.retain(|d| d.alias != target);
        })
        .await;
    if persist.is_err() {
        return Response::text(500, "Internal Server Error", "persist failed");
    }
    let _ = state.join_tokens.evict_alias(alias).await;
    Response::text(200, "OK", "deleted")
}

// ── endpoint-report ───────────────────────────────────────────

#[derive(Deserialize)]
struct EndpointReportReq {
    endpoint: String,
}

async fn endpoint_report(state: Arc<AppState>, req: Request) -> Response {
    let Some(token) = bearer(&req) else {
        return Response::text(401, "Unauthorized", "missing bearer");
    };
    let body: EndpointReportReq = match serde_json::from_slice(&req.body) {
        Ok(b) => b,
        Err(_) => return Response::text(400, "Bad Request", "invalid json"),
    };
    if body.endpoint.parse::<std::net::SocketAddr>().is_err() {
        return Response::text(400, "Bad Request", "endpoint must be ip:port");
    }

    // Constant-time lookup: walk all devices, compare token against each. An
    // attacker without a valid token cannot learn whether *any* token exists
    // because the loop always completes.
    let snapshot = state.store.snapshot().await;
    let mut matched_pk: Option<String> = None;
    for d in &snapshot.devices {
        if !d.device_token.is_empty() && token_matches(&d.device_token, token) {
            matched_pk = Some(d.x25519_pubkey.clone());
            // do not break — keeps timing independent of position
        }
    }
    let Some(pk) = matched_pk else {
        return Response::text(401, "Unauthorized", "unknown device token");
    };

    let new_ep = body.endpoint;
    let persist = state
        .store
        .mutate(move |st| {
            if let Some(d) = st.devices.iter_mut().find(|d| d.x25519_pubkey == pk) {
                d.endpoint = Some(new_ep);
            }
        })
        .await;
    if persist.is_err() {
        return Response::text(500, "Internal Server Error", "persist failed");
    }
    Response::text(200, "OK", "ok")
}

// ── peers ─────────────────────────────────────────────────────

async fn peers(state: Arc<AppState>, req: Request) -> Response {
    let Some(pk) = req.header("x-device-pubkey") else {
        return Response::text(401, "Unauthorized", "missing X-Device-Pubkey");
    };
    let snapshot = state.store.snapshot().await;
    if !snapshot.devices.iter().any(|d| d.x25519_pubkey == pk) {
        return Response::text(401, "Unauthorized", "unknown device");
    }
    let list: Vec<PeerView> = snapshot
        .devices
        .iter()
        .filter(|d| d.x25519_pubkey != pk)
        .map(peer_view)
        .collect();
    Response::json(&list)
}

// ── helpers ───────────────────────────────────────────────────

fn peer_view(d: &Device) -> PeerView {
    PeerView {
        alias: d.alias.clone(),
        x25519_pubkey: d.x25519_pubkey.clone(),
        mlkem_ek: d.mlkem_ek.clone(),
        overlay_v4: d.overlay_v4.clone(),
        overlay_v6: d.overlay_v6.clone(),
        endpoint: d.endpoint.clone(),
        relay_eligible: d.relay_eligible,
    }
}

fn bearer(req: &Request) -> Option<&str> {
    req.header("authorization")
        .and_then(|s| s.strip_prefix("Bearer "))
}

fn valid_alias(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && is_lower_hex(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_test_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        gnet_rand::fill(&mut r);
        p.push(format!("gnet-discover-apitest-{}.json", gnet_hex::encode(&r)));

        let store = Store::load(&p).await.unwrap();
        let state = Arc::new(AppState {
            config: Config {
                bind: "127.0.0.1:0".parse().unwrap(),
                state_path: p.clone(),
                admin_token: "test-token-1234567890".into(),
                overlay_v4_prefix: [10, 42, 42],
                overlay_v6_prefix: [0xfd8d, 0xf090, 0x2ebb, 0],
            },
            store,
            join_tokens: JoinTokenStore::new(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let h = handler();
        let task = tokio::spawn(async move {
            let _ = crate::http::serve(listener, state, h).await;
        });
        (addr, task)
    }

    async fn raw(addr: std::net::SocketAddr, req: &[u8]) -> (u16, String) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(req).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).to_string();
        let status: u16 = text[9..12].parse().unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    fn enrol_req(alias: &str, token: &str) -> Vec<u8> {
        let body = format!(r#"{{"alias":"{alias}"}}"#);
        format!(
            "POST /admin/enrol HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn join_request(join_tok: &str, pk: &str, ek: &str) -> Vec<u8> {
        let body = format!(r#"{{"x25519_pubkey":"{pk}","mlkem_ek":"{ek}","endpoint":null}}"#);
        format!(
            "POST /join HTTP/1.1\r\nhost: x\r\nx-join-token: {join_tok}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn healthz() {
        let (addr, _t) = spawn_test_server().await;
        let (status, body) = raw(addr, b"GET /healthz HTTP/1.1\r\nhost: x\r\n\r\n").await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
    }

    #[tokio::test]
    async fn admin_enrol_rejects_missing_bearer() {
        let (addr, _t) = spawn_test_server().await;
        let req = b"POST /admin/enrol HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 17\r\n\r\n{\"alias\":\"alpha\"}";
        let (status, _) = raw(addr, req).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn admin_enrol_rejects_bad_token() {
        let (addr, _t) = spawn_test_server().await;
        let (status, _) = raw(addr, &enrol_req("alpha", "wrong-token-12345")).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn admin_enrol_invalid_alias() {
        let (addr, _t) = spawn_test_server().await;
        let req = enrol_req("has space", "test-token-1234567890");
        let (status, _) = raw(addr, &req).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn end_to_end_enrol_join_peers() {
        let (addr, _t) = spawn_test_server().await;
        let pk_alpha = "a".repeat(64);
        let pk_beta = "b".repeat(64);
        let ek_alpha = "aa".repeat(32);
        let ek_beta = "bb".repeat(32);

        // device 1 enrol
        let (st, body) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok1 = v["join_token"].as_str().unwrap().to_string();
        assert_eq!(v["overlay_v4"], "10.42.42.2");

        // device 1 join
        let (st, body) = raw(addr, &join_request(&tok1, &pk_alpha, &ek_alpha)).await;
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["alias"], "alpha");
        assert_eq!(v["peers"].as_array().unwrap().len(), 0);
        assert!(
            v["device_token"].as_str().is_some_and(|t| t.len() == 48),
            "device_token must be returned on successful join"
        );

        // device 2 enrol
        let (st, body) = raw(addr, &enrol_req("beta", "test-token-1234567890")).await;
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok2 = v["join_token"].as_str().unwrap().to_string();
        assert_eq!(v["overlay_v4"], "10.42.42.3");

        // device 2 join → should see device 1 in peers
        let (st, body) = raw(addr, &join_request(&tok2, &pk_beta, &ek_beta)).await;
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["alias"], "alpha");

        // device 1 polls /peers → sees device 2
        let req_str = format!(
            "GET /peers HTTP/1.1\r\nhost: x\r\nx-device-pubkey: {pk_alpha}\r\n\r\n"
        );
        let (st, body) = raw(addr, req_str.as_bytes()).await;
        assert_eq!(st, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let peers = v.as_array().unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0]["alias"], "beta");
    }

    #[tokio::test]
    async fn duplicate_alias_after_completed_join() {
        let (addr, _t) = spawn_test_server().await;
        let pk_1 = "c".repeat(64);
        let ek_1 = "dd".repeat(32);

        // first enrol + join
        let (_, body) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok = v["join_token"].as_str().unwrap().to_string();
        let _ = raw(addr, &join_request(&tok, &pk_1, &ek_1)).await;

        // re-enrol same alias must now collide
        let (st, _) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        assert_eq!(st, 409);
    }

    #[tokio::test]
    async fn unknown_path_404() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(addr, b"GET /nope HTTP/1.1\r\nhost: x\r\n\r\n").await;
        assert_eq!(st, 404);
    }

    #[tokio::test]
    async fn join_rejects_short_pubkey() {
        let (addr, _t) = spawn_test_server().await;
        // first enrol to get a valid join token
        let (_, body) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok = v["join_token"].as_str().unwrap().to_string();
        let (st, _) = raw(addr, &join_request(&tok, "shortpk", "abcd")).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn join_rejects_uppercase_hex_pubkey() {
        let (addr, _t) = spawn_test_server().await;
        let (_, body) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok = v["join_token"].as_str().unwrap().to_string();
        let bad_pk = "A".repeat(64);
        let (st, _) = raw(addr, &join_request(&tok, &bad_pk, "abcd")).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn concurrent_enrols_get_distinct_overlay_ips() {
        // Bug fix: previously two enrols before any join completed both saw an
        // empty devices snapshot and were each assigned 10.42.42.2 (live
        // pending tokens were ignored by the allocator).
        let (addr, _t) = spawn_test_server().await;
        let (_, b1) = raw(addr, &enrol_req("t01", "test-token-1234567890")).await;
        let v1: serde_json::Value = serde_json::from_str(&b1).unwrap();
        let (_, b2) = raw(addr, &enrol_req("t02", "test-token-1234567890")).await;
        let v2: serde_json::Value = serde_json::from_str(&b2).unwrap();
        assert_ne!(
            v1["overlay_v4"], v2["overlay_v4"],
            "two consecutive enrols must get distinct overlay IPs"
        );
        assert_eq!(v1["overlay_v4"], "10.42.42.2");
        assert_eq!(v2["overlay_v4"], "10.42.42.3");
    }

    #[tokio::test]
    async fn pending_alias_collides_on_repeat_enrol() {
        // Same alias enrolled twice before any join should 409 — the first
        // enrol's pending token already holds the alias.
        let (addr, _t) = spawn_test_server().await;
        let (st1, _) = raw(addr, &enrol_req("dup", "test-token-1234567890")).await;
        assert_eq!(st1, 200);
        let (st2, _) = raw(addr, &enrol_req("dup", "test-token-1234567890")).await;
        assert_eq!(st2, 409);
    }

    fn endpoint_report_request(device_token: &str, endpoint: &str) -> Vec<u8> {
        let body = format!(r#"{{"endpoint":"{endpoint}"}}"#);
        format!(
            "POST /endpoint-report HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {device_token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    async fn enrol_and_join(addr: std::net::SocketAddr, alias: &str, pk: &str, ek: &str) -> String {
        let (_, body) = raw(addr, &enrol_req(alias, "test-token-1234567890")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let join_tok = v["join_token"].as_str().unwrap().to_string();
        let (_, body) = raw(addr, &join_request(&join_tok, pk, ek)).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        v["device_token"].as_str().unwrap().to_string()
    }

    fn delete_device_req(alias: &str, admin_token: &str) -> Vec<u8> {
        format!(
            "DELETE /admin/devices/{alias} HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {admin_token}\r\n\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn admin_delete_device_happy_path() {
        let (addr, _t) = spawn_test_server().await;
        let pk = "a".repeat(64);
        let _ = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;

        // alias is present in /peers (from a second device's perspective)
        let pk_other = "b".repeat(64);
        let _ = enrol_and_join(addr, "beta", &pk_other, &"bb".repeat(32)).await;
        let probe = format!("GET /peers HTTP/1.1\r\nhost: x\r\nx-device-pubkey: {pk_other}\r\n\r\n");
        let (_, body) = raw(addr, probe.as_bytes()).await;
        assert!(body.contains("alpha"), "alpha should be visible before delete");

        // delete
        let (st, body) = raw(addr, &delete_device_req("alpha", "test-token-1234567890")).await;
        assert_eq!(st, 200, "{body}");

        // gone from /peers
        let (_, body) = raw(addr, probe.as_bytes()).await;
        assert!(!body.contains("alpha"), "alpha should be gone after delete");

        // alias slot is now free — re-enrol succeeds (would 409 if still held)
        let (st, _) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        assert_eq!(st, 200);
    }

    #[tokio::test]
    async fn admin_delete_device_unknown_alias_404() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(addr, &delete_device_req("nobody", "test-token-1234567890")).await;
        assert_eq!(st, 404);
    }

    #[tokio::test]
    async fn admin_delete_device_rejects_bad_token() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(addr, &delete_device_req("anyalias", "wrong-token-12345")).await;
        assert_eq!(st, 401);
    }

    #[tokio::test]
    async fn admin_delete_device_evicts_pending_alias() {
        // Even if no completed device row exists, an unfinished /admin/enrol
        // holds the alias slot. DELETE should evict the pending token so the
        // alias can be re-issued without waiting for the 10-min TTL.
        let (addr, _t) = spawn_test_server().await;
        let (_, _) = raw(addr, &enrol_req("ghost", "test-token-1234567890")).await;
        // re-enrol immediately → conflict
        let (st, _) = raw(addr, &enrol_req("ghost", "test-token-1234567890")).await;
        assert_eq!(st, 409);
        // delete (returns 404 since no completed row, but should still evict pending)
        let _ = raw(addr, &delete_device_req("ghost", "test-token-1234567890")).await;
        // now re-enrol works
        let (st, _) = raw(addr, &enrol_req("ghost", "test-token-1234567890")).await;
        assert_eq!(st, 200);
    }

    fn patch_device_req(alias: &str, admin_token: &str, body: &str) -> Vec<u8> {
        format!(
            "PATCH /admin/devices/{alias} HTTP/1.1\r\nhost: x\r\nauthorization: Bearer {admin_token}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn admin_patch_relay_eligible_visible_in_peers() {
        let (addr, _t) = spawn_test_server().await;
        let pk = "a".repeat(64);
        let _ = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;

        // initially relay_eligible is false in /peers (from a 2nd device's view)
        let pk_other = "b".repeat(64);
        let _ = enrol_and_join(addr, "beta", &pk_other, &"bb".repeat(32)).await;
        let probe = format!("GET /peers HTTP/1.1\r\nhost: x\r\nx-device-pubkey: {pk_other}\r\n\r\n");
        let (_, body) = raw(addr, probe.as_bytes()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let alpha = v.as_array().unwrap().iter().find(|p| p["alias"] == "alpha").unwrap();
        assert_eq!(alpha["relay_eligible"], false);

        // PATCH alpha → relay_eligible: true
        let (st, _) = raw(
            addr,
            &patch_device_req("alpha", "test-token-1234567890", r#"{"relay_eligible":true}"#),
        )
        .await;
        assert_eq!(st, 200);

        // /peers now shows it true
        let (_, body) = raw(addr, probe.as_bytes()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let alpha = v.as_array().unwrap().iter().find(|p| p["alias"] == "alpha").unwrap();
        assert_eq!(alpha["relay_eligible"], true);
    }

    #[tokio::test]
    async fn admin_patch_unknown_device_404() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(
            addr,
            &patch_device_req("nobody", "test-token-1234567890", r#"{"relay_eligible":true}"#),
        )
        .await;
        assert_eq!(st, 404);
    }

    #[tokio::test]
    async fn admin_patch_rejects_bad_token() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) =
            raw(addr, &patch_device_req("alpha", "wrong", r#"{"relay_eligible":true}"#)).await;
        assert_eq!(st, 401);
    }

    #[tokio::test]
    async fn admin_patch_no_field_is_noop() {
        let (addr, _t) = spawn_test_server().await;
        let pk = "a".repeat(64);
        let _ = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;
        // empty body {} is valid (all fields optional); should not change state
        let (st, _) = raw(addr, &patch_device_req("alpha", "test-token-1234567890", "{}")).await;
        assert_eq!(st, 200);
    }

    #[tokio::test]
    async fn admin_delete_device_rejects_invalid_alias() {
        // `!` is rejected by valid_alias (alphanumeric + `-_` only).
        // Space cannot be used here — httparse rejects spaces in the request-uri
        // and the server drops the connection without a response.
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(addr, &delete_device_req("bad!alias", "test-token-1234567890")).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn endpoint_report_happy_path() {
        let (addr, _t) = spawn_test_server().await;
        let pk = "a".repeat(64);
        let device_token = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;

        let (st, _) =
            raw(addr, &endpoint_report_request(&device_token, "203.0.113.7:65432")).await;
        assert_eq!(st, 200);

        // peer list should now include the reported endpoint
        let pk_other = "b".repeat(64);
        let _other_dt = enrol_and_join(addr, "beta", &pk_other, &"bb".repeat(32)).await;
        let req = format!("GET /peers HTTP/1.1\r\nhost: x\r\nx-device-pubkey: {pk_other}\r\n\r\n");
        let (st, body) = raw(addr, req.as_bytes()).await;
        assert_eq!(st, 200);
        let peers: serde_json::Value = serde_json::from_str(&body).unwrap();
        let alpha = peers
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["alias"] == "alpha")
            .unwrap();
        assert_eq!(alpha["endpoint"], "203.0.113.7:65432");
    }

    #[tokio::test]
    async fn endpoint_report_rejects_unknown_token() {
        let (addr, _t) = spawn_test_server().await;
        let (st, _) = raw(
            addr,
            &endpoint_report_request("ffeeddccbbaa99887766554433221100ffeeddccbbaa9988", "1.2.3.4:5000"),
        )
        .await;
        assert_eq!(st, 401);
    }

    #[tokio::test]
    async fn endpoint_report_rejects_bad_endpoint_format() {
        let (addr, _t) = spawn_test_server().await;
        let pk = "a".repeat(64);
        let device_token = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;
        let (st, _) = raw(addr, &endpoint_report_request(&device_token, "not-an-address")).await;
        assert_eq!(st, 400);
    }

    #[tokio::test]
    async fn endpoint_report_rejects_empty_token_match() {
        // pre-v0.3 devices with `device_token == ""` must not match a bearer
        // header that happens to also be empty (the constant-time compare
        // would otherwise succeed against any unjoined-legacy row).
        let (addr, _t) = spawn_test_server().await;
        // join a device, then deliberately blank its token via the store —
        // simulates a legacy on-disk row loaded with #[serde(default)].
        let pk = "a".repeat(64);
        let _ = enrol_and_join(addr, "alpha", &pk, &"aa".repeat(32)).await;
        // can't easily reach into store from here without extra wiring, but
        // we can test the auth path: bearer with empty string must be rejected
        // by HTTP parsing (no value after `Bearer `).
        let body = r#"{"endpoint":"1.2.3.4:5000"}"#;
        let req = format!(
            "POST /endpoint-report HTTP/1.1\r\nhost: x\r\nauthorization: Bearer \r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        let (st, _) = raw(addr, req.as_bytes()).await;
        assert_eq!(st, 401);
    }

    #[tokio::test]
    async fn join_validation_does_not_burn_join_token() {
        // bad-pubkey rejection must NOT consume the join token — otherwise an
        // accidental retry after a typo would force a fresh admin enrol.
        let (addr, _t) = spawn_test_server().await;
        let (_, body) = raw(addr, &enrol_req("alpha", "test-token-1234567890")).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let tok = v["join_token"].as_str().unwrap().to_string();
        // first attempt with garbage pubkey
        let (st, _) = raw(addr, &join_request(&tok, "garbage", "abcd")).await;
        assert_eq!(st, 400);
        // second attempt with a well-formed pubkey using the SAME token
        let good_pk = "a".repeat(64);
        let (st, _) = raw(addr, &join_request(&tok, &good_pk, "abcd")).await;
        assert_eq!(st, 200, "join token should still be valid after validation rejection");
    }
}
