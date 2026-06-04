//! Relay admin HTTP surface (v1.1 §17.8 — lite).
//!
//! Opt-in: only starts when `GNET_RELAY_ADMIN_BIND` is set. The forwarder
//! itself (see `main.rs::run`) is untouched and keeps owning the UDP loop;
//! the admin server runs on a dedicated OS thread with its own current-
//! thread Tokio runtime, sharing the live `peers` table and `Stats` via
//! `Arc<RwLock>` / `Arc<AtomicU64>`.
//!
//! # Lite deviation from `docs/v1.1-plan.md` §5.3
//!
//! The plan lists `POST /api/auth/login` + `GET /api/audit` alongside the
//! read endpoints; both belong to a full relay account / audit DB the
//! v1.1 lite mode deliberately does not ship. We replace the login with a
//! single static **bearer token** (`GNET_RELAY_ADMIN_TOKEN`) so the read
//! endpoints stay protected without dragging a PG schema in, and we omit
//! the audit endpoint entirely (there's nothing persistent to audit on a
//! pure in-memory forwarder). A future deployment that wants a multi-user
//! relay admin can layer login + audit on top in §17.x or v1.2 without
//! changing the read endpoints' wire shape.
//!
//! # Endpoints
//!
//! | Method | Path             | Auth        |
//! |--------|------------------|-------------|
//! | GET    | `/api/host-role` | none (open) |
//! | GET    | `/api/peers`     | bearer      |
//! | GET    | `/api/traffic`   | bearer      |
//!
//! `/api/host-role` is left open to match the dispatcher / console
//! convention (the SPA shell hits it before any session exists to decide
//! which UI to mount). Everything else requires
//! `Authorization: Bearer <GNET_RELAY_ADMIN_TOKEN>`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::Router;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use crate::shared::{SharedPeers, Stats};

#[cfg(test)]
use crate::shared::{PeerEntry, PeerKey};
#[cfg(test)]
use std::sync::RwLock;

/// Minimum length for the static bearer token. 16 bytes ≈ 128 bits of
/// brute-force resistance — adequate for a single-credential admin surface
/// behind a reverse proxy or loopback bind.
pub const MIN_ADMIN_TOKEN_LEN: usize = 16;

#[derive(Clone)]
pub struct AdminState {
    pub peers: SharedPeers,
    pub stats: Arc<Stats>,
    pub started_at: Instant,
    /// Already-validated to be ≥ MIN_ADMIN_TOKEN_LEN at startup; we
    /// compare with constant-time `eq` per request.
    pub expected_token: Arc<String>,
}

/// Build the admin router. Exposed for tests so they can drive the routes
/// without a live TCP listener.
pub fn router(state: AdminState) -> Router {
    Router::new()
        .route("/api/host-role", get(host_role))
        .route("/api/peers", get(peers))
        .route("/api/traffic", get(traffic))
        .layer(middleware::from_fn_with_state(state.clone(), bearer_guard))
        // SPA fallback after the bearer layer so static assets are
        // open (the SPA shell needs to load before sign-in to render
        // the login form). The fallback never wraps under the bearer
        // guard since `Router::fallback` is matched outside the merge
        // chain; the API surface above stays protected.
        .merge(crate::spa::routes())
        .with_state(state)
}

/// Start the admin HTTP listener on `bind`. Blocks until the server exits.
/// Runs inside a current-thread Tokio runtime — the caller is expected to
/// spawn an OS thread for this so the forwarder's `recv_from` loop on the
/// main thread keeps owning its UDP socket untouched.
pub fn run_blocking(bind: SocketAddr, state: AdminState) -> std::io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!("gnet-relay-server: admin HTTP listening on {bind}");
        axum::serve(listener, router(state)).await
    })
}

async fn bearer_guard(
    State(state): State<AdminState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    // /api/host-role is the SPA's pre-auth probe — keep it open so a
    // console federation handshake can identify the binary before
    // supplying credentials.
    if req.uri().path() == "/api/host-role" {
        return Ok(next.run(req).await);
    }

    let Some(presented) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
    else {
        return Err((StatusCode::UNAUTHORIZED, "missing bearer\n").into_response());
    };

    if !constant_time_eq(presented.as_bytes(), state.expected_token.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, "bad bearer\n").into_response());
    }
    Ok(next.run(req).await)
}

/// `subtle`-style constant-time bytes comparison. Hand-rolled to avoid
/// dragging in a 1-purpose crate; OR-folded XOR over the longer slice so
/// length differences don't shortcut.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Touch both slices anyway so the rejection cost is independent
        // of which one is shorter.
        let n = a.len().max(b.len());
        let mut acc: u8 = 1;
        for i in 0..n {
            let x = *a.get(i).unwrap_or(&0);
            let y = *b.get(i).unwrap_or(&0);
            acc |= x ^ y;
        }
        let _ = acc; // squash a "value never read" lint without changing behaviour
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[derive(Serialize)]
struct HostRoleResponse {
    role: &'static str,
    version: &'static str,
}

async fn host_role() -> Json<HostRoleResponse> {
    Json(HostRoleResponse {
        role: "relay",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct PeersResponse {
    count: usize,
    peers: Vec<PeerView>,
}

#[derive(Serialize)]
struct PeerView {
    /// Hex of the X25519 pubkey identifying the peer (32 bytes → 64 chars).
    pubkey_hex: String,
    /// `ip:port` the relay last received a datagram from for this peer.
    endpoint: String,
    /// Seconds since that last datagram. With keepalives cadence ≈ 30s,
    /// healthy peers stay well under `--idle-secs` (default 300).
    last_seen_secs_ago: u64,
}

async fn peers(State(state): State<AdminState>) -> Result<Json<PeersResponse>, AdminError> {
    let now = Instant::now();
    let table = state.peers.read().map_err(|_| AdminError::Poisoned)?;
    let mut views: Vec<PeerView> = table
        .iter()
        .map(|(k, e)| PeerView {
            pubkey_hex: gnet_hex::encode(k),
            endpoint: e.endpoint.to_string(),
            last_seen_secs_ago: now.saturating_duration_since(e.last_seen).as_secs(),
        })
        .collect();
    // Deterministic order — handy for diff'ing snapshots in tests / scripts.
    views.sort_by(|a, b| a.pubkey_hex.cmp(&b.pubkey_hex));
    Ok(Json(PeersResponse {
        count: views.len(),
        peers: views,
    }))
}

#[derive(Serialize)]
struct TrafficResponse {
    /// Seconds since the relay started.
    uptime_secs: u64,
    /// Active peer count (matches `/api/peers.count`).
    peers: usize,
    /// Cumulative counters since boot. The minute-by-minute log line is
    /// derived from these (delta vs. previous tick); HTTP exposes the
    /// totals so a Prometheus-style scraper can compute its own deltas.
    forwarded: u64,
    bytes_in: u64,
    bytes_out: u64,
    unknown_dst: u64,
    non_relay: u64,
    self_addressed: u64,
}

async fn traffic(State(state): State<AdminState>) -> Result<Json<TrafficResponse>, AdminError> {
    let table = state.peers.read().map_err(|_| AdminError::Poisoned)?;
    let peers = table.len();
    drop(table);
    let s = state.stats.snapshot();
    let uptime_secs = Instant::now()
        .saturating_duration_since(state.started_at)
        .as_secs();
    Ok(Json(TrafficResponse {
        uptime_secs,
        peers,
        forwarded: s.forwarded,
        bytes_in: s.bytes_in,
        bytes_out: s.bytes_out,
        unknown_dst: s.unknown_dst,
        non_relay: s.non_relay,
        self_addressed: s.self_addressed,
    }))
}

#[derive(Debug)]
enum AdminError {
    Poisoned,
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        match self {
            AdminError::Poisoned => {
                (StatusCode::INTERNAL_SERVER_ERROR, "peer table poisoned\n").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;

    fn state_with(token: &str) -> AdminState {
        AdminState {
            peers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(Stats::default()),
            started_at: Instant::now(),
            expected_token: Arc::new(token.to_string()),
        }
    }

    fn key(b: u8) -> PeerKey {
        [b; 32]
    }

    /// Drive the routers by spinning the server on `127.0.0.1:0`, then
    /// using a Tokio TcpStream + raw HTTP/1.1 request line to verify the
    /// bearer middleware + JSON bodies end-to-end. Avoids dragging
    /// `tower` / hyper-client into dev-deps just to test 3 GET routes.
    async fn boot(state: AdminState) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(state);
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    async fn http_get(addr: SocketAddr, path: &str, bearer: Option<&str>) -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        let auth = bearer
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{auth}\r\n");
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = text
            .split_once(' ')
            .and_then(|(_, rest)| rest.split_once(' '))
            .and_then(|(code, _)| code.parse().ok())
            .unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        (status, body.to_string())
    }

    #[tokio::test]
    async fn host_role_is_open() {
        let addr = boot(state_with("dev-token-please-rotate")).await;
        let (status, body) = http_get(addr, "/api/host-role", None).await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["role"], "relay");
        assert!(v["version"].is_string());
    }

    #[tokio::test]
    async fn peers_without_bearer_is_401() {
        let addr = boot(state_with("dev-token-please-rotate")).await;
        let (status, _) = http_get(addr, "/api/peers", None).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn peers_with_wrong_bearer_is_401() {
        let addr = boot(state_with("dev-token-please-rotate")).await;
        let (status, _) = http_get(addr, "/api/peers", Some("not-the-right-token")).await;
        assert_eq!(status, 401);
    }

    #[tokio::test]
    async fn peers_with_good_bearer_lists_entries() {
        let st = state_with("dev-token-please-rotate");
        {
            let mut t = st.peers.write().unwrap();
            t.insert(
                key(0xAA),
                PeerEntry {
                    endpoint: "203.0.113.5:40000".parse().unwrap(),
                    last_seen: Instant::now(),
                },
            );
            t.insert(
                key(0xBB),
                PeerEntry {
                    endpoint: "198.51.100.7:50000".parse().unwrap(),
                    last_seen: Instant::now(),
                },
            );
        }
        let addr = boot(st).await;
        let (status, body) = http_get(addr, "/api/peers", Some("dev-token-please-rotate")).await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["count"], 2);
        let arr = v["peers"].as_array().unwrap();
        // Deterministic sort: 0xAA < 0xBB hex-wise.
        assert!(arr[0]["pubkey_hex"].as_str().unwrap().starts_with("aa"));
        assert!(arr[1]["pubkey_hex"].as_str().unwrap().starts_with("bb"));
    }

    #[tokio::test]
    async fn traffic_exposes_atomic_totals() {
        let st = state_with("dev-token-please-rotate");
        st.stats.forwarded.fetch_add(7, Ordering::Relaxed);
        st.stats.bytes_in.fetch_add(1500, Ordering::Relaxed);
        st.stats.bytes_out.fetch_add(1500, Ordering::Relaxed);
        let addr = boot(st).await;
        let (status, body) = http_get(addr, "/api/traffic", Some("dev-token-please-rotate")).await;
        assert_eq!(status, 200);
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["forwarded"], 7);
        assert_eq!(v["bytes_in"], 1500);
        assert_eq!(v["bytes_out"], 1500);
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
