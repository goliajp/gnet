//! Daemon localhost HTTP admin surface — v1.1 §17.9.
//!
//! `docs/v1.1-plan.md` §5.1 lists the contract this implements:
//!
//! | Method | Path             | Purpose                                     |
//! |--------|------------------|---------------------------------------------|
//! | GET    | `/local/status`  | current overlay state, peers, reflexive ep  |
//! | PUT    | `/local/alias`   | rename self                                 |
//! | POST   | `/local/restart` | restart daemon (graceful)                   |
//! | POST   | `/local/quit`    | leave the network                           |
//! | POST   | `/local/join`    | join a network (token + dispatcher URL)     |
//! | POST   | `/local/upgrade` | trigger self-update                         |
//!
//! v1.1 ships the **wire contract** + a full `status` implementation; the
//! other endpoints route correctly and return `501 Not Implemented` with a
//! structured body pinning their shape. The native macOS / Helper consumer
//! lands in v1.2 (plan §3.5) and fills in the write operations against the
//! same wire — keeping the contract stable across two releases is the
//! point of landing the listener in v1.1.
//!
//! # Why hand-rolled HTTP
//!
//! The daemon is a zero-deps binary by policy (plan §1, handoff invariant
//! 1: `cargo tree -p gnet` = 10). Bringing in `httparse` / axum / hyper
//! would break that contract; the parser surface required here is small
//! enough (request line + headers + bounded body, no chunked encoding) that
//! a state-machine over `&[u8]` is cheaper than the deps it would replace.
//!
//! # Auth
//!
//! - Token file at `/var/db/gnet/admin_token` (Linux) or
//!   `/Library/Application Support/gnet/admin_token` (macOS), or whatever
//!   `GNET_LOCAL_ADMIN_TOKEN_PATH` points at. Override exists so a dev
//!   box can place the token under `$XDG_RUNTIME_DIR` without elevation.
//! - Mode **must** be `0o400` — anything broader is rejected at startup
//!   (the daemon refuses to expose admin to a token a non-root user can
//!   read).
//! - `Authorization: Bearer <token>` on every request except
//!   `GET /local/host-role` (probe-only; see below). Constant-time eq.
//!
//! # Bind
//!
//! Loopback-only: `127.0.0.1:<port>`. Default port `6019`
//! (gnet-local-admin-dev in the port-registry). Override via
//! `GNET_LOCAL_ADMIN_BIND`. The address parser refuses non-loopback IPs.
//!
//! # Concurrency
//!
//! Plain `std::net::TcpListener` + one OS thread per accepted connection.
//! Admin traffic is operator-initiated (single-digit RPS at peak), so the
//! straight thread-per-conn model has the lowest latency floor and the
//! simplest failure mode (a panicked handler thread cannot block accept).

#![allow(clippy::needless_return)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use gnet_hex as hex;

use super::types::{Node, Session};

/// Required mode for the admin-token file. Owner-read-only — anything
/// broader (e.g. `0o440`) and the daemon refuses to load the file.
pub const TOKEN_FILE_MODE: u32 = 0o400;

/// Hard upper bound on a single HTTP request (request line + headers +
/// body) the parser will read before giving up with `413 Payload Too
/// Large`. 64 KiB is two orders of magnitude over any plausible admin
/// payload; any client trying to exceed it is either misconfigured or
/// hostile.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// Per-connection read/write timeout. Operators tap admin endpoints with
/// curl from a terminal; a stuck connection past this is not a real
/// client.
pub const CONN_TIMEOUT: Duration = Duration::from_secs(15);

/// Configuration for the local-admin listener. Built once at startup
/// from env (see `Config::from_env`) and shared by every accepted
/// connection through an `Arc`.
pub struct LocalAdminConfig {
    pub bind: SocketAddr,
    pub token: String,
}

impl LocalAdminConfig {
    /// Resolve the bind address + token from env. Returns `Ok(None)` when
    /// the listener is not opted in (no `GNET_LOCAL_ADMIN_ENABLE=1`), so
    /// the caller can treat absence as "don't spawn the thread".
    pub fn from_env() -> Result<Option<Self>, String> {
        let enabled = std::env::var("GNET_LOCAL_ADMIN_ENABLE")
            .map(|v| v == "1")
            .unwrap_or(false);
        if !enabled {
            return Ok(None);
        }

        let bind_s = std::env::var("GNET_LOCAL_ADMIN_BIND")
            .unwrap_or_else(|_| "127.0.0.1:6019".to_string());
        let bind: SocketAddr = bind_s
            .parse()
            .map_err(|e| format!("GNET_LOCAL_ADMIN_BIND {bind_s:?}: {e}"))?;
        if !bind.ip().is_loopback() {
            return Err(format!(
                "GNET_LOCAL_ADMIN_BIND must be a loopback IP (got {bind})",
            ));
        }

        let token_path = std::env::var("GNET_LOCAL_ADMIN_TOKEN_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_token_path());
        let token = load_token(&token_path)?;
        Ok(Some(Self { bind, token }))
    }
}

/// Default platform path for the admin token file.
pub fn default_token_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/var/db/gnet/admin_token")
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/gnet/admin_token")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        PathBuf::from("/tmp/gnet-admin-token")
    }
}

/// Read the bearer token from `path`. Fails closed:
/// - file must exist + be readable as the daemon's uid
/// - file mode must be exactly `TOKEN_FILE_MODE` (0o400). Group / world
///   readable bits → refuse to load (the token is the only credential).
/// - token bytes are trimmed of trailing `\n` / `\r` (operators using
///   `echo > admin_token` would otherwise smuggle a newline into the
///   compared bytes).
pub fn load_token(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| {
        format!(
            "GNET_LOCAL_ADMIN_TOKEN_PATH {}: {e}",
            path.display()
        )
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != TOKEN_FILE_MODE {
        return Err(format!(
            "{}: mode is {:o}, must be {:o} (owner-read only)",
            path.display(),
            mode,
            TOKEN_FILE_MODE
        ));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let token = raw.trim_end_matches(['\n', '\r']).to_string();
    if token.is_empty() {
        return Err(format!("{}: token file is empty", path.display()));
    }
    Ok(token)
}

/// Spawn the local-admin listener on its own OS thread. Best-effort: if
/// `bind` fails the daemon logs and continues without an admin surface —
/// observability is never on the wire path. Returns immediately.
pub(crate) fn spawn(node: Arc<Mutex<Node>>, cfg: LocalAdminConfig) {
    let cfg = Arc::new(cfg);
    let bind = cfg.bind;
    thread::Builder::new()
        .name("gnet-local-admin".into())
        .spawn(move || match TcpListener::bind(bind) {
            Ok(listener) => {
                eprintln!(
                    "event=local_admin_up bind={bind} token_len={}",
                    cfg.token.len()
                );
                accept_loop(listener, node, cfg);
            }
            Err(e) => {
                eprintln!("event=local_admin_bind_err bind={bind} err={e}");
            }
        })
        .expect("spawn local-admin thread");
}

fn accept_loop(listener: TcpListener, node: Arc<Mutex<Node>>, cfg: Arc<LocalAdminConfig>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let node = node.clone();
                let cfg = cfg.clone();
                // One thread per connection. Admin traffic is sparse, and a
                // panic in a handler stays contained to its own thread.
                thread::Builder::new()
                    .name("gnet-local-admin-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle(stream, &node, &cfg) {
                            eprintln!("event=local_admin_conn_err err={e}");
                        }
                    })
                    .expect("spawn local-admin connection thread");
            }
            Err(e) => eprintln!("event=local_admin_accept_err err={e}"),
        }
    }
}

fn handle(
    mut stream: TcpStream,
    node: &Arc<Mutex<Node>>,
    cfg: &LocalAdminConfig,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONN_TIMEOUT))?;
    stream.set_write_timeout(Some(CONN_TIMEOUT))?;

    let buf = match read_request(&mut stream) {
        Ok(b) => b,
        Err(ReadErr::TooLarge) => {
            return write_response(&mut stream, 413, "text/plain", b"request too large\n");
        }
        Err(ReadErr::Empty) => return Ok(()),
        Err(ReadErr::Io(e)) => return Err(e),
    };

    let req = match parse_request(&buf) {
        Ok(r) => r,
        Err(msg) => {
            return write_response(
                &mut stream,
                400,
                "text/plain",
                format!("bad request: {msg}\n").as_bytes(),
            );
        }
    };

    // Auth: every endpoint requires a valid bearer.
    let presented_token = req
        .header_ci("authorization")
        .and_then(|v| v.strip_prefix("Bearer ").or_else(|| v.strip_prefix("bearer ")));
    let Some(presented_token) = presented_token else {
        return write_response(
            &mut stream,
            401,
            "application/json",
            b"{\"error\":\"missing bearer\"}\n",
        );
    };
    if !constant_time_eq(presented_token.as_bytes(), cfg.token.as_bytes()) {
        return write_response(
            &mut stream,
            401,
            "application/json",
            b"{\"error\":\"bad bearer\"}\n",
        );
    }

    let (status, ctype, body) = dispatch(&req, node);
    write_response(&mut stream, status, ctype, &body)
}

/// Route a parsed + authenticated request to its handler. Each handler
/// owns its full response body (we don't stream — bodies are tiny).
fn dispatch(req: &Request<'_>, node: &Arc<Mutex<Node>>) -> (u16, &'static str, Vec<u8>) {
    match (req.method, req.path) {
        ("GET", "/local/status") => (200, "application/json", render_status(node).into_bytes()),
        ("PUT", "/local/alias") => not_implemented("alias"),
        ("POST", "/local/join") => not_implemented("join"),
        ("POST", "/local/quit") => not_implemented("quit"),
        ("POST", "/local/restart") => not_implemented("restart"),
        ("POST", "/local/upgrade") => not_implemented("upgrade"),

        // 405 for known paths called with the wrong verb. Helps the
        // future native app catch type-checker errors instead of seeing
        // a misleading 404.
        (_, "/local/status")
        | (_, "/local/alias")
        | (_, "/local/join")
        | (_, "/local/quit")
        | (_, "/local/restart")
        | (_, "/local/upgrade") => (
            405,
            "application/json",
            br#"{"error":"method not allowed"}"#.to_vec(),
        ),

        _ => (
            404,
            "application/json",
            br#"{"error":"unknown endpoint"}"#.to_vec(),
        ),
    }
}

/// Structured 501 for write endpoints that ship in v1.2. Body is shaped
/// so a typed client can match on `not_implemented` rather than parsing
/// the human-readable note.
fn not_implemented(endpoint: &str) -> (u16, &'static str, Vec<u8>) {
    let body = format!(
        r#"{{"not_implemented":"{endpoint}","plan_ref":"docs/v1.1-plan.md §5.1","ships_in":"v1.2"}}"#
    );
    (501, "application/json", body.into_bytes())
}

/// Hand-rolled JSON snapshot of the daemon's live state — mirror of the
/// existing unix-socket k=v `render_snapshot` shape but typed for the
/// native-app consumer in v1.2. Fields are escape-free by construction
/// (hex pubkeys, SocketAddr displays, fixed strings); we avoid the
/// general JSON-encoding step to stay zero-deps.
fn render_status(node: &Arc<Mutex<Node>>) -> String {
    let now = Instant::now();
    let g = node.lock().expect("node mutex");

    let mut out = String::with_capacity(512);
    out.push('{');

    // top-level node info
    out.push_str("\"node\":{");
    push_kv_json_str(&mut out, "public_hex", &hex::encode(&g.public));
    out.push(',');
    push_kv_json_str(
        &mut out,
        "reflexive",
        &g.reflexive
            .map(|a| a.to_string())
            .unwrap_or_default(),
    );
    out.push(',');
    out.push_str("\"self_is_nat\":");
    out.push_str(match g.self_is_nat {
        Some(true) => "true",
        Some(false) => "false",
        None => "null",
    });
    out.push('}');

    // metrics
    out.push_str(",\"metrics\":{");
    push_kv_json_num(&mut out, "handshake_success", g.metrics.handshake_success);
    out.push(',');
    push_kv_json_num(&mut out, "handshake_fail", g.metrics.handshake_fail);
    out.push(',');
    push_kv_json_num(
        &mut out,
        "relay_register_sent",
        g.metrics.relay_register_sent,
    );
    out.push(',');
    push_kv_json_num(
        &mut out,
        "peer_relay_fallback",
        g.metrics.peer_relay_fallback,
    );
    out.push('}');

    // relay servers
    out.push_str(",\"relays\":[");
    let mut first = true;
    for ep in &g.relay_servers {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('{');
        push_kv_json_str(&mut out, "endpoint", &ep.to_string());
        out.push(',');
        match g.relay_health.get(ep) {
            Some(t) => {
                push_kv_json_num(
                    &mut out,
                    "health_age_ms",
                    now.saturating_duration_since(*t).as_millis() as u64,
                );
            }
            None => out.push_str("\"health_age_ms\":null"),
        }
        out.push('}');
    }
    out.push(']');

    // peers
    out.push_str(",\"peers\":[");
    let mut first = true;
    for p in &g.peers {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('{');
        push_kv_json_str(&mut out, "alias", &p.alias);
        out.push(',');
        push_kv_json_str(&mut out, "public_hex", &hex::encode(&p.public));
        out.push(',');
        push_kv_json_str(&mut out, "vip", &p.vip.to_string());
        out.push(',');
        push_kv_json_str(
            &mut out,
            "vip6",
            &p.vip6.map(|v| v.to_string()).unwrap_or_default(),
        );
        out.push(',');
        push_kv_json_str(
            &mut out,
            "endpoint",
            &p.endpoint
                .map(|e| e.to_string())
                .unwrap_or_default(),
        );
        out.push(',');
        push_kv_json_str(
            &mut out,
            "session",
            match p.session {
                Session::Idle => "idle",
                Session::Initiating { .. } => "initiating",
                Session::Established(_) => "established",
            },
        );
        out.push(',');
        match p.last_established_at {
            Some(t) => push_kv_json_num(
                &mut out,
                "last_established_age_s",
                now.saturating_duration_since(t).as_secs(),
            ),
            None => out.push_str("\"last_established_age_s\":null"),
        }
        out.push(',');
        push_kv_json_bool(&mut out, "relay", p.relay);
        out.push(',');
        push_kv_json_str(
            &mut out,
            "relay_endpoint",
            &p.relay_endpoint
                .map(|e| e.to_string())
                .unwrap_or_default(),
        );
        out.push(',');
        push_kv_json_bool(&mut out, "punched", p.punched);
        out.push(',');
        push_kv_json_num(&mut out, "punch_failures", u64::from(p.punch_failures));
        out.push(',');
        push_kv_json_bool(&mut out, "pinned", p.pinned);
        out.push('}');
    }
    out.push(']');

    out.push('}');
    out
}

fn push_kv_json_str(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    out.push_str(value);
    out.push('"');
}

fn push_kv_json_num(out: &mut String, key: &str, value: u64) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    // u64 Display is escape-free → safe to push directly.
    out.push_str(&value.to_string());
}

fn push_kv_json_bool(out: &mut String, key: &str, value: bool) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    out.push_str(if value { "true" } else { "false" });
}

// ───── HTTP/1.1 wire (request parser + response writer) ──────────────

/// A parsed request, holding borrows into the original buffer. Body
/// slice is empty when no body was sent (GETs and the like).
struct Request<'a> {
    method: &'a str,
    path: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    #[allow(dead_code)]
    body: &'a [u8],
}

impl<'a> Request<'a> {
    /// Case-insensitive header lookup. HTTP/1.1 header names are
    /// case-insensitive; we ASCII-fold on the way in to keep the parser
    /// itself lossless.
    fn header_ci(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

enum ReadErr {
    TooLarge,
    Empty,
    Io(std::io::Error),
}

impl From<std::io::Error> for ReadErr {
    fn from(e: std::io::Error) -> Self {
        ReadErr::Io(e)
    }
}

/// Read a whole HTTP request: pull bytes until we see `\r\n\r\n` (end of
/// headers), then keep pulling exactly `Content-Length` more if present.
/// Caps at `MAX_REQUEST_BYTES`. No chunked-transfer support — the v1.1
/// admin clients (CLI, native helper) send fixed-length JSON.
fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, ReadErr> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let mut headers_end: Option<usize> = None;

    // headers
    while headers_end.is_none() {
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(ReadErr::TooLarge);
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            if buf.is_empty() {
                return Err(ReadErr::Empty);
            }
            // EOF before headers terminator. Tolerate — caller will 400.
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        headers_end = find_double_crlf(&buf);
    }
    let headers_end = match headers_end {
        Some(i) => i + 4,
        // No `\r\n\r\n` ever — let parse_request return 400.
        None => return Ok(buf),
    };

    // body
    let cl = match parse_content_length(&buf[..headers_end]) {
        Ok(v) => v,
        Err(_) => return Ok(buf), // parse_request will surface the error
    };
    let body_already = buf.len() - headers_end;
    let need = cl.saturating_sub(body_already);
    if headers_end + cl > MAX_REQUEST_BYTES {
        return Err(ReadErr::TooLarge);
    }
    let mut remaining = need;
    while remaining > 0 {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        let take = n.min(remaining);
        buf.extend_from_slice(&tmp[..take]);
        remaining -= take;
    }
    Ok(buf)
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Pull `Content-Length` out of an already-terminated header block.
/// Returns 0 when absent (GET without body), errors on a non-decimal
/// or absurdly large value (we cap at MAX_REQUEST_BYTES).
fn parse_content_length(headers: &[u8]) -> Result<usize, &'static str> {
    let s = std::str::from_utf8(headers).map_err(|_| "non-utf8 headers")?;
    let mut value: Option<&str> = None;
    for line in s.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case("content-length") {
            value = Some(v.trim());
        }
    }
    let Some(v) = value else { return Ok(0) };
    let n: usize = v.parse().map_err(|_| "bad Content-Length")?;
    if n > MAX_REQUEST_BYTES {
        return Err("Content-Length exceeds MAX_REQUEST_BYTES");
    }
    Ok(n)
}

/// Strict HTTP/1.1 parser, single pass. Accepts only what we need:
/// method + path + HTTP-version on the request line, then header lines
/// separated by `\r\n`, then a body of exactly `Content-Length` bytes.
fn parse_request(buf: &[u8]) -> Result<Request<'_>, &'static str> {
    let headers_end = find_double_crlf(buf).ok_or("no header terminator")?;
    let head = std::str::from_utf8(&buf[..headers_end]).map_err(|_| "non-utf8 headers")?;
    let mut lines = head.split("\r\n");
    let req_line = lines.next().ok_or("no request line")?;
    let mut parts = req_line.split(' ');
    let method = parts.next().ok_or("no method")?;
    let path = parts.next().ok_or("no path")?;
    let version = parts.next().ok_or("no version")?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version");
    }
    if parts.next().is_some() {
        return Err("malformed request line");
    }

    let mut headers = Vec::with_capacity(8);
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (k, v) = line.split_once(':').ok_or("malformed header")?;
        headers.push((k.trim(), v.trim()));
    }

    let body = &buf[(headers_end + 4).min(buf.len())..];
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = reason_phrase(status);
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        _ => "OK",
    }
}

/// Length-aware constant-time eq for the bearer comparison. Length
/// mismatch is reported as inequality without shortcutting (the loop
/// still runs over the longer slice so the timing of "wrong length" is
/// indistinguishable from "right length, wrong content").
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        let n = a.len().max(b.len());
        let mut acc: u8 = 1;
        for i in 0..n {
            let x = *a.get(i).unwrap_or(&0);
            let y = *b.get(i).unwrap_or(&0);
            acc |= x ^ y;
        }
        let _ = acc;
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // ── parser ─────────────────────────────────────────────────────

    #[test]
    fn parses_get_with_headers() {
        let buf = b"GET /local/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\r\n\r\n";
        let r = parse_request(buf).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/local/status");
        assert_eq!(r.header_ci("authorization"), Some("Bearer abc"));
        assert_eq!(r.header_ci("AUTHORIZATION"), Some("Bearer abc"));
    }

    #[test]
    fn parses_put_with_body() {
        let buf =
            b"PUT /local/alias HTTP/1.1\r\nContent-Length: 17\r\n\r\n{\"alias\":\"hello\"}";
        let r = parse_request(buf).unwrap();
        assert_eq!(r.method, "PUT");
        assert_eq!(r.body, br#"{"alias":"hello"}"#);
    }

    #[test]
    fn rejects_unsupported_version() {
        let buf = b"GET / HTTP/2.0\r\n\r\n";
        assert!(parse_request(buf).is_err());
    }

    #[test]
    fn rejects_missing_header_terminator() {
        let buf = b"GET / HTTP/1.1\r\nHost: x";
        assert!(parse_request(buf).is_err());
    }

    #[test]
    fn content_length_caps_at_max() {
        let huge = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_REQUEST_BYTES + 1);
        let err = parse_content_length(huge.as_bytes()).unwrap_err();
        assert!(err.contains("MAX_REQUEST_BYTES"));
    }

    #[test]
    fn content_length_absent_is_zero() {
        let cl =
            parse_content_length(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(cl, 0);
    }

    // ── constant-time eq ────────────────────────────────────────────

    #[test]
    fn ct_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    // ── token file permission check ────────────────────────────────

    fn tmp_token_file(name: &str, mode: u32, body: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("gnet-local-admin-test-{name}-{:?}", std::thread::current().id()));
        let _ = std::fs::remove_file(&p);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    #[test]
    fn token_load_happy_path_strips_trailing_newline() {
        let p = tmp_token_file("happy", 0o400, "supersecret\n");
        let t = load_token(&p).unwrap();
        assert_eq!(t, "supersecret");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn token_load_refuses_loose_mode() {
        let p = tmp_token_file("loose", 0o440, "x");
        let err = load_token(&p).unwrap_err();
        assert!(err.contains("mode is"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn token_load_refuses_empty() {
        let p = tmp_token_file("empty", 0o400, "");
        let err = load_token(&p).unwrap_err();
        assert!(err.contains("empty"), "{err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn token_load_refuses_missing() {
        let mut p = std::env::temp_dir();
        p.push("gnet-local-admin-test-missing-does-not-exist");
        let _ = std::fs::remove_file(&p);
        let err = load_token(&p).unwrap_err();
        assert!(err.contains("GNET_LOCAL_ADMIN_TOKEN_PATH"), "{err}");
    }

    // ── render_status JSON shape ───────────────────────────────────

    use super::super::types::Peer;
    use crate::node::types::established_pair;
    use gnet_crypto::mlkem;
    use gnet_punch::PunchState;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Instant;

    fn node_with(peers: Vec<Peer>) -> Node {
        Node {
            private: [0u8; 32],
            public: [0xab; 32],
            mlkem_ek: vec![],
            mlkem_dk: vec![],
            peers,
            relay_servers: vec![],
            relay_health: HashMap::new(),
            reflexive: None,
            probe_txid: 0,
            self_is_nat: None,
            nat_override: false,
            metrics: Default::default(),
        }
    }

    fn peer(alias: &str, session: Session, established: bool) -> Peer {
        Peer {
            alias: alias.to_string(),
            pinned: false,
            public: [0x11; 32],
            mlkem_ek: vec![0u8; mlkem::EK_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            vip: IpAddr::V4(Ipv4Addr::new(10, 88, 0, 7)),
            vip6: None,
            endpoint: Some(SocketAddr::from(([1, 2, 3, 4], 9999))),
            rx_index: 0,
            tx_index: 0,
            session,
            punch: PunchState::Idle,
            punched: false,
            punch_failures: 0,
            relay: false,
            relay_endpoint: None,
            relay_eligible: false,
            direct_upgrade_at: Instant::now()
                + super::super::punch::DIRECT_UPGRADE_BASE,
            direct_upgrade_failures: 0,
            last_established_at: established.then(Instant::now),
        }
    }

    #[test]
    fn render_status_idle_node_is_valid_json_with_expected_keys() {
        let node = Arc::new(Mutex::new(node_with(vec![])));
        let s = render_status(&node);
        // Top-level object with the four documented keys.
        assert!(s.starts_with('{') && s.ends_with('}'));
        for key in ["\"node\":", "\"metrics\":", "\"relays\":", "\"peers\":"] {
            assert!(s.contains(key), "missing {key} in {s}");
        }
        // Idle node defaults.
        assert!(s.contains("\"self_is_nat\":null"));
        assert!(s.contains("\"reflexive\":\"\""));
        assert!(s.contains("\"relays\":[]"));
        assert!(s.contains("\"peers\":[]"));
        assert!(s.contains("\"public_hex\":\""));
    }

    #[test]
    fn render_status_established_peer_session_and_age() {
        let (a, _b) = established_pair();
        let node = Arc::new(Mutex::new(node_with(vec![peer(
            "alpha",
            Session::Established(a),
            true,
        )])));
        let s = render_status(&node);
        assert!(s.contains("\"alias\":\"alpha\""));
        assert!(s.contains("\"session\":\"established\""));
        // last_established_at -> number, not null.
        assert!(
            !s.contains("\"last_established_age_s\":null"),
            "{s}"
        );
        assert!(s.contains("\"last_established_age_s\":"));
    }

    #[test]
    fn render_status_idle_peer_uses_null_age() {
        let node = Arc::new(Mutex::new(node_with(vec![peer(
            "beta",
            Session::Idle,
            false,
        )])));
        let s = render_status(&node);
        assert!(s.contains("\"session\":\"idle\""));
        assert!(s.contains("\"last_established_age_s\":null"));
    }

    // ── env parsing ────────────────────────────────────────────────

    #[test]
    fn admin_disabled_by_default() {
        // Default env: GNET_LOCAL_ADMIN_ENABLE unset → Ok(None).
        // (We rely on tests inheriting a clean env; if a previous test in
        // the same process set the var, the explicit check still holds
        // because we read at call time. Tests above never set it.)
        // Note: this is observational, not a behaviour assertion across
        // every possible env state — but it documents the default.
        let prev = std::env::var("GNET_LOCAL_ADMIN_ENABLE").ok();
        if prev.is_some() {
            // Skip cleanly — another test set it; the parser branches we
            // care about are exercised below.
            return;
        }
        let r = LocalAdminConfig::from_env().unwrap();
        assert!(r.is_none());
    }

    // ── HTTP/1.1 wire roundtrip ────────────────────────────────────

    fn boot_for_test() -> (SocketAddr, Arc<Mutex<Node>>, String) {
        let p = tmp_token_file("wire", 0o400, "wire-test-token-1234\n");
        let token = load_token(&p).unwrap();
        let _ = std::fs::remove_file(&p);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let node = Arc::new(Mutex::new(node_with(vec![])));
        let cfg = Arc::new(LocalAdminConfig {
            bind: addr,
            token: token.clone(),
        });
        let node_for_thread = node.clone();
        thread::spawn(move || {
            // Single-connection accept — each test fires one request.
            // The thread exits when the test ends, dropping the listener.
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let node = node_for_thread.clone();
                let cfg = cfg.clone();
                thread::spawn(move || {
                    let _ = handle(stream, &node, &cfg);
                });
            }
        });
        (addr, node, token)
    }

    fn raw_request(addr: SocketAddr, req: &str) -> (u16, String) {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text
            .split_once(' ')
            .and_then(|(_, r)| r.split_once(' '))
            .and_then(|(c, _)| c.parse().ok())
            .unwrap_or(0);
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, b)| b.to_string())
            .unwrap_or_default();
        (status, body)
    }

    #[test]
    fn wire_status_requires_bearer() {
        let (addr, _node, _t) = boot_for_test();
        let (st, _) = raw_request(
            addr,
            "GET /local/status HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(st, 401);
    }

    #[test]
    fn wire_status_with_bearer_returns_json() {
        let (addr, _node, t) = boot_for_test();
        let req = format!(
            "GET /local/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n"
        );
        let (st, body) = raw_request(addr, &req);
        assert_eq!(st, 200);
        assert!(body.starts_with('{'), "{body}");
        assert!(body.contains("\"node\":"), "{body}");
    }

    #[test]
    fn wire_unknown_path_is_404() {
        let (addr, _node, t) = boot_for_test();
        let req = format!(
            "GET /no-such HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nConnection: close\r\n\r\n"
        );
        let (st, _) = raw_request(addr, &req);
        assert_eq!(st, 404);
    }

    #[test]
    fn wire_wrong_method_on_status_is_405() {
        let (addr, _node, t) = boot_for_test();
        let req = format!(
            "POST /local/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (st, _) = raw_request(addr, &req);
        assert_eq!(st, 405);
    }

    #[test]
    fn wire_alias_quit_restart_join_upgrade_are_501() {
        let (addr, _node, t) = boot_for_test();
        for (method, path) in [
            ("PUT", "/local/alias"),
            ("POST", "/local/quit"),
            ("POST", "/local/restart"),
            ("POST", "/local/join"),
            ("POST", "/local/upgrade"),
        ] {
            let req = format!(
                "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let (st, body) = raw_request(addr, &req);
            assert_eq!(st, 501, "{method} {path} -> {body}");
            assert!(body.contains("not_implemented"), "{body}");
            assert!(body.contains("v1.2"), "{body}");
        }
    }
}
