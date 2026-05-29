//! `gnet status` — operator visibility into a node's conf, coordinator view,
//! and running daemon, without juggling `cat /etc/gnet/main.conf` +
//! `curl /peers` + `journalctl` by hand.
//!
//! Reads the local conf (default `/etc/gnet/main.conf` on Linux,
//! `/usr/local/etc/gnet/main.conf` on macOS, matching `gnet join`'s default
//! output path), derives our X25519 pubkey from the `private` directive,
//! queries `<coordinator>/peers` for the cluster view, and pretty-prints both
//! the self conf and the coordinator-side rows side by side. Falls back
//! gracefully when the coordinator is unreachable — local conf is still shown.
//!
//! Daemon liveness is reported from `pgrep`. Daemon-internal state (current
//! reflexive endpoint, per-peer session phase, last handshake) is *not* yet
//! exposed by the daemon over IPC, so the status output sticks to what the
//! conf and coordinator already publish. A future addition (v0.4.x) would
//! plumb a unix-socket query into the daemon so `gnet status` can show live
//! `Session::Established`/`Initiating` plus RTT.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use gnet::keys;
use gnet_hex as hex;

/// Entry point for the `gnet status` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;
    let text = std::fs::read_to_string(&opts.conf)
        .map_err(|e| io::Error::other(format!("read {}: {e}", opts.conf.display())))?;
    let config = gnet_config::parse(&text).map_err(io::Error::other)?;
    let self_alias = parse_alias_comment(&text);
    let pubkey = keys::public_key(&config.private);
    let pubkey_hex = hex::encode(&pubkey);

    print_self(&opts.conf, &config, self_alias.as_deref(), &pubkey_hex);
    print_blank();
    print_daemon();
    print_blank();
    print_coordinator(&config, &pubkey_hex);
    Ok(())
}

// ── output sections ──────────────────────────────────────────

fn print_self(path: &Path, c: &gnet_config::Config, alias: Option<&str>, pubkey_hex: &str) {
    println!("self");
    println!("  conf         {}", path.display());
    // operator-facing name always carries the `gnet-` prefix so it can't be
    // confused with a same-named Tailscale MagicDNS / mDNS host.
    let display_alias = alias
        .map(|a| format!("gnet-{a}"))
        .unwrap_or_else(|| "(no `# alias` line in conf)".to_string());
    println!("  alias        {display_alias}");
    println!("  overlay_v4   {}", c.address);
    match c.address6 {
        Some(v) => println!("  overlay_v6   {v}"),
        None => println!("  overlay_v6   (none — single-stack)"),
    }
    println!("  listen       {}", c.listen);
    match c.keepalive {
        Some(d) => println!("  keepalive    {}s", d.as_secs()),
        None => println!("  keepalive    (disabled)"),
    }
    println!(
        "  coordinator  {}",
        if c.coordinators.is_empty() {
            "(none)".to_string()
        } else {
            c.coordinators.join(", ")
        }
    );
    println!(
        "  device_token {}",
        if c.device_token.is_some() {
            "set (endpoint-report enabled)"
        } else {
            "absent (legacy join, no endpoint-report)"
        }
    );
    println!("  pubkey       {pubkey_hex}");
    println!("  peers in conf: {}", c.peers.len());
}

fn print_daemon() {
    println!("daemon");
    match pgrep_gnet_up() {
        Ok(pids) if !pids.is_empty() => {
            for pid in pids {
                println!("  pid          {pid} (running `gnet up`)");
            }
        }
        Ok(_) => println!("  pid          (no `gnet up` process found)"),
        Err(e) => println!("  pid          (pgrep failed: {e})"),
    }
}

fn print_coordinator(c: &gnet_config::Config, our_pubkey_hex: &str) {
    if c.coordinators.is_empty() {
        println!("coordinator  (none configured — `gnet status` shows local conf only)");
        return;
    }
    // Probe in preference order (primary first), showing which one answered —
    // mirrors the daemon's failover so status reflects the live coordinator.
    let mut last_err = None;
    let mut answered = None;
    for coord in &c.coordinators {
        match fetch_peers(coord, our_pubkey_hex) {
            Ok(body) => {
                answered = Some((coord.as_str(), body));
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    let (coord, body) = match answered {
        Some(v) => v,
        None => {
            println!("coordinator {}", c.coordinators.join(", "));
            println!(
                "  unreachable: {}",
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no coordinators answered".into())
            );
            return;
        }
    };
    println!("coordinator {coord}");
    {
        let relays = parse_relay_list(&body);
        if relays.is_empty() {
            println!("  relays       (none advertised)");
        } else {
            println!("  relays       {}", relays.join(", "));
        }
        let peers = parse_peer_summaries(&body);
        if peers.is_empty() {
            println!("  (empty peer list)");
        } else {
            println!("  {} peer(s):", peers.len());
            for p in &peers {
                let endpoint = p.endpoint.as_deref().unwrap_or("(unreported)");
                let relay = if p.relay_eligible { " [relay]" } else { "" };
                println!(
                    "    {:6} {:14} endpoint={}{relay}",
                    format!("gnet-{}", p.alias),
                    p.overlay_v4,
                    endpoint,
                );
            }
        }
    }
}

fn print_blank() {
    println!();
}

// ── conf helpers ─────────────────────────────────────────────

fn parse_alias_comment(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("# alias ") {
            let alias = rest.trim();
            if !alias.is_empty() {
                return Some(alias.to_string());
            }
        }
    }
    None
}

// ── coordinator query ────────────────────────────────────────

#[derive(Debug)]
struct PeerSummary {
    alias: String,
    overlay_v4: String,
    endpoint: Option<String>,
    relay_eligible: bool,
}

fn fetch_peers(coordinator: &str, our_pubkey_hex: &str) -> io::Result<String> {
    let url = format!("{coordinator}/peers");
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("10")
        .arg("-H")
        .arg(format!("X-Device-Pubkey: {our_pubkey_hex}"))
        .arg(&url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let body = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "curl GET {url} exit={:?} stderr={stderr} body={body}",
            out.status.code()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Narrow a `/peers` body to the peer-array text the object scanner walks.
/// v0.17 coordinators wrap the list in `{"peers":[...],"relays":[...]}`;
/// pre-v0.17 ones return a bare `[...]`. For the object shape we return the
/// inner peers array so the wrapper object and the relays list don't confuse
/// the brace scanner; for the bare-array shape we return the body unchanged.
fn peers_scan_slice(body: &str) -> &str {
    if body.trim_start().starts_with('{') {
        array_after(body, "peers").unwrap_or("")
    } else {
        body
    }
}

/// Inner text of the `[...]` array following the first `"<key>"`, string- and
/// depth-aware so brackets inside quoted strings (IPv6 endpoints) and nested
/// arrays are handled. `None` if the key or a balanced array is absent.
fn array_after<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let after_key = body.find(&needle)? + needle.len();
    let bytes = body.as_bytes();
    let mut i = after_key;
    while i < bytes.len() && bytes[i] != b'[' {
        i += 1;
    }
    let start = i + 1;
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escape = false;
    i = start;
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
                    return Some(&body[start..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Advertised relay servers from a `/peers` object's `"relays"` array. Empty
/// for a bare-array (pre-v0.17) response or when none are configured.
fn parse_relay_list(body: &str) -> Vec<String> {
    let Some(arr) = array_after(body, "relays") else {
        return Vec::new();
    };
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
            if bytes[j] == b'\\' {
                j += 1;
            }
            j += 1;
        }
        if j >= bytes.len() {
            break;
        }
        out.push(arr[start..j].to_string());
        i = j + 1;
    }
    out
}

/// Minimal hand-rolled parser for the `/peers` array. Schema-locked: same
/// fields as `node::discovery::parse_peer_object` but only the columns
/// `gnet status` displays (alias, overlay_v4, endpoint, relay_eligible).
/// Designed to be lenient — any parse failure on a single object skips that
/// row rather than aborting the whole status output.
fn parse_peer_summaries(body: &str) -> Vec<PeerSummary> {
    let body = peers_scan_slice(body);
    let mut out = Vec::new();
    let bytes = body.as_bytes();
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
                        let obj = &body[start..i];
                        if let Some(p) = parse_one(obj) {
                            out.push(p);
                        }
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

fn parse_one(obj: &str) -> Option<PeerSummary> {
    Some(PeerSummary {
        alias: extract_string(obj, "alias")?,
        overlay_v4: extract_string(obj, "overlay_v4")?,
        endpoint: extract_string(obj, "endpoint"),
        relay_eligible: extract_bool(obj, "relay_eligible").unwrap_or(false),
    })
}

fn extract_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut i = body.find(&needle)? + needle.len();
    let bytes = body.as_bytes();
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b':' || bytes[i] == b'\t') {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    if body[i..].starts_with("null") {
        return None;
    }
    if bytes[i] != b'"' {
        return None;
    }
    i += 1;
    let start = i;
    let mut escape = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if !escape => escape = true,
            b'"' if !escape => return Some(body[start..i].to_string()),
            _ => escape = false,
        }
        i += 1;
    }
    None
}

fn extract_bool(body: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let mut i = body.find(&needle)? + needle.len();
    let bytes = body.as_bytes();
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b':' || bytes[i] == b'\t') {
        i += 1;
    }
    if body[i..].starts_with("true") {
        Some(true)
    } else if body[i..].starts_with("false") {
        Some(false)
    } else {
        None
    }
}

// ── daemon discovery ─────────────────────────────────────────

fn pgrep_gnet_up() -> io::Result<Vec<String>> {
    // -f matches against full command line so we find `gnet up ...` not
    // any incidental "gnet" in process names. We then filter for processes
    // whose argv starts with our `gnet` binary path AND contains `up`.
    let out = Command::new("pgrep")
        .arg("-x")
        .arg("gnet")
        .output()?;
    if !out.status.success() && out.stdout.is_empty() {
        return Ok(Vec::new());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect())
}

// ── options ──────────────────────────────────────────────────

struct Options {
    conf: PathBuf,
}

impl Options {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut conf = default_conf_path();
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--conf" => {
                    conf = PathBuf::from(
                        args.get(i + 1)
                            .ok_or_else(|| io::Error::other("missing value for --conf"))?,
                    );
                    i += 2;
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unknown argument `{other}`; expected --conf"
                    )));
                }
            }
        }
        Ok(Self { conf })
    }
}

#[cfg(target_os = "linux")]
fn default_conf_path() -> PathBuf {
    PathBuf::from("/etc/gnet/main.conf")
}

#[cfg(target_os = "macos")]
fn default_conf_path() -> PathBuf {
    PathBuf::from("/usr/local/etc/gnet/main.conf")
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn default_conf_path() -> PathBuf {
    PathBuf::from("/etc/gnet/main.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_alias_comment() {
        assert_eq!(parse_alias_comment("# alias gnet-mini\nprivate ..."), Some("gnet-mini".into()));
        assert_eq!(parse_alias_comment("# alias   t01   \n"), Some("t01".into()));
        assert_eq!(parse_alias_comment("private ...\n"), None);
        assert_eq!(parse_alias_comment("# alias \n"), None);
    }

    #[test]
    fn parses_peer_summaries_happy_path() {
        let body = r#"[
            {"alias":"t01","x25519_pubkey":"aa","mlkem_ek":"bb","overlay_v4":"10.42.42.2","overlay_v6":"fd8d::2","endpoint":"1.2.3.4:65432","relay_eligible":true},
            {"alias":"t02","x25519_pubkey":"cc","mlkem_ek":"dd","overlay_v4":"10.42.42.3","overlay_v6":"fd8d::3","endpoint":null,"relay_eligible":false}
        ]"#;
        let peers = parse_peer_summaries(body);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].alias, "t01");
        assert_eq!(peers[0].overlay_v4, "10.42.42.2");
        assert_eq!(peers[0].endpoint.as_deref(), Some("1.2.3.4:65432"));
        assert!(peers[0].relay_eligible);
        assert_eq!(peers[1].alias, "t02");
        assert_eq!(peers[1].endpoint, None);
        assert!(!peers[1].relay_eligible);
    }

    #[test]
    fn parses_empty_array() {
        assert!(parse_peer_summaries("[]").is_empty());
    }

    #[test]
    fn parses_peer_summaries_v017_object_shape() {
        // v0.17 wraps peers in an object alongside a relays list — the scanner
        // must read the peers array, not the wrapper object, and must not be
        // tripped by the relays strings (incl. an IPv6 endpoint with brackets).
        let body = r#"{"peers":[
            {"alias":"t01","x25519_pubkey":"aa","mlkem_ek":"bb","overlay_v4":"10.42.42.2","overlay_v6":"fd8d::2","endpoint":"1.2.3.4:65432","relay_eligible":true},
            {"alias":"t02","x25519_pubkey":"cc","mlkem_ek":"dd","overlay_v4":"10.42.42.3","overlay_v6":null,"endpoint":null,"relay_eligible":false}
        ],"relays":["198.51.100.9:65433","[2001:db8::1]:65433"]}"#;
        let peers = parse_peer_summaries(body);
        assert_eq!(peers.len(), 2, "both peers parsed from the object shape");
        assert_eq!(peers[0].alias, "t01");
        assert_eq!(peers[0].endpoint.as_deref(), Some("1.2.3.4:65432"));
        assert_eq!(peers[1].alias, "t02");

        let relays = parse_relay_list(body);
        assert_eq!(relays, vec!["198.51.100.9:65433", "[2001:db8::1]:65433"]);
    }

    #[test]
    fn parse_relay_list_absent_for_bare_array() {
        // pre-v0.17 bare array has no relays key → empty list, no panic.
        assert!(parse_relay_list("[]").is_empty());
        assert!(parse_relay_list(r#"[{"alias":"t01"}]"#).is_empty());
    }

    #[test]
    fn parses_object_with_empty_peers_and_relays() {
        assert!(parse_peer_summaries(r#"{"peers":[],"relays":[]}"#).is_empty());
        assert!(parse_relay_list(r#"{"peers":[],"relays":[]}"#).is_empty());
    }

    #[test]
    fn parse_one_tolerates_missing_optional_fields() {
        let obj = r#"{"alias":"x","overlay_v4":"10.0.0.1"}"#;
        let p = parse_one(obj).unwrap();
        assert_eq!(p.alias, "x");
        assert_eq!(p.endpoint, None);
        assert!(!p.relay_eligible);
    }

    #[test]
    fn parse_one_skips_invalid() {
        // missing required `alias`
        let obj = r#"{"overlay_v4":"10.0.0.1"}"#;
        assert!(parse_one(obj).is_none());
    }
}
