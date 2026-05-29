//! `gnet join` — onboard a daemon against a gnet-discover coordinator.
//!
//! Generates a fresh X25519 + ML-KEM-768 identity, POSTs to
//! `<coordinator>/join` carrying the one-shot join token in the
//! `X-Join-Token` header, and writes a complete config file to disk (the
//! daemon's static private key is prepended locally; the coordinator never
//! sees it).
//!
//! HTTP transport is delegated to the system `curl` binary so the gnet
//! crate itself stays free of any external Rust dependencies. JSON
//! parsing is done with a tiny hand-rolled extractor that handles the
//! known response schema only — not a general-purpose parser.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use gnet::hosts;
use gnet::keys;
use gnet_hex as hex;

const LISTEN_DEFAULT: &str = "0.0.0.0:65432";
/// Default hosts file. The same path on macOS and Linux — we splice a
/// marker block into it rather than running our own DNS server, to
/// keep system resolution unaffected when the gnet daemon is down.
const HOSTS_DEFAULT: &str = "/etc/hosts";

/// Entry point for the `gnet join` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;

    // 1. Fresh identity.
    let (sk, pk) = keys::generate_static();
    let (mlkem_ek, _dk) = keys::derive_mlkem(&sk);
    let pk_hex = hex::encode(&pk);
    let mlkem_ek_hex = hex::encode(&mlkem_ek);

    // 2. POST to coordinator. The join token rides in X-Join-Token; the body
    //    carries the device's public material + reflexive endpoint hint.
    let body = build_request_json(&pk_hex, &mlkem_ek_hex, opts.endpoint.as_deref());
    eprintln!("posting join to {}/join", opts.coordinator);
    let resp = post_json(
        &format!("{}/join", opts.coordinator),
        &body,
        &opts.token,
    )?;

    // 3. Parse response (hand-rolled subset of JSON).
    let alias = extract_string(&resp, "alias")
        .ok_or_else(|| io::Error::other("response missing `alias`"))?;
    let overlay_v4 = extract_string(&resp, "overlay_v4")
        .ok_or_else(|| io::Error::other("response missing `overlay_v4`"))?;
    let overlay_v6 = extract_string(&resp, "overlay_v6")
        .ok_or_else(|| io::Error::other("response missing `overlay_v6`"))?;
    // device_token is optional only for backward compat with pre-v0.3 coordinators;
    // a current coordinator always emits it, so its absence is logged but not fatal.
    let device_token = extract_string(&resp, "device_token");
    let peers_block = extract_array(&resp, "peers")
        .ok_or_else(|| io::Error::other("response missing `peers` array"))?;
    let peer_objs = split_objects(peers_block);

    // 4. Build conf text (gnet-config format).
    let mut conf = String::new();
    // `alias` is a real directive (not a comment): the daemon reads it to
    // write its own `gnet-<alias>` entry when it keeps /etc/hosts fresh.
    conf.push_str(&format!("alias {alias}\n"));
    conf.push_str(&format!("private {}\n", hex::encode(&sk)));
    conf.push_str(&format!("address  {overlay_v4}\n"));
    conf.push_str(&format!("address6 {overlay_v6}\n"));
    conf.push_str(&format!("listen   {LISTEN_DEFAULT}\n"));
    // The daemon's discovery thread polls this URL for peer-list refreshes.
    conf.push_str(&format!("coordinator {}\n", opts.coordinator));
    if let Some(tok) = &device_token {
        conf.push_str(&format!("device_token {tok}\n"));
    }
    // Persist the operator's hosts choice so the daemon's discovery loop keeps
    // /etc/hosts fresh as peers join later — the one-shot splice in step 6
    // only captures the peer set as of join time.
    if opts.no_hosts {
        conf.push_str("manage_hosts false\n");
    }
    if let Some(h) = &opts.hosts {
        conf.push_str(&format!("hosts_path {}\n", h.display()));
    }
    // Peer entries pulled out as we build the conf, so we can also
    // hand them to the /etc/hosts splice below without re-parsing.
    let mut peer_hosts: Vec<hosts::Entry> = Vec::with_capacity(peer_objs.len());
    for obj in &peer_objs {
        let p_pk = extract_string(obj, "x25519_pubkey")
            .ok_or_else(|| io::Error::other("peer missing x25519_pubkey"))?;
        let p_ek = extract_string(obj, "mlkem_ek")
            .ok_or_else(|| io::Error::other("peer missing mlkem_ek"))?;
        let p_vip4 = extract_string(obj, "overlay_v4")
            .ok_or_else(|| io::Error::other("peer missing overlay_v4"))?;
        // overlay_v6 is optional on the wire only as a defensive guard; the
        // server always emits it since v0.1 (both stacks are dual-stack).
        let p_vip6 = extract_string(obj, "overlay_v6");
        let p_alias =
            extract_string(obj, "alias").ok_or_else(|| io::Error::other("peer missing alias"))?;
        let vip_token = match &p_vip6 {
            Some(v6) if !v6.is_empty() => format!("{p_vip4},{v6}"),
            _ => p_vip4.clone(),
        };
        let endpoint = extract_string(obj, "endpoint");
        match &endpoint {
            Some(ep) if !ep.is_empty() => {
                conf.push_str(&format!("peer {p_pk} {p_ek} {vip_token} {ep}\n"));
            }
            _ => conf.push_str(&format!("peer {p_pk} {p_ek} {vip_token}\n")),
        }
        peer_hosts.push(hosts::Entry {
            alias: p_alias,
            v4: Some(p_vip4),
            v6: p_vip6.filter(|s| !s.is_empty()),
        });
    }

    // 5. Write conf atomically — failure here is fatal, the daemon
    //    can't run without it.
    write_conf_atomic(&opts.out, &conf)?;

    // 6. Splice the hosts block (best-effort).
    //    `no_hosts` is the opt-out; otherwise we update the chosen
    //    hosts path so that `ssh gnet-<alias>` resolves through the
    //    overlay. A failure here NEVER aborts join — DNS resolution
    //    is advisory; the conf is already on disk and the daemon can
    //    start.
    let hosts_path = opts
        .hosts
        .clone()
        .unwrap_or_else(|| PathBuf::from(HOSTS_DEFAULT));
    let hosts_status = if opts.no_hosts {
        "skipped (--no-hosts)".to_string()
    } else {
        let self_entry = hosts::Entry {
            alias: alias.clone(),
            v4: Some(overlay_v4.clone()),
            v6: Some(overlay_v6.clone()).filter(|s| !s.is_empty()),
        };
        // our own host first, then the peers from the join response.
        let mut entries = Vec::with_capacity(1 + peer_hosts.len());
        entries.push(self_entry);
        entries.extend(peer_hosts);
        match hosts::splice_atomic(&hosts_path, &entries) {
            Ok(()) => format!("{}", hosts_path.display()),
            Err(e) => {
                eprintln!(
                    "warning: could not update {}: {e} — `ssh gnet-<alias>` will not resolve until you splice the block manually or re-run with sufficient privileges",
                    hosts_path.display()
                );
                format!("FAILED ({})", hosts_path.display())
            }
        }
    };

    println!("alias      {alias}");
    println!("overlay_v4 {overlay_v4}");
    println!("overlay_v6 {overlay_v6}");
    println!("peers      {}", peer_objs.len());
    println!("conf       {} ({} bytes)", opts.out.display(), conf.len());
    println!("hosts      {hosts_status}");
    Ok(())
}

#[derive(Debug)]
struct Options {
    token: String,
    coordinator: String,
    endpoint: Option<String>,
    out: PathBuf,
    /// Opt-out of writing the /etc/hosts marker block.
    no_hosts: bool,
    /// Override target for the hosts splice; defaults to `/etc/hosts`.
    /// Useful for sysadmins who want to splice into a sidecar file
    /// (e.g. `/etc/hosts.d/gnet`) that they include from dnsmasq.
    hosts: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut token = None;
        let mut coordinator = None;
        let mut endpoint = None;
        let mut out = default_conf_path();
        let mut no_hosts = false;
        let mut hosts: Option<PathBuf> = None;
        let mut i = 2;
        while i < args.len() {
            let flag = args[i].as_str();
            let val_at = |idx: usize, name: &str| -> io::Result<String> {
                args.get(idx)
                    .cloned()
                    .ok_or_else(|| io::Error::other(format!("missing value for {name}")))
            };
            match flag {
                "--token" => {
                    token = Some(val_at(i + 1, "--token")?);
                    i += 2;
                }
                "--coordinator" => {
                    coordinator = Some(val_at(i + 1, "--coordinator")?);
                    i += 2;
                }
                "--endpoint" => {
                    endpoint = Some(val_at(i + 1, "--endpoint")?);
                    i += 2;
                }
                "--out" => {
                    out = PathBuf::from(val_at(i + 1, "--out")?);
                    i += 2;
                }
                "--no-hosts" => {
                    no_hosts = true;
                    i += 1;
                }
                "--hosts" => {
                    hosts = Some(PathBuf::from(val_at(i + 1, "--hosts")?));
                    i += 2;
                }
                other => {
                    return Err(io::Error::other(format!(
                        "unknown argument `{other}`; expected --token/--coordinator/--endpoint/--out/--no-hosts/--hosts"
                    )));
                }
            }
        }
        let token = token.ok_or_else(|| io::Error::other("missing required --token"))?;
        let coordinator = coordinator
            .ok_or_else(|| io::Error::other("missing required --coordinator"))?
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            token,
            coordinator,
            endpoint,
            out,
            no_hosts,
            hosts,
        })
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
    PathBuf::from("./gnet.conf")
}

fn build_request_json(
    x25519_pubkey: &str,
    mlkem_ek: &str,
    endpoint: Option<&str>,
) -> String {
    let mut s = String::with_capacity(512);
    s.push('{');
    s.push_str(&format!("\"x25519_pubkey\":\"{x25519_pubkey}\""));
    s.push_str(&format!(",\"mlkem_ek\":\"{mlkem_ek}\""));
    if let Some(ep) = endpoint {
        s.push_str(&format!(",\"endpoint\":\"{}\"", json_escape(ep)));
    } else {
        s.push_str(",\"endpoint\":null");
    }
    s.push('}');
    s
}

fn json_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// POST a JSON body via `curl`, attaching the one-shot join token in the
/// `X-Join-Token` header. Returns the response body on 2xx; errors on
/// transport failure or non-2xx HTTP status.
fn post_json(url: &str, body: &str, join_token: &str) -> io::Result<String> {
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
        .arg("Content-Type: application/json")
        .arg("-H")
        .arg("Accept: application/json")
        .arg("-H")
        .arg(format!("X-Join-Token: {join_token}"))
        .arg("-d")
        .arg(body)
        .arg(url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "curl POST {url} failed (exit={:?}): stderr={stderr}; body={stdout}",
            out.status.code()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn write_conf_atomic(path: &PathBuf, contents: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other(format!("invalid conf path: {}", path.display())))?;
    if !parent.as_os_str().is_empty() {
        std::fs::create_dir_all(parent)?;
    }
    let mut tmp = path.clone();
    let final_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("conf path has no filename component"))?
        .to_string_lossy()
        .into_owned();
    tmp.set_file_name(format!(".{final_name}.tmp"));
    {
        use std::io::Write;
        let mut f = open_secure(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn open_secure(path: &PathBuf) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_secure(path: &PathBuf) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

// ----- tiny JSON extractors -----
//
// Limited to the schema we control:
//   { "deviceId":"...", "alias":"...", "overlayV4":"...", "overlayV6":"...",
//     "peers":[{"x25519Pubkey":"...","mlkemEk":"...","overlayV4":"...",
//               "overlayV6":"...","alias":"...","endpoint":"..." }, ...] }
//
// Whitespace tolerant, escape-aware enough not to be fooled by `\"` inside
// strings, but NOT a general parser. If the server schema changes, update
// here.

/// Extract a top-level (or nested-within-object) string value by key:
/// matches `"<key>": "<value>"` allowing whitespace. Returns the decoded
/// (escape-resolved) value.
fn extract_string(body: &str, key: &str) -> Option<String> {
    let key_pos = find_key(body, key)?;
    let after_colon = skip_to_value(body, key_pos)?;
    let s = body.get(after_colon..)?;
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
            b'"' => return Some(decode_string(&s[..end])),
            _ => end += 1,
        }
    }
    None
}

/// Extract a JSON array value by key — returns the slice between the
/// matching outer `[` and `]` (exclusive), depth- and string-aware.
fn extract_array<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let key_pos = find_key(body, key)?;
    let after_colon = skip_to_value(body, key_pos)?;
    let s = body.get(after_colon..)?;
    if !s.starts_with('[') {
        return None;
    }
    let bytes = s.as_bytes();
    let mut i = 1usize;
    let mut depth = 1i32;
    let mut in_string = false;
    let mut escape = false;
    while i < bytes.len() {
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
                }
                b'"' => {
                    in_string = false;
                }
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
                    return Some(&s[1..i]);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Split the contents of an array (the slice returned by `extract_array`)
/// into its top-level `{...}` objects.
fn split_objects(array_body: &str) -> Vec<&str> {
    let bytes = array_body.as_bytes();
    let mut objs = Vec::new();
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
                    b'\\' => {
                        escape = true;
                    }
                    b'"' => {
                        in_string = false;
                    }
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
                        objs.push(&array_body[start..i]);
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }
    objs
}

/// Locate the byte position of `"<key>"` in `body`, skipping any
/// occurrences that fall inside another string literal. Returns the
/// position of the opening quote.
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
            // confirm it's followed by `:` (after whitespace) → a key,
            // not a value.
            let mut j = i + nbytes.len();
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t' || bytes[j] == b'\n') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b':' {
                return Some(i);
            }
            // otherwise consume this string literal so we don't re-enter it
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

/// Given the start of the `"key"` token, advance past the closing `"`
/// and the `:` separator (skipping whitespace) and return the byte
/// position of the first value character.
fn skip_to_value(body: &str, key_pos: usize) -> Option<usize> {
    let bytes = body.as_bytes();
    // skip past the key's opening quote, name, closing quote
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

/// Resolve JSON `\` escapes. Only the escapes we emit on the server side
/// are decoded; `\uXXXX` is folded to '?' as a defensive fallback rather
/// than failing the parse — server output is ASCII-clean.
fn decode_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some('/') => out.push('/'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('b') => out.push('\u{0008}'),
            Some('f') => out.push('\u{000c}'),
            Some('u') => {
                for _ in 0..4 {
                    chars.next();
                }
                out.push('?');
            }
            Some(other) => out.push(other),
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_string_basic() {
        let body = r#"{"deviceId":"abc-123","alias":"gnet-mini"}"#;
        assert_eq!(extract_string(body, "deviceId").as_deref(), Some("abc-123"));
        assert_eq!(extract_string(body, "alias").as_deref(), Some("gnet-mini"));
        assert_eq!(extract_string(body, "missing"), None);
    }

    #[test]
    fn extract_string_tolerates_whitespace() {
        let body = "{\n  \"alias\" : \"gnet-mini\",\n  \"x\": 1\n}";
        assert_eq!(extract_string(body, "alias").as_deref(), Some("gnet-mini"));
    }

    #[test]
    fn extract_string_skips_inside_other_string() {
        // a value that contains the key name should not be returned
        let body = r#"{"note":"alias is computed","alias":"real"}"#;
        assert_eq!(extract_string(body, "alias").as_deref(), Some("real"));
    }

    #[test]
    fn extract_string_handles_escapes() {
        let body = r#"{"note":"a \"quoted\" word"}"#;
        assert_eq!(
            extract_string(body, "note").as_deref(),
            Some("a \"quoted\" word")
        );
    }

    #[test]
    fn extract_array_and_split_objects() {
        let body = r#"{"peers":[{"a":"1"},{"a":"2"}]}"#;
        let arr = extract_array(body, "peers").expect("peers");
        let objs = split_objects(arr);
        assert_eq!(objs.len(), 2);
        assert_eq!(extract_string(objs[0], "a").as_deref(), Some("1"));
        assert_eq!(extract_string(objs[1], "a").as_deref(), Some("2"));
    }

    #[test]
    fn extract_array_handles_nested_braces_in_strings() {
        let body = r#"{"peers":[{"alias":"x]y[z","v":"ok"}]}"#;
        let arr = extract_array(body, "peers").expect("peers");
        let objs = split_objects(arr);
        assert_eq!(objs.len(), 1);
        assert_eq!(extract_string(objs[0], "alias").as_deref(), Some("x]y[z"));
        assert_eq!(extract_string(objs[0], "v").as_deref(), Some("ok"));
    }

    #[test]
    fn build_request_json_endpoint_null_when_absent() {
        let s = build_request_json("aa", "bb", None);
        assert!(s.contains("\"x25519_pubkey\":\"aa\""));
        assert!(s.contains("\"mlkem_ek\":\"bb\""));
        assert!(s.contains("\"endpoint\":null"));
        assert!(!s.contains("authKey"));
        assert!(!s.contains("hostname"));
    }

    #[test]
    fn build_request_json_escapes_quotes_in_endpoint() {
        let s = build_request_json("aa", "bb", Some("ho\"st:1"));
        assert!(s.contains("\"endpoint\":\"ho\\\"st:1\""));
    }

    #[test]
    fn json_escape_handles_specials() {
        assert_eq!(json_escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(json_escape("plain"), "plain");
        // control char → unicode escape
        let s = json_escape("\u{0001}");
        assert_eq!(s, "\\u0001");
    }

    #[test]
    fn options_parse_full() {
        let argv = vec![
            "gnet".to_string(),
            "join".to_string(),
            "--token".into(),
            "tsk-1".into(),
            "--coordinator".into(),
            "http://gnet.golia.jp:44520/".into(),
            "--endpoint".into(),
            "1.2.3.4:51820".into(),
            "--out".into(),
            "/tmp/x.conf".into(),
            "--hosts".into(),
            "/tmp/x.hosts".into(),
        ];
        let opts = Options::parse(&argv).unwrap();
        assert_eq!(opts.token, "tsk-1");
        // trailing / stripped from coordinator
        assert_eq!(opts.coordinator, "http://gnet.golia.jp:44520");
        assert_eq!(opts.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(opts.out, PathBuf::from("/tmp/x.conf"));
        assert_eq!(opts.hosts, Some(PathBuf::from("/tmp/x.hosts")));
        assert!(!opts.no_hosts, "default off when flag absent");
    }

    #[test]
    fn options_parse_no_hosts_flag() {
        let argv = vec![
            "gnet".into(),
            "join".into(),
            "--token".into(),
            "t".into(),
            "--coordinator".into(),
            "u".into(),
            "--no-hosts".into(),
        ];
        let opts = Options::parse(&argv).unwrap();
        assert!(opts.no_hosts);
        assert_eq!(opts.hosts, None);
    }

    #[test]
    fn options_parse_requires_token_and_coordinator() {
        let argv = vec!["gnet".into(), "join".into()];
        assert!(Options::parse(&argv).is_err());
        let argv = vec!["gnet".into(), "join".into(), "--token".into(), "t".into()];
        assert!(Options::parse(&argv).is_err());
    }

    #[test]
    fn options_parse_rejects_unknown_flag() {
        let argv = vec![
            "gnet".into(),
            "join".into(),
            "--token".into(),
            "t".into(),
            "--coordinator".into(),
            "u".into(),
            "--bogus".into(),
        ];
        assert!(Options::parse(&argv).is_err());
    }
}
