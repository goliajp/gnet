//! `gnet join` — onboard a daemon against a coordinator.
//!
//! Generates a fresh X25519 + ML-KEM-768 identity, POSTs to
//! `<coordinator>/gnet/login` with the supplied one-shot auth-key, and
//! writes a complete config file to disk (the daemon's static private
//! key is prepended locally; the coordinator never sees it).
//!
//! HTTP transport is delegated to the system `curl` binary so the gnet
//! crate itself stays free of any external Rust dependencies. JSON
//! parsing is done with a tiny hand-rolled extractor that handles the
//! known response schema only — not a general-purpose parser.

use std::io;
use std::path::PathBuf;
use std::process::Command;

use gnet::keys;
use gnet_hex as hex;

const LISTEN_DEFAULT: &str = "0.0.0.0:51820";

/// Entry point for the `gnet join` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;

    // 1. Fresh identity.
    let (sk, pk) = keys::generate_static();
    let (mlkem_ek, _dk) = keys::derive_mlkem(&sk);
    let pk_hex = hex::encode(&pk);
    let mlkem_ek_hex = hex::encode(&mlkem_ek);

    // 2. POST to coordinator.
    let hostname = opts
        .hostname
        .clone()
        .or_else(read_system_hostname)
        .ok_or_else(|| io::Error::other("hostname: not provided and `hostname` lookup failed"))?;
    let body = build_request_json(
        &opts.token,
        &pk_hex,
        &mlkem_ek_hex,
        &hostname,
        opts.endpoint.as_deref(),
    );
    eprintln!(
        "posting enrol to {}/gnet/login (hostname={hostname})",
        opts.coordinator
    );
    let resp = post_json(&format!("{}/gnet/login", opts.coordinator), &body)?;

    // 3. Parse response (hand-rolled subset of JSON).
    let alias = extract_string(&resp, "alias")
        .ok_or_else(|| io::Error::other("response missing `alias`"))?;
    let device_id = extract_string(&resp, "deviceId")
        .ok_or_else(|| io::Error::other("response missing `deviceId`"))?;
    let overlay_v4 = extract_string(&resp, "overlayV4")
        .ok_or_else(|| io::Error::other("response missing `overlayV4`"))?;
    let overlay_v6 = extract_string(&resp, "overlayV6")
        .ok_or_else(|| io::Error::other("response missing `overlayV6`"))?;
    let peers_block = extract_array(&resp, "peers")
        .ok_or_else(|| io::Error::other("response missing `peers` array"))?;
    let peer_objs = split_objects(peers_block);

    // 4. Build conf text (gnet-config format).
    let mut conf = String::new();
    conf.push_str(&format!("# device_id {device_id}\n"));
    conf.push_str(&format!("# alias {alias}\n"));
    conf.push_str(&format!("# overlay_v6 {overlay_v6}\n"));
    conf.push_str(&format!("private {}\n", hex::encode(&sk)));
    conf.push_str(&format!("address {overlay_v4}\n"));
    conf.push_str(&format!("listen {LISTEN_DEFAULT}\n"));
    for obj in &peer_objs {
        let p_pk = extract_string(obj, "x25519Pubkey")
            .ok_or_else(|| io::Error::other("peer missing x25519Pubkey"))?;
        let p_ek = extract_string(obj, "mlkemEk")
            .ok_or_else(|| io::Error::other("peer missing mlkemEk"))?;
        let p_vip = extract_string(obj, "overlayV4")
            .ok_or_else(|| io::Error::other("peer missing overlayV4"))?;
        let endpoint = extract_string(obj, "endpoint");
        match endpoint {
            Some(ep) if !ep.is_empty() => {
                conf.push_str(&format!("peer {p_pk} {p_ek} {p_vip} {ep}\n"));
            }
            _ => conf.push_str(&format!("peer {p_pk} {p_ek} {p_vip}\n")),
        }
    }

    // 5. Write atomically.
    write_conf_atomic(&opts.out, &conf)?;
    println!("device_id  {device_id}");
    println!("alias      {alias}");
    println!("overlay_v4 {overlay_v4}");
    println!("overlay_v6 {overlay_v6}");
    println!("peers      {}", peer_objs.len());
    println!("conf       {} ({} bytes)", opts.out.display(), conf.len());
    Ok(())
}

#[derive(Debug)]
struct Options {
    token: String,
    coordinator: String,
    hostname: Option<String>,
    endpoint: Option<String>,
    out: PathBuf,
}

impl Options {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut token = None;
        let mut coordinator = None;
        let mut hostname = None;
        let mut endpoint = None;
        let mut out = default_conf_path();
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
                "--hostname" => {
                    hostname = Some(val_at(i + 1, "--hostname")?);
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
                other => {
                    return Err(io::Error::other(format!(
                        "unknown argument `{other}`; expected --token/--coordinator/--hostname/--endpoint/--out"
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
            hostname,
            endpoint,
            out,
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

fn read_system_hostname() -> Option<String> {
    let out = Command::new("hostname").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn build_request_json(
    token: &str,
    x25519_pubkey: &str,
    mlkem_ek: &str,
    hostname: &str,
    endpoint: Option<&str>,
) -> String {
    let mut s = String::with_capacity(2048);
    s.push('{');
    s.push_str(&format!("\"authKey\":\"{}\"", json_escape(token)));
    s.push_str(&format!(",\"x25519Pubkey\":\"{x25519_pubkey}\""));
    s.push_str(&format!(",\"mlkemEk\":\"{mlkem_ek}\""));
    s.push_str(&format!(",\"hostname\":\"{}\"", json_escape(hostname)));
    if let Some(ep) = endpoint {
        s.push_str(&format!(",\"endpoint\":\"{}\"", json_escape(ep)));
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

/// POST a JSON body via `curl`. Returns the response body on 2xx; errors
/// on transport failure or non-2xx HTTP status.
fn post_json(url: &str, body: &str) -> io::Result<String> {
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
    fn build_request_json_omits_endpoint_when_absent() {
        let s = build_request_json("tok", "aa", "bb", "host", None);
        assert!(s.contains("\"authKey\":\"tok\""));
        assert!(s.contains("\"x25519Pubkey\":\"aa\""));
        assert!(s.contains("\"mlkemEk\":\"bb\""));
        assert!(s.contains("\"hostname\":\"host\""));
        assert!(!s.contains("endpoint"));
    }

    #[test]
    fn build_request_json_escapes_quotes_in_hostname() {
        let s = build_request_json("tok", "aa", "bb", "ho\"st", None);
        assert!(s.contains("\"hostname\":\"ho\\\"st\""));
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
            "https://portal.golia.jp/".into(),
            "--hostname".into(),
            "mini".into(),
            "--endpoint".into(),
            "1.2.3.4:51820".into(),
            "--out".into(),
            "/tmp/x.conf".into(),
        ];
        let opts = Options::parse(&argv).unwrap();
        assert_eq!(opts.token, "tsk-1");
        // trailing / stripped from coordinator
        assert_eq!(opts.coordinator, "https://portal.golia.jp");
        assert_eq!(opts.hostname.as_deref(), Some("mini"));
        assert_eq!(opts.endpoint.as_deref(), Some("1.2.3.4:51820"));
        assert_eq!(opts.out, PathBuf::from("/tmp/x.conf"));
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
