//! `gnet rotate-key` — generate a fresh X25519 + ML-KEM identity, ask the
//! coordinator to swap our keys in place (alias / overlay IP / device_token
//! preserved), and atomically rewrite the local conf with the new private key.
//!
//! Used when an operator suspects a static key has been compromised, or as a
//! routine periodic rotation. The daemon is not signal-aware, so the operator
//! must restart it after this command (`systemctl restart gnet@main` /
//! `sudo launchctl kickstart -k system/com.gnet.gnet`).
//!
//! Other peers' daemons will see the new pubkey on their next 30-second
//! `/peers` poll and, thanks to discovery's alias-keyed lookup, swap their
//! local Peer entry in place and reset the session so the next outbound
//! packet re-handshakes with the new keys — no peer restart needed.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use gnet::keys;
use gnet_hex as hex;

/// Entry point for the `gnet rotate-key` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;
    let text = std::fs::read_to_string(&opts.conf)
        .map_err(|e| io::Error::other(format!("read {}: {e}", opts.conf.display())))?;
    let config = gnet_config::parse(&text).map_err(io::Error::other)?;

    let coordinator = config
        .coordinator
        .as_deref()
        .ok_or_else(|| io::Error::other("conf has no `coordinator` — rotation requires one"))?;
    let device_token = config.device_token.as_deref().ok_or_else(|| {
        io::Error::other("conf has no `device_token` — re-`gnet join` first (legacy join)")
    })?;

    // 1. fresh identity
    let (new_sk, new_pk) = keys::generate_static();
    let (new_mlkem_ek, _new_dk) = keys::derive_mlkem(&new_sk);
    let new_pk_hex = hex::encode(&new_pk);
    let new_ek_hex = hex::encode(&new_mlkem_ek);

    // 2. POST to coordinator
    let url = format!("{coordinator}/devices/self/rotate");
    eprintln!("posting rotation to {url}");
    post_rotate(&url, device_token, &new_pk_hex, &new_ek_hex)?;

    // 3. rewrite conf — atomic tmp+rename. Only the `private` directive
    //    changes; comments, peers, keepalive, device_token, coordinator
    //    all stay put.
    let new_text = swap_private_directive(&text, &hex::encode(&new_sk));
    write_atomic(&opts.conf, &new_text)?;

    eprintln!("rotation ok");
    eprintln!("  new pubkey:      {new_pk_hex}");
    eprintln!("  conf updated:    {}", opts.conf.display());
    eprintln!("  next step:       restart the daemon to load the new key");
    eprintln!("    systemd:       systemctl restart gnet@main");
    eprintln!("    launchd:       sudo launchctl kickstart -k system/com.gnet.gnet");
    Ok(())
}

fn post_rotate(url: &str, device_token: &str, new_pk_hex: &str, new_ek_hex: &str) -> io::Result<()> {
    let body = format!(r#"{{"x25519_pubkey":"{new_pk_hex}","mlkem_ek":"{new_ek_hex}"}}"#);
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
        .arg(url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let body = String::from_utf8_lossy(&out.stdout);
        return Err(io::Error::other(format!(
            "curl POST {url} exit={:?} stderr={stderr} body={body}",
            out.status.code()
        )));
    }
    Ok(())
}

/// Replace the `private <hex>` directive in `text` with the new value. The
/// rest of the file (comments, blank lines, other directives, peers) is
/// preserved byte-for-byte. If no `private` directive exists, returns the
/// original text — caller's POST would have failed earlier so this never
/// races into "wrote a malformed conf".
fn swap_private_directive(text: &str, new_hex: &str) -> String {
    let mut out = String::with_capacity(text.len() + new_hex.len());
    let mut replaced = false;
    for (i, line) in text.lines().enumerate() {
        if !replaced && line.trim_start().starts_with("private ") {
            out.push_str(&format!("private {new_hex}"));
            replaced = true;
        } else {
            out.push_str(line);
        }
        // preserve trailing newline shape — push '\n' after every line, then
        // strip the last one if the original didn't have one.
        if i + 1 < text.lines().count() || text.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn write_atomic(path: &Path, content: &str) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other(format!("invalid conf path: {}", path.display())))?;
    let final_name = path
        .file_name()
        .ok_or_else(|| io::Error::other("conf path has no filename component"))?
        .to_string_lossy()
        .into_owned();
    let mut tmp = path.to_path_buf();
    tmp.set_file_name(format!(".{final_name}.rotate.tmp"));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        let _ = parent;
        f.write_all(content.as_bytes())?;
        // preserve 0600 if the target already had it (conf carries the
        // private key, must never be world-readable).
        if let Ok(meta) = std::fs::metadata(path) {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(
                meta.permissions().mode() & 0o7777,
            ));
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

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
    fn swap_private_keeps_rest_byte_for_byte() {
        let before = "\
# alias gnet-mini
private 0000000000000000000000000000000000000000000000000000000000000001
address  10.42.42.4
address6 fd8d:f090:2ebb::4
listen   0.0.0.0:65432
coordinator http://gnet.golia.jp:65432
device_token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
peer abc def 10.42.42.2 1.2.3.4:65432
";
        let new_hex = "ff".repeat(32);
        let after = swap_private_directive(before, &new_hex);
        assert!(after.contains(&format!("private {new_hex}")));
        assert!(!after.contains("000000000000000000000000000000000000000000000000000000000000000"));
        assert!(after.contains("# alias gnet-mini"));
        assert!(after.contains("device_token aaaaaaaa"));
        assert!(after.contains("peer abc def 10.42.42.2 1.2.3.4:65432"));
        // single `private` directive remains
        assert_eq!(after.matches("\nprivate ").count() + after.starts_with("private ") as usize, 1);
    }

    #[test]
    fn swap_private_replaces_only_first_match() {
        // A conf with two `private ` lines (pathological) should only replace
        // the first one. (The parser would reject this conf anyway, but the
        // function should be deterministic regardless.)
        let before = "private 01\nprivate 02\n";
        let after = swap_private_directive(before, "ee");
        assert_eq!(after, "private ee\nprivate 02\n");
    }

    #[test]
    fn swap_private_no_match_returns_unchanged() {
        let before = "address 10.0.0.1\nlisten 0.0.0.0:1\n";
        let after = swap_private_directive(before, "ff");
        assert_eq!(after, before);
    }

    #[test]
    fn swap_private_preserves_trailing_newline_shape() {
        let with_nl = "private 01\n";
        assert_eq!(swap_private_directive(with_nl, "ff"), "private ff\n");
        let no_nl = "private 01";
        assert_eq!(swap_private_directive(no_nl, "ff"), "private ff");
    }

    #[test]
    fn write_atomic_preserves_0600_perms() {
        use std::os::unix::fs::PermissionsExt;
        let mut p = std::env::temp_dir();
        let mut r = [0u8; 8];
        gnet_rand::fill(&mut r);
        p.push(format!("gnet-rotate-test-{}.conf", gnet_hex::encode(&r)));
        std::fs::write(&p, "old\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_atomic(&p, "new\n").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "new\n");
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600, "0600 must survive the tmp+rename dance");
        let _ = std::fs::remove_file(&p);
    }
}
