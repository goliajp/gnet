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
use std::path::PathBuf;
use std::process::Command;

use gnet::conf_io::{swap_private_directive, write_atomic};
use gnet::keys;
use gnet_hex as hex;

/// Entry point for the `gnet rotate-key` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;
    let text = std::fs::read_to_string(&opts.conf)
        .map_err(|e| io::Error::other(format!("read {}: {e}", opts.conf.display())))?;
    let config = gnet_config::parse(&text).map_err(io::Error::other)?;

    // Rotation talks to the primary (first) coordinator — that's where this
    // device's row and token live; standbys mirror it read-only.
    let coordinator = config
        .coordinators
        .first()
        .map(String::as_str)
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

fn post_rotate(
    url: &str,
    device_token: &str,
    new_pk_hex: &str,
    new_ek_hex: &str,
) -> io::Result<()> {
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

// In-place rewrite + atomic write helpers live in gnet::conf_io; the
// control-channel `rotate_key` op handler in `node/discovery.rs` shares
// them. Their unit tests moved with them.
