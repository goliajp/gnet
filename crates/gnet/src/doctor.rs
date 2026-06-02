//! `gnet doctor` — pre-flight + post-deploy diagnostic.
//!
//! Different shape from `gnet status`: `status` is the "full picture for an
//! operator who already knows what they're looking at"; `doctor` is the
//! "green / red verdict with reasons" — quick to read, exits non-zero if
//! anything's actually broken, friendly to scripts and to a freshly-onboarded
//! operator.
//!
//! Checks run in a stable order so output is diffable across runs:
//!
//! 1. conf parses (`hard fail` — without conf nothing else makes sense)
//! 2. private key derives
//! 3. coordinator known us (GET /peers with X-Device-Pubkey — tests
//!    reachability AND that our pubkey is in the coord's roster, in one
//!    syscall; multi-coord failover)
//! 4. admin socket reachable (unix-socket connect + read)
//! 5. /etc/hosts gnet block present (only when conf has coordinator +
//!    `manage_hosts` not turned off)
//! 6. service unit state (systemctl on Linux, launchctl on macOS)
//!
//! Notes on what's *not* checked:
//!
//! - `device_token` write capability — no read-only probe on the coord
//!   side; a misconfigured token surfaces in the daemon's event log as
//!   `event=endpoint_report_failed` and via `gnet status`, so a redundant
//!   doctor check isn't worth a write-mutation probe.
//! - Relay UDP reachability — no echo protocol on the relay; the daemon's
//!   own `event=relay_*` logs and `gnet metrics`'s
//!   `gnet_relay_health_age_ms` already cover it.
//!
//! Each check yields PASS / WARN / FAIL with a one-line detail. Exit code:
//! 0 if zero FAILs, 1 otherwise. WARNs do not flip the verdict — they are
//! the "this might be deliberate, but worth knowing" tier.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::os::unix::net::UnixStream;

use gnet::keys;
use gnet_hex as hex;

/// Entry point for the `gnet doctor` subcommand.
pub fn run(args: &[String]) -> io::Result<()> {
    let opts = Options::parse(args)?;
    let checks = run_checks(&opts.conf);
    print_report(&opts.conf, &checks);
    let failed = checks.iter().any(|c| c.verdict == Verdict::Fail);
    if failed {
        std::process::exit(1);
    }
    Ok(())
}

// ── verdict + check shape ────────────────────────────────────

#[derive(PartialEq, Eq, Clone, Copy)]
enum Verdict {
    Pass,
    Warn,
    Fail,
}

impl Verdict {
    fn tag(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
        }
    }
}

struct Check {
    name: &'static str,
    verdict: Verdict,
    detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            verdict: Verdict::Pass,
            detail: detail.into(),
        }
    }
    fn warn(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            verdict: Verdict::Warn,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Check {
            name,
            verdict: Verdict::Fail,
            detail: detail.into(),
        }
    }
}

// ── orchestration ────────────────────────────────────────────

fn run_checks(conf_path: &Path) -> Vec<Check> {
    let mut checks = Vec::new();

    let text = match std::fs::read_to_string(conf_path) {
        Ok(t) => t,
        Err(e) => {
            checks.push(Check::fail(
                "conf readable",
                format!("read {}: {e}", conf_path.display()),
            ));
            return checks;
        }
    };
    let config = match gnet_config::parse(&text) {
        Ok(c) => c,
        Err(e) => {
            checks.push(Check::fail("conf parses", format!("parse error: {e}")));
            return checks;
        }
    };
    checks.push(Check::pass("conf parses", conf_path.display().to_string()));

    let pubkey = keys::public_key(&config.private);
    let pubkey_hex = hex::encode(&pubkey);
    checks.push(Check::pass(
        "private key",
        format!("pubkey {}…", &pubkey_hex[..16]),
    ));

    checks.push(check_coordinator(&config, &pubkey_hex));
    checks.push(check_admin_socket());

    if !config.coordinators.is_empty() && config.manage_hosts {
        checks.push(check_hosts_block(&config, &pubkey_hex));
    }
    checks.push(check_service_unit());

    checks
}

fn print_report(conf_path: &Path, checks: &[Check]) {
    let widest_name = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    println!("gnet doctor — {}", conf_path.display());
    println!();
    for c in checks {
        println!(
            "  {}  {:width$}  {}",
            c.verdict.tag(),
            c.name,
            c.detail,
            width = widest_name
        );
    }
    let pass = checks.iter().filter(|c| c.verdict == Verdict::Pass).count();
    let warn = checks.iter().filter(|c| c.verdict == Verdict::Warn).count();
    let fail = checks.iter().filter(|c| c.verdict == Verdict::Fail).count();
    let verdict = if fail > 0 {
        "RED"
    } else if warn > 0 {
        "AMBER"
    } else {
        "GREEN"
    };
    println!();
    println!("{pass} PASS, {warn} WARN, {fail} FAIL — {verdict}");
}

// ── individual checks ────────────────────────────────────────

fn check_coordinator(config: &gnet_config::Config, pubkey_hex: &str) -> Check {
    if config.coordinators.is_empty() {
        return Check::warn(
            "coordinator",
            "none configured (static-conf-only — peers must be hand-written)",
        );
    }
    // GET /peers tests reachability AND that this device's pubkey is in the
    // coord's roster (the handler returns 401 for an unknown pubkey). A
    // successful response carries the peer count too, which is a useful
    // sanity number in the doctor's output.
    let mut errs = Vec::new();
    for coord in &config.coordinators {
        match http_get(&format!("{coord}/peers"), pubkey_hex) {
            Ok(body) => {
                let peer_count = body.matches("\"x25519_pubkey\"").count();
                return Check::pass(
                    "coordinator",
                    format!("{coord} /peers OK (pubkey recognised, {peer_count} peer(s))"),
                );
            }
            Err(e) => errs.push(format!("{coord}: {e}")),
        }
    }
    Check::fail(
        "coordinator",
        format!("none reachable: {}", errs.join("; ")),
    )
}

fn check_admin_socket() -> Check {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let path = gnet::node::admin_socket_path();
        match read_admin_snapshot(&path) {
            Ok(snap) => {
                let peer_count = snap.lines().filter(|l| l.starts_with("peer ")).count();
                let est = snap
                    .lines()
                    .filter(|l| l.starts_with("peer "))
                    .filter(|l| l.split(' ').any(|t| t == "session=established"))
                    .count();
                Check::pass(
                    "admin socket",
                    format!(
                        "{} reachable ({est}/{peer_count} peer(s) established)",
                        path.display()
                    ),
                )
            }
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    || e.kind() == io::ErrorKind::ConnectionRefused =>
            {
                Check::warn(
                    "admin socket",
                    format!(
                        "{} unreachable — daemon down or pre-v0.21 ({e})",
                        gnet::node::admin_socket_path().display()
                    ),
                )
            }
            Err(e) => Check::fail("admin socket", format!("read error: {e}")),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Check::warn(
            "admin socket",
            "not supported on this OS (Linux / macOS only)",
        )
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_admin_snapshot(path: &Path) -> io::Result<String> {
    let mut sock = UnixStream::connect(path)?;
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = String::new();
    sock.read_to_string(&mut buf)?;
    Ok(buf)
}

fn check_hosts_block(config: &gnet_config::Config, _pubkey_hex: &str) -> Check {
    let hosts_path = config
        .hosts_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("/etc/hosts"));
    let text = match std::fs::read_to_string(&hosts_path) {
        Ok(t) => t,
        Err(e) => {
            return Check::warn(
                "hosts splice",
                format!("read {}: {e}", hosts_path.display()),
            );
        }
    };
    // markers must match hosts.rs's BEGIN_MARKER / END_MARKER exactly
    let Some(begin) = text.find("# ---BEGIN gnet---") else {
        return Check::warn(
            "hosts splice",
            format!(
                "no gnet block in {} — daemon discovery may not have polled yet",
                hosts_path.display()
            ),
        );
    };
    let Some(end) = text[begin..].find("# ---END gnet---") else {
        return Check::fail(
            "hosts splice",
            format!(
                "BEGIN marker without matching END in {}",
                hosts_path.display()
            ),
        );
    };
    let block = &text[begin..begin + end];
    let entries = block
        .lines()
        .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()) || l.starts_with("fd"))
        .count();
    Check::pass(
        "hosts splice",
        format!("{} carries {} entry line(s)", hosts_path.display(), entries),
    )
}

fn check_service_unit() -> Check {
    #[cfg(target_os = "linux")]
    {
        let out = Command::new("systemctl")
            .arg("is-active")
            .arg("gnet@main")
            .output();
        match out {
            Ok(o) => {
                let state = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if state == "active" {
                    Check::pass("service unit", "gnet@main: active")
                } else {
                    Check::warn("service unit", format!("gnet@main: {state}"))
                }
            }
            Err(e) => Check::warn("service unit", format!("systemctl not available: {e}")),
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("launchctl")
            .arg("print")
            .arg("system/com.gnet.gnet")
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let txt = String::from_utf8_lossy(&o.stdout);
                let state = txt
                    .lines()
                    .find(|l| l.trim_start().starts_with("state ="))
                    .map(|l| l.split('=').nth(1).unwrap_or("?").trim().to_string())
                    .unwrap_or_else(|| "unknown".into());
                Check::pass("service unit", format!("com.gnet.gnet: {state}"))
            }
            Ok(_) => Check::warn(
                "service unit",
                "com.gnet.gnet: not bootstrapped in system domain",
            ),
            Err(e) => Check::warn("service unit", format!("launchctl failed: {e}")),
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Check::warn("service unit", "not supported on this OS")
    }
}

// ── small helpers ────────────────────────────────────────────

fn http_get(url: &str, pubkey_hex: &str) -> io::Result<String> {
    let out = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--fail-with-body")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("10")
        .arg("-H")
        .arg(format!("X-Device-Pubkey: {pubkey_hex}"))
        .arg(url)
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::other(format!(
            "exit {:?}: {}",
            out.status.code(),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
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
        Ok(Options { conf })
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
    fn verdict_aggregation_red_when_any_fail() {
        let checks = [
            Check::pass("a", ""),
            Check::warn("b", ""),
            Check::fail("c", ""),
        ];
        let fail = checks.iter().any(|c| c.verdict == Verdict::Fail);
        assert!(fail);
    }

    #[test]
    fn verdict_aggregation_amber_when_warn_no_fail() {
        let checks = [Check::pass("a", ""), Check::warn("b", "")];
        let fail = checks.iter().any(|c| c.verdict == Verdict::Fail);
        let warn = checks.iter().any(|c| c.verdict == Verdict::Warn);
        assert!(!fail && warn);
    }

    #[test]
    fn options_parses_conf_override() {
        let args = vec![
            "gnet".to_string(),
            "doctor".to_string(),
            "--conf".to_string(),
            "/custom/path".to_string(),
        ];
        let opts = Options::parse(&args).unwrap();
        assert_eq!(opts.conf, PathBuf::from("/custom/path"));
    }

    #[test]
    fn options_defaults_to_platform_path_when_omitted() {
        let args = vec!["gnet".to_string(), "doctor".to_string()];
        let opts = Options::parse(&args).unwrap();
        assert_eq!(opts.conf, default_conf_path());
    }
}
