//! Enumerate the host's IP addresses by shelling out to the platform's
//! network tool (`ip` on Linux, `ifconfig` on macOS).
//!
//! Used by the NAT-detection path: after `note_reflexive` learns our
//! observed-by-others endpoint, we compare its IP to the addresses on
//! our own interfaces. A match means we are sitting directly on the
//! public Internet (or in a non-rewriting NAT — same thing for path
//! selection). A miss means we are behind a NAT that rewrote our source
//! address, and we must use coordinator-mediated punch (`gnet-punch`)
//! to talk to other NAT'd peers — direct init from one NAT to another
//! cold-starts only by accident.
//!
//! Hand-rolled string parsing rather than pulling in the `if_addrs`
//! crate, in keeping with the gnet stack's no-external-deps rule. The
//! call runs at most a handful of times over a daemon's lifetime
//! (each reflexive change triggers one), so we accept the fork+exec
//! cost.

use std::net::IpAddr;
use std::process::Command;

/// Collect every IPv4 / IPv6 address bound to a local interface. Returns
/// an empty vec if the platform tool is missing or its output cannot be
/// parsed — the caller treats that as "do not know, assume NAT'd"
/// (the safer default: an extra DCUtR round-trip is cheap, a missed
/// punch is permanent breakage).
pub(super) fn list_local_ips() -> Vec<IpAddr> {
    if let Some(ips) = try_ip_command() {
        return ips;
    }
    try_ifconfig_command().unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn try_ip_command() -> Option<Vec<IpAddr>> {
    let out = Command::new("ip")
        .arg("-o")
        .arg("addr")
        .arg("show")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_ip_output(&String::from_utf8_lossy(&out.stdout)))
}

#[cfg(not(target_os = "linux"))]
fn try_ip_command() -> Option<Vec<IpAddr>> {
    None
}

fn try_ifconfig_command() -> Option<Vec<IpAddr>> {
    let out = Command::new("ifconfig").arg("-a").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_ifconfig_output(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse `ip -o addr show` output. Each line is one address:
///
/// ```text
/// 1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever ...
/// 1: lo    inet6 ::1/128 scope host \       valid_lft forever ...
/// 2: eth0  inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft ...
/// ```
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_ip_output(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        // tokens after `inet`/`inet6` may carry a /prefix — strip it.
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "inet" || tok == "inet6" {
                if let Some(addr_with_prefix) = tokens.next() {
                    let addr = addr_with_prefix.split('/').next().unwrap_or(addr_with_prefix);
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
                break;
            }
        }
    }
    out
}

/// Parse `ifconfig -a` output. Each interface block has one or more
/// `inet`/`inet6` lines:
///
/// ```text
/// utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
///     inet 10.42.42.4 --> 10.42.42.4 netmask 0xff000000
///     inet6 fe80::d211:e5ff:fe21:73a%utun5 prefixlen 64 ...
/// ```
///
/// We need only the first IP token after `inet`/`inet6`; macOS dumps
/// IPv6 zone IDs (`%utun5`) which we strip.
fn parse_ifconfig_output(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "inet" || tok == "inet6" {
                if let Some(addr) = tokens.next() {
                    // strip IPv6 zone id (`fe80::1%utun5`) and any prefix
                    let addr = addr.split('%').next().unwrap_or(addr);
                    let addr = addr.split('/').next().unwrap_or(addr);
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_linux_output() {
        let sample = "1: lo    inet 127.0.0.1/8 scope host lo\n\
                      1: lo    inet6 ::1/128 scope host\n\
                      2: eth0  inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n\
                      2: eth0  inet6 fe80::5054:ff:feaa:bbcc/64 scope link\n";
        let ips = parse_ip_output(sample);
        assert_eq!(ips.len(), 4);
        assert!(ips.contains(&"127.0.0.1".parse().unwrap()));
        assert!(ips.contains(&"::1".parse().unwrap()));
        assert!(ips.contains(&"10.0.0.5".parse().unwrap()));
        assert!(ips.contains(&"fe80::5054:ff:feaa:bbcc".parse().unwrap()));
    }

    #[test]
    fn parse_ifconfig_macos_output() {
        let sample = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\
                      \tinet 127.0.0.1 netmask 0xff000000\n\
                      \tinet6 ::1 prefixlen 128\n\
                      \tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n\
                      en0: flags=8863<UP,BROADCAST,...> mtu 1500\n\
                      \tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n\
                      utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500\n\
                      \tinet 10.42.42.4 --> 10.42.42.4 netmask 0xff000000\n\
                      \tinet6 fd8d:f090:2ebb::4 prefixlen 64\n";
        let ips = parse_ifconfig_output(sample);
        assert!(ips.contains(&"127.0.0.1".parse().unwrap()));
        assert!(ips.contains(&"::1".parse().unwrap()));
        assert!(ips.contains(&"fe80::1".parse().unwrap()), "zone id stripped");
        assert!(ips.contains(&"192.168.1.42".parse().unwrap()));
        assert!(ips.contains(&"10.42.42.4".parse().unwrap()));
        assert!(ips.contains(&"fd8d:f090:2ebb::4".parse().unwrap()));
    }

    #[test]
    fn parse_empty_returns_empty() {
        assert!(parse_ip_output("").is_empty());
        assert!(parse_ifconfig_output("").is_empty());
    }

    #[test]
    fn parse_handles_malformed_lines_gracefully() {
        let bogus = "garbage line\n   inet notanip\n   inet6 also-not-an-ip\n";
        assert!(parse_ip_output(bogus).is_empty());
        assert!(parse_ifconfig_output(bogus).is_empty());
    }

    #[test]
    fn list_local_ips_returns_at_least_loopback() {
        // The host running this test always has at least 127.0.0.1.
        let ips = list_local_ips();
        if !ips.is_empty() {
            assert!(
                ips.contains(&"127.0.0.1".parse().unwrap())
                    || ips.contains(&"::1".parse().unwrap()),
                "expected loopback in {ips:?}"
            );
        }
        // (empty result acceptable: the test environment may lack ip/ifconfig)
    }
}
