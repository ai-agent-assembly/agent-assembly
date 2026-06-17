//! SSRF guard for the CONNECT path.
//!
//! The proxy dials arbitrary upstream hosts on behalf of an agent. Without a
//! filter, an agent could coax the proxy into reaching the host's own loopback
//! services, private RFC-1918 networks, link-local addresses, or — most
//! dangerously — the cloud metadata endpoint (`169.254.169.254`), turning the
//! proxy into a confused deputy for SSRF and credential exfiltration.
//!
//! Two checks are needed because a hostname-only allowlist cannot stop this:
//!
//! 1. **Literal check** — a CONNECT target may be an IP literal
//!    (`CONNECT 169.254.169.254:80`); reject it before resolution.
//! 2. **Resolved-IP re-validation** — a hostname that passes the allowlist can
//!    still resolve to a blocked address, and a DNS-rebinding attacker can flip
//!    the answer between the policy check and the dial. We therefore re-validate
//!    every resolved address immediately before connecting.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` when `ip` is in a range the proxy must never dial on an
/// agent's behalf: loopback, private (RFC 1918 / unique-local), link-local
/// (including the `169.254.169.254` cloud metadata endpoint), unspecified,
/// broadcast, or other non-globally-routable space.
///
/// Fail-closed: any address whose reachability is not unambiguously public is
/// treated as blocked.
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        // Map IPv4-mapped forms back to v4 so `::ffff:127.0.0.1` and
        // `::ffff:169.254.169.254` cannot smuggle a blocked v4 past the filter.
        // Only `to_ipv4_mapped` is used — the deprecated `to_ipv4` also maps
        // `::1` to `0.0.0.1`, which would slip IPv6 loopback past the v4 path.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => is_blocked_ipv4(v4),
            None => is_blocked_ipv6(v6),
        },
    }
}

fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        // Carrier-grade NAT (100.64.0.0/10) — not globally routable.
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        // Unique-local (fc00::/7).
        || (v6.segments()[0] & 0xfe00) == 0xfc00
        // Link-local (fe80::/10).
        || (v6.segments()[0] & 0xffc0) == 0xfe80
}

/// When `host` is an IP literal, returns whether it is blocked. Returns `None`
/// when `host` is not an IP literal (i.e. a name that must be resolved and
/// re-validated separately).
pub fn blocked_ip_literal(host: &str) -> Option<bool> {
    host.parse::<IpAddr>().ok().map(is_blocked_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_endpoint_is_blocked() {
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn loopback_is_blocked() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));
    }

    #[test]
    fn rfc1918_is_blocked() {
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.5.4".parse().unwrap()));
        assert!(is_blocked_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn link_local_and_cgnat_are_blocked() {
        assert!(is_blocked_ip("169.254.1.1".parse().unwrap()));
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("fc00::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_mapped_v6_cannot_smuggle_blocked_v4() {
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn public_ips_are_allowed() {
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_literal_distinguishes_names() {
        assert_eq!(blocked_ip_literal("169.254.169.254"), Some(true));
        assert_eq!(blocked_ip_literal("8.8.8.8"), Some(false));
        assert_eq!(blocked_ip_literal("api.openai.com"), None);
    }
}
