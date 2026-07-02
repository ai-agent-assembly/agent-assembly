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
        // "This network" (0.0.0.0/8) — non-routable source space; on many
        // stacks 0.x.x.x is treated as loopback/local. `is_unspecified` only
        // covers the single 0.0.0.0, so block the whole /8 (AAASM-3997).
        || v4.octets()[0] == 0
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    let seg = v6.segments();
    v6.is_loopback()
        || v6.is_unspecified()
        // Unique-local (fc00::/7).
        || (seg[0] & 0xfe00) == 0xfc00
        // Link-local (fe80::/10).
        || (seg[0] & 0xffc0) == 0xfe80
        // NAT64 well-known prefix (64:ff9b::/96): embeds an IPv4 in the low 32
        // bits that a translator forwards to — an attacker can embed an
        // internal IPv4 here, so reject the whole prefix (AAASM-3997).
        || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0)
        // 6to4 (2002::/16): embeds an IPv4 in seg[1..3] that could be internal;
        // reject the whole range rather than trust the embedded address.
        || seg[0] == 0x2002
        // IPv4-compatible IPv6 (::/96, deprecated): the low 32 bits are an IPv4
        // literal, so `::a.b.c.d` could smuggle an internal v4. `::`/`::1` are
        // already covered above; this catches the rest of ::/96.
        || (seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0)
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
    fn this_network_0_0_0_0_8_is_blocked() {
        // 0.0.0.0/8 — "this network"; not just the single unspecified address.
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("0.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("0.255.255.255".parse().unwrap()));
    }

    #[test]
    fn nat64_well_known_prefix_is_blocked() {
        // 64:ff9b::/96 embedding 10.0.0.1 and 169.254.169.254.
        assert!(is_blocked_ip("64:ff9b::a00:1".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::a9fe:a9fe".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::".parse().unwrap()));
    }

    #[test]
    fn six_to_four_2002_16_is_blocked() {
        // 2002::/16 (6to4) embedding a private and a metadata v4.
        assert!(is_blocked_ip("2002:0a00:0001::1".parse().unwrap()));
        assert!(is_blocked_ip("2002:a9fe:a9fe::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_compatible_ipv6_is_blocked() {
        // ::/96 (deprecated IPv4-compatible) — low 32 bits are an IPv4 literal.
        assert!(is_blocked_ip("::a00:1".parse().unwrap())); // ::10.0.0.1
        assert!(is_blocked_ip("::a9fe:a9fe".parse().unwrap())); // ::169.254.169.254
        assert!(is_blocked_ip("::808:808".parse().unwrap())); // ::8.8.8.8 — still deprecated space
    }

    #[test]
    fn public_ips_are_allowed() {
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
        // A global IPv6 that merely starts with 0x20 (but is not 6to4/2002) stays allowed.
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_literal_distinguishes_names() {
        assert_eq!(blocked_ip_literal("169.254.169.254"), Some(true));
        assert_eq!(blocked_ip_literal("8.8.8.8"), Some(false));
        assert_eq!(blocked_ip_literal("api.openai.com"), None);
    }
}
