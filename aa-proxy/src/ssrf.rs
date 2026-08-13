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
//!
//! The blocked-range set itself lives in [`aa_core::net`] so this CONNECT guard
//! and the webhook-destination egress guard in `aa-api` share one definition
//! and can't drift apart (AAASM-4859). This module re-exports it for the
//! proxy's existing call sites.

pub use aa_core::net::{blocked_ip_literal, is_blocked_ip};

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
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("0.1.2.3".parse().unwrap()));
        assert!(is_blocked_ip("0.255.255.255".parse().unwrap()));
    }

    #[test]
    fn nat64_well_known_prefix_is_blocked() {
        assert!(is_blocked_ip("64:ff9b::a00:1".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::a9fe:a9fe".parse().unwrap()));
        assert!(is_blocked_ip("64:ff9b::".parse().unwrap()));
    }

    #[test]
    fn six_to_four_2002_16_is_blocked() {
        assert!(is_blocked_ip("2002:0a00:0001::1".parse().unwrap()));
        assert!(is_blocked_ip("2002:a9fe:a9fe::1".parse().unwrap()));
    }

    #[test]
    fn ipv4_compatible_ipv6_is_blocked() {
        assert!(is_blocked_ip("::a00:1".parse().unwrap()));
        assert!(is_blocked_ip("::a9fe:a9fe".parse().unwrap()));
        assert!(is_blocked_ip("::808:808".parse().unwrap()));
    }

    #[test]
    fn public_ips_are_allowed() {
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("2606:4700:4700::1111".parse().unwrap()));
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn blocked_ip_literal_distinguishes_names() {
        assert_eq!(blocked_ip_literal("169.254.169.254"), Some(true));
        assert_eq!(blocked_ip_literal("8.8.8.8"), Some(false));
        assert_eq!(blocked_ip_literal("api.openai.com"), None);
    }
}
