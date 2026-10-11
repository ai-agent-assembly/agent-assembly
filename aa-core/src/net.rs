//! Shared SSRF IP blocklist (AAASM-4859).
//!
//! Every enforcement mechanism that dials an address on an agent's (or operator's)
//! behalf must refuse the same set of non-globally-routable ranges — otherwise
//! an attacker coaxes one mechanism into reaching loopback services, RFC-1918
//! networks, or the cloud metadata endpoint (`169.254.169.254`) for a confused-
//! deputy SSRF.
//!
//! This module is the single source of truth for that range set, so the proxy's
//! CONNECT guard (`aa-proxy/src/ssrf.rs`) and the webhook-destination egress
//! guard (`aa-api/src/destinations/validate.rs`) can't drift apart again — the
//! original drift is exactly what AAASM-4859 fixed, where the AAASM-3997
//! hardening lived only in the proxy.
//!
//! Fail-closed: any address whose reachability is not unambiguously public is
//! treated as blocked. Lives in `aa-core` (`no_std` via `core::net`) so it
//! carries no I/O or std dependency.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns `true` when `ip` is in a range no interception layer may dial on
/// another party's behalf: loopback, private (RFC 1918 / unique-local),
/// link-local (including the `169.254.169.254` cloud metadata endpoint),
/// unspecified, broadcast, documentation, CGNAT, or other non-globally-routable
/// space — including IPv6 encodings that embed an internal IPv4.
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

/// Returns `true` when the IPv4 address is in a range that must never be dialed.
///
/// See [`is_blocked_ip`] for the rationale; the ranges beyond the standard
/// loopback/private/link-local set (CGNAT `100.64.0.0/10` and `0.0.0.0/8`) were
/// added under AAASM-3997.
pub fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
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

/// Returns `true` when the IPv6 address is in a range that must never be dialed.
///
/// Beyond loopback/unspecified/ULA/link-local, this rejects the transition
/// prefixes (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible `::/96`)
/// that can embed an internal IPv4 a translator would forward to (AAASM-3997).
pub fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
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
    parse_ip_literal(host).map(is_blocked_ip)
}

/// Parse `host` as an IP literal under the same rules the platform resolver
/// applies, not just `std`'s strict dotted-quad grammar (AAASM-6304).
///
/// `std`'s `FromStr<IpAddr>` rejects the legacy `inet_aton` IPv4 notations that
/// `getaddrinfo`/`connect` paths (libc, and many HTTP clients) still accept:
/// a single decimal integer (`2852039166`), hex (`0xA9FEA9FE`), octal
/// (`0251.0376.0251.0376`) and short forms (`169.254.43518`). Classifying such a
/// string as a *name* lets `169.254.169.254` reach the dialer without ever being
/// range-checked, so the check and the use must agree on what an IP literal is.
///
/// Accepts, after trimming surrounding whitespace and one trailing dot: anything
/// `std` accepts (including `::ffff:a9fe:a9fe`), plus 1-4 part `inet_aton`
/// IPv4 (each part decimal, `0`-prefixed octal or `0x`-prefixed hex, the last
/// part filling the remaining bytes). Returns `None` for everything else, which
/// is then a name that must be resolved and re-validated.
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let host = host.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    parse_inet_aton(host).map(IpAddr::V4)
}

fn parse_inet_aton(host: &str) -> Option<Ipv4Addr> {
    let mut parts = [0u64; 4];
    let mut n = 0;
    for part in host.split('.') {
        if n == 4 {
            return None;
        }
        parts[n] = parse_inet_aton_part(part)?;
        n += 1;
    }
    // Every part but the last is one byte; the last fills the remaining bytes.
    let (leading, last) = parts[..n].split_at(n - 1);
    if leading.iter().any(|&p| p > 0xff) || last[0] >= 1u64 << (8 * (5 - n)) {
        return None;
    }
    let mut value = last[0];
    for (i, &p) in leading.iter().enumerate() {
        value |= p << (8 * (3 - i));
    }
    Some(Ipv4Addr::from(value as u32))
}

fn parse_inet_aton_part(part: &str) -> Option<u64> {
    let (digits, radix) = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        (hex, 16)
    } else if part.len() > 1 && part.starts_with('0') {
        (&part[1..], 8)
    } else {
        (part, 10)
    };
    if digits.is_empty() {
        // `0x` alone is zero under inet_aton; a bare empty label is not a number.
        return if radix == 16 { Some(0) } else { None };
    }
    // `from_str_radix` also accepts a leading `+`; a numeric label is digits only.
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix)
        .ok()
        .filter(|&v| v <= u64::from(u32::MAX))
}

/// Strip an optional `:port` suffix from a host, correctly handling a bracketed
/// IPv6 literal (AAASM-4829, moved from `aa-proxy` under AAASM-6163 so the
/// egress contract in `aa-isolation` can canonicalize a destination without a
/// dependency on `aa-proxy`).
///
/// A bare `host.split(':').next()` mangles IPv6 literals: `[::1]:443` becomes
/// `[`, which both lets a CONNECT-time SSRF check miss the real address (it can
/// no longer `parse::<IpAddr>()`) and over-blocks legitimate IPv6 under a
/// denylist. This unwraps the brackets and drops the port so the returned value
/// is the real literal (`::1`).
///
/// Rules:
/// - `[<ipv6>]:port` / `[<ipv6>]` → `<ipv6>` (brackets and port removed).
/// - `host:port` (single `:`) → `host`.
/// - a bare, unbracketed IPv6 literal (multiple `:`, no brackets) is returned
///   whole — an IPv6 address requires brackets to carry a port, so every colon
///   is part of the address.
/// - anything else is returned unchanged (trimmed).
///
/// `no_std`-clean: no allocation, borrows from `host`.
pub fn strip_host_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // Bracketed IPv6 literal — take the text up to the closing bracket,
        // discarding any `:port` that follows it. A malformed value with no
        // closing bracket falls back to the un-bracketed remainder.
        return match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest,
        };
    }
    match host.rfind(':') {
        // More than one colon and no brackets → bare IPv6 literal, no port.
        Some(idx) if host[..idx].contains(':') => host,
        Some(idx) => &host[..idx],
        None => host,
    }
}

/// Canonicalize a host for denylist/allowlist comparison: strip the port
/// (bracket-aware), a single trailing dot, and lowercase (AAASM-3983, moved
/// from `aa-proxy` under AAASM-6163).
#[cfg(feature = "alloc")]
pub fn canonical_host(host: &str) -> alloc::string::String {
    let no_port = strip_host_port(host);
    let no_dot = no_port.strip_suffix('.').unwrap_or(no_port);
    no_dot.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "alloc")]
    fn canonical_host_strips_port_trailing_dot_and_case() {
        // AAASM-3983: port, single trailing dot, and case are all normalised.
        assert_eq!(canonical_host("EVIL.COM"), "evil.com");
        assert_eq!(canonical_host("evil.com."), "evil.com");
        assert_eq!(canonical_host("Evil.Com.:443"), "evil.com");
        assert_eq!(canonical_host("evil.com"), "evil.com");
    }

    #[test]
    fn strip_host_port_handles_bracketed_ipv6() {
        // AAASM-4829: a bracketed IPv6 literal must yield the real address, not
        // the mangled `[` that `split(':')` produced.
        assert_eq!(strip_host_port("[::1]:443"), "::1");
        assert_eq!(strip_host_port("[::1]"), "::1");
        assert_eq!(strip_host_port("[2001:db8::1]:8443"), "2001:db8::1");
        // Bare (unbracketed) IPv6 literal has no port — every colon is address.
        assert_eq!(strip_host_port("::1"), "::1");
        assert_eq!(strip_host_port("2001:db8::1"), "2001:db8::1");
        // IPv4 / DNS host:port and bare hosts behave as before.
        assert_eq!(strip_host_port("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(strip_host_port("api.openai.com:443"), "api.openai.com");
        assert_eq!(strip_host_port("api.openai.com"), "api.openai.com");
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn canonical_host_preserves_bracketed_ipv6_literal() {
        // AAASM-4829: the previous `split(':')` mangled `[::1]:443` into `[`,
        // breaking both denylist compares and the SSRF check.
        assert_eq!(canonical_host("[::1]:443"), "::1");
        assert_eq!(canonical_host("[2001:DB8::1]:8443"), "2001:db8::1");
    }

    #[test]
    fn numeric_ipv4_encodings_of_the_metadata_address_are_blocked_literals() {
        // AAASM-6304: every inet_aton spelling of 169.254.169.254.
        for v in [
            "2852039166",
            "0xA9FEA9FE",
            "0Xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.43518",
            "169.16689662",
            "0xA9.0xFE.0xA9.0xFE",
            "169.0xFE.169.254",
            "025177524776",
            "2852039166.",
            " 2852039166 ",
            "::ffff:a9fe:a9fe",
            "::FFFF:169.254.169.254",
        ] {
            assert_eq!(blocked_ip_literal(v), Some(true), "{v:?} must be a blocked literal");
        }
    }

    #[test]
    fn numeric_ipv4_encodings_parse_to_the_right_address() {
        let a = |s: &str| parse_ip_literal(s);
        assert_eq!(a("2130706433"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(a("0x7f.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(a("0"), Some("0.0.0.0".parse().unwrap()));
        assert_eq!(a("134744072"), Some("8.8.8.8".parse().unwrap()));
        assert_eq!(a("4294967295"), Some("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn numeric_encodings_of_a_public_address_are_not_blocked() {
        assert_eq!(blocked_ip_literal("134744072"), Some(false));
        assert_eq!(blocked_ip_literal("0x08080808"), Some(false));
        assert_eq!(blocked_ip_literal("8.8.8.8"), Some(false));
        assert_eq!(blocked_ip_literal("8.526344"), Some(false));
    }

    #[test]
    fn non_numeric_or_malformed_strings_stay_names() {
        for v in [
            "api.openai.com",
            "0x.com",
            "1.2.3.4.5",
            "4294967296",
            "256.1.1.1",
            "1.16777216",
            "1.2.3.65536",
            "08",
            "0xg1",
            "+1",
            "1..2",
            "",
            ".",
            "1.2.3.4x",
            "-1",
            "169.254.169.254/latest",
        ] {
            assert_eq!(blocked_ip_literal(v), None, "{v:?} must remain a name");
        }
    }

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
