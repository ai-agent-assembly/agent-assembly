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

/// Parse `host` as an IP literal the way the platform resolver may, not just
/// `std`'s strict dotted-quad grammar (AAASM-6304).
///
/// `std`'s `FromStr<IpAddr>` rejects legacy IPv4 notations that
/// `getaddrinfo`/`connect` paths still accept: a single decimal integer
/// (`2852039166`), hex (`0xA9FEA9FE`), octal (`0251.0376.0251.0376`) and short
/// forms (`169.254.43518`). Classifying such a string as a *name* lets
/// `169.254.169.254` reach the dialer without a range check, so the check and
/// the use must agree on what an IP literal is.
///
/// Resolvers disagree with each other on the edge cases, so the contract is
/// **fail closed**: a numeric-looking host is reported as a public address only
/// when every plausible interpretation yields that one public address. When
/// interpretations differ, the restricted one wins; when they differ and none
/// is restricted (or a value needed truncation), `0.0.0.0` is returned so the
/// caller refuses it. The interpretations are:
///
/// * `inet_aton`: `0x` hex, leading-`0` octal, otherwise decimal, 1-4 parts,
///   the last part filling the remaining bytes;
/// * macOS `getaddrinfo`: a leading-zero part is read as *decimal* (so
///   `0127.0.0.1` is `127.0.0.1`, not `87.0.0.1`), including parts with the
///   digits 8/9 that are not valid octal;
/// * a single value of 2^32 or more, which macOS truncates to its low 32 bits.
///
/// Also accepted: surrounding whitespace, one trailing dot, an IPv6 zone id
/// (`fe80::1%en0`, classified by its address), and anything `std` accepts
/// (including `::ffff:a9fe:a9fe`). Returns `None` for everything else, which is
/// a name that must be resolved and re-validated.
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim();
    let inner = trimmed.strip_suffix('.').unwrap_or(trimmed);
    // Only a spelling a resolver really accepts may be reported as a public
    // address. Whitespace padding and a trailing dot are tolerated so a
    // restricted address is still caught, but a *public* result for such a
    // spelling is refused (`0.0.0.0`): libc rejects `8.8.8.8.` and ` 64.1`, so
    // reporting them routable would skip the name-resolution path.
    let non_canonical = inner.len() != host.len();
    let ip = parse_ip_literal_inner(inner)?;
    if non_canonical && !is_blocked_ip(ip) {
        return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    Some(ip)
}

fn parse_ip_literal_inner(host: &str) -> Option<IpAddr> {
    // A zone id only exists on an IPv6 literal and `getaddrinfo` ignores
    // whatever follows the `%` (even whitespace), so classify the address part.
    if let Some((addr, _zone)) = host.split_once('%') {
        if addr.contains(':') {
            if let Ok(v6) = addr.parse::<Ipv6Addr>() {
                return Some(IpAddr::V6(v6));
            }
            if looks_like_ipv6_text(addr) {
                return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            }
            // Not IPv6 text (e.g. `20<TAB>1:4860::8%x`): fall through so a
            // whitespace-terminated IPv4 head is still judged.
        }
    }
    if host.contains(char::is_whitespace) {
        // `inet_aton`/`inet_addr` stop at the first whitespace and ignore the
        // rest (`127.0.0.1 x`), `getaddrinfo` rejects the whole string. Only a
        // restricted head matters: anything else is a name.
        let head = host.split(char::is_whitespace).next().unwrap_or("");
        return legacy_ipv4(head).map(IpAddr::V4).filter(|a| is_blocked_ip(*a));
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    // `getaddrinfo` accepts IPv6 spellings `std` rejects: leading zeros in a
    // group (`0fe80::1`, `::ffff:0a9fe:a9fe`) or in a dotted tail
    // (`::ffff:127.0.0.001`). Modelling each by hand has failed review three
    // times, so fail closed structurally: a colon-bearing string of nothing but
    // hex digits, colons and dots that `std` did not accept is refused, since
    // it is either one of those spellings or not a usable address at all and
    // can never be a DNS name.
    if looks_like_ipv6_text(host) {
        return Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    legacy_ipv4(host).map(IpAddr::V4)
}

/// True for IPv6-shaped text: a colon, only hex digits, `:` and `.`, and not a
/// `host:port` pair (exactly one colon followed by digits).
fn looks_like_ipv6_text(s: &str) -> bool {
    if !s.contains(':') || !s.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
        return false;
    }
    let mut colons = s.split(':');
    let head_and_tail = (colons.next(), colons.next(), colons.next());
    let is_port_pair = matches!(head_and_tail, (Some(_), Some(port), None) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()));
    !is_port_pair
}

/// How a part with a leading `0` is read.
#[derive(Clone, Copy)]
enum LeadingZero {
    /// `inet_aton`: octal (a part with an 8/9 digit is invalid).
    Octal,
    /// macOS `getaddrinfo`: decimal.
    Decimal,
}

fn legacy_ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut readings = [None::<Ipv4Addr>; 2];
    let mut truncated = false;
    let mut any = false;
    for (slot, mode) in readings.iter_mut().zip([LeadingZero::Octal, LeadingZero::Decimal]) {
        if let Some((addr, t)) = compose_ipv4(host, mode) {
            *slot = Some(addr);
            truncated |= t;
            any = true;
        }
    }
    if !any {
        return None;
    }
    // Fail closed: a blocked reading wins over any public one.
    if let Some(blocked) = readings.iter().flatten().copied().find(|a| is_blocked_ipv4(*a)) {
        return Some(blocked);
    }
    let first = readings.iter().flatten().copied().next()?;
    let disagree = readings.iter().flatten().any(|a| *a != first);
    // A lone leading-zero value with an 8/9 digit (`0123456789`) is invalid
    // octal and libc rejects it; only the decimal reading survives, which no
    // resolver backs, so a public result is refused rather than called routable.
    let decimal_only_lone = readings[0].is_none() && !host.contains('.');
    if truncated || disagree || decimal_only_lone {
        // Ambiguous between public-looking readings: report an address in a
        // blocked range so the caller refuses rather than guesses.
        return Some(Ipv4Addr::UNSPECIFIED);
    }
    Some(first)
}

/// One reading of `host` as 1-4 dot-separated numeric parts. The boolean is
/// true when the value only fits after truncation to 32 bits.
fn compose_ipv4(host: &str, mode: LeadingZero) -> Option<(Ipv4Addr, bool)> {
    if matches!(mode, LeadingZero::Decimal) {
        // `getaddrinfo` reads leading zeros as decimal only for a lone value or
        // a full four-part decimal quad (observed on macOS); `08.1` is rejected.
        let n = host.split('.').count();
        let all_decimal = host
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        if !(all_decimal && (n == 1 || n == 4)) {
            return None;
        }
    }
    let mut parts = [(0u64, false); 4];
    let mut n = 0;
    let total = host.split('.').count();
    for part in host.split('.') {
        if n == 4 {
            return None;
        }
        parts[n] = parse_numeric_part(part, mode, n + 1 == total)?;
        n += 1;
    }
    if n == 1 {
        // A lone value: libc keeps only the low 32 bits, however long it is.
        let (low, big) = parts[0];
        return Some((Ipv4Addr::from(low as u32), big));
    }
    // Each part wraps modulo 2^64 exactly as macOS `inet_aton` accumulates it,
    // and only the wrapped value is range-checked below, so
    // `169.254.169.18446744073709551870` (2^64 + 254) is 169.254.169.254 while
    // `169.254.169.4294967550` (a value that does not wrap) is out of range.
    // Every part but the last is one byte; the last fills the remaining bytes.
    let (leading, last) = parts[..n].split_at(n - 1);
    if leading.iter().any(|&(p, _)| p > 0xff) || last[0].0 >= 1u64 << (8 * (5 - n)) {
        return None;
    }
    let mut value = last[0].0;
    for (i, &(p, _)) in leading.iter().enumerate() {
        value |= p << (8 * (3 - i));
    }
    Some((Ipv4Addr::from(value as u32), false))
}

/// A numeric part as `(value wrapped modulo 2^64, did it exceed 32 bits)`.
/// Arbitrarily long digit strings wrap exactly as libc's accumulator does, so a value of 2^64 or
/// more is not silently treated as "not a number".
fn parse_numeric_part(part: &str, mode: LeadingZero, is_last: bool) -> Option<(u64, bool)> {
    let (digits, radix) = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        (hex, 16u32)
    } else if part.len() > 1 && part.starts_with('0') {
        match mode {
            LeadingZero::Octal => (&part[1..], 8),
            LeadingZero::Decimal => (part, 10),
        }
    } else {
        (part, 10)
    };
    if digits.is_empty() {
        // Observed on macOS: a bare `0x` is zero in a non-final part (`0x.1` is
        // 0.0.0.1) but rejected as the final part (`1.0x`); an empty label is
        // never a number.
        return if radix == 16 && !is_last {
            Some((0, false))
        } else {
            None
        };
    }
    let mut low = 0u64;
    let mut exact = Some(0u64);
    for c in digits.chars() {
        // `to_digit` is digits/letters only, so no sign or underscore slips in.
        let d = c.to_digit(radix)?;
        low = low.wrapping_mul(u64::from(radix)).wrapping_add(u64::from(d));
        exact = exact.and_then(|e| e.checked_mul(u64::from(radix))?.checked_add(u64::from(d)));
    }
    let big = exact.map_or(true, |e| e > u64::from(u32::MAX));
    Some((low, big))
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
            "256.1.1.1",
            "1.16777216",
            "1.2.3.65536",
            "0xg1",
            "+1",
            "1..2",
            "",
            ".",
            "1.2.3.4x",
            "-1",
            "1.2.3.4%lo0",
            "evil.com%lo0",
            "169.254.169.254/latest",
        ] {
            assert_eq!(blocked_ip_literal(v), None, "{v:?} must remain a name");
        }
    }

    /// Differential table (AAASM-6304 review). `libc` is what macOS
    /// `getaddrinfo`/`inet_aton` was OBSERVED to resolve the string to; glibc
    /// and other resolvers may differ, which is why the classifier fails closed
    /// instead of copying one platform. `None` = libc rejects it. Invariant
    /// checked for every row: if libc's address is restricted, the host must be
    /// classified restricted. `Expect` pins our own (possibly stricter) verdict.
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Expect {
        Restricted,
        Public,
        Name,
    }

    #[test]
    fn differential_table_against_observed_macos_libc() {
        use Expect::*;
        let table: &[(&str, Option<&str>, Expect)] = &[
            // Ticket spellings of 169.254.169.254.
            ("2852039166", Some("169.254.169.254"), Restricted),
            ("0xA9FEA9FE", Some("169.254.169.254"), Restricted),
            ("0251.0376.0251.0376", Some("169.254.169.254"), Restricted),
            ("169.254.43518", Some("169.254.169.254"), Restricted),
            ("169.16689662", Some("169.254.169.254"), Restricted),
            ("0xA9.0xFE.0xA9.0xFE", Some("169.254.169.254"), Restricted),
            ("::ffff:a9fe:a9fe", Some("169.254.169.254"), Restricted),
            // Leading-zero dotted forms: libc reads DECIMAL, inet_aton OCTAL.
            ("0127.0.0.1", Some("127.0.0.1"), Restricted),
            ("010.0.0.1", Some("10.0.0.1"), Restricted),
            ("0172.016.0.1", Some("172.16.0.1"), Restricted),
            ("0100.0100.0100.0100", Some("100.100.100.100"), Restricted),
            ("00127.0.0.1", Some("127.0.0.1"), Restricted),
            ("0127.00.00.01", Some("127.0.0.1"), Restricted),
            // Values of 2^32 or more: libc keeps the low 32 bits.
            ("4294967296", Some("0.0.0.0"), Restricted),
            ("0x100000000", Some("0.0.0.0"), Restricted),
            ("1099511627776", Some("0.0.0.0"), Restricted),
            ("6425673729", Some("127.0.0.1"), Restricted),
            ("0x17F000001", Some("127.0.0.1"), Restricted),
            // Truncates to a PUBLIC address (8.8.8.8): still refused, because
            // a resolver that rejects instead of truncating would disagree.
            ("0x108080808", Some("8.8.8.8"), Restricted),
            // Invalid-octal parts: libc falls back to decimal.
            ("0192.0168.0.1", Some("192.168.0.1"), Restricted),
            ("192.168.0.08", Some("192.168.0.8"), Restricted),
            ("0.008.0010.0254", Some("0.8.10.254"), Restricted),
            ("08", Some("0.0.0.8"), Restricted),
            // IPv6 zone ids.
            ("::1%lo0", Some("::1"), Restricted),
            ("fe80::1%1", Some("fe80::1"), Restricted),
            ("fe80::1%lo0", Some("fe80::1"), Restricted),
            // Over-refusal is acceptable: readings disagree, fail closed.
            ("0177.0.0.1", Some("177.0.0.1"), Restricted),
            ("0251.254.169.254", Some("251.254.169.254"), Restricted),
            ("0100.0.0.1", Some("100.0.0.1"), Restricted),
            // A MULTI-part value also wraps modulo 2^64 (round 4): every row is
            // 169.254.169.254, 127.0.0.1 or 192.168.1.1 to macOS libc.
            ("169.254.169.18446744073709551870", Some("169.254.169.254"), Restricted),
            ("169.254.18446744073709595134", Some("169.254.169.254"), Restricted),
            ("169.18446744073726241278", Some("169.254.169.254"), Restricted),
            ("18446744073709551785.254.169.254", Some("169.254.169.254"), Restricted),
            ("0x100000000000000a9.254.169.254", Some("169.254.169.254"), Restricted),
            ("169.254.169.0x100000000000000fe", Some("169.254.169.254"), Restricted),
            ("127.0.0.18446744073709551617", Some("127.0.0.1"), Restricted),
            ("192.168.1.18446744073709551617", Some("192.168.1.1"), Restricted),
            // 2^32 + k does NOT wrap in a 64-bit accumulator, so libc rejects it.
            ("169.254.169.4294967550", None, Name),
            // Single-colon garbage is refused, not a name (only `host:port` is exempt).
            ("dead:beef", None, Restricted),
            ("a:b", None, Restricted),
            // 2^64 or more: libc still wraps to the low 32 bits (AAASM-6304 re-review).
            ("18446744076561590782", Some("169.254.169.254"), Restricted),
            ("0x100000000a9fea9fe", Some("169.254.169.254"), Restricted),
            ("0x1000000007f000001", Some("127.0.0.1"), Restricted),
            ("0x100000000c0a80101", Some("192.168.1.1"), Restricted),
            ("0x10000000000000000", Some("0.0.0.0"), Restricted),
            ("18446744073709551617", Some("0.0.0.1"), Restricted),
            ("02000000000000000000000", Some("0.0.0.0"), Restricted),
            ("100000000000000000000000000000127", Some("0.0.0.127"), Restricted),
            // An empty zone id is still that IPv6 address.
            ("99999999999999999999999", None, Restricted),
            ("fe80::1%", Some("fe80::1"), Restricted),
            ("::1%", Some("::1"), Restricted),
            // No libc accepts these, so they must never be reported as a routable
            // address (which skips name resolution): Name, or refused.
            // A bare `0x` is zero in a non-final part (libc: `0x.1` is 0.0.0.1).
            ("0x.1", Some("0.0.0.1"), Restricted),
            ("0X.8", Some("0.0.0.8"), Restricted),
            ("08.1", None, Name),
            ("09.1", None, Name),
            ("1.0x", None, Name),
            ("8.8.8.8.", None, Restricted),
            ("1.8.", None, Restricted),
            (" 64.1", None, Restricted),
            // `inet_aton` ignores text after whitespace; a restricted head is refused.
            ("127.0.0.1 x", Some("127.0.0.1"), Restricted),
            ("169.254.169.254 .evil.com", Some("169.254.169.254"), Restricted),
            ("8.8.8.8 x", None, Name),
            // IPv6 spellings getaddrinfo accepts and `std` rejects (round 3).
            ("::ffff:169.254.169.0254", Some("::ffff:169.254.169.254"), Restricted),
            ("::ffff:169.254.169.00254", Some("::ffff:169.254.169.254"), Restricted),
            ("::ffff:127.0.0.001", Some("::ffff:127.0.0.1"), Restricted),
            ("::ffff:0127.0.0.1", Some("::ffff:127.0.0.1"), Restricted),
            ("::0.0.00.1", Some("::1"), Restricted),
            ("::00.0.0.0", Some("::"), Restricted),
            ("::01.1.1.1", Some("::1.1.1.1"), Restricted),
            ("::ffff:0a9fe:a9fe", Some("::ffff:169.254.169.254"), Restricted),
            ("::ffff:a9fe:0a9fe", Some("::ffff:169.254.169.254"), Restricted),
            ("::ffff:00000a9fe:a9fe", Some("::ffff:169.254.169.254"), Restricted),
            ("00000::1", Some("::1"), Restricted),
            ("0fe80::1", Some("fe80::1"), Restricted),
            ("00fe80::1%en0", Some("fe80::1"), Restricted),
            // A zone id is ignored by getaddrinfo whatever it contains.
            ("fe80::1% en", Some("fe80::1"), Restricted),
            ("fe80::1%a b", Some("fe80::1"), Restricted),
            ("fe80::%e\t0", Some("fe80::"), Restricted),
            // inet_aton stops at whitespace even when an IPv6-looking tail follows.
            ("20\t1:4860:4860::88%88", Some("0.0.0.20"), Restricted),
            ("7\t2001:4860:4860:%:8888", Some("0.0.0.7"), Restricted),
            // A lone leading-zero 8/9 value is invalid octal: libc rejects it, so it
            // must never be reported as a routable address.
            ("0123456789", None, Restricted),
            ("0852039166", None, Restricted),
            ("016843009", None, Restricted),
            // `host:port` is not IPv6 text.
            ("api.openai.com:443", None, Name),
            ("1.2.3.4:80", None, Name),
            // Unambiguous public and plain names are unchanged.
            ("134744072", Some("8.8.8.8"), Public),
            ("0x08080808", Some("8.8.8.8"), Public),
            ("8.8.8.8", Some("8.8.8.8"), Public),
            ("93.184.216.34", Some("93.184.216.34"), Public),
            ("api.openai.com", None, Name),
            ("0x.com", None, Name),
            ("1.2.3.4.5", None, Name),
        ];
        for &(input, libc, expect) in table {
            let got = match blocked_ip_literal(input) {
                Some(true) => Expect::Restricted,
                Some(false) => Expect::Public,
                None => Expect::Name,
            };
            assert_eq!(got, expect, "{input:?}");
            if let Some(addr) = libc {
                let addr: IpAddr = addr.parse().unwrap();
                if is_blocked_ip(addr) {
                    assert_eq!(got, Expect::Restricted, "{input:?}: libc says {addr}, restricted");
                }
            }
        }
    }

    #[test]
    fn zone_id_is_stripped_and_the_address_classified() {
        assert_eq!(parse_ip_literal("::1%lo0"), Some("::1".parse().unwrap()));
        assert_eq!(parse_ip_literal("fe80::1%en0"), Some("fe80::1".parse().unwrap()));
        assert_eq!(blocked_ip_literal("2606:4700:4700::1111%en0"), Some(false));
    }

    #[test]
    fn leading_zero_forms_report_the_restricted_reading() {
        // inet_aton: 87.0.0.1 (public); macOS: 127.0.0.1. Restricted wins.
        assert_eq!(parse_ip_literal("0127.0.0.1"), Some("127.0.0.1".parse().unwrap()));
        assert_eq!(
            parse_ip_literal("0251.254.169.254"),
            Some("169.254.169.254".parse().unwrap())
        );
        // Both readings public but different: ambiguity is refused, not guessed.
        assert_eq!(blocked_ip_literal("0100.0.0.1"), Some(true));
        // Only the decimal reading is valid (08 is not octal) and it is public.
        assert_eq!(blocked_ip_literal("08.8.8.8"), Some(false));
        assert_eq!(parse_ip_literal("8.8.8.8"), Some("8.8.8.8".parse().unwrap()));
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
