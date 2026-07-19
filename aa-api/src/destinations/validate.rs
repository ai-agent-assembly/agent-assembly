//! Kind-discriminated destination validation (AAASM-1388).
//!
//! Each `DestinationConfig` variant is validated against the rules its
//! connector relies on at dispatch time (URL parse, https-only for Slack,
//! non-empty PagerDuty routing key, OpsGenie key + team).

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::destinations::types::{Destination, DestinationConfig};

/// Reason a destination payload failed validation. The `'static str`
/// description is reused as the RFC 7807 `detail` field by the HTTP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// `kind` discriminator was missing or unknown.
    InvalidKind,
    /// Configuration body was structurally invalid.
    InvalidConfig(&'static str),
}

/// Validate a complete `Destination` — config + identity fields.
pub fn validate_destination(d: &Destination) -> Result<(), ValidationError> {
    validate_config(&d.config)?;
    if d.name.trim().is_empty() {
        return Err(ValidationError::InvalidConfig("name must be non-empty"));
    }
    Ok(())
}

/// Whether `host` is an allowed Slack incoming-webhook host.
///
/// Anchored so a look-alike domain like `evil-slack.com` cannot satisfy the
/// check: only the apex `slack.com` or a genuine `*.slack.com` subdomain is
/// accepted. A bare `host.ends_with("slack.com")` matched `evil-slack.com`
/// (AAASM-3868).
fn slack_host_allowed(host: &str) -> bool {
    host == "slack.com" || host.ends_with(".slack.com")
}

/// Validate the configuration body in isolation.
pub fn validate_config(c: &DestinationConfig) -> Result<(), ValidationError> {
    match c {
        DestinationConfig::Webhook { url, .. } => {
            let parsed =
                url::Url::parse(url).map_err(|_| ValidationError::InvalidConfig("webhook.url is not a valid URL"))?;
            match parsed.scheme() {
                "http" | "https" => Ok(()),
                _ => Err(ValidationError::InvalidConfig(
                    "webhook.url scheme must be http or https",
                )),
            }
        }
        DestinationConfig::Slack { webhook_url, .. } => {
            let parsed = url::Url::parse(webhook_url)
                .map_err(|_| ValidationError::InvalidConfig("slack.webhook_url is not a valid URL"))?;
            if parsed.scheme() != "https" {
                return Err(ValidationError::InvalidConfig("slack.webhook_url must use https"));
            }
            let host = parsed.host_str().unwrap_or("");
            // Allow loopback in cfg(test) so integration tests can stand up
            // an httpmock server. Production builds enforce slack.com host.
            #[cfg(not(test))]
            if !slack_host_allowed(host) {
                return Err(ValidationError::InvalidConfig(
                    "slack.webhook_url host must be slack.com or a slack.com subdomain",
                ));
            }
            #[cfg(test)]
            {
                let _ = host;
            }
            Ok(())
        }
        DestinationConfig::PagerDuty { routing_key, .. } => {
            if routing_key.trim().is_empty() {
                Err(ValidationError::InvalidConfig(
                    "pagerduty.routing_key must be non-empty",
                ))
            } else {
                Ok(())
            }
        }
        DestinationConfig::OpsGenie { api_key, team_id } => {
            if api_key.trim().is_empty() {
                return Err(ValidationError::InvalidConfig("opsgenie.api_key must be non-empty"));
            }
            if team_id.trim().is_empty() {
                return Err(ValidationError::InvalidConfig("opsgenie.team_id must be non-empty"));
            }
            Ok(())
        }
    }
}

/// Environment variable that, when set to a truthy value (`1`/`true`/`yes`/`on`),
/// disables the webhook egress guard.
///
/// Unset — the default and the SaaS posture — keeps the guard active so an
/// outbound webhook test-fire can never reach an internal address (cloud
/// metadata, loopback, RFC1918, link-local). A *limited-function self-hosted*
/// deployment that legitimately needs to reach a webhook on its own private
/// network can opt out via this flag — the configurable egress allowlist the
/// remediation calls for (AAASM-3789).
const ALLOW_PRIVATE_EGRESS_ENV: &str = "AA_ALLOW_PRIVATE_WEBHOOK_EGRESS";

/// Whether the operator has explicitly opted in to private-network webhook
/// egress via [`ALLOW_PRIVATE_EGRESS_ENV`].
fn private_egress_allowed() -> bool {
    std::env::var(ALLOW_PRIVATE_EGRESS_ENV)
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false)
}

/// True when `ip` is an address the webhook egress guard must refuse.
///
/// Delegates to the shared [`aa_core::net::is_blocked_ip`] so this guard and the
/// proxy's CONNECT guard enforce one identical range set. The local copy used to
/// miss CGNAT `100.64.0.0/10`, `0.0.0.0/8`, and the IPv6 transition prefixes
/// (NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, IPv4-compatible `::/96`) that can
/// embed an internal IPv4 such as `169.254.169.254` (AAASM-4859).
fn ip_is_internal(ip: IpAddr) -> bool {
    aa_core::net::is_blocked_ip(ip)
}

/// Reject an address that resolves into a disallowed internal range.
fn check_egress_addr(ip: IpAddr) -> Result<(), ValidationError> {
    if ip_is_internal(ip) {
        Err(ValidationError::InvalidConfig(
            "webhook.url resolves to a disallowed internal address",
        ))
    } else {
        Ok(())
    }
}

/// Guard a webhook URL against SSRF before it is dispatched (AAASM-3789) and
/// return the **vetted socket addresses** the dispatch must pin to (AAASM-3826).
///
/// Rejects a URL whose host — or any address it resolves to — falls in a
/// loopback / private / link-local / ULA / metadata range. Literal-IP hosts are
/// checked directly; hostnames are resolved and *every* returned address must be
/// allowed, so a single internal answer rejects the whole host (defeating
/// DNS-rebinding to an internal target).
///
/// To close the DNS-rebinding TOCTOU, the connector must connect to exactly the
/// addresses returned here rather than re-resolving the host at connect time
/// (where a low-TTL name could have flipped to an internal address after this
/// check). The returned vector carries every vetted [`SocketAddr`] for the
/// host; an **empty** vector means "do not pin" — returned only when the
/// operator has opted out via [`ALLOW_PRIVATE_EGRESS_ENV`].
///
/// Performs a **blocking** DNS lookup for hostname targets, so call it from a
/// blocking context (e.g. `tokio::task::spawn_blocking`) rather than directly
/// on an async task.
pub fn validate_webhook_egress(url: &url::Url) -> Result<Vec<SocketAddr>, ValidationError> {
    if private_egress_allowed() {
        return Ok(Vec::new());
    }
    let host = url
        .host()
        .ok_or(ValidationError::InvalidConfig("webhook.url has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    match host {
        url::Host::Ipv4(ip) => {
            let addr = IpAddr::V4(ip);
            check_egress_addr(addr)?;
            Ok(vec![SocketAddr::new(addr, port)])
        }
        url::Host::Ipv6(ip) => {
            let addr = IpAddr::V6(ip);
            check_egress_addr(addr)?;
            Ok(vec![SocketAddr::new(addr, port)])
        }
        url::Host::Domain(domain) => {
            let resolved: Vec<SocketAddr> = (domain, port)
                .to_socket_addrs()
                .map_err(|_| ValidationError::InvalidConfig("webhook.url host could not be resolved"))?
                .collect();
            if resolved.is_empty() {
                return Err(ValidationError::InvalidConfig("webhook.url host did not resolve"));
            }
            for sa in &resolved {
                check_egress_addr(sa.ip())?;
            }
            Ok(resolved)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook(url: &str) -> DestinationConfig {
        DestinationConfig::Webhook {
            url: url.to_string(),
            secret_header: None,
        }
    }

    fn slack(url: &str) -> DestinationConfig {
        DestinationConfig::Slack {
            webhook_url: url.to_string(),
            channel_override: None,
        }
    }

    #[test]
    fn webhook_http_and_https_ok() {
        assert!(validate_config(&webhook("https://example.com/hook")).is_ok());
        assert!(validate_config(&webhook("http://internal.svc/hook")).is_ok());
    }

    #[test]
    fn webhook_bad_url_rejected() {
        assert_eq!(
            validate_config(&webhook("not-a-url")),
            Err(ValidationError::InvalidConfig("webhook.url is not a valid URL"))
        );
    }

    #[test]
    fn webhook_non_http_scheme_rejected() {
        assert_eq!(
            validate_config(&webhook("ftp://example.com/hook")),
            Err(ValidationError::InvalidConfig(
                "webhook.url scheme must be http or https"
            ))
        );
    }

    #[test]
    fn slack_https_ok_in_test_cfg() {
        // Under #[cfg(test)] we allow any host so httpmock URLs can stand in.
        assert!(validate_config(&slack("https://hooks.slack.com/services/X/Y/Z")).is_ok());
        assert!(validate_config(&slack("https://127.0.0.1:1234/hook")).is_ok());
    }

    #[test]
    fn slack_host_allowed_anchors_suffix() {
        // AAASM-3868: the anchored host check accepts the apex and true
        // subdomains but rejects look-alike domains that the old
        // `ends_with("slack.com")` suffix matched.
        assert!(slack_host_allowed("hooks.slack.com"));
        assert!(slack_host_allowed("slack.com"));
        assert!(!slack_host_allowed("evil-slack.com"));
        assert!(!slack_host_allowed("slack.com.evil.com"));
        assert!(!slack_host_allowed("notslack.com"));
    }

    #[test]
    fn slack_http_rejected() {
        assert_eq!(
            validate_config(&slack("http://hooks.slack.com/services/X")),
            Err(ValidationError::InvalidConfig("slack.webhook_url must use https"))
        );
    }

    #[test]
    fn pagerduty_empty_routing_key_rejected() {
        let cfg = DestinationConfig::PagerDuty {
            routing_key: "  ".to_string(),
            severity_map: None,
        };
        assert_eq!(
            validate_config(&cfg),
            Err(ValidationError::InvalidConfig(
                "pagerduty.routing_key must be non-empty"
            ))
        );
    }

    #[test]
    fn opsgenie_missing_team_id_rejected() {
        let cfg = DestinationConfig::OpsGenie {
            api_key: "k".to_string(),
            team_id: String::new(),
        };
        assert_eq!(
            validate_config(&cfg),
            Err(ValidationError::InvalidConfig("opsgenie.team_id must be non-empty"))
        );
    }

    #[test]
    fn opsgenie_missing_api_key_rejected() {
        let cfg = DestinationConfig::OpsGenie {
            api_key: "".to_string(),
            team_id: "team".to_string(),
        };
        assert_eq!(
            validate_config(&cfg),
            Err(ValidationError::InvalidConfig("opsgenie.api_key must be non-empty"))
        );
    }

    #[test]
    fn destination_empty_name_rejected() {
        let dst = Destination {
            id: "dst_1".into(),
            name: "  ".into(),
            config: webhook("https://example.com/hook"),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
            team_id: None,
            org_id: None,
        };
        assert_eq!(
            validate_destination(&dst),
            Err(ValidationError::InvalidConfig("name must be non-empty"))
        );
    }

    // ── Egress guard (AAASM-3789) ────────────────────────────────────────────

    fn egress(url: &str) -> Result<(), ValidationError> {
        validate_webhook_egress(&url::Url::parse(url).expect("test url parses")).map(|_| ())
    }

    #[test]
    fn egress_rejects_loopback_metadata_and_private() {
        // Loopback, the cloud-metadata link-local address, and an RFC1918 host
        // must all be refused before any request is dispatched.
        for url in [
            "http://127.0.0.1/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/hook",
            "http://192.168.1.1/hook",
            "http://172.16.0.1/hook",
            "http://[::1]/hook",
        ] {
            assert_eq!(
                egress(url),
                Err(ValidationError::InvalidConfig(
                    "webhook.url resolves to a disallowed internal address"
                )),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn egress_rejects_newly_closed_ranges() {
        // AAASM-4859: ranges the local blocklist previously missed, now covered
        // by the shared aa_core::net set. Each embeds an internal/non-routable
        // target (several encode the 169.254.169.254 metadata endpoint).
        for url in [
            // CGNAT 100.64.0.0/10 and "this network" 0.0.0.0/8.
            "http://100.64.0.1/hook",
            "http://0.1.2.3/hook",
            // 169.254.169.254 via each IPv6 encoding a translator could forward.
            "http://[::ffff:a9fe:a9fe]/hook",   // IPv4-mapped
            "http://[64:ff9b::a9fe:a9fe]/hook", // NAT64 64:ff9b::/96
            "http://[2002:a9fe:a9fe::1]/hook",  // 6to4 2002::/16
            "http://[::a9fe:a9fe]/hook",        // IPv4-compatible ::/96
        ] {
            assert_eq!(
                egress(url),
                Err(ValidationError::InvalidConfig(
                    "webhook.url resolves to a disallowed internal address"
                )),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn egress_rejects_metadata_via_every_encoding() {
        // The 169.254.169.254 cloud-metadata endpoint must be refused however it
        // is spelled — as a v4 literal and through each IPv6 form.
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/",
            "http://[::ffff:a9fe:a9fe]/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "http://[2002:a9fe:a9fe::1]/",
            "http://[::a9fe:a9fe]/",
        ] {
            assert_eq!(
                egress(url),
                Err(ValidationError::InvalidConfig(
                    "webhook.url resolves to a disallowed internal address"
                )),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn egress_allows_public_ip() {
        // A public literal IP carries no DNS dependency and must be allowed.
        assert!(egress("http://8.8.8.8/hook").is_ok());
        assert!(egress("https://1.1.1.1/hook").is_ok());
    }

    #[test]
    fn egress_returns_vetted_addr_for_pinning() {
        // AAASM-3826: the guard hands back the exact vetted socket address(es)
        // so the connector can pin its connection to them rather than
        // re-resolving the host at connect time (the DNS-rebinding window).
        let addrs = validate_webhook_egress(&url::Url::parse("http://8.8.8.8:80/hook").expect("url parses"))
            .expect("public literal IP is allowed");
        assert_eq!(addrs, vec![SocketAddr::from(([8, 8, 8, 8], 80))]);

        // The default https port is filled in for scheme-default URLs.
        let https = validate_webhook_egress(&url::Url::parse("https://1.1.1.1/hook").expect("url parses"))
            .expect("public literal IP is allowed");
        assert_eq!(https, vec![SocketAddr::from(([1, 1, 1, 1], 443))]);
    }

    #[test]
    fn egress_opt_out_returns_no_pin() {
        // With the self-host opt-out set, the guard is disabled and returns an
        // empty vetted set, signalling the connector not to pin.
        std::env::set_var(ALLOW_PRIVATE_EGRESS_ENV, "1");
        let addrs = validate_webhook_egress(&url::Url::parse("http://127.0.0.1/hook").expect("url parses"));
        std::env::remove_var(ALLOW_PRIVATE_EGRESS_ENV);
        assert_eq!(addrs, Ok(Vec::new()));
    }

    #[test]
    fn egress_env_escape_allows_private() {
        // The documented self-host opt-out disables the guard.
        std::env::set_var(ALLOW_PRIVATE_EGRESS_ENV, "1");
        let allowed = egress("http://127.0.0.1/hook");
        std::env::remove_var(ALLOW_PRIVATE_EGRESS_ENV);
        assert!(allowed.is_ok(), "private egress must be allowed when opted in");
    }
}

#[cfg(test)]
mod tests_extra {
    use super::*;
    use crate::destinations::types::{Destination, DestinationConfig};

    fn dest(name: &str, config: DestinationConfig) -> Destination {
        Destination {
            id: "dst_test".to_string(),
            name: name.to_string(),
            config,
            enabled: true,
            created_at: "2026-06-25T00:00:00Z".to_string(),
            updated_at: "2026-06-25T00:00:00Z".to_string(),
            team_id: None,
            org_id: None,
        }
    }

    #[test]
    fn empty_name_is_rejected() {
        let d = dest(
            "  ",
            DestinationConfig::Webhook {
                url: "https://example.com/h".to_string(),
                secret_header: None,
            },
        );
        assert!(matches!(
            validate_destination(&d),
            Err(ValidationError::InvalidConfig("name must be non-empty"))
        ));
    }

    #[test]
    fn valid_webhook_passes() {
        let d = dest(
            "wh",
            DestinationConfig::Webhook {
                url: "https://example.com/h".to_string(),
                secret_header: None,
            },
        );
        assert!(validate_destination(&d).is_ok());
    }

    #[test]
    fn pagerduty_requires_non_empty_routing_key() {
        let bad = DestinationConfig::PagerDuty {
            routing_key: "   ".to_string(),
            severity_map: None,
        };
        assert!(validate_config(&bad).is_err());

        let ok = DestinationConfig::PagerDuty {
            routing_key: "R0UTING".to_string(),
            severity_map: None,
        };
        assert!(validate_config(&ok).is_ok());
    }

    #[test]
    fn opsgenie_requires_api_key_and_team_id() {
        let no_key = DestinationConfig::OpsGenie {
            api_key: "".to_string(),
            team_id: "team".to_string(),
        };
        assert!(validate_config(&no_key).is_err());

        let no_team = DestinationConfig::OpsGenie {
            api_key: "key".to_string(),
            team_id: "  ".to_string(),
        };
        assert!(validate_config(&no_team).is_err());

        let ok = DestinationConfig::OpsGenie {
            api_key: "key".to_string(),
            team_id: "team".to_string(),
        };
        assert!(validate_config(&ok).is_ok());
    }

    #[test]
    fn slack_requires_https_url() {
        let bad = DestinationConfig::Slack {
            webhook_url: "http://hooks.slack.com/services/x".to_string(),
            channel_override: None,
        };
        assert!(validate_config(&bad).is_err());

        let ok = DestinationConfig::Slack {
            webhook_url: "https://hooks.slack.com/services/x".to_string(),
            channel_override: None,
        };
        assert!(validate_config(&ok).is_ok());
    }
}
