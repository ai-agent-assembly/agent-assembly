//! Kind-discriminated destination validation (AAASM-1388).
//!
//! Each `DestinationConfig` variant is validated against the rules its
//! connector relies on at dispatch time (URL parse, https-only for Slack,
//! non-empty PagerDuty routing key, OpsGenie key + team).

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
            if !host.ends_with("slack.com") {
                return Err(ValidationError::InvalidConfig(
                    "slack.webhook_url host must end with slack.com",
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
        };
        assert_eq!(
            validate_destination(&dst),
            Err(ValidationError::InvalidConfig("name must be non-empty"))
        );
    }
}
