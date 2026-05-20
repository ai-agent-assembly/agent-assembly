//! Domain types for notification destinations (AAASM-1388).
//!
//! A `Destination` is a target the gateway can dispatch an alert notification
//! to (a webhook URL, a Slack incoming webhook, PagerDuty, OpsGenie). The
//! per-kind configuration is captured in [`DestinationConfig`], which is
//! serialised with an internally-tagged `kind` discriminator so the JSON
//! payload matches the public API contract.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Kind of notification destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DestinationKind {
    /// Generic outbound HTTP webhook (any service that accepts a JSON POST).
    Webhook,
    /// Slack incoming-webhook URL.
    Slack,
    /// PagerDuty Events API v2 routing key.
    PagerDuty,
    /// OpsGenie REST API key + team.
    OpsGenie,
}

impl std::fmt::Display for DestinationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DestinationKind::Webhook => "webhook",
            DestinationKind::Slack => "slack",
            DestinationKind::PagerDuty => "pagerduty",
            DestinationKind::OpsGenie => "opsgenie",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for DestinationKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webhook" => Ok(DestinationKind::Webhook),
            "slack" => Ok(DestinationKind::Slack),
            "pagerduty" => Ok(DestinationKind::PagerDuty),
            "opsgenie" => Ok(DestinationKind::OpsGenie),
            _ => Err(()),
        }
    }
}

/// Per-kind configuration payload for a `Destination`.
///
/// Serialised as `{ "kind": "...", "config": { ... } }` so that the API
/// surface keeps configuration fields cleanly grouped under `config`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", content = "config", rename_all = "lowercase")]
pub enum DestinationConfig {
    /// Generic HTTP webhook.
    Webhook {
        /// Target URL (http or https).
        url: String,
        /// Optional secret shipped in the `X-AAASM-Token` header.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret_header: Option<String>,
    },
    /// Slack incoming webhook.
    Slack {
        /// Slack-issued incoming webhook URL.
        webhook_url: String,
        /// Optional `#channel` or `@user` override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        channel_override: Option<String>,
    },
    /// PagerDuty Events API v2.
    #[serde(rename = "pagerduty")]
    PagerDuty {
        /// Integration routing key.
        routing_key: String,
        /// Optional severity-name mapping (AAASM severity → PagerDuty severity).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        severity_map: Option<HashMap<String, String>>,
    },
    /// OpsGenie REST alerts API.
    #[serde(rename = "opsgenie")]
    OpsGenie {
        /// OpsGenie API key (GenieKey).
        api_key: String,
        /// Target team identifier.
        team_id: String,
    },
}

impl DestinationConfig {
    /// Return the [`DestinationKind`] matching this configuration variant.
    pub fn kind(&self) -> DestinationKind {
        match self {
            DestinationConfig::Webhook { .. } => DestinationKind::Webhook,
            DestinationConfig::Slack { .. } => DestinationKind::Slack,
            DestinationConfig::PagerDuty { .. } => DestinationKind::PagerDuty,
            DestinationConfig::OpsGenie { .. } => DestinationKind::OpsGenie,
        }
    }
}

/// A persisted notification destination.
///
/// `config` is flattened into the surrounding JSON object so the public
/// representation is `{ id, name, kind, config, enabled, created_at, updated_at }`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Destination {
    /// Stable identifier, prefix `dst_` followed by 32 hex chars.
    pub id: String,
    /// Operator-supplied display name.
    pub name: String,
    /// Discriminated per-kind configuration.
    #[serde(flatten)]
    pub config: DestinationConfig,
    /// Whether dispatch is allowed against this destination.
    pub enabled: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-mutation timestamp.
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn destination_kind_round_trip_lowercase() {
        for kind in [
            DestinationKind::Webhook,
            DestinationKind::Slack,
            DestinationKind::PagerDuty,
            DestinationKind::OpsGenie,
        ] {
            let s = kind.to_string();
            assert_eq!(s, s.to_lowercase());
            assert_eq!(DestinationKind::from_str(&s).unwrap(), kind);
        }
    }

    #[test]
    fn destination_kind_from_str_rejects_unknown() {
        assert!(DestinationKind::from_str("carrier_pigeon").is_err());
    }

    #[test]
    fn destination_config_webhook_serialization_round_trip() {
        let cfg = DestinationConfig::Webhook {
            url: "https://example.com/hook".to_string(),
            secret_header: Some("shh".to_string()),
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "webhook");
        assert_eq!(json["config"]["url"], "https://example.com/hook");
        assert_eq!(json["config"]["secret_header"], "shh");

        let parsed: DestinationConfig = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.kind(), DestinationKind::Webhook);
    }

    #[test]
    fn destination_config_pagerduty_uses_lowercase_kind() {
        let cfg = DestinationConfig::PagerDuty {
            routing_key: "abc123".to_string(),
            severity_map: None,
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "pagerduty");
        assert_eq!(json["config"]["routing_key"], "abc123");
    }

    #[test]
    fn destination_config_opsgenie_uses_lowercase_kind() {
        let cfg = DestinationConfig::OpsGenie {
            api_key: "key".to_string(),
            team_id: "team-1".to_string(),
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["kind"], "opsgenie");
    }

    #[test]
    fn destination_flattens_config_into_outer_object() {
        let dst = Destination {
            id: "dst_1".to_string(),
            name: "demo".to_string(),
            config: DestinationConfig::Webhook {
                url: "https://example.com/hook".to_string(),
                secret_header: None,
            },
            enabled: true,
            created_at: "2026-05-20T00:00:00Z".to_string(),
            updated_at: "2026-05-20T00:00:00Z".to_string(),
        };
        let json = serde_json::to_value(&dst).unwrap();
        assert_eq!(json["id"], "dst_1");
        assert_eq!(json["kind"], "webhook");
        assert_eq!(json["config"]["url"], "https://example.com/hook");
    }
}
