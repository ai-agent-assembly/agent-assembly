//! Non-follow mode: paginated audit log query via REST.

use std::process::ExitCode;

use serde::Deserialize;

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

use super::format::{format_log_json, format_log_line, is_within_time_range, parse_since, parse_until, LogLineData};
use super::types::LogEventType;
use super::LogsArgs;

/// Paginated response envelope from `GET /api/v1/logs`.
#[derive(Debug, Deserialize)]
pub struct PaginatedResponse {
    pub items: Vec<LogEntry>,
    #[allow(dead_code)]
    pub page: u32,
    #[allow(dead_code)]
    pub per_page: u32,
    #[allow(dead_code)]
    pub total: u64,
}

/// A single audit log entry as returned by the REST API.
#[derive(Debug, Deserialize)]
pub struct LogEntry {
    #[allow(dead_code)]
    pub seq: u64,
    pub timestamp: String,
    pub agent_id: String,
    #[allow(dead_code)]
    pub session_id: String,
    pub event_type: String,
    pub payload: String,
}

impl LogEntry {
    /// Convert a REST API log entry into the normalised display format.
    fn to_line_data(&self) -> LogLineData {
        LogLineData {
            timestamp: self.timestamp.clone(),
            event_type: self.event_type.clone(),
            agent_id: self.agent_id.clone(),
            message: self.payload.clone(),
        }
    }
}

/// Build the query URL for `GET /api/v1/logs` with filter parameters.
fn build_url(ctx: &ResolvedContext, args: &LogsArgs) -> String {
    let mut url = format!("{}/api/v1/logs?per_page={}&page=1", ctx.api_url, args.limit);

    if let Some(ref agent) = args.agent {
        url.push_str(&format!("&agent_id={agent}"));
    }

    if let Some(ref types) = args.r#type {
        if types.len() == 1 {
            url.push_str(&format!("&event_type={}", types[0].as_api_str()));
        }
        // Multiple types: fetch all and filter client-side (API accepts only one).
    }

    url
}

/// Fetch paginated log entries from `GET /api/v1/logs`.
pub fn run(args: LogsArgs, ctx: &ResolvedContext) -> ExitCode {
    let url = build_url(ctx, &args);

    let use_json = matches!(args.output, Some(OutputFormat::Json));
    let use_color = !args.no_color && !use_json;

    let since = args.since.as_deref().and_then(parse_since);
    let until = args.until.as_deref().and_then(parse_until);

    let response = match reqwest::blocking::get(&url) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to connect to {}: {e}", ctx.api_url);
            return ExitCode::FAILURE;
        }
    };

    if !response.status().is_success() {
        eprintln!("error: API returned status {} for {}", response.status(), url);
        return ExitCode::FAILURE;
    }

    let paginated: PaginatedResponse = match response.json() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to parse API response: {e}");
            return ExitCode::FAILURE;
        }
    };

    for entry in &paginated.items {
        if !is_within_time_range(&entry.timestamp, since.as_ref(), until.as_ref()) {
            continue;
        }
        if !entry_matches_type_filter(entry, args.r#type.as_deref()) {
            continue;
        }
        let line_data = entry.to_line_data();
        if use_json {
            println!("{}", format_log_json(&line_data));
        } else {
            println!("{}", format_log_line(&line_data, use_color));
        }
    }

    ExitCode::SUCCESS
}

/// Whether `entry` passes the client-side multi-type filter.
///
/// The API accepts only a single `event_type`, so when more than one type was
/// requested the gateway returns all of them and the surplus is filtered here.
/// A single requested type (or none) is already satisfied by the server query.
fn entry_matches_type_filter(entry: &LogEntry, types: Option<&[LogEventType]>) -> bool {
    match types {
        Some(types) if types.len() > 1 => types.iter().any(|t| t.as_api_str() == entry.event_type),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_to_line_data_preserves_fields() {
        let entry = LogEntry {
            seq: 1,
            timestamp: "2026-04-30T10:00:00Z".to_string(),
            agent_id: "aa001".to_string(),
            session_id: "sess001".to_string(),
            event_type: "violation".to_string(),
            payload: "denied".to_string(),
        };
        let data = entry.to_line_data();
        assert_eq!(data.timestamp, "2026-04-30T10:00:00Z");
        assert_eq!(data.event_type, "violation");
        assert_eq!(data.agent_id, "aa001");
        assert_eq!(data.message, "denied");
    }

    #[test]
    fn build_url_with_no_filters() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = LogsArgs {
            follow: false,
            agent: None,
            r#type: None,
            since: None,
            until: None,
            limit: 50,
            no_color: false,
            output: None,
        };
        let url = build_url(&ctx, &args);
        assert_eq!(url, "http://localhost:8080/api/v1/logs?per_page=50&page=1");
    }

    #[test]
    fn build_url_with_agent_filter() {
        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = LogsArgs {
            follow: false,
            agent: Some("aa001".to_string()),
            r#type: None,
            since: None,
            until: None,
            limit: 25,
            no_color: false,
            output: None,
        };
        let url = build_url(&ctx, &args);
        assert!(url.contains("agent_id=aa001"));
        assert!(url.contains("per_page=25"));
    }

    #[test]
    fn build_url_with_type_filter() {
        use super::super::types::LogEventType;

        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = LogsArgs {
            follow: false,
            agent: None,
            r#type: Some(vec![LogEventType::Violation]),
            since: None,
            until: None,
            limit: 50,
            no_color: false,
            output: None,
        };
        let url = build_url(&ctx, &args);
        assert!(url.contains("event_type=violation"));
    }

    #[test]
    fn build_url_with_multiple_types_omits_server_filter() {
        use super::super::types::LogEventType;

        let ctx = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        let args = LogsArgs {
            follow: false,
            agent: None,
            r#type: Some(vec![LogEventType::Violation, LogEventType::Budget]),
            since: None,
            until: None,
            limit: 50,
            no_color: false,
            output: None,
        };
        let url = build_url(&ctx, &args);
        // Multiple types cannot be sent server-side; filtered client-side instead.
        assert!(!url.contains("event_type="));
    }
}
