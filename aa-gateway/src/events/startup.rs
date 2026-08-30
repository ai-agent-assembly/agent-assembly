//! Webhook delivery startup wiring.
//!
//! Reads `AA_WEBHOOK_URL` from the environment and, if set, subscribes to the
//! approval and budget broadcast channels and spawns the delivery loop.

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use aa_runtime::approval::ApprovalRequest;

use super::delivery::webhook_delivery_loop;
use super::webhook::WebhookTarget;
use crate::budget::BudgetAlert;

/// Environment variable name for the webhook URL.
pub const WEBHOOK_URL_ENV: &str = "AA_WEBHOOK_URL";

/// Optionally spawn the webhook delivery loop.
///
/// Reads `AA_WEBHOOK_URL` from the environment. If set, creates a shared
/// [`reqwest::Client`], subscribes to both broadcast channels, and spawns the
/// delivery loop as a background tokio task.
///
/// If the variable is unset or empty, logs an INFO message and returns `None`.
pub fn maybe_spawn_webhook(
    approval_queue: &Arc<aa_runtime::approval::ApprovalQueue>,
    budget_alert_rx: broadcast::Receiver<BudgetAlert>,
) -> Option<JoinHandle<()>> {
    let url = match std::env::var(WEBHOOK_URL_ENV) {
        Ok(url) if !url.is_empty() => url,
        _ => {
            tracing::info!(
                env = WEBHOOK_URL_ENV,
                "webhook URL not configured, event notifications disabled"
            );
            return None;
        }
    };

    // AAASM-5973: most webhook providers (Slack, Discord, Teams, generic signed
    // endpoints) put the delivery credential in the URL's path or query, not in
    // a header — so logging the URL in full at INFO discloses it on every
    // gateway start. `webhook_origin` prints only the part that answers "where
    // does this traffic go" (scheme + host + port + a path *segment count*,
    // AAASM-5935's `project_url_origin` pattern), never the parts that can
    // carry a credential.
    match webhook_origin(&url) {
        Some(origin) => tracing::info!(origin = %origin, "webhook delivery enabled"),
        None => tracing::info!("webhook delivery enabled with an unparseable AA_WEBHOOK_URL value"),
    }

    let client = reqwest::Client::new();
    let target = WebhookTarget::new(client, url);
    let approval_rx: broadcast::Receiver<ApprovalRequest> = approval_queue.subscribe_events();

    let handle = tokio::spawn(webhook_delivery_loop(target, approval_rx, budget_alert_rx));
    Some(handle)
}

/// Whether an optional trailing `:port` is a port and nothing else.
///
/// An empty string is fine — the port is optional. A `:` must be followed by at
/// least one digit and only digits.
fn is_port_suffix(suffix: &str) -> bool {
    match suffix.strip_prefix(':') {
        Some(port) => !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()),
        None => suffix.is_empty(),
    }
}

/// Whether the host position of an authority is actually shaped like a host.
///
/// A **shape** gate, not a resolution or validity check — mirrors
/// `aa-cli`'s `is_host_shaped` (AAASM-5935), which the doc comment on
/// [`webhook_origin`] explains the reasoning for: printing an authority
/// position on the assumption a host is what landed there is how a credential
/// leaks, so an unrecognised shape must be withheld rather than guessed at.
fn is_host_shaped(host_port: &str) -> bool {
    if let Some(rest) = host_port.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return false;
        };
        return !inner.is_empty()
            && inner.bytes().all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
            && is_port_suffix(after);
    }

    let (host, port_suffix) = match host_port.find(':') {
        Some(colon) => (&host_port[..colon], &host_port[colon..]),
        None => (host_port, ""),
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        && is_port_suffix(port_suffix)
}

/// Project a webhook URL onto the part of it that answers "where does this
/// traffic go", discarding every part that can carry a credential.
///
/// Keeps **scheme, host and port**. Discards userinfo, query and fragment
/// outright, and replaces the path with a segment *count* — most webhook
/// providers (Slack, Discord, Teams, generic signed endpoints) put the
/// delivery token in the path or query, so either one surviving into a log
/// line defeats the point of projecting at all.
///
/// Ported from `aa-cli`'s `project_url_origin` (AAASM-5935) rather than
/// shared, to keep this fix bounded to the one call site AAASM-5973 reported;
/// see that function's doc comment for the fuller "why a projection, not more
/// redaction" rationale — it applies unchanged here.
///
/// Returns [`None`] for a value that is not shaped like an `http(s)` URL,
/// so the caller can say "present and unparseable" instead of guessing.
fn webhook_origin(value: &str) -> Option<String> {
    let scheme_end = value.find("://")?;
    let scheme = &value[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }

    let rest = &value[scheme_end + 3..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    let host_port = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    if !is_host_shaped(host_port) {
        return None;
    }

    let after_authority = &rest[authority_end..];
    let path_end = after_authority.find(['?', '#']).unwrap_or(after_authority.len());
    let segments = after_authority[..path_end].split('/').filter(|s| !s.is_empty()).count();

    let path_marker = match segments {
        0 => String::new(),
        1 => "<path:1 segment>".to_string(),
        n => format!("<path:{n} segments>"),
    };
    Some(format!("{scheme}://{host_port}{path_marker}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // AAASM-5973: a synthetic, non-functional URL — resolves nowhere, no real
    // webhook provider issued it. The distinctive path segment
    // "SENTINEL-DO-NOT-LOG-9f3a" stands in for a bearer credential without
    // being one; the test only ever asserts on its *presence or absence* in
    // captured output, never decodes, stores or fingerprints it.
    const SYNTHETIC_WEBHOOK_URL: &str = "https://hooks.example.invalid/services/T000/B000/SENTINEL-DO-NOT-LOG-9f3a";
    const SENTINEL: &str = "SENTINEL-DO-NOT-LOG-9f3a";

    #[test]
    fn webhook_origin_drops_the_path_that_carries_the_token() {
        let origin = webhook_origin(SYNTHETIC_WEBHOOK_URL).expect("http(s) URL parses");
        assert!(
            !origin.contains(SENTINEL),
            "the sentinel must not survive into the origin: {origin}"
        );
        assert_eq!(origin, "https://hooks.example.invalid<path:4 segments>");
    }

    #[test]
    fn webhook_origin_drops_a_query_string_token() {
        let url = "https://gw.example.invalid/webhook?token=SENTINEL-DO-NOT-LOG-9f3a";
        let origin = webhook_origin(url).expect("http(s) URL parses");
        assert!(!origin.contains(SENTINEL), "{origin}");
        assert_eq!(origin, "https://gw.example.invalid<path:1 segment>");
    }

    #[test]
    fn webhook_origin_drops_userinfo() {
        let url = "https://user:SENTINEL-DO-NOT-LOG-9f3a@gw.example.invalid/webhook";
        let origin = webhook_origin(url).expect("http(s) URL parses");
        assert!(!origin.contains(SENTINEL), "{origin}");
        assert_eq!(origin, "https://gw.example.invalid<path:1 segment>");
    }

    #[test]
    fn webhook_origin_withholds_rather_than_guesses_on_an_unparseable_value() {
        assert_eq!(webhook_origin("not a url at all"), None);
        assert_eq!(
            webhook_origin("ftp://gw.example.invalid/x"),
            None,
            "not an http(s) scheme"
        );
    }

    /// AAASM-5973 AC4's negative control: capture real `tracing` output from
    /// `maybe_spawn_webhook` with the synthetic sentinel URL and assert the
    /// sentinel never appears while the origin does. This is the assertion
    /// that must redden if the projection is removed — proven manually by
    /// temporarily reverting to `tracing::info!(url = %url, ...)` and
    /// confirming this test fails with the sentinel visible in the captured
    /// output, then restoring the fix.
    // `#[tokio::test]`, not `#[test]`: `maybe_spawn_webhook` calls `tokio::spawn`
    // internally, which requires an ambient Tokio runtime context — without one,
    // it panics with "there is no reactor running" before this test can assert
    // anything about the logged output.
    #[tokio::test]
    async fn maybe_spawn_webhook_never_logs_the_full_url() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;

        #[derive(Clone, Default)]
        struct CapturingWriter(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for CapturingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturingWriter(captured.clone());
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(move || writer.clone())
                .with_ansi(false),
        );

        // SAFETY (test-only, single-threaded env mutation): `AA_WEBHOOK_URL`
        // is read once at the top of `maybe_spawn_webhook`, synchronously,
        // before this function returns — no other thread in this test binary
        // reads or writes it, and it is removed again before returning.
        unsafe {
            std::env::set_var(WEBHOOK_URL_ENV, SYNTHETIC_WEBHOOK_URL);
        }
        let result = tracing::subscriber::with_default(subscriber, || {
            let approval_queue = Arc::new(aa_runtime::approval::ApprovalQueue::new());
            let (_tx, rx) = broadcast::channel(1);
            maybe_spawn_webhook(&approval_queue, rx)
        });
        unsafe {
            std::env::remove_var(WEBHOOK_URL_ENV);
        }
        if let Some(handle) = result {
            handle.abort();
        }

        let output = String::from_utf8(captured.lock().unwrap().clone()).expect("utf8 log output");
        assert!(
            !output.contains(SENTINEL),
            "the sentinel must never appear in log output: {output}"
        );
        assert!(
            output.contains("hooks.example.invalid"),
            "the origin host must still be visible so an operator can tell a misrouted \
             webhook from an unconfigured one: {output}"
        );
    }
}
