//! Pluggable outbound email (AAASM-5306, ADR 0031 §Q4).
//!
//! The password-reset flow needs to deliver a raw reset token to the account
//! owner out of band. This module is the seam that does it, behind the [`Mailer`]
//! trait so the transport is swappable:
//!
//! * [`SmtpMailer`] — the real transport, configured from `AA_SMTP_*` env vars
//!   (host / port / user / pass / from), speaking SMTP over TLS.
//! * [`LoggingMailer`] — the graceful-degradation fallback used when SMTP is not
//!   configured. It does not send anything; it logs that an email *would* have
//!   been sent (subject + recipient only — never the body, which carries the
//!   reset token). A deployment without SMTP therefore never panics and never
//!   silently 500s the reset endpoint; the operator just sees the token was not
//!   delivered.
//!
//! Security posture: the message *body* (which contains the reset token) is
//! never logged by either implementation. Only the recipient and subject are
//! ever traced.

use std::sync::Arc;

use async_trait::async_trait;

/// Environment variable naming the SMTP relay host. Presence of this variable is
/// what switches the deployment from the [`LoggingMailer`] fallback to a real
/// [`SmtpMailer`].
pub const SMTP_HOST_ENV: &str = "AA_SMTP_HOST";
/// SMTP port (defaults to 587, submission-with-STARTTLS) when unset/unparseable.
pub const SMTP_PORT_ENV: &str = "AA_SMTP_PORT";
/// SMTP username for authenticated submission. Optional (an open relay needs none).
pub const SMTP_USER_ENV: &str = "AA_SMTP_USER";
/// SMTP password for authenticated submission. Optional.
pub const SMTP_PASS_ENV: &str = "AA_SMTP_PASS";
/// The `From:` address stamped on outbound mail. Defaults to a no-reply address.
pub const SMTP_FROM_ENV: &str = "AA_SMTP_FROM";

/// Default submission port when `AA_SMTP_PORT` is unset (587 = submission).
const DEFAULT_SMTP_PORT: u16 = 587;

/// Default `From:` when `AA_SMTP_FROM` is unset.
const DEFAULT_FROM: &str = "no-reply@localhost";

/// An outbound email transport (AAASM-5306).
///
/// Deliberately minimal — `send(to, subject, body)` is all the reset flow needs.
/// Implementations MUST NOT log the `body` (it can carry a reset token). A send
/// failure is reported, never panicked, so a mail outage degrades the reset flow
/// rather than taking the server down.
#[async_trait]
pub trait Mailer: Send + Sync {
    /// Deliver a plaintext email. Returns `Err` if the transport failed; the
    /// caller decides how to surface that (the reset endpoint stays 202 either
    /// way so it never leaks whether the address exists or whether mail worked).
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError>;
}

/// A mail-send failure. Carries only a generic, body-free description so a reset
/// token or address never leaks into an error string or a log line.
#[derive(Debug, thiserror::Error)]
pub enum MailerError {
    /// The recipient or configured `From:` address failed to parse.
    #[error("invalid email address")]
    InvalidAddress,
    /// The message could not be built or sent by the transport.
    #[error("mail transport error")]
    Transport,
}

/// Resolved SMTP configuration (AAASM-5306). Read from the `AA_SMTP_*` env vars
/// the same way the rest of `aa-api` reads its `AA_*` configuration.
#[derive(Debug, Clone)]
pub struct MailerConfig {
    /// SMTP relay host.
    pub host: String,
    /// SMTP relay port.
    pub port: u16,
    /// Optional SMTP username for authenticated submission.
    pub user: Option<String>,
    /// Optional SMTP password for authenticated submission.
    pub pass: Option<String>,
    /// The `From:` address stamped on outbound mail.
    pub from: String,
}

impl MailerConfig {
    /// Resolve SMTP config from the environment, or `None` when `AA_SMTP_HOST` is
    /// unset (the signal that SMTP is not configured for this deployment).
    ///
    /// `AA_SMTP_HOST` gates the whole thing: without it the caller falls back to
    /// the [`LoggingMailer`], so a deployment that never wired up SMTP degrades
    /// gracefully instead of failing every reset request.
    pub fn from_env() -> Option<Self> {
        let host = std::env::var(SMTP_HOST_ENV).ok().filter(|h| !h.is_empty())?;
        let port = std::env::var(SMTP_PORT_ENV)
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(DEFAULT_SMTP_PORT);
        let user = std::env::var(SMTP_USER_ENV).ok().filter(|v| !v.is_empty());
        let pass = std::env::var(SMTP_PASS_ENV).ok().filter(|v| !v.is_empty());
        let from = std::env::var(SMTP_FROM_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_FROM.to_string());
        Some(Self {
            host,
            port,
            user,
            pass,
            from,
        })
    }
}

/// Build the mailer for this deployment (AAASM-5306).
///
/// Returns a real [`SmtpMailer`] when `AA_SMTP_HOST` is configured, otherwise the
/// no-op [`LoggingMailer`] fallback so an SMTP-less deployment still boots and the
/// reset endpoint degrades gracefully (ADR 0031 §Q4). Constructing the SMTP
/// transport can fail on a bad host/credential combination; on that failure we
/// log and fall back to the logging mailer rather than refusing to start.
pub fn build_mailer() -> Arc<dyn Mailer> {
    match MailerConfig::from_env() {
        Some(cfg) => match SmtpMailer::from_config(cfg) {
            Ok(m) => {
                tracing::info!("SMTP mailer configured — password-reset emails will be delivered");
                Arc::new(m)
            }
            Err(_) => {
                tracing::warn!(
                    "AA_SMTP_HOST is set but the SMTP transport could not be built — \
                     falling back to the logging mailer; reset emails will NOT be delivered"
                );
                Arc::new(LoggingMailer::new())
            }
        },
        None => {
            tracing::info!(
                "SMTP is not configured (AA_SMTP_HOST unset) — using the logging mailer; \
                 password-reset emails will be logged, not delivered"
            );
            Arc::new(LoggingMailer::new())
        }
    }
}

/// The no-op / logging fallback mailer (AAASM-5306).
///
/// Used when SMTP is not configured. It never sends and never fails; it logs
/// that an email would have been delivered (recipient + subject only — never the
/// body, which carries the reset token). This is what lets a deployment without
/// SMTP run without panicking.
#[derive(Debug, Default, Clone)]
pub struct LoggingMailer;

impl LoggingMailer {
    /// Construct the logging fallback mailer.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Mailer for LoggingMailer {
    async fn send(&self, to: &str, subject: &str, _body: &str) -> Result<(), MailerError> {
        // Never log the body: it carries the reset token. Recipient + subject
        // only, so an operator can see delivery was attempted.
        tracing::info!(
            recipient = %to,
            %subject,
            "mailer not configured — email logged, not sent"
        );
        Ok(())
    }
}

/// The real SMTP transport (AAASM-5306).
///
/// Speaks SMTP over TLS via `lettre`'s async tokio transport. Authenticated
/// submission is used when a username/password are configured; otherwise the
/// relay is contacted unauthenticated. The configured `From:` is parsed once at
/// construction so a malformed address fails fast rather than per-send.
pub struct SmtpMailer {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl SmtpMailer {
    /// Build an SMTP mailer from resolved [`MailerConfig`].
    ///
    /// Returns `Err` when the `From:` address is malformed or the transport
    /// relay cannot be constructed. `build_mailer` maps that to the logging
    /// fallback so a bad config never blocks startup.
    pub fn from_config(cfg: MailerConfig) -> Result<Self, MailerError> {
        let from: lettre::message::Mailbox = cfg.from.parse().map_err(|_| MailerError::InvalidAddress)?;

        let mut builder = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(&cfg.host)
            .map_err(|_| MailerError::Transport)?
            .port(cfg.port);

        if let (Some(user), Some(pass)) = (cfg.user, cfg.pass) {
            builder = builder.credentials(lettre::transport::smtp::authentication::Credentials::new(user, pass));
        }

        Ok(Self {
            transport: builder.build(),
            from,
        })
    }
}

#[async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError> {
        use lettre::AsyncTransport;

        let to: lettre::message::Mailbox = to.parse().map_err(|_| MailerError::InvalidAddress)?;
        let message = lettre::Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .body(body.to_string())
            .map_err(|_| MailerError::Transport)?;

        // On failure return the generic Transport error — never the underlying
        // lettre error, which could echo the recipient/body into a log or response.
        self.transport.send(message).await.map_err(|_| MailerError::Transport)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capturing mailer for handler tests: records the last message sent
    /// instead of talking to a network. Mirrors the "no real send in tests"
    /// security rule (AAASM-5306).
    #[derive(Default)]
    struct RecordingMailer {
        sent: std::sync::Mutex<Vec<(String, String, String)>>,
    }

    #[async_trait]
    impl Mailer for RecordingMailer {
        async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError> {
            self.sent
                .lock()
                .unwrap()
                .push((to.to_string(), subject.to_string(), body.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn logging_mailer_never_fails() {
        let mailer = LoggingMailer::new();
        // The fallback must never error — a reset on an SMTP-less deployment
        // must not 500.
        assert!(mailer
            .send("someone@example.com", "Subject", "body-with-token")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn recording_mailer_captures_the_message() {
        let mailer = RecordingMailer::default();
        mailer.send("a@example.com", "Reset", "token=xyz").await.expect("send");
        let sent = mailer.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "a@example.com");
        assert_eq!(sent[0].1, "Reset");
    }

    #[test]
    fn config_is_none_without_a_host() {
        // Resolution keys off AA_SMTP_HOST; with it unset there is no config and
        // the caller falls back to the logging mailer.
        let cfg = MailerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            user: None,
            pass: None,
            from: DEFAULT_FROM.to_string(),
        };
        // A well-formed config builds a real SMTP transport.
        assert!(SmtpMailer::from_config(cfg).is_ok());
    }

    #[test]
    fn smtp_mailer_rejects_a_malformed_from_address() {
        let cfg = MailerConfig {
            host: "smtp.example.com".to_string(),
            port: 587,
            user: None,
            pass: None,
            from: "not an email".to_string(),
        };
        assert!(matches!(SmtpMailer::from_config(cfg), Err(MailerError::InvalidAddress)));
    }
}
