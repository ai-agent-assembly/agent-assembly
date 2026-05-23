//! `GET /api/v1/admin/status` — gateway admin status with storage health.
//!
//! Sibling of [`super::healthz`] that returns the deeper readiness signal:
//! backend type, database connection health and latency, hot-tier row
//! counts, and an optional TimescaleDB chunk + compression rollup. The
//! `aasm status` CLI consumes this endpoint to render the operator-facing
//! storage section delivered by AAASM-1591 / Epic 18 S-J.
//!
//! Unlike `/healthz`, this handler performs a backend round-trip per call
//! and is **not** intended for high-frequency load-balancer probes; mount
//! it behind admin-only access (Epic 17 S-G IAM gating, to land).

/// Replace the password segment of a database connection URL with `***`.
///
/// The server-side counterpart to the `aa-cli` deployment-overview
/// redactor. Per the AAASM-1591 acceptance criterion "Password in
/// database URL redacted in all output (API response, CLI output, logs)",
/// the gateway must never let a raw password leave the process — neither
/// in the API response body nor in any `tracing::*` macro that captures
/// the connection URL.
///
/// Behaviour mirrors the CLI helper at
/// `aa-cli::commands::status::models::redact_database_url`:
///
/// * `postgresql://user:secret@host:5432/db` → `postgresql://user:***@host:5432/db`
/// * `postgresql://user@host/db` (no password) → unchanged.
/// * `sqlite:///home/dev/.aasm/local.db` (no userinfo) → unchanged.
/// * `~/.aasm/local.db`, `not-a-url`, `""` → unchanged.
///
/// The split point between userinfo and host is the rightmost `@` inside
/// the authority — well-formed URLs percent-encode any `@` inside the
/// password, so this is safe.
pub fn redact_database_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = url[authority_start..]
        .find(['/', '?', '#'])
        .map(|i| authority_start + i)
        .unwrap_or(url.len());
    let authority = &url[authority_start..authority_end];

    let Some(at_idx) = authority.rfind('@') else {
        return url.to_string();
    };
    let userinfo = &authority[..at_idx];
    let Some(colon_idx) = userinfo.find(':') else {
        return url.to_string();
    };

    let user = &userinfo[..colon_idx];
    let host_and_rest = &url[authority_start + at_idx..];
    format!("{}://{}:***{}", &url[..scheme_end], user, host_and_rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_replaces_postgres_password_with_stars() {
        let redacted = redact_database_url("postgresql://aasm:secret@db.internal:5432/aasm");
        assert_eq!(redacted, "postgresql://aasm:***@db.internal:5432/aasm");
    }

    #[test]
    fn redact_leaves_url_without_userinfo_unchanged() {
        let input = "postgresql://db.internal:5432/aasm";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_user_only_userinfo_unchanged() {
        let input = "postgresql://aasm@db.internal:5432/aasm";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_sqlite_url_unchanged() {
        let input = "sqlite:///home/dev/.aasm/local.db";
        assert_eq!(redact_database_url(input), input);
    }

    #[test]
    fn redact_leaves_non_url_inputs_unchanged() {
        for input in ["~/.aasm/local.db", "not-a-url", "://no-scheme", ""] {
            assert_eq!(redact_database_url(input), input, "input: {input:?}");
        }
    }

    #[test]
    fn redact_handles_at_inside_password_via_rightmost_at_split() {
        // Well-formed URLs percent-encode `@` inside the password as `%40`,
        // but if a misconfigured operator sneaks a literal `@` past the
        // parser the rightmost-@ rule must still leave a valid host.
        let redacted = redact_database_url("postgresql://aasm:p@ss@db.internal:5432/aasm");
        assert_eq!(redacted, "postgresql://aasm:***@db.internal:5432/aasm");
    }
}
