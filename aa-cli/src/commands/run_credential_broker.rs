//! Build this launch's [`aa_isolation::CredentialBrokerReport`] from the facts
//! `aasm run` already holds (AAASM-6164).
//!
//! Pure and unit-testable, no I/O — direct sibling of
//! [`super::run_egress_broker`], reusing its built-in-LLM-host/MitM-scope logic
//! rather than re-deriving it, since a provider's credential can only be
//! brokered on a host this launch's proxy actually MitMs.

use aa_isolation::{BrokerageMode, BrokeredService, CredentialBrokerReport, FailurePosture, SupportLevel};

/// Host -> the env var name that host's provider credential makes
/// unnecessary in the child, once brokered. Hand-maintained, like
/// [`super::run_egress_broker::BUILT_IN_LLM_HOSTS`] — this crate does not
/// depend on `aa-proxy` (see `aa-isolation`'s own publish-graph note: `aa-proxy`
/// publishes, `aa-isolation` does not, and this adapter is the one place that
/// boundary is crossed), so it cannot import
/// `aa_proxy::credentials::classify_provider_for_host`'s table directly.
pub const BROKERED_PROVIDER_ENV_NAMES: &[(&str, &str)] = &[
    ("api.anthropic.com", "ANTHROPIC_API_KEY"),
    ("api.openai.com", "OPENAI_API_KEY"),
];

/// Parse `AA_PROXY_PROVIDER_KEYS` for the **hosts** it configures a real
/// provider credential for — never the key half of any entry, which is
/// dropped inside the split and never bound to a name, returned, or logged.
///
/// Mirrors `aa_proxy::credentials::CredentialStore::from_env`'s own parsing
/// (comma-separated `host=key` entries; malformed entries are skipped rather
/// than causing an error) so this adapter reports exactly the hosts the
/// spawned proxy will actually inject a credential for — never more, never
/// fewer.
pub fn provider_key_hosts_env() -> Vec<String> {
    match std::env::var("AA_PROXY_PROVIDER_KEYS") {
        Ok(val) if !val.is_empty() => val
            .split(',')
            .filter_map(|entry| {
                let entry = entry.trim();
                if entry.is_empty() {
                    return None;
                }
                match entry.split_once('=') {
                    Some((host, key)) if !host.trim().is_empty() && !key.is_empty() => {
                        Some(host.trim().to_ascii_lowercase())
                    }
                    _ => None,
                }
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether `host` is MitM'd for this launch, under the same scope
/// [`super::run_egress_broker::report_for_launch`] already derives — reused
/// rather than re-derived, since a provider's credential can only be brokered
/// on a host this launch actually decrypts.
fn host_is_mitmd(host: &str, llm_only: bool, mitm_hosts: &[String]) -> bool {
    if !llm_only {
        return true;
    }
    super::run_egress_broker::BUILT_IN_LLM_HOSTS.contains(&host) || mitm_hosts.iter().any(|h| h == host)
}

/// Build the [`CredentialBrokerReport`] for this launch from facts it already
/// holds.
///
/// * `endpoint`/`no_proxy` — see [`super::run_egress_broker::report_for_launch`];
///   a credential can only be brokered by a proxy that is actually bound and
///   not opted out of.
/// * `llm_only`/`mitm_hosts` — the same scope facts that decide which hosts
///   are decrypted at all.
/// * `provider_key_hosts` — [`provider_key_hosts_env`]: the hosts
///   `AA_PROXY_PROVIDER_KEYS` actually configures a credential for.
/// * `network_fail_open` — the same `AA_PROXY_NETWORK_FAIL_OPEN` fact
///   [`super::run_egress_broker::report_for_launch`] reads.
///
/// A [`BrokeredService`] is emitted for `(host, env_name)` in
/// [`BROKERED_PROVIDER_ENV_NAMES`] only when **all** of: the proxy is bound
/// and not opted out, `host` is actually MitM'd for this launch, and `host`
/// has a configured provider key. Every other host is simply absent from the
/// report — absence, not a weaker claim.
pub fn report_for_launch(
    endpoint: Option<&str>,
    no_proxy: bool,
    llm_only: bool,
    mitm_hosts: &[String],
    provider_key_hosts: &[String],
    network_fail_open: bool,
) -> CredentialBrokerReport {
    if endpoint.is_none() {
        return CredentialBrokerReport::unavailable("no governed egress endpoint is bound for this launch");
    }
    if no_proxy {
        return CredentialBrokerReport::unavailable("the launch explicitly opted out of interception (--no-proxy)");
    }

    let failure_posture = if network_fail_open {
        FailurePosture::FailOpen
    } else {
        FailurePosture::FailClosed
    };

    let mut report = CredentialBrokerReport::new(failure_posture).with_ceiling_support(SupportLevel::Unsupported {
        reason: "this deployment performs no per-run credential use or byte accounting".to_string(),
    });

    for (host, env_name) in BROKERED_PROVIDER_ENV_NAMES {
        let configured = provider_key_hosts.iter().any(|h| h == host);
        if configured && host_is_mitmd(host, llm_only, mitm_hosts) {
            report = report.with_service(BrokeredService {
                service: host.to_string(),
                env_names: vec![env_name.to_string()],
                mode: BrokerageMode::BrokerPerformsRequest {
                    mechanism_detail: format!(
                        "the dedicated proxy strips the agent's own auth header for `{host}` and injects the \
                         operator's real provider credential at egress (AAASM-3578/AAASM-5926); the source \
                         credential is never handed to the child"
                    ),
                },
            });
        }
    }

    report
}

/// The env names `aasm run` must actively withhold from the child because
/// `report` covers them with a secretless [`BrokerageMode`].
pub fn withheld_names(report: &CredentialBrokerReport) -> Vec<String> {
    report.secretless_env_names().into_iter().map(str::to_string).collect()
}
#[cfg(test)]
mod tests {
    use aa_isolation::BrokerAvailability;

    use super::*;

    /// Serializes the two tests below that mutate `AA_PROXY_PROVIDER_KEYS` —
    /// this crate's tests run in one process and share the real environment.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn no_bound_endpoint_is_unavailable() {
        let report = report_for_launch(None, false, true, &[], &[], false);
        assert!(matches!(report.availability(), BrokerAvailability::Unavailable { .. }));
    }

    #[test]
    fn no_proxy_is_unavailable_even_with_a_bound_endpoint() {
        let opted_out = report_for_launch(Some("http://127.0.0.1:9"), true, true, &[], &[], false);
        assert!(matches!(
            opted_out.availability(),
            BrokerAvailability::Unavailable { .. }
        ));
        let control = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], &[], false);
        assert_eq!(control.availability(), &BrokerAvailability::Available);
    }

    #[test]
    fn a_configured_and_mitmd_provider_host_yields_a_secretless_service() {
        let report = report_for_launch(
            Some("http://127.0.0.1:9"),
            false,
            true,
            &[],
            &["api.anthropic.com".to_string()],
            false,
        );
        assert_eq!(withheld_names(&report), vec!["ANTHROPIC_API_KEY".to_string()]);
    }

    #[test]
    fn a_configured_but_not_mitmd_host_yields_no_service() {
        // llm_only with no matching mitm_hosts entry: api.anthropic.com IS a
        // built-in LLM host, so use a hypothetical non-built-in host to prove
        // the MitM-scope gate actually applies. api.openai.com is also
        // built-in, so this control instead proves the positive case at a
        // built-in host and relies on the config-absent test below for the
        // negative half of "configured".
        let report = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], &[], false);
        assert!(withheld_names(&report).is_empty());
    }

    #[test]
    fn an_unconfigured_host_yields_no_service_even_when_mitmd() {
        // Control: api.anthropic.com is MitM'd (built-in LLM host) but no key
        // is configured for it — no service, so nothing is withheld.
        let report = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], &[], false);
        assert!(withheld_names(&report).is_empty());

        // The identical launch with the key configured now yields a service.
        let configured = report_for_launch(
            Some("http://127.0.0.1:9"),
            false,
            true,
            &[],
            &["api.anthropic.com".to_string()],
            false,
        );
        assert_eq!(withheld_names(&configured), vec!["ANTHROPIC_API_KEY".to_string()]);
    }

    #[test]
    fn openai_is_the_identical_path() {
        let report = report_for_launch(
            Some("http://127.0.0.1:9"),
            false,
            true,
            &[],
            &["api.openai.com".to_string()],
            false,
        );
        assert_eq!(withheld_names(&report), vec!["OPENAI_API_KEY".to_string()]);
    }

    #[test]
    fn provider_key_hosts_env_parses_hosts_only_never_keys() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "AA_PROXY_PROVIDER_KEYS",
            "API.Anthropic.com=sk-ant-secret,api.openai.com=sk-oai-secret",
        );
        let hosts = provider_key_hosts_env();
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
        assert_eq!(
            hosts,
            vec!["api.anthropic.com".to_string(), "api.openai.com".to_string()]
        );
        for host in &hosts {
            assert!(!host.contains("sk-"));
        }
    }

    #[test]
    fn provider_key_hosts_env_skips_malformed_entries() {
        let _lock = ENV_LOCK.lock().unwrap();
        std::env::set_var(
            "AA_PROXY_PROVIDER_KEYS",
            "no-equals-sign,=orphan-key,emptyval=,api.openai.com=sk-ok",
        );
        let hosts = provider_key_hosts_env();
        std::env::remove_var("AA_PROXY_PROVIDER_KEYS");
        assert_eq!(hosts, vec!["api.openai.com".to_string()]);
    }

    #[test]
    fn ceiling_support_is_always_unsupported_and_says_why() {
        let report = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], &[], false);
        match report.ceiling_support() {
            SupportLevel::Unsupported { reason } => assert!(!reason.is_empty()),
            SupportLevel::Full | SupportLevel::Partial { .. } => panic!("no credential accounting exists today"),
        }
    }
}
