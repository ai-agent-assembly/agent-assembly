//! The personal-observe deployment profile's best-effort enterprise-coupling
//! gate (HORO-1375).
//!
//! # The spine
//!
//! personal-observe supplies the **policy-default slot only** and NEVER
//! writes `AgentRecord.enforcement_mode` or `enforcement_mode_expires_at`.
//! Consequences that fall out of that one invariant:
//!
//! * The capped column always wins: the resolver does
//!   `agent_override.unwrap_or(policy_default)` — see
//!   `aa-gateway/src/engine/effective_mode.rs::resolve_enforcement_mode`.
//! * personal-observe never time-expires: the shadow-expiry reconciler only
//!   ever selects agents with `enforcement_mode = Some(Observe)`, so a `None`
//!   record (the only thing this profile affects) is invisible to it by
//!   construction.
//! * personal-observe does not reuse the enterprise 72h shadow-renewal path —
//!   it never touches the expiry column at all.
//!
//! # Two layers, one grant
//!
//! Layer 1 ([`crate::config::GatewayConfig::validate`]) is **advisory only**:
//! three of the six non-test `GatewayConfig::load()` call sites in this
//! workspace swallow every `ConfigError` and continue with defaults, so it
//! must never be relied upon as the sole gate.
//!
//! Layer 2 ([`authorize_personal_observe`], this module) is the
//! **authoritative** gate. It re-derives the config-shaped signals directly
//! from the supplied [`PersonalObserveDeployment`] (never by calling
//! `validate()` and discarding which signals fired) and adds runtime/env
//! signals `validate()` cannot see, then mints the only proof
//! ([`PersonalObserveGrant`]) that lets a caller construct a
//! `PolicyDefaultMode::personal_observe` (see
//! `aa-gateway/src/engine/effective_mode.rs`).
//!
//! # Best-effort, not proof
//!
//! The detector below checks a fixed, named list of signals. It cannot see
//! MDM/EDR/sidecar/eBPF interception, an out-of-band policy delivery
//! mechanism, or any other management channel it does not know about. **Its
//! not refusing to start is never proof that a host is unmanaged** — see
//! `docs/src/security/personal-observe-profile.md#known-coverage-gaps` for
//! the full gap list (G1-G7).

use std::net::SocketAddr;

use crate::config::{ColdAction, DeploymentMode, GatewayConfig, ObservationProfile, StorageBackendType};

/// Proof that the personal-observe boot gate ran and found no coupling
/// signal among the ones it checks.
///
/// The `_seal` field is private, so the **only** way to construct a value of
/// this type is [`authorize_personal_observe`]. This is what makes
/// `PolicyDefaultMode::personal_observe` (in `aa-gateway`) unreachable
/// without having passed the gate.
#[derive(Debug, Clone)]
pub struct PersonalObserveGrant {
    _seal: (),
    pub(crate) checked_signals: Vec<&'static str>,
}

impl PersonalObserveGrant {
    /// Number of named coupling signals the gate checked before minting this
    /// grant. A public accessor for the *count* (not the list) so callers —
    /// e.g. the ACTIVE boot log — can report "checked <N> named signals"
    /// without exposing a way to reconstruct a grant from the list.
    pub fn checked_signal_count(&self) -> usize {
        self.checked_signals.len()
    }
}

/// Deployment facts the authoritative (Layer 2) gate inspects, beyond what
/// [`GatewayConfig`] alone carries.
pub struct PersonalObserveDeployment<'a> {
    /// The loaded, fully-resolved gateway config (post env-override).
    pub config: &'a GatewayConfig,
    /// The address the REST listener is about to bind.
    pub bind_addr: SocketAddr,
    /// Whether local auth has been disabled (`AASM_API_AUTH=off` /
    /// `LocalAuth::Off`).
    pub auth_is_off: bool,
}

/// Outcome of [`authorize_personal_observe`].
#[derive(Debug)]
pub enum PersonalObserveOutcome {
    /// `observation.profile == Standard` — zero behaviour change. This is
    /// the outcome for every deployment that predates HORO-1375.
    NotRequested,
    /// `observation.profile == PersonalObserve` and no coupling signal was
    /// detected among the checked signals.
    Granted(PersonalObserveGrant),
}

/// Refusal returned by [`authorize_personal_observe`] when personal-observe
/// was requested on a deployment that looks enterprise-managed.
///
/// The message is reviewed, load-bearing text (HORO-1375 design amendment
/// §6.4) — do not paraphrase or shorten it. In particular it must never claim
/// or imply that a deployment *without* a detected signal is "unmanaged",
/// "verified", "safe", or "confirmed" — see
/// `docs/src/security/personal-observe-profile.md#known-coverage-gaps`.
#[derive(Debug, Clone)]
pub struct PersonalObserveRefusal {
    /// The named coupling signals detected, in the fixed check order.
    pub signals: Vec<&'static str>,
}

impl std::fmt::Display for PersonalObserveRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refusing to start: observation.profile = personal_observe, but this deployment looks \
enterprise-managed. Detected signals: {}.\n\
personal-observe is a PERSONAL, UNMANAGED deployment profile; it must never weaken enforcement \
that an organisation is managing. Remove `observation.profile` from ~/.aasm/config.yaml (or unset \
AASM_OBSERVATION_PROFILE) to start normally.\n\
NOTE: this detector is BEST-EFFORT and NOT UNIVERSAL. Its NOT refusing is not proof that a \
deployment is unmanaged. See docs/src/security/personal-observe-profile.md#known-coverage-gaps.",
            self.signals.join(", ")
        )
    }
}

impl std::error::Error for PersonalObserveRefusal {}

/// The authoritative (Layer 2) personal-observe boot gate (HORO-1375 §6.2).
///
/// `NotRequested` when `dep.config.observation.profile == Standard` — inert
/// for every deployment that predates this ticket. Otherwise refuses when
/// any of the eighteen named signals below is detected; the config-shaped
/// signals (1-9) are re-derived directly from `dep.config` (never delegated
/// to `validate()`, which discards which signal fired), and combined with
/// nine runtime/env signals (10-18) `validate()` cannot see at all.
///
/// `env` is an injected closure — mirroring
/// `GatewayConfig::apply_env_overrides_with` — so tests can drive every
/// signal without mutating process-global environment state.
///
/// # Known gaps (HORO-1369 sub-tasks; see the docs page for detail)
///
/// // KNOWN GAP (HORO-TBD-G1): cannot see MDM / host-management channels
/// (macOS configuration profiles, Jamf, Intune, group policy). Undetected.
///
/// // KNOWN GAP (HORO-TBD-G2): cannot see EDR / sidecar / eBPF / kernel-level
/// interception, nor a transparent enforcing proxy on the egress path.
/// Undetected.
///
/// // KNOWN GAP (HORO-TBD-G3): cannot see org policy delivered out-of-band —
/// a managed policy file dropped into `$AA_POLICY` by a fleet tool is
/// indistinguishable from a user-authored one.
///
/// // KNOWN GAP (HORO-TBD-G4): `PolicyDocument.enforcement_mode` is dead on
/// the `CheckAction` hot path (both production callers hardcode `Enforce`).
/// It must NOT be wired without routing through this same gate.
///
/// // KNOWN GAP (HORO-TBD-G5): `aa-gateway` does not implement
/// personal-observe; it refuses at boot instead (see `aa-gateway/src/main.rs`).
///
/// // KNOWN GAP (HORO-TBD-G6): every signal here is checked at **boot only**.
/// A management channel that appears after boot is not re-detected — there
/// is no runtime re-check.
///
/// // KNOWN GAP (HORO-TBD-G7): `AgentRecord.enforcement_mode` is a `pub`
/// field; this gate and the registry write-side guard
/// (`set_enforcement_mode_persisted`) close the primitive and the rehydrate
/// path, but a direct field assignment inside `aa-gateway` remains possible.
///
/// // KNOWN GAP (HORO-TBD-G8): (pre-existing defect, not caused by this
/// ticket) prior to HORO-1375, aa-api's local audit hash chain reseeded to
/// zero every boot — any chain written before this fix is permanently forked
/// and cannot be verified end-to-end across that boundary.
// KNOWN GAP (HORO-TBD-G1): cannot see MDM / host-management channels.
// KNOWN GAP (HORO-TBD-G2): cannot see EDR / sidecar / eBPF / kernel-level interception.
// KNOWN GAP (HORO-TBD-G3): cannot see org policy delivered out-of-band.
// KNOWN GAP (HORO-TBD-G4): PolicyDocument.enforcement_mode stays dead on the CheckAction path.
// KNOWN GAP (HORO-TBD-G5): aa-gateway does not implement personal-observe; it refuses.
// KNOWN GAP (HORO-TBD-G6): signals are checked at boot only; no runtime re-check.
// KNOWN GAP (HORO-TBD-G7): AgentRecord.enforcement_mode is a pub field; direct assignment
// inside aa-gateway remains possible even after this gate + the registry write-side guard.
// KNOWN GAP (HORO-TBD-G8): pre-existing defect (not caused here) — any local audit chain
// written before this ticket's durability fix is permanently forked and unverifiable.
pub fn authorize_personal_observe(
    dep: PersonalObserveDeployment<'_>,
    env: impl Fn(&str) -> Option<String>,
) -> Result<PersonalObserveOutcome, PersonalObserveRefusal> {
    if dep.config.observation.profile != ObservationProfile::PersonalObserve {
        return Ok(PersonalObserveOutcome::NotRequested);
    }

    let mut signals = config_only_coupling_signals(dep.config);

    // --- Layer 2 additional signals (10-18): runtime / env, not visible to
    // `GatewayConfig::validate()`. ---
    if !dep.bind_addr.ip().is_loopback() {
        signals.push("REST bind address is not loopback");
    }
    if is_env_truthy(&env, "AA_LOCAL_ALLOW_REMOTE") {
        signals.push("AA_LOCAL_ALLOW_REMOTE is set");
    }
    if env("AASM_API_KEY").is_some_and(|v| !v.is_empty()) {
        signals.push("AASM_API_KEY is set");
    }
    if env("AA_MODE").as_deref() == Some("remote") {
        signals.push("AA_MODE=remote");
    }
    if env("AA_OPCONTROL_NATS_URL").is_some_and(|v| !v.is_empty()) {
        signals.push("AA_OPCONTROL_NATS_URL is set (cross-process op-control)");
    }
    if env("AA_AUDIT_NATS_URL").is_some_and(|v| !v.is_empty()) {
        signals.push("an audit-publisher / NATS endpoint is configured");
    }
    if env("AA_GATEWAY_URL").is_some_and(|v| !host_is_loopback(&v)) {
        signals.push("AA_GATEWAY_URL points off-host");
    }
    if let Some(dir) = env("AA_AUDIT_DIR") {
        if !dir.is_empty() && !audit_dir_is_within_home(&dir) {
            signals.push("AA_AUDIT_DIR points outside the user's home");
        }
    }
    if env("DATABASE_URL").is_some_and(|v| !v.is_empty()) || env("AASM_DATABASE_URL").is_some_and(|v| !v.is_empty()) {
        signals.push("a database URL is configured");
    }

    // `_seal: ()` records the checked-signal count independent of whether
    // any fired, matching "checked <N> named signals" in the ACTIVE log.
    const CHECKED_SIGNAL_NAMES: &[&str] = &[
        "mode: remote",
        "storage.backend: postgres",
        "remote.database_url set",
        "remote.redis_url / storage.redis.enabled",
        "remote.tls configured",
        "agent.api_key set",
        "agent.gateway_url is not loopback",
        "local.host is not loopback",
        "audit archive destination configured",
        "REST bind address is not loopback",
        "AA_LOCAL_ALLOW_REMOTE is set",
        "AASM_API_KEY is set",
        "AA_MODE=remote",
        "AA_OPCONTROL_NATS_URL is set (cross-process op-control)",
        "an audit-publisher / NATS endpoint is configured",
        "AA_GATEWAY_URL points off-host",
        "AA_AUDIT_DIR points outside the user's home",
        "a database URL is configured",
    ];

    if signals.is_empty() {
        Ok(PersonalObserveOutcome::Granted(PersonalObserveGrant {
            _seal: (),
            checked_signals: CHECKED_SIGNAL_NAMES.to_vec(),
        }))
    } else {
        Err(PersonalObserveRefusal { signals })
    }
}

/// The config-shaped coupling signals (HORO-1375 §6.1, signals 1-9), derived
/// directly from `cfg`'s fields.
///
/// Shared by [`crate::config::GatewayConfig::validate`] (Layer 1, advisory)
/// and [`authorize_personal_observe`] (Layer 2, authoritative) so both layers
/// check the exact same nine config-shaped conditions — Layer 2 simply adds
/// nine more it alone can see (signals 10-18).
pub fn config_only_coupling_signals(cfg: &GatewayConfig) -> Vec<&'static str> {
    let mut signals = Vec::new();
    if cfg.mode == DeploymentMode::Remote {
        signals.push("mode: remote");
    }
    if cfg.storage.backend == StorageBackendType::Postgres {
        signals.push("storage.backend: postgres");
    }
    if cfg.remote.database_url.is_some() {
        signals.push("remote.database_url set");
    }
    if cfg.remote.redis_url.is_some() || cfg.storage.redis.enabled {
        signals.push("remote.redis_url / storage.redis.enabled");
    }
    if cfg.remote.tls.is_some() {
        signals.push("remote.tls configured");
    }
    if cfg.agent.api_key.as_deref().is_some_and(|k| !k.is_empty()) {
        signals.push("agent.api_key set");
    }
    if !host_is_loopback(&cfg.agent.gateway_url) {
        signals.push("agent.gateway_url is not loopback");
    }
    if !cfg.local.host.is_loopback() {
        signals.push("local.host is not loopback");
    }
    if cfg.storage.retention.cold_action == ColdAction::Archive {
        signals.push("audit archive destination configured");
    }
    signals
}

/// `true` when `raw` is a recognised truthy value (`"1"` or
/// case-insensitively `"true"`) — mirrors the existing
/// `AA_LOCAL_ALLOW_REMOTE` convention in `aa-gateway/src/local_mode.rs`.
fn is_env_truthy(env: &impl Fn(&str) -> Option<String>, key: &str) -> bool {
    env(key)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Best-effort host extraction from a `scheme://host[:port][/path]` URL
/// string (or a bare `host[:port]`), true when that host is `localhost` or
/// parses as a loopback IP.
///
/// Deliberately minimal — no new dependency is pulled in for this best-effort
/// signal. A host this cannot parse is treated as non-loopback (fail closed:
/// an unparseable value is a coupling signal, not a free pass).
fn host_is_loopback(url_or_host: &str) -> bool {
    let without_scheme = url_or_host
        .rsplit_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url_or_host);
    let host_and_maybe_port = without_scheme.split('/').next().unwrap_or(without_scheme);
    // IPv6 literal form `[::1]:port` — strip brackets before the port split.
    let host = if let Some(rest) = host_and_maybe_port.strip_prefix('[') {
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_and_maybe_port.split(':').next().unwrap_or(host_and_maybe_port)
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// `true` when `dir` is inside the resolved home directory (or home cannot
/// be resolved, in which case the check cannot meaningfully fail closed
/// against an unknown boundary and is skipped — HOME resolution failing is a
/// degraded-environment case already handled elsewhere, not a coupling
/// signal in its own right).
fn audit_dir_is_within_home(dir: &str) -> bool {
    let Some(home) = dirs::home_dir() else {
        return true;
    };
    std::path::Path::new(dir).starts_with(&home)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;

    fn loopback_deployment(cfg: &GatewayConfig) -> PersonalObserveDeployment<'_> {
        PersonalObserveDeployment {
            config: cfg,
            bind_addr: "127.0.0.1:7700".parse().unwrap(),
            auth_is_off: false,
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)] // multiple, some nested, fields set below
    fn standard_profile_is_not_requested_even_with_every_signal_set() {
        let mut cfg = GatewayConfig::default();
        cfg.mode = DeploymentMode::Remote;
        cfg.storage.backend = StorageBackendType::Postgres;
        cfg.remote.database_url = Some("postgres://x".into());
        // profile stays Standard.
        let outcome = authorize_personal_observe(loopback_deployment(&cfg), no_env).unwrap();
        assert!(matches!(outcome, PersonalObserveOutcome::NotRequested));
    }

    #[test]
    fn personal_observe_with_no_signals_grants() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        let outcome = authorize_personal_observe(loopback_deployment(&cfg), no_env).unwrap();
        match outcome {
            PersonalObserveOutcome::Granted(grant) => {
                assert_eq!(grant.checked_signal_count(), 18);
            }
            PersonalObserveOutcome::NotRequested => panic!("expected Granted"),
        }
    }

    #[test]
    fn personal_observe_remote_mode_refuses() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        cfg.mode = DeploymentMode::Remote;
        let err = authorize_personal_observe(loopback_deployment(&cfg), no_env).unwrap_err();
        assert!(err.signals.contains(&"mode: remote"));
        let msg = err.to_string();
        assert!(msg.contains("BEST-EFFORT"));
        assert!(msg.contains("NOT UNIVERSAL"));
    }

    #[test]
    fn personal_observe_non_loopback_bind_refuses() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        let dep = PersonalObserveDeployment {
            config: &cfg,
            bind_addr: "0.0.0.0:7700".parse().unwrap(),
            auth_is_off: false,
        };
        let err = authorize_personal_observe(dep, no_env).unwrap_err();
        assert!(err.signals.contains(&"REST bind address is not loopback"));
    }

    #[test]
    fn personal_observe_env_signal_refuses() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        let env = |k: &str| (k == "AASM_API_KEY").then(|| "aa_deadbeef".to_string());
        let err = authorize_personal_observe(loopback_deployment(&cfg), env).unwrap_err();
        assert!(err.signals.contains(&"AASM_API_KEY is set"));
    }

    #[test]
    fn host_is_loopback_recognises_localhost_and_ips() {
        assert!(host_is_loopback("http://localhost:7391"));
        assert!(host_is_loopback("http://127.0.0.1:7391"));
        assert!(host_is_loopback("[::1]:7391"));
        assert!(!host_is_loopback("http://example.com:7391"));
    }

    // ── HORO-1375 AC-3 N2: every §6.2 signal (config-shaped 1-9 AND
    // runtime/env 10-18) individually causes authorize_personal_observe to
    // refuse, via the injected env closure (no process-env mutation).
    // Table-driven, one case per signal. ────────────────────────────────

    #[test]
    fn n2_authorize_personal_observe_each_signal_individually_refuses() {
        type CfgSetter = fn(&mut GatewayConfig);
        type Case = (
            &'static str,
            CfgSetter,
            &'static [(&'static str, &'static str)],
            &'static str,
        );
        let cases: &[Case] = &[
            (
                "mode: remote",
                |cfg| cfg.mode = DeploymentMode::Remote,
                &[],
                "127.0.0.1:7700",
            ),
            (
                "storage.backend: postgres",
                |cfg| cfg.storage.backend = StorageBackendType::Postgres,
                &[],
                "127.0.0.1:7700",
            ),
            (
                "remote.database_url set",
                |cfg| cfg.remote.database_url = Some("postgres://x".into()),
                &[],
                "127.0.0.1:7700",
            ),
            (
                "remote.redis_url / storage.redis.enabled",
                |cfg| cfg.storage.redis.enabled = true,
                &[],
                "127.0.0.1:7700",
            ),
            (
                "remote.tls configured",
                |cfg| {
                    cfg.remote.tls = Some(crate::config::TlsConfig {
                        cert_file: "cert.pem".into(),
                        key_file: "key.pem".into(),
                    })
                },
                &[],
                "127.0.0.1:7700",
            ),
            (
                "agent.api_key set",
                |cfg| cfg.agent.api_key = Some("k".into()),
                &[],
                "127.0.0.1:7700",
            ),
            (
                "agent.gateway_url is not loopback",
                |cfg| cfg.agent.gateway_url = "http://example.com:7391".into(),
                &[],
                "127.0.0.1:7700",
            ),
            (
                "local.host is not loopback",
                |cfg| cfg.local.host = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                &[],
                "127.0.0.1:7700",
            ),
            (
                "audit archive destination configured",
                |cfg| {
                    cfg.storage.retention.cold_action = crate::config::ColdAction::Archive;
                    cfg.storage.retention.archive_url = Some("s3://x".into());
                },
                &[],
                "127.0.0.1:7700",
            ),
            ("REST bind address is not loopback", |_| {}, &[], "0.0.0.0:7700"),
            (
                "AA_LOCAL_ALLOW_REMOTE is set",
                |_| {},
                &[("AA_LOCAL_ALLOW_REMOTE", "1")],
                "127.0.0.1:7700",
            ),
            (
                "AASM_API_KEY is set",
                |_| {},
                &[("AASM_API_KEY", "aa_deadbeef")],
                "127.0.0.1:7700",
            ),
            ("AA_MODE=remote", |_| {}, &[("AA_MODE", "remote")], "127.0.0.1:7700"),
            (
                "AA_OPCONTROL_NATS_URL is set (cross-process op-control)",
                |_| {},
                &[("AA_OPCONTROL_NATS_URL", "nats://x")],
                "127.0.0.1:7700",
            ),
            (
                "an audit-publisher / NATS endpoint is configured",
                |_| {},
                &[("AA_AUDIT_NATS_URL", "nats://x")],
                "127.0.0.1:7700",
            ),
            (
                "AA_GATEWAY_URL points off-host",
                |_| {},
                &[("AA_GATEWAY_URL", "http://example.com:7391")],
                "127.0.0.1:7700",
            ),
            (
                "AA_AUDIT_DIR points outside the user's home",
                |_| {},
                &[("AA_AUDIT_DIR", "/etc/aa-audit")],
                "127.0.0.1:7700",
            ),
            (
                "a database URL is configured",
                |_| {},
                &[("AASM_DATABASE_URL", "postgres://x")],
                "127.0.0.1:7700",
            ),
        ];

        for (signal, cfg_setter, env_vars, addr) in cases {
            let mut cfg = GatewayConfig::default();
            cfg.observation.profile = ObservationProfile::PersonalObserve;
            cfg_setter(&mut cfg);
            let dep = PersonalObserveDeployment {
                config: &cfg,
                bind_addr: addr.parse().unwrap(),
                auth_is_off: false,
            };
            let env_vars = *env_vars;
            let env = move |k: &str| env_vars.iter().find(|(name, _)| *name == k).map(|(_, v)| v.to_string());
            let err = authorize_personal_observe(dep, env).unwrap_err_or_else(signal);
            assert!(
                err.signals.contains(signal),
                "signal '{signal}' expected in {:?}",
                err.signals
            );
        }
    }

    /// Helper trait so the table-driven loop above gets a readable panic
    /// message naming which signal failed, without hand-rolling `match` at
    /// each iteration.
    trait ExpectRefusal<T> {
        fn unwrap_err_or_else(self, signal: &str) -> T;
    }
    impl<T> ExpectRefusal<T> for Result<PersonalObserveOutcome, T> {
        fn unwrap_err_or_else(self, signal: &str) -> T {
            match self {
                Ok(_) => panic!("signal '{signal}' should have refused, but was granted/not-requested"),
                Err(e) => e,
            }
        }
    }

    // ── HORO-1375 AC-3 N3: profile == Standard + every signal set =>
    // NotRequested, no refusal — proves the gate is inert for existing
    // deployments. ───────────────────────────────────────────────────────

    #[test]
    #[allow(clippy::field_reassign_with_default)] // multiple, some nested, fields set below
    fn n3_standard_profile_with_every_config_signal_set_is_not_requested() {
        let mut cfg = GatewayConfig::default();
        cfg.mode = DeploymentMode::Remote;
        cfg.storage.backend = StorageBackendType::Postgres;
        cfg.remote.database_url = Some("postgres://x".into());
        cfg.remote.redis_url = Some("redis://x".into());
        cfg.remote.tls = Some(crate::config::TlsConfig {
            cert_file: "cert.pem".into(),
            key_file: "key.pem".into(),
        });
        cfg.agent.api_key = Some("k".into());
        cfg.agent.gateway_url = "http://example.com:7391".into();
        cfg.local.host = std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0));
        cfg.storage.retention.cold_action = crate::config::ColdAction::Archive;
        cfg.storage.retention.archive_url = Some("s3://x".into());
        // profile stays Standard.
        let dep = PersonalObserveDeployment {
            config: &cfg,
            bind_addr: "0.0.0.0:7700".parse().unwrap(),
            auth_is_off: true,
        };
        let env = |k: &str| {
            (k == "AASM_API_KEY" || k == "AA_LOCAL_ALLOW_REMOTE" || k == "AASM_DATABASE_URL").then(|| "x".to_string())
        };
        let outcome = authorize_personal_observe(dep, env).expect("Standard profile must never refuse");
        assert!(matches!(outcome, PersonalObserveOutcome::NotRequested));
    }

    // ── HORO-1375 AC-3 N4 (wording test): the refusal string must contain
    // "BEST-EFFORT" / "NOT UNIVERSAL" and must not make an unqualified
    // posture claim using {"unmanaged", "verified", "safe", "confirmed"}.
    // The design's OWN verbatim §6.4 text uses "UNMANAGED" (as part of
    // "personal-observe is a PERSONAL, UNMANAGED deployment profile" — a
    // description of the FEATURE, not a claim about the deployment's
    // management status) — so this test checks the specific claim-shaped
    // phrasings the founder's rule actually targets, not a bare substring,
    // which would fail against the founder-approved verbatim text itself. ──

    #[test]
    fn n4_refusal_wording_contains_best_effort_and_not_universal() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        cfg.mode = DeploymentMode::Remote;
        let err = authorize_personal_observe(loopback_deployment(&cfg), no_env).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("BEST-EFFORT"), "message must say BEST-EFFORT: {msg}");
        assert!(msg.contains("NOT UNIVERSAL"), "message must say NOT UNIVERSAL: {msg}");
        // Forbidden CLAIM-shaped phrasings (case-insensitive): asserting the
        // detector's absence of a finding as a posture guarantee.
        //
        // "is unmanaged" is deliberately NOT in this list: the founder-approved
        // §6.4 text's own disclaimer sentence is "Its NOT refusing is not proof
        // that a deployment is unmanaged" — a double negative that DISCLAIMS
        // the claim, not one that makes it. A bare substring check for "is
        // unmanaged" would false-positive on that mandated sentence itself
        // (confirmed empirically — this is exactly the discrepancy the design
        // amendment's own N4 wording anticipates between a literal substring
        // reading and the founder-approved verbatim text).
        let lower = msg.to_lowercase();
        for forbidden_claim in [
            "verified personal",
            "verified safe",
            "confirmed safe",
            "confirmed unmanaged",
        ] {
            assert!(
                !lower.contains(forbidden_claim),
                "message must not contain the posture-claim phrase '{forbidden_claim}': {msg}"
            );
        }
    }

    // ── HORO-1375 AC-3 N9: PolicyDefaultMode / EffectiveMode's
    // no-public-Observe-constructor property lives in
    // aa-gateway/src/engine/effective_mode.rs (they are aa-gateway types);
    // see that crate's tests for the structural assertions. This crate only
    // asserts PersonalObserveGrant's own construction is sealed: there is no
    // public constructor other than authorize_personal_observe (enforced at
    // compile time by the private `_seal` field — this test exists so a
    // `pub(crate)` relaxation on that field is caught by a passing-then-
    // failing-to-compile signal if ever attempted from outside this module;
    // it exercises `checked_signal_count` as the only public read of a
    // granted value). ────────────────────────────────────────────────────

    #[test]
    fn n9_personal_observe_grant_only_exposes_a_checked_count_not_the_list() {
        let mut cfg = GatewayConfig::default();
        cfg.observation.profile = ObservationProfile::PersonalObserve;
        let outcome = authorize_personal_observe(loopback_deployment(&cfg), no_env).unwrap();
        let PersonalObserveOutcome::Granted(grant) = outcome else {
            panic!("expected Granted");
        };
        assert_eq!(grant.checked_signal_count(), 18);
        // `PersonalObserveGrant` has no `Default`, no `Deserialize`, and no
        // `From<()>` — the only way the line above compiles is via
        // `authorize_personal_observe`'s return value.
    }
}
