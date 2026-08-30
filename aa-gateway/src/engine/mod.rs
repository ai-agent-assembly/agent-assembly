//! Policy engine implementation.
//!
//! Core rate limiting and enforcement mechanisms for the Agent Assembly policy engine.

pub mod cache;
pub mod decision;
pub mod detection;
pub(crate) mod rate_limit;
pub mod scope_index;
pub mod sensitive_data;
pub(crate) mod watcher;

pub use scope_index::PolicyId;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::engine::cache::{CacheKey, DecisionCache};

use crate::budget::BudgetTracker;

use crate::engine::decision::PolicyDecision;
use crate::engine::scope_index::ScopeIndex;
use crate::policy::document::{ActionOnExceed, CredentialAction};
use crate::policy::{PolicyDocument, PolicyValidator};
use crate::registry::AgentRegistry;

/// Side-effect action the service layer should take when a request is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyAction {
    /// Default: just deny this request, keep the agent active.
    Block,
    /// Deny this request and request that the caller suspend the agent.
    SuspendAgent,
}

/// The outcome of a [`PolicyEngine::evaluate`] call.
///
/// Carries the governance decision alongside any credential or PII findings
/// produced by the scanner pass. If `credential_findings` is non-empty the
/// original payload was redacted; `redacted_payload` holds the sanitised text.
///
/// Security invariant: `credential_findings` stores only the kind and byte
/// offset of each finding — never the matched secret or the raw payload.
pub struct EvaluationResult {
    /// Governance decision: `Allow`, `Deny`, or `RequiresApproval`.
    pub decision: aa_core::PolicyResult,
    /// Redacted version of the action payload when one or more findings were
    /// detected. `None` when the payload was clean.
    pub redacted_payload: Option<String>,
    /// All credential and PII findings detected during the scanner pass.
    /// Empty when the payload was clean.
    pub credential_findings: Vec<aa_security::CredentialFinding>,
    /// AAASM-5354 — the same Stage 6 findings described in the canonical,
    /// provider-neutral vocabulary of ADR 0032 §2, sorted by span.
    ///
    /// A parallel projection, not a replacement: `credential_findings` remains
    /// the enforcement-tier list every existing consumer reads, and it is
    /// byte-identical to what the pre-port code produced. This list is what a
    /// reporting consumer should read, because it is the only one that can
    /// describe a finding from a detector with no
    /// [`CredentialKind`](aa_security::CredentialKind) — every
    /// [`detection::LocalePack`] hit.
    ///
    /// The two lists are not in bijection, and both directions occur:
    ///
    /// - A locale-pack finding appears here and **not** in
    ///   `credential_findings`, because fabricating a `CredentialKind` for it
    ///   would extend a catalogue ADR 0032 §2 freezes.
    /// - A zero-width operator-regex match appears in `credential_findings` and
    ///   **not** here, because a canonical finding covers at least one byte.
    ///
    /// # Who reads this, exactly
    ///
    /// Stated precisely because an earlier draft of this doc claimed the field
    /// "feeds the audit write", which was false when written — nothing read it
    /// at all. Three consumers read it today, and all three read it as a
    /// **presence test**, not as content:
    ///
    /// - [`service::convert::eval_result_to_response`](crate::service::convert::eval_result_to_response)
    ///   — a finding here makes the wire decision `Redact` and contributes a
    ///   [`RedactRule`] naming the canonical category. Without this the caller
    ///   was told "allow, nothing to redact" and forwarded the original payload.
    /// - `PolicyService`'s audit write — a finding here attaches the
    ///   [`Redaction`](aa_security::Redaction), so the sanitised payload reaches
    ///   the audit entry instead of nothing.
    /// - The anomaly detector — a finding here counts toward the behavioural
    ///   baseline and sets `has_pii`.
    ///
    /// The findings themselves are **not** serialised into the audit entry;
    /// that projection is AAASM-5357's work. `maybe_emit_secret_alert` also does
    /// not read this field — see its docs for why alerting a kindless finding
    /// through `aa-api`'s `detected_pattern_type` would publish a wrong answer.
    ///
    /// Spans are audit-tier only (ADR 0032 §9). This field carries them for the
    /// same reason `credential_findings` already does, and must not be projected
    /// into a metric label, a log line or an API response without going through
    /// [`SensitiveDataFindingRecord`](aa_core::types::sensitive_data::SensitiveDataFindingRecord),
    /// which drops the span by construction.
    pub canonical_findings: Vec<aa_security::canonical::CanonicalFinding>,
    /// Optional side-effect action for the service layer when the decision is `Deny`.
    /// `None` means no side-effect beyond denying the request.
    pub deny_action: Option<DenyAction>,
    /// AAASM-5107 — content digest of the policy document that produced this
    /// decision (`"sha256:<hex>"`), as reported by
    /// [`decision::merge_decisions_attributed`]. Carried to the audit write so a
    /// per-document 24h hit count is queryable and the deciding document is
    /// unambiguous even across two versions of the same `(scope, name)`.
    ///
    /// `None` on the pre-cascade / primary-policy paths and the empty-cascade
    /// fail-closed deny — those verdicts are produced without a nameable cascade
    /// document, so no digest is attributed rather than a misleading one.
    pub policy_doc_id: Option<String>,
    /// AAASM-5100 / ADR-0018 item A — `true` when this action was **permitted but
    /// scoped down** by an in-force policy allow-list rather than blocked: the
    /// action's capability was admitted only because it fell inside the merged
    /// cascade's restricted allow-list. Purely observational metadata carried to
    /// the audit write so the read-side can render the `narrow` runtime verdict
    /// (distinct from a plain `allow`); it never changes the decision. Always
    /// `false` for non-`Allow` decisions and for a default-allow with no allow-
    /// list restriction in force.
    pub narrowed: bool,
}

impl EvaluationResult {
    /// A bare `Deny` with the given reason: no redacted payload, no findings,
    /// no side-effect action. Used by the pre-scan pipeline stages where there
    /// is nothing else to carry.
    fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: aa_core::PolicyResult::Deny { reason: reason.into() },
            redacted_payload: None,
            credential_findings: vec![],
            canonical_findings: vec![],
            deny_action: None,
            policy_doc_id: None,
            narrowed: false,
        }
    }

    /// A `Deny` that still carries the post-scan redaction state (redacted
    /// payload + findings) and an optional side-effect action. Used by the
    /// budget stage, which denies after the credential scan has already run.
    fn deny_with(
        reason: impl Into<String>,
        redacted_payload: Option<String>,
        credential_findings: Vec<aa_security::CredentialFinding>,
        canonical_findings: Vec<aa_security::canonical::CanonicalFinding>,
        deny_action: Option<DenyAction>,
    ) -> Self {
        Self {
            decision: aa_core::PolicyResult::Deny { reason: reason.into() },
            redacted_payload,
            credential_findings,
            canonical_findings,
            deny_action,
            policy_doc_id: None,
            narrowed: false,
        }
    }
}

/// Metadata captured when observe-mode evaluation suppresses a non-Allow
/// decision. Returned alongside the (now-Allow) `EvaluationResult` so the
/// service layer can emit a `dry_run: true` audit event recording what
/// would have happened under live enforcement.
///
/// The shadow event never carries the rejected payload itself — that lives
/// in the surrounding `AuditEvent` constructed at the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowEvent {
    /// The decision the engine would have returned in `Enforce` mode.
    /// One of `"deny"`, `"redact"`, `"pending"`. Mirrors the proto enum
    /// `AuditEvent.shadow_decision`.
    pub shadow_decision: String,
    /// Reason carried by the original decision (e.g. "tool denied by policy").
    /// Recorded so the audit reader can render the same explanation an
    /// operator would have seen in enforce mode.
    pub reason: String,
}

/// Resolve the effective enforcement mode for a given agent + policy document.
///
/// Lookup order (first match wins):
///
/// 1. The agent's per-record override (set via `RegisterRequest.enforcement_mode`).
/// 2. The policy document's `enforcement_mode` field.
///
/// Both inputs are `Copy` so this is a cheap pure function callable from the
/// `CheckAction` hot path without locks or allocations.
pub fn resolve_enforcement_mode(
    agent_override: Option<aa_core::EnforcementMode>,
    policy_default: aa_core::EnforcementMode,
) -> aa_core::EnforcementMode {
    agent_override.unwrap_or(policy_default)
}

/// Transform an [`EvaluationResult`] according to the active enforcement mode.
///
/// In `Enforce` mode: returns the input unchanged with `None` shadow event.
///
/// In `Observe` mode: if the decision is non-`Allow`, rewrites it to
/// `PolicyResult::Allow`, strips any deny-side-effect, and produces a
/// `ShadowEvent` carrying the original decision string + reason. The caller
/// is responsible for emitting an `AuditEvent { dry_run: true, ... }` from
/// the returned metadata.
///
/// In `Disabled` mode: returns the input unchanged with `None` shadow event.
/// Disabled is intended for hermetic test harnesses; production policy
/// engines should not run with `Disabled` and `transform_for_observe_mode`
/// makes no effort to mask its decisions.
pub fn transform_for_observe_mode(
    result: EvaluationResult,
    mode: aa_core::EnforcementMode,
) -> (EvaluationResult, Option<ShadowEvent>) {
    if mode != aa_core::EnforcementMode::Observe {
        return (result, None);
    }

    let (shadow_decision, reason) = match &result.decision {
        aa_core::PolicyResult::Allow => return (result, None),
        aa_core::PolicyResult::Deny { reason } => ("deny", reason.clone()),
        aa_core::PolicyResult::RequiresApproval { .. } => ("pending", String::new()),
    };

    let shadow = ShadowEvent {
        shadow_decision: shadow_decision.to_string(),
        reason,
    };

    let transformed = EvaluationResult {
        decision: aa_core::PolicyResult::Allow,
        redacted_payload: None,
        credential_findings: result.credential_findings,
        canonical_findings: vec![],
        deny_action: None,
        // AAASM-5107 — observe mode rewrites the verdict to Allow but the policy
        // document still fired; preserve its attribution so the dry-run audit
        // entry still names the document that would have decided in enforce mode.
        policy_doc_id: result.policy_doc_id,
        // The observe-mode allow masks a would-be deny/pending, not a scoping —
        // it is a dry-run allow, never a `narrow`.
        narrowed: false,
    };

    (transformed, Some(shadow))
}

/// Summary of the currently active policy, returned by
/// [`PolicyEngine::active_policy_info`].
#[derive(Debug, Clone)]
pub struct ActivePolicyInfo {
    /// Policy name from YAML envelope `metadata.name`.
    pub name: Option<String>,
    /// Policy version from YAML envelope `metadata.version`.
    pub policy_version: Option<String>,
    /// Number of per-tool rules in the active policy.
    pub rule_count: usize,
}

/// Assembled policy engine that evaluates governance actions through a 7-step pipeline.
pub struct PolicyEngine {
    policy: Arc<ArcSwap<PolicyDocument>>,
    /// Pre-compiled Aho-Corasick credential scanner (built-in patterns).
    ///
    /// Built once at construction time from [`aa_security::CredentialScanner`].
    /// Always active — scans every action payload regardless of policy data section.
    scanner: aa_security::CredentialScanner,
    rate_state: DashMap<String, Mutex<crate::engine::rate_limit::TokenBucket>>,
    budget: Arc<BudgetTracker>,
    /// Hot-swappable cascade state: the scope-keyed policy index plus the
    /// regex patterns compiled from the Global doc's `data.sensitive_patterns`.
    ///
    /// Held behind an [`ArcSwap`] so the directory watcher (AAASM-3497) can
    /// atomically replace the whole cascade — index and compiled patterns
    /// together — when a `*.yaml` in the policy directory is added, removed,
    /// or modified, without locking the request hot path. For the single-file
    /// and in-memory construction paths the slot is built once and never
    /// swapped.
    ///
    /// Known residual: the single-file watcher ([`watcher::start_watcher`])
    /// swaps the `policy` document but not these `compiled_patterns`, so a
    /// single-file hot-reload still serves the construction-time
    /// `sensitive_patterns`. The directory path recompiles them on every swap;
    /// recompiling on the single-file path is left out of scope for AAASM-3497.
    cascade: Arc<ArcSwap<CascadeState>>,
    /// Directory watcher for the multi-document cascade (AAASM-3497).
    ///
    /// Present only when the engine was built from a policy *directory*
    /// (`load_cascade_from_dir*`); drop it to stop watching. Distinct from
    /// `_watcher`, which is the single-file watcher.
    _cascade_watcher: Option<notify::RecommendedWatcher>,
    _watcher: Option<notify::RecommendedWatcher>,
    /// Optional registry for resolving agent lineage during cascade evaluation.
    /// When `None`, `collect_cascade` walks only Global and Agent scopes.
    registry: Option<Arc<AgentRegistry>>,
    /// Monotonic policy epoch — incremented on every `load_policy` or `apply_yaml`
    /// call. Embedded in `CacheKey` so stale cache entries are automatically
    /// invalidated when policy changes without any active eviction step.
    policy_epoch: Arc<AtomicU64>,
    /// Bounded LRU cache for cascade evaluation results.
    /// Only the cascade path (`evaluate_with_cascade`) consults this cache.
    decision_cache: DecisionCache,
    /// Optional push-invalidation hub. When set, `apply_yaml` fans a
    /// `PolicyInvalidated` event out to every subscribed Assembly so their L1
    /// caches drop stale decisions within ~100 ms instead of awaiting TTL.
    invalidation_hub: Option<Arc<crate::invalidation::InvalidationHub>>,
    /// AAASM-5440 — where a decision carrying canonical findings is projected
    /// for the durable sensitive-data tier. `None` leaves the projection
    /// unwritten, which is the default: ADR 0032 §8 makes the whole tier
    /// opt-in, and an engine that was never given a sink must behave exactly as
    /// it did before this field existed.
    ///
    /// Deliberately **not** carried into either simulation engine
    /// ([`Self::ephemeral_for_simulation`] and the one
    /// [`Self::simulate_against`] builds inline): a dry run applies no
    /// enforcement and writes no audit entry, so it must not deposit rows in a
    /// governance table either.
    sensitive_data: Option<sensitive_data::SensitiveDataProjectionSink>,
}

/// Error returned when loading a policy from a file fails.
#[derive(Debug)]
pub enum PolicyLoadError {
    /// An I/O error occurred reading the file.
    Io(std::io::Error),
    /// The YAML parsed but failed policy validation.
    Validation(Vec<crate::policy::ValidationError>),
    /// An error from the policy history store.
    History(crate::policy::history::PolicyHistoryError),
}

/// Parse the optional `budget.timezone`, **failing closed** on a misconfigured
/// value (AAASM-3875).
///
/// The budget timezone governs the daily/monthly reset boundaries, not an
/// allow/deny decision directly — but silently falling back to UTC on an
/// unparseable value (the former `parse().ok().unwrap_or(UTC)` behavior)
/// shifted those boundaries without warning, masking the operator's
/// misconfiguration. Mirroring the schedule fix (AAASM-3847,
/// `eval_schedule_stage`), a present-but-unparseable timezone is now a hard
/// configuration error that aborts the policy load rather than degrading
/// silently to UTC. `None` (no timezone configured) keeps the documented UTC
/// default, since absence is a deliberate choice, not a misconfiguration.
fn parse_budget_tz(timezone: Option<&str>) -> Result<chrono_tz::Tz, PolicyLoadError> {
    match timezone {
        None => Ok(chrono_tz::UTC),
        Some(s) => s.parse::<chrono_tz::Tz>().map_err(|_| {
            PolicyLoadError::Validation(vec![crate::policy::ValidationError::new(
                "budget.timezone",
                format!("invalid budget timezone: {s}"),
            )])
        }),
    }
}

/// Stage 6 outcome for [`PolicyEngine::apply_credential_scan`]: either a
/// hard-block deny (the `credential_action: block` short-circuit) or the
/// redacted payload + findings to carry into the remaining stages.
enum CredentialScanOutcome {
    /// `credential_action: block` with at least one finding — deny outright,
    /// the payload never reaches the LLM in any form.
    Block(EvaluationResult),
    /// Continue evaluation with this (redacted_payload, enforcement-tier
    /// findings, canonical findings) triple.
    Continue(
        Option<String>,
        Vec<aa_security::CredentialFinding>,
        Vec<aa_security::canonical::CanonicalFinding>,
    ),
}

/// Parsed result of reading a cascade directory, before a budget tracker is
/// chosen. Shared between [`PolicyEngine::load_cascade_from_dir`] (fresh
/// tracker) and [`PolicyEngine::load_cascade_from_dir_with_budget`]
/// (externally-restored tracker) so the parse path stays identical.
struct ParsedCascade {
    scope_index: ScopeIndex,
    /// First Global-scoped document, if any — becomes the primary slot.
    primary: Option<PolicyDocument>,
    compiled_patterns: Vec<regex::Regex>,
    budget_tz: chrono_tz::Tz,
    daily_limit: Option<rust_decimal::Decimal>,
    monthly_limit: Option<rust_decimal::Decimal>,
    team_daily_limit: Option<rust_decimal::Decimal>,
    team_monthly_limit: Option<rust_decimal::Decimal>,
    org_daily_limit: Option<rust_decimal::Decimal>,
    org_monthly_limit: Option<rust_decimal::Decimal>,
}

/// The hot-swappable half of a cascade engine: the scope-keyed policy index
/// plus the regex patterns compiled from the Global document's
/// `data.sensitive_patterns`.
///
/// Bundled into one [`ArcSwap`] slot so the directory watcher (AAASM-3497)
/// replaces the index and its derived patterns as a single atomic unit — a
/// request never observes a new index against stale patterns or vice versa.
#[derive(Debug, Default, Clone)]
pub(crate) struct CascadeState {
    pub(crate) scope_index: ScopeIndex,
    /// Regex patterns compiled from the Global doc's `data.sensitive_patterns`.
    /// Recompiled on every cascade swap so hot-reload keeps them in sync with
    /// the directory's current Global document.
    pub(crate) compiled_patterns: Vec<regex::Regex>,
}

impl PolicyEngine {
    /// Load a policy from a YAML file, parse it, validate it, and start the filesystem watcher.
    ///
    /// `budget_alert_tx` is the broadcast sender for budget threshold alerts.
    /// Pass the sender half of the channel created in `main.rs` so alerts
    /// reach the webhook delivery loop.
    pub fn load_from_file(
        path: &Path,
        budget_alert_tx: tokio::sync::broadcast::Sender<crate::budget::BudgetAlert>,
    ) -> Result<Self, PolicyLoadError> {
        let yaml = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;
        let output = PolicyValidator::from_yaml(&yaml).map_err(PolicyLoadError::Validation)?;
        let compiled_patterns = output
            .document
            .data
            .as_ref()
            .map(|dp| {
                dp.sensitive_patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let budget_tz = parse_budget_tz(output.document.budget.as_ref().and_then(|bp| bp.timezone.as_deref()))?;
        let daily_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let monthly_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        // AAASM-5087 — Lift team-tier limits from BudgetPolicy into the tracker.
        let team_daily_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.team_daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let team_monthly_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.team_monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        // AAASM-2022 — Lift org-tier limits from BudgetPolicy into the tracker.
        let org_daily_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.org_daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let org_monthly_limit = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.org_monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let mut budget_tracker = BudgetTracker::new_with_alert_sender(
            crate::budget::PricingTable::default_table(),
            daily_limit,
            monthly_limit,
            budget_tz,
            budget_alert_tx,
        );
        if let Some(limit) = team_daily_limit {
            budget_tracker = budget_tracker.with_team_daily_limit(limit);
        }
        if let Some(limit) = team_monthly_limit {
            budget_tracker = budget_tracker.with_team_monthly_limit(limit);
        }
        if let Some(limit) = org_daily_limit {
            budget_tracker = budget_tracker.with_org_daily_limit(limit);
        }
        if let Some(limit) = org_monthly_limit {
            budget_tracker = budget_tracker.with_org_monthly_limit(limit);
        }
        let budget = Arc::new(budget_tracker);
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(output.document)));
        let watcher = crate::engine::watcher::start_watcher(path, policy_arc.clone()).ok();
        Ok(PolicyEngine {
            policy: policy_arc,
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget,
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState {
                scope_index: ScopeIndex::new(),
                compiled_patterns,
            })),
            _cascade_watcher: None,
            _watcher: watcher,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(100_000),
        })
    }

    /// AAASM-2023 — Load **multiple** policy documents from every `*.yaml`
    /// file in a directory and populate the `scope_index` cascade.
    ///
    /// Each YAML file is parsed independently and inserted into the
    /// `scope_index` keyed by its `scope` field (`Global` / `Org(...)` /
    /// `Team(...)` / `Agent(...)`). At evaluation time, the cascade
    /// collector at `evaluate()` walks the scopes for the calling agent's
    /// lineage and merges every matching document — which finally lets
    /// `scope: org:<id>` policies fire ONLY for agents in that org
    /// (closes the gateway-side gap that AAASM-2008 ST-org-4 surfaced).
    ///
    /// ## Semantics
    ///
    /// * Files are loaded in alphabetical filename order (deterministic).
    /// * The first Global-scoped document found supplies the budget and
    ///   data-pattern config; if no Global-scoped document is present,
    ///   budget limits default to None and the data-pattern set is empty.
    /// * Files that fail to parse abort the entire load — the caller gets
    ///   a `PolicyParseError` for the first bad file. (Partial loads would
    ///   be a worse failure mode than the loud abort.)
    /// * The `policy: ArcSwap<Arc<PolicyDocument>>` primary field is set
    ///   to the first Global-scoped document (or a fresh default when
    ///   none is present). With a non-empty `scope_index`, `evaluate()`
    ///   routes through `evaluate_with_cascade` and the primary slot is
    ///   only consulted by callers that bypass the cascade path.
    /// * A directory watcher is attached (AAASM-3497): editing, adding, or
    ///   removing a `*.yaml` in `dir` re-reads the whole directory and
    ///   atomically swaps the rebuilt cascade into the live slot. A read or
    ///   parse failure during reload is ignored and the current cascade is
    ///   preserved — a broken edit never degrades to allow-all.
    ///
    /// ## Example
    ///
    /// ```text
    /// policies/
    /// ├── 000-global-allow-all.yaml   # scope: global (or omitted)
    /// ├── 100-org-acme-deny-bash.yaml # scope: org:acme
    /// └── 200-team-platform.yaml      # scope: team:platform
    /// ```
    ///
    /// Loading this directory gives every agent in `acme/platform` the
    /// Global rules + the org-acme deny + the team-platform rules.
    /// Agents in other orgs see only the Global rules.
    pub fn load_cascade_from_dir(
        dir: &Path,
        budget_alert_tx: tokio::sync::broadcast::Sender<crate::budget::BudgetAlert>,
    ) -> Result<Self, PolicyLoadError> {
        let parsed = Self::read_cascade_dir(dir)?;

        // The Global-scoped document supplies the budget limits; build a
        // fresh tracker around them. (The `_with_budget` sibling instead
        // adopts an externally-restored tracker — see
        // [`load_cascade_from_dir_with_budget`].)
        let mut budget_tracker = BudgetTracker::new_with_alert_sender(
            crate::budget::PricingTable::default_table(),
            parsed.daily_limit,
            parsed.monthly_limit,
            parsed.budget_tz,
            budget_alert_tx,
        );
        if let Some(limit) = parsed.team_daily_limit {
            budget_tracker = budget_tracker.with_team_daily_limit(limit);
        }
        if let Some(limit) = parsed.team_monthly_limit {
            budget_tracker = budget_tracker.with_team_monthly_limit(limit);
        }
        if let Some(limit) = parsed.org_daily_limit {
            budget_tracker = budget_tracker.with_org_daily_limit(limit);
        }
        if let Some(limit) = parsed.org_monthly_limit {
            budget_tracker = budget_tracker.with_org_monthly_limit(limit);
        }
        Ok(Self::assemble_cascade(dir, parsed, Arc::new(budget_tracker)))
    }

    /// Directory-cascade loader that adopts a **pre-built** budget tracker —
    /// the multi-document analogue of `load_from_file_with_budget`.
    ///
    /// The shipped `aa-gateway` binary uses this so the gateway's
    /// persistence loop (background writer + shutdown flush) owns the same
    /// `Arc<BudgetTracker>` it restored from disk, exactly as it does for the
    /// single-file path. Scope-index population and primary-doc selection are
    /// identical to `load_cascade_from_dir`; only the budget-tracker
    /// ownership differs. A directory watcher is attached for hot-reload —
    /// see `load_cascade_from_dir` semantics (AAASM-3497).
    pub fn load_cascade_from_dir_with_budget(dir: &Path, budget: Arc<BudgetTracker>) -> Result<Self, PolicyLoadError> {
        let parsed = Self::read_cascade_dir(dir)?;
        Ok(Self::assemble_cascade(dir, parsed, budget))
    }

    /// Re-read `dir` and produce the swap-ready primary document and cascade
    /// state for a hot-reload (AAASM-3497). Used by the directory watcher.
    ///
    /// Returns the same `(primary_doc, CascadeState)` pair that
    /// [`Self::assemble_cascade`] would build at construction time, so a reload
    /// is byte-for-byte equivalent to a fresh load of the directory. A read or
    /// parse failure surfaces as `Err`; the watcher preserves the current
    /// cascade in that case rather than swapping in a degraded one.
    pub(crate) fn rebuild_cascade_state(dir: &Path) -> Result<(Arc<PolicyDocument>, CascadeState), PolicyLoadError> {
        let ParsedCascade {
            scope_index,
            primary,
            compiled_patterns,
            ..
        } = Self::read_cascade_dir(dir)?;
        let primary_doc = Arc::new(primary.unwrap_or_else(Self::empty_primary_doc));
        Ok((
            primary_doc,
            CascadeState {
                scope_index,
                compiled_patterns,
            },
        ))
    }

    /// Read and parse every `*.yaml` file in `dir` (alphabetical order) into
    /// a populated [`ScopeIndex`] plus the budget/pattern config drawn from
    /// the first Global-scoped document. Shared by both cascade loaders so
    /// the parse semantics stay identical regardless of budget ownership.
    fn read_cascade_dir(dir: &Path) -> Result<ParsedCascade, PolicyLoadError> {
        // Collect *.yaml entries in alphabetical order so the cascade is
        // deterministic across runs and filesystems with different
        // dir-iteration orders.
        let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
            .map_err(PolicyLoadError::Io)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();

        let mut scope_index = ScopeIndex::new();
        let mut primary: Option<PolicyDocument> = None;
        let mut compiled_patterns = Vec::new();
        let mut budget_tz = chrono_tz::UTC;
        let mut daily_limit: Option<rust_decimal::Decimal> = None;
        let mut monthly_limit: Option<rust_decimal::Decimal> = None;
        // AAASM-5087 — Team-tier limits from the Global-scoped doc.
        let mut team_daily_limit: Option<rust_decimal::Decimal> = None;
        let mut team_monthly_limit: Option<rust_decimal::Decimal> = None;
        // AAASM-2022 — Org-tier limits from the Global-scoped doc.
        let mut org_daily_limit: Option<rust_decimal::Decimal> = None;
        let mut org_monthly_limit: Option<rust_decimal::Decimal> = None;

        for path in &entries {
            let yaml = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;
            // Fail closed on an empty (whitespace-only) document. On Linux
            // (inotify), a truncate+write overwrite emits a Modify event for
            // the 0-byte file *before* the new content lands; an empty YAML
            // otherwise parses as a valid Global-scoped allow-all document,
            // so re-reading the directory mid-truncation would silently drop
            // a deny doc and degrade the live cascade to allow-all. Treat it
            // as a parse error so the watcher preserves the current cascade —
            // mirroring the single-file watcher's empty-file guard
            // (`watcher::handle_fs_event`). (AAASM-3561)
            if yaml.trim().is_empty() {
                return Err(PolicyLoadError::Validation(vec![crate::policy::ValidationError::new(
                    "(document)",
                    format!("empty policy document: {}", path.display()),
                )]));
            }
            let output = PolicyValidator::from_yaml(&yaml).map_err(PolicyLoadError::Validation)?;
            let doc = output.document;

            // First Global-scoped document supplies budget + sensitive-pattern config.
            if matches!(doc.scope, crate::policy::scope::PolicyScope::Global) && primary.is_none() {
                compiled_patterns = doc
                    .data
                    .as_ref()
                    .map(|dp| {
                        dp.sensitive_patterns
                            .iter()
                            .filter_map(|p| regex::Regex::new(p).ok())
                            .collect()
                    })
                    .unwrap_or_default();
                budget_tz = parse_budget_tz(doc.budget.as_ref().and_then(|bp| bp.timezone.as_deref()))?;
                daily_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.daily_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                monthly_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.monthly_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                team_daily_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.team_daily_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                team_monthly_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.team_monthly_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                org_daily_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.org_daily_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                org_monthly_limit = doc
                    .budget
                    .as_ref()
                    .and_then(|bp| bp.org_monthly_limit_usd)
                    .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
                primary = Some(doc.clone());
            }

            scope_index.insert(doc);
        }

        Ok(ParsedCascade {
            scope_index,
            primary,
            compiled_patterns,
            budget_tz,
            daily_limit,
            monthly_limit,
            team_daily_limit,
            team_monthly_limit,
            org_daily_limit,
            org_monthly_limit,
        })
    }

    /// The default primary `PolicyDocument` used when a cascade directory has
    /// no Global-scoped document. An empty allow-by-default Global doc — the
    /// cascade's scoped documents still apply on top via `scope_index`.
    fn empty_primary_doc() -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: crate::policy::scope::PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: std::collections::HashMap::new(),
            capabilities: None,
            filesystem: None,
            syscall_allowlist: None,
        }
    }

    /// Assemble a [`PolicyEngine`] from a [`ParsedCascade`] and the budget
    /// tracker the caller chose to own (freshly built or externally restored).
    ///
    /// Attaches a directory watcher on `dir` (AAASM-3497) so the cascade
    /// re-evaluates when any `*.yaml` is added, removed, or modified.
    fn assemble_cascade(dir: &Path, parsed: ParsedCascade, budget: Arc<BudgetTracker>) -> Self {
        let ParsedCascade {
            scope_index,
            primary,
            compiled_patterns,
            ..
        } = parsed;

        let primary_doc = primary.unwrap_or_else(Self::empty_primary_doc);
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(primary_doc)));
        let cascade = Arc::new(ArcSwap::from_pointee(CascadeState {
            scope_index,
            compiled_patterns,
        }));
        let policy_epoch = Arc::new(AtomicU64::new(0));

        // Hot-reload: re-read the directory and swap the rebuilt cascade +
        // primary doc into the live slots when a `*.yaml` changes. Invalid
        // edits are ignored and the current cascade is preserved (fail-safe,
        // mirroring the single-file watcher) — see `start_cascade_watcher`.
        let cascade_watcher = crate::engine::watcher::start_cascade_watcher(
            dir,
            policy_arc.clone(),
            cascade.clone(),
            policy_epoch.clone(),
        )
        .ok();

        PolicyEngine {
            policy: policy_arc,
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget,
            cascade,
            _cascade_watcher: cascade_watcher,
            _watcher: None,
            registry: None,
            policy_epoch,
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(100_000),
        }
    }

    /// Load a policy from a YAML file using a pre-built budget tracker.
    ///
    /// Use this when restoring budget state from disk — the caller constructs
    /// the tracker via [`BudgetTracker::with_state`] and passes it in.
    pub fn load_from_file_with_budget(path: &Path, budget: Arc<BudgetTracker>) -> Result<Self, PolicyLoadError> {
        let yaml = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;
        let output = PolicyValidator::from_yaml(&yaml).map_err(PolicyLoadError::Validation)?;
        let compiled_patterns = output
            .document
            .data
            .as_ref()
            .map(|dp| {
                dp.sensitive_patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(output.document)));
        let watcher = crate::engine::watcher::start_watcher(path, policy_arc.clone()).ok();
        Ok(PolicyEngine {
            policy: policy_arc,
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget,
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState {
                scope_index: ScopeIndex::new(),
                compiled_patterns,
            })),
            _cascade_watcher: None,
            _watcher: watcher,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(100_000),
        })
    }

    /// Construct an engine with an empty, un-named policy document.
    ///
    /// The returned engine has `active_policy_info().name == None` and zero rules.
    /// Intended for integration tests that exercise the "no active policy → 404"
    /// path in `GET /api/v1/policies/active`; do not use in production code.
    #[doc(hidden)]
    pub fn for_testing() -> Self {
        let budget = Arc::new(crate::budget::BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let doc = PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: crate::policy::scope::PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: std::collections::HashMap::new(),
            capabilities: None,
            filesystem: None,
            syscall_allowlist: None,
        };
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(doc)));
        PolicyEngine {
            policy: policy_arc,
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget,
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState::default())),
            _cascade_watcher: None,
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(100_000),
        }
    }

    /// Attach an `AgentRegistry` so `collect_cascade` can resolve org/team lineage.
    ///
    /// Consumes `self` and returns a new `PolicyEngine` with the registry set.
    /// Call this after `load_from_file` in the server startup path.
    pub fn with_registry(mut self, registry: Arc<AgentRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Attach a push-invalidation hub so `apply_yaml` broadcasts a
    /// `PolicyInvalidated` event to every subscribed Assembly on each mutation.
    ///
    /// Call this after construction in the server startup path, sharing the
    /// same hub instance that backs the `InvalidationService` gRPC server.
    pub fn with_invalidation_hub(mut self, hub: Arc<crate::invalidation::InvalidationHub>) -> Self {
        self.invalidation_hub = Some(hub);
        self
    }

    /// Return the attached push-invalidation hub, if any.
    ///
    /// A composition root that builds the engine with [`Self::with_invalidation_hub`]
    /// uses this to serve the same hub over the `InvalidationService` gRPC, so an
    /// HTTP policy mutation (`apply_yaml`) and the subscriber stream share one hub.
    pub fn invalidation_hub(&self) -> Option<Arc<crate::invalidation::InvalidationHub>> {
        self.invalidation_hub.clone()
    }

    /// Apply a raw YAML policy string: validate, swap into the live slot, and
    /// persist a versioned snapshot to the history store.
    ///
    /// This is the integration point between the policy engine and the version
    /// history system — every `apply_yaml` call creates a new history entry.
    pub async fn apply_yaml(
        &self,
        yaml: &str,
        applied_by: Option<&str>,
        history: &dyn crate::policy::history::PolicyHistoryStore,
    ) -> Result<crate::policy::history::PolicyVersionMeta, PolicyLoadError> {
        // Validate the YAML
        let output = PolicyValidator::from_yaml(yaml).map_err(PolicyLoadError::Validation)?;

        // Save to history
        let meta = history.save(yaml, applied_by).await.map_err(PolicyLoadError::History)?;

        // Hot-swap the live policy
        self.policy.store(Arc::new(output.document));

        // Invalidate cached decisions — stale entries with the old epoch will be ignored.
        let new_epoch = self.policy_epoch.fetch_add(1, Ordering::Relaxed) + 1;

        // Push the invalidation out to subscribed Assembly instances so their L1
        // caches drop stale decisions immediately. An empty agent_id means
        // "invalidate all cached agents" — a policy swap is global.
        if let Some(hub) = &self.invalidation_hub {
            hub.broadcast_policy_invalidated(String::new(), new_epoch);
        }

        Ok(meta)
    }

    /// Evaluate a governance action through the 7-step pipeline.
    ///
    /// When scoped policies are loaded in the `scope_index`, delegates to the
    /// cascade path (`evaluate_with_cascade`). Falls back to the original
    /// single-policy pipeline (`evaluate_primary`) when no scoped policies are
    /// present, preserving full backward compatibility.
    pub fn evaluate(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> EvaluationResult {
        // AAASM-3729: the policy cascade is selected by the agent's (org, team)
        // lineage, so that lineage MUST be authoritative tenancy — the agent's
        // *registered* owner — not values the client asserted in the request.
        // Trusting client-supplied `org_id` / `team_id` lets a caller name a
        // tenant whose scoped policy is more permissive (e.g. an org with no
        // deny rules) and thereby DOWNGRADE the policy that applies to it.
        // Resolve from the registry by agent_id first; fall back to the
        // ctx-supplied lineage only when no registry is attached or the agent
        // is unregistered (untenanted / pre-registry deployments, and the
        // convert.rs path where the agent isn't keyed in the registry).
        let lineage = self.authoritative_lineage(ctx);
        let mut cascade = self.collect_cascade_with_lineage(&ctx.agent_id, &lineage);

        // AAASM-3981: append the `tool:`-scoped tier at the most-restrictive end
        // (after Agent). The tool identity comes from the action being evaluated
        // (`ToolCall` / `ToolResult`); actions with no resolvable tool skip the
        // tier rather than fabricate one. Without this, `scope: tool:X` documents
        // load and validate but are never consulted — a fail-open by omission
        // that leaves a tool-scoped deny silently dead.
        if let Some(tool_name) = action_tool_name(action) {
            self.push_scope_policies(
                &crate::policy::scope::PolicyScope::Tool(tool_name.to_owned()),
                &mut cascade,
            );
        }

        // Backward-compat: no scoped policies loaded → use primary policy only.
        if cascade.is_empty() {
            return self.evaluate_primary(ctx, action);
        }

        self.evaluate_with_cascade(cascade, ctx, action)
    }

    /// Dry-run a hypothetical governance action, returning the verdict the live
    /// policy would produce **without any state change or enforcement side
    /// effect** (AAASM-5037).
    ///
    /// This is the pure "what-if" behind the dashboard's Policy Simulate panel
    /// and `POST /api/v1/policies/simulate`. It runs the *same* decision
    /// pipeline as [`Self::evaluate`] against the live policy document,
    /// cascade, and registry (all read-only), but evaluates through an
    /// ephemeral engine ([`Self::ephemeral_for_simulation`]) that owns
    /// throwaway rate-limit, decision-cache, and budget state. As a result a
    /// simulate call:
    ///
    /// - consumes **no** rate-limit token — [`Self::evaluate`] decrements a
    ///   shared token bucket on a rate-limited tool; the dry-run's bucket is
    ///   fresh and discarded, so repeated simulation can never exhaust an
    ///   agent's real rate budget;
    /// - pollutes **no** decision cache — the cascade path caches merged
    ///   verdicts; the dry-run's cache is fresh and discarded;
    /// - never resets or debits the live budget window — the budget check
    ///   mutates a per-agent window on rollover, so the dry-run runs against a
    ///   fresh, zero-spend tracker instead of the live one;
    /// - writes no audit entry and applies no enforcement — this method only
    ///   *returns* a verdict; the caller performs no side effect from it.
    ///
    /// Because the throwaway budget tracker starts at zero recorded spend, a
    /// simulate verdict reflects the policy **rules** for the (agent, tool,
    /// target) triple, not live budget-exhaustion state — an intentional
    /// trade-off that keeps the dry-run free of shared-state mutation.
    pub fn simulate(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> EvaluationResult {
        self.ephemeral_for_simulation().evaluate(ctx, action)
    }

    /// Dry-run an action against a **proposed** policy document, returning the
    /// verdict that document would produce **without touching any live state**
    /// (AAASM-5094).
    ///
    /// This is the per-request evaluation primitive behind the policy-impact
    /// traffic-replay endpoint (`POST /api/v1/policies/replay`): it lets a caller
    /// score a corpus of recorded actions against a draft policy that is *not*
    /// loaded, so the endpoint can diff the draft's verdict against the recorded
    /// one and tally aggregate impact.
    ///
    /// Unlike [`Self::simulate`] — which evaluates against this engine's *live*
    /// primary document and cascade — this seeds a throwaway engine with
    /// `proposed` as the sole primary document and an **empty cascade**, so the
    /// verdict reflects the proposed document's rules alone. It reuses the same
    /// no-mutation guarantees as [`Self::ephemeral_for_simulation`]: fresh
    /// rate-limit, decision-cache, and zero-spend budget state, all discarded
    /// after the call. The live engine's `registry` is shared read-only so the
    /// agent's org/team lineage still resolves for cascade-tier selection, but
    /// because the ephemeral cascade is empty the evaluation always falls through
    /// to [`Self::evaluate_primary`] against `proposed`.
    pub fn simulate_against(
        &self,
        proposed: Arc<PolicyDocument>,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> EvaluationResult {
        let compiled_patterns = proposed
            .data
            .as_ref()
            .map(|dp| {
                dp.sensitive_patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let ephemeral = PolicyEngine {
            policy: Arc::new(ArcSwap::new(proposed)),
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new(
                crate::budget::PricingTable::default_table(),
                None,
                None,
                chrono_tz::UTC,
            )),
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState {
                scope_index: ScopeIndex::new(),
                compiled_patterns,
            })),
            _cascade_watcher: None,
            _watcher: None,
            registry: self.registry.clone(),
            policy_epoch: self.policy_epoch.clone(),
            invalidation_hub: None,
            // AAASM-5440 — a replay scores a *hypothetical* document against a
            // recorded action. It reaches `evaluate_primary`, which projects; a
            // sink here would file rows describing enforcement that never
            // happened, under the same tenant as the real ones.
            sensitive_data: None,
            decision_cache: DecisionCache::new(1),
        };
        ephemeral.evaluate(ctx, action)
    }

    /// Build a throwaway [`PolicyEngine`] for a single dry-run evaluation
    /// (see [`Self::simulate`]).
    ///
    /// Shares this engine's live `policy`, `cascade`, and `registry` via `Arc`
    /// (read-only during evaluation) so the dry-run sees exactly the rules a
    /// real request would, while giving it its own empty `rate_state`,
    /// `decision_cache`, and a fresh zero-spend `budget` so nothing it does can
    /// touch the live engine's mutable state. No filesystem watcher or
    /// invalidation hub is attached — the ephemeral engine is dropped after one
    /// evaluation.
    fn ephemeral_for_simulation(&self) -> PolicyEngine {
        PolicyEngine {
            policy: Arc::new(ArcSwap::new(self.policy.load_full())),
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new(
                crate::budget::PricingTable::default_table(),
                None,
                None,
                chrono_tz::UTC,
            )),
            cascade: Arc::new(ArcSwap::new(self.cascade.load_full())),
            _cascade_watcher: None,
            _watcher: None,
            registry: self.registry.clone(),
            policy_epoch: self.policy_epoch.clone(),
            invalidation_hub: None,
            // AAASM-5440 — a dry run reaches **both** seams (an empty cascade
            // routes to `evaluate_primary`, a populated one to
            // `evaluate_with_cascade`), so this `None` is the only thing keeping
            // the Simulate panel out of a governance table. ADR 0032: a
            // simulation applies no enforcement and writes no audit entry.
            sensitive_data: None,
            decision_cache: DecisionCache::new(1),
        }
    }

    /// Stage 1 of [`Self::evaluate_primary`]: deny when the current time is
    /// outside the policy's active-hours window. `None` when in-window or no
    /// schedule is configured.
    fn eval_schedule_stage(policy: &PolicyDocument) -> Option<EvaluationResult> {
        let ah = policy.schedule.as_ref()?.active_hours.as_ref()?;
        use chrono::Timelike;
        // AAASM-3847: an unparseable timezone must fail closed. Silently
        // falling back to UTC let an operator's active-hours window be
        // evaluated in the wrong zone — e.g. a window meant for business hours
        // in `America/New_York` evaluated in UTC could be wide open when it
        // should be shut, bypassing the schedule control. Deny when the
        // configured tz does not parse, matching the cascade twin
        // `decision.rs::stage_schedule` (AAASM-3133).
        let Ok(tz) = ah.timezone.parse::<chrono_tz::Tz>() else {
            return Some(EvaluationResult::deny(format!(
                "invalid schedule timezone: {}",
                ah.timezone
            )));
        };
        let now = chrono::Utc::now().with_timezone(&tz);
        let current_hhmm = format!("{:02}:{:02}", now.hour(), now.minute());
        if current_hhmm < ah.start || current_hhmm >= ah.end {
            return Some(EvaluationResult::deny("outside active hours"));
        }
        None
    }

    /// Stage 2 of [`Self::evaluate_primary`]: deny a `NetworkRequest` whose host
    /// is absent from a non-empty network allowlist. `None` otherwise.
    fn eval_network_stage(policy: &PolicyDocument, action: &aa_core::GovernanceAction) -> Option<EvaluationResult> {
        let aa_core::GovernanceAction::NetworkRequest { url, .. } = action else {
            return None;
        };
        let np = policy.network.as_ref()?;
        // AAASM-3728: this single-file path previously failed OPEN — an empty
        // allowlist returned `None` (allow-all) and matching was exact-only
        // (`entry == host`), so wildcard entries never matched and a blank
        // allowlist disabled egress control entirely, while the hardened
        // cascade path (`decision::stage_network`) already denied. Route both
        // through the one shared helper so they cannot diverge again.
        if !crate::engine::decision::network_request_url_allowed(url, np) {
            return Some(EvaluationResult::deny("host not in network allowlist"));
        }
        None
    }

    /// Stages 3-5b of [`Self::evaluate_primary`]: per-tool allow/deny, rate
    /// limit, and approval conditions (for both `ToolCall` and `SendMessage`).
    /// Returns the first non-Allow decision, or `None` to continue.
    fn eval_tool_stages(
        &self,
        policy: &PolicyDocument,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> Option<EvaluationResult> {
        // Stages 3-5 apply to ToolCall; stage 5b applies to SendMessage.
        match action {
            aa_core::GovernanceAction::ToolCall { name, .. } => self.eval_toolcall_stages(policy, ctx, name, action),
            // Stage 5b — Approval condition for SendMessage (channel policy).
            aa_core::GovernanceAction::SendMessage { .. } => {
                self.eval_approval_condition(policy, policy.tools.get("message"), ctx, action)
            }
            _ => None,
        }
    }

    /// Stages 3-5 for a `ToolCall`: per-tool allow/deny, rate limit, and the
    /// `requires_approval_if` condition. Resolves the tool policy once for the
    /// given `name`. Returns the first non-Allow decision, or `None`.
    fn eval_toolcall_stages(
        &self,
        policy: &PolicyDocument,
        ctx: &aa_core::AgentContext,
        name: &str,
        action: &aa_core::GovernanceAction,
    ) -> Option<EvaluationResult> {
        let tool_policy = policy.tools.get(name);

        // Stage 3 — Tool allow/deny. AAASM-4152: fall back to the `"*"` wildcard
        // entry when the tool has no explicit policy, so a
        // `tools: { "*": { allow: false } }` document denies unknown tools
        // (fail closed) instead of letting them through the engine's
        // allow-by-default. Explicit per-tool entries take precedence. This is
        // the single-file twin of the cascade path's `decision::stage_tool_allow`
        // — both must honour the wildcard or they diverge (the twin the network
        // stage shares via `network_request_url_allowed`). AAASM-4164: rate-limit
        // (stage 4) and approval (stage 5) below apply the same `"*"` fallback,
        // so a wildcard entry carrying `limit_per_hour` / `requires_approval_if`
        // gates unlisted tools rather than silently skipping those stages. The
        // cascade twins (`Self::cascade_rate_limit`, `decision::stage_approval`)
        // consult `"*"` too.
        if let Some(tp) = tool_policy.or_else(|| policy.tools.get("*")) {
            if !tp.allow {
                return Some(EvaluationResult::deny("tool denied by policy"));
            }
        }

        // Stage 4 — Tool rate limit. AAASM-4164: fall back to the `"*"` wildcard
        // entry (exact entry wins) so a `tools: { "*": { limit_per_hour: N } }`
        // document rate-limits unlisted tools instead of leaving them uncapped.
        if let Some(limit) = tool_policy
            .or_else(|| policy.tools.get("*"))
            .and_then(|tp| tp.limit_per_hour)
        {
            if !self.try_consume_rate(&self.rate_scope(ctx), name, limit) {
                return Some(EvaluationResult::deny("rate limit exceeded"));
            }
        }

        // Stage 5 — Approval condition for ToolCall. AAASM-4164: fall back to the
        // `"*"` wildcard entry (exact entry wins) so a
        // `tools: { "*": { requires_approval_if: "<guard>" } }` document gates
        // unlisted tools behind approval instead of skipping the check.
        self.eval_approval_condition(policy, tool_policy.or_else(|| policy.tools.get("*")), ctx, action)
    }

    /// Evaluate a tool/channel policy's `requires_approval_if` expression for
    /// `action`. Returns a `RequiresApproval` result when the expression is
    /// non-empty and evaluates true; `None` when there is no policy, no
    /// expression, or the condition is not met.
    fn eval_approval_condition(
        &self,
        policy: &PolicyDocument,
        tool_policy: Option<&crate::policy::document::ToolPolicy>,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> Option<EvaluationResult> {
        let expr = tool_policy?.requires_approval_if.as_ref()?;
        if expr.is_empty() {
            return None;
        }
        let now_secs = chrono::Utc::now().timestamp() as u64;
        let pctx = self.registry.as_ref().map(|reg| {
            crate::policy::context::ProductionPolicyContext::new(
                reg.as_ref(),
                self.budget.as_ref(),
                *ctx.agent_id.as_bytes(),
                ctx.team_id.clone(),
                now_secs,
            )
        });
        let pctx_dyn: Option<&dyn crate::policy::context::PolicyContext> = pctx.as_ref().map(|c| c as _);
        // ADR 0015 §4: `requires_approval_if` is a guard clause; a graph-context
        // resolution failure fails closed (fires) and is recorded for audit.
        let mut failures = Vec::new();
        let fired = crate::policy::expr::evaluate_clause(
            expr,
            action,
            Some(ctx.governance_level),
            pctx_dyn,
            crate::policy::expr::ClauseKind::RequireApproval,
            &mut failures,
        );
        Self::emit_resolution_failures(&failures);
        if fired {
            return Some(EvaluationResult {
                decision: aa_core::PolicyResult::RequiresApproval {
                    timeout_secs: policy.approval_timeout_secs,
                },
                redacted_payload: None,
                credential_findings: vec![],
                canonical_findings: vec![],
                deny_action: None,
                policy_doc_id: None,
                narrowed: false,
            });
        }
        None
    }

    /// Emit audit evidence for every graph-context variable that failed to
    /// resolve during evaluation (ADR 0015 §4 rule 5), so a decision made on
    /// degraded context is never invisible to an operator.
    ///
    /// Emitted on the `audit` tracing target — the same log-based audit-visibility
    /// path the engine uses for other audit-only side effects. The variable name
    /// and fail-safe verdict are safe to log; the underlying error detail (which
    /// could reference secret-adjacent state) is deliberately not surfaced here.
    fn emit_resolution_failures(failures: &[crate::policy::expr::ResolutionFailure]) {
        for f in failures {
            tracing::warn!(
                target: "audit",
                variable = %f.variable,
                fail_safe_action = %f.fail_safe_action(),
                "graph-context resolution failure — policy clause failed closed"
            );
        }
    }

    /// Map a budget policy's `action_on_exceed` to the [`DenyAction`] the
    /// service layer should apply on a budget denial.
    fn budget_deny_action(bp: &crate::policy::BudgetPolicy) -> Option<DenyAction> {
        match bp.action_on_exceed {
            ActionOnExceed::Suspend => Some(DenyAction::SuspendAgent),
            ActionOnExceed::Deny => None,
        }
    }

    /// Check a single budget policy's monthly-then-daily limits for `agent_id`,
    /// returning the deny reason for the first limit exceeded, or `None` when
    /// within budget (or a limit can't be represented as a decimal).
    fn budget_exceeded_reason(
        &self,
        bp: &crate::policy::BudgetPolicy,
        agent_id: &aa_core::identity::AgentId,
    ) -> Option<&'static str> {
        if let Some(limit) = bp.monthly_limit_usd {
            if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                if self.budget.check_monthly(agent_id, limit_dec) {
                    return Some("monthly budget exceeded");
                }
            }
        }
        if let Some(limit) = bp.daily_limit_usd {
            if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                if self.budget.check_daily(agent_id, limit_dec) {
                    return Some("daily budget exceeded");
                }
            }
        }
        None
    }

    /// Resolve the tenant scope key that isolates rate-limit buckets, mirroring
    /// the per-team granularity budgets use (AAASM-4173). The team is derived
    /// from the authoritative registry owner via [`Self::authoritative_tenancy`]
    /// — NOT the client-supplied `ctx.team_id` — so a caller cannot forge a
    /// fresh team id to mint an unshared bucket and slip past the limit (the
    /// same trust anchor AAASM-3138 established for budget keying).
    ///
    /// AAASM-4190: when no team is assigned, the fallback depends on whether the
    /// agent is *registered*:
    /// - **Registered** agents (found in registry) → `agent:{hex}` where the
    ///   agent_id is token-authenticated, so each registered teamless agent gets
    ///   its own isolated bucket.
    /// - **Unregistered/anonymous** agents (not in registry) → `anon` shared
    ///   bucket. The client-supplied `agent_id` is unauthenticated, so rotating
    ///   it on every request would mint fresh buckets and bypass the rate limit.
    ///   Collapsing all anonymous callers into one shared bucket closes this
    ///   bypass — they share the same rate-limit pool.
    ///
    /// The fallback never collapses to an empty key, so a missing team can only
    /// ever narrow isolation — never disable the limit (fail closed).
    fn rate_scope(&self, ctx: &aa_core::AgentContext) -> String {
        // Check registry to determine if the agent is registered (authenticated).
        let is_registered = self
            .registry
            .as_ref()
            .is_some_and(|r| r.get(ctx.agent_id.as_bytes()).is_some());

        let (team_id, _org_id) = self.authoritative_tenancy(ctx);
        match team_id {
            Some(team) => format!("team:{team}"),
            None if is_registered => {
                // Registered but teamless: agent_id is token-authenticated, safe to isolate.
                let hex: String = ctx.agent_id.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                format!("agent:{hex}")
            }
            None => {
                // Unregistered/anonymous: agent_id is client-controlled, use shared bucket.
                "anon".to_string()
            }
        }
    }

    /// Try to consume one token from the per-tenant, per-tool rate-limit bucket,
    /// creating it at `limit` tokens/hour on first use. Returns `false` when the
    /// bucket is empty (request should be denied).
    ///
    /// The bucket is keyed by `(scope, name)` — the tenant `scope` from
    /// [`Self::rate_scope`] joined with the tool `name` — so a `limit_per_hour`
    /// isolates per tenant instead of collapsing to one global bucket per tool
    /// name shared across every team and agent (AAASM-4173). The `\u{1}` (SOH)
    /// separator cannot appear in a team id or tool name, so distinct
    /// `(scope, name)` pairs can never alias onto the same bucket.
    ///
    /// AAASM-4190: when a bucket already exists with a higher capacity, passing
    /// a tighter `limit` now reduces the bucket's capacity and clamps its tokens
    /// accordingly. This prevents a bypass when multiple policies apply: a
    /// single-policy evaluation that created a bucket with limit 100 must not
    /// allow a cascade with minimum limit 10 to slip through the old capacity.
    fn try_consume_rate(&self, scope: &str, name: &str, limit: u32) -> bool {
        let key = format!("{scope}\u{1}{name}");
        let entry = self
            .rate_state
            .entry(key)
            .or_insert_with(|| Mutex::new(rate_limit::TokenBucket::new(limit)));
        let mut bucket = entry.lock().unwrap_or_else(|e| e.into_inner());
        bucket.try_consume_with_limit(limit)
    }

    /// Apply the shared Stage 6 credential decision over the findings the
    /// detection port produced for `text`, under the resolved
    /// `credential_action`.
    ///
    /// Identical for the single-policy and cascade paths: `block` + findings →
    /// deny; `alert_only` forwards the unredacted payload (the only path that
    /// leaks the raw secret, AAASM-3137); every other mode redacts in-memory.
    /// Findings are sorted by offset for deterministic output.
    ///
    /// # What the decision is, and is not, taken on
    ///
    /// Only on **whether a finding exists** (ADR 0002; ADR 0032 §4). Nothing
    /// here reads a finding's
    /// [`ConfidenceBand`](aa_security::canonical::ConfidenceBand),
    /// [`Severity`](aa_security::canonical::Severity) or
    /// [`Recognizer`](aa_security::canonical::Recognizer) — Agent Assembly owns
    /// the decision and a detector's own opinion of itself is evidence carried
    /// beside it, never an authorisation input.
    ///
    /// # Which redaction primitive applies
    ///
    /// With no canonical-only finding — the default, ungated case — the merged
    /// list is exactly what the pre-port code produced and
    /// [`ScanResult::redact`](aa_security::ScanResult) still owns redaction,
    /// byte for byte. A locale-pack finding has no
    /// [`CredentialKind`](aa_security::CredentialKind) for that primitive to
    /// splice, so its presence switches the whole payload to
    /// [`redact_findings`](aa_security::canonical::redact_findings) over the
    /// canonical union — one pass, because two passes over shifting offsets
    /// cannot be made correct.
    ///
    /// The two primitives agree on every label except one case: when findings
    /// of different categories overlap, `ScanResult::redact` keeps the
    /// higher-priority kind's label while `redact_findings` emits the opaque
    /// `[REDACTED]` rather than picking a winner. Only the gated path can reach
    /// that difference, and losing label precision on an overlap does not leave
    /// bytes behind either way.
    fn apply_credential_scan(
        text: &str,
        mut all_findings: Vec<aa_security::CredentialFinding>,
        canonical_findings: Vec<aa_security::canonical::CanonicalFinding>,
        canonical_only_present: bool,
        credential_action: CredentialAction,
    ) -> CredentialScanOutcome {
        // A finding in either tier is a finding. Reading only `all_findings`
        // here would let a locale-pack hit — which by construction has no
        // enforcement-tier counterpart — pass `credential_action: block`
        // silently, which is the "detected but not acted on" degrade ADR 0032
        // §5 forbids.
        let clean = all_findings.is_empty() && canonical_findings.is_empty();

        // Hard-block path: short-circuit every downstream stage.
        if credential_action == CredentialAction::Block && !clean {
            all_findings.sort_by_key(|f| f.offset);
            return CredentialScanOutcome::Block(EvaluationResult {
                decision: aa_core::PolicyResult::Deny {
                    reason: "credential detected".into(),
                },
                redacted_payload: None,
                credential_findings: all_findings,
                canonical_findings,
                deny_action: None,
                policy_doc_id: None,
                narrowed: false,
            });
        }

        if clean {
            return CredentialScanOutcome::Continue(None, vec![], vec![]);
        }

        // Sort by offset for deterministic redaction order.
        all_findings.sort_by_key(|f| f.offset);
        // TODO(AAASM-31): wrap in EnrichedEvent::DataLeak(DataLeakEvent { ... }) and
        // send on the broadcast_tx once AAASM-31 adds the DataLeak variant to EnrichedEvent.
        tracing::warn!(
            finding_count = all_findings.len(),
            "DataLeakEvent emission pending AAASM-31 EnrichedEvent::DataLeak variant"
        );
        if credential_action == CredentialAction::AlertAndRedact {
            // AAASM-3137: alert AND redact — notify but never leak the secret.
            tracing::warn!(
                finding_count = all_findings.len(),
                "credential_action=alert_and_redact: alert emission pending AAASM-1545"
            );
        }
        if credential_action == CredentialAction::AlertOnly {
            // SECURITY (AAASM-3137): the ONLY path that forwards the raw secret.
            // A documented, deliberate audit-only downgrade; alert side-effect
            // emission is wired by sibling subtask AAASM-1545.
            tracing::warn!(
                finding_count = all_findings.len(),
                "credential_action=alert_only: forwarding UNREDACTED payload (alert emission pending AAASM-1545)"
            );
            return CredentialScanOutcome::Continue(None, all_findings, canonical_findings);
        }
        let redacted = if canonical_only_present {
            aa_security::canonical::redact_findings(text, &canonical_findings)
        } else {
            aa_security::ScanResult {
                findings: all_findings.clone(),
            }
            .redact(text)
        };
        CredentialScanOutcome::Continue(Some(redacted), all_findings, canonical_findings)
    }

    /// Fail closed when a configured detection pass could not run.
    ///
    /// A detection source that cannot answer is not a source that answered
    /// "clean" (ADR 0032 §5). Because this is the synchronous **pre-action**
    /// path, continuing with no findings would forward a payload nothing
    /// inspected, so the action is denied instead.
    ///
    /// The reason names the pack tag from the policy document — operator-
    /// authored configuration, never bytes read from the scanned payload — so
    /// no scanned content reaches a deny reason, a log line or an audit record.
    fn detection_unavailable_deny(err: &detection::DetectionError) -> EvaluationResult {
        tracing::error!(error = %err, "stage 6 detection pass could not run; failing closed");
        EvaluationResult::deny(format!("sensitive-data detection unavailable: {err}"))
    }

    /// Resolve the locale packs a single policy document asks for.
    fn document_locale_packs(
        data: Option<&crate::policy::document::DataPolicy>,
    ) -> Result<Vec<detection::LocalePack>, detection::DetectionError> {
        match data {
            // The overwhelmingly common case, and the one the hot-path perf
            // gate measures: no packs configured, no allocation, no pass.
            None => Ok(Vec::new()),
            Some(dp) => detection::resolve_locale_packs(&dp.locale_packs),
        }
    }

    /// Run `passes` and split the outcome into the two lists Stage 6 consumes.
    ///
    /// Exists so both evaluation paths agree on the port's contract rather than
    /// each interpreting it — the drift that let the two open-coded Stage 6
    /// implementations diverge in the first place.
    fn run_detection(
        text: &str,
        passes: &[&dyn detection::DetectionPass],
    ) -> Result<
        (
            Vec<aa_security::CredentialFinding>,
            Vec<aa_security::canonical::CanonicalFinding>,
            bool,
        ),
        detection::DetectionError,
    > {
        let outcome = detection::run(text, passes)?;
        let canonical_only_present = outcome.has_canonical_only();
        let (credential, canonical) = outcome.into_parts();
        Ok((credential, canonical, canonical_only_present))
    }

    /// Single-policy evaluation path: used when no scoped policies are registered.
    ///
    /// AAASM-5440 — the projection write is here, wrapping the pipeline, rather
    /// than at each of the pipeline's post-Stage-6 exits. Stage 6 has three of
    /// them (the `credential_action: block` short-circuit, the budget deny, the
    /// final allow) and every one can carry findings, so a per-exit call site is
    /// three chances to add a fourth exit later and record nothing from it. The
    /// wrapper cannot be escaped by a new `return`.
    ///
    /// This is the seam AAASM-5440's primary-path falsification test cuts:
    /// removing the `project_sensitive_data` call below kills the primary tests
    /// and leaves every cascade test green.
    fn evaluate_primary(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> EvaluationResult {
        let result = self.evaluate_primary_inner(ctx, action);
        self.project_sensitive_data(ctx, action, &result);
        result
    }

    /// The 7-stage pipeline itself — the original from before AAASM-220. When
    /// the `scope_index` is empty, `evaluate` delegates here for full backward
    /// compat.
    fn evaluate_primary_inner(
        &self,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> EvaluationResult {
        let policy = self.policy.load();

        // Stage 1 — Schedule: check active hours window.
        if let Some(result) = Self::eval_schedule_stage(&policy) {
            return result;
        }

        // Stage 2 — Network allowlist: only for NetworkRequest actions.
        if let Some(result) = Self::eval_network_stage(&policy, action) {
            return result;
        }

        // Stage 2b — Capability authorization (AAASM-4123). Mirrors the cascade
        // path's `cascade_capability_guard` via the shared `capability_guard`
        // helper so the single-file/primary surface (`aasm policy simulate`,
        // aa-api, single-file gateway) enforces per-op read/write/delete instead
        // of silently permitting every capability-denied action. Runs before the
        // tool stages so a capability-denied action never consumes a rate-limit
        // token. A doc with no `capabilities` block imposes no restriction.
        if let Some(caps) = &policy.capabilities {
            if let Some(result) = Self::capability_guard(caps, action) {
                return result;
            }
        }

        // Stages 3-5b — Tool/message rules: allow/deny, rate limit, approval.
        if let Some(result) = self.eval_tool_stages(&policy, ctx, action) {
            return result;
        }

        // Stage 6 — Credential scan + custom pattern scan: redact in-memory, never deny.
        //
        // Every pass runs through the canonical detection port (AAASM-5354,
        // `engine::detection`), which is sealed so nothing out of process can be
        // reached from this synchronous pre-action path (ADR 0032 D-1):
        //
        //   Pass 1  the built-in Aho-Corasick scan — 27 detector kinds in
        //           `aa_security::CredentialKind::ALL`, 28 counting `Custom` —
        //           via `aa_security::CredentialScanner` (not `aa-core`).
        //   Pass 2  the operator's `data.sensitive_patterns` regexes,
        //           pre-compiled into the cascade state.
        //   Pass 3  any `data.locale_packs` the policy names — off unless
        //           configured, so the two-pass merge above is unchanged.
        //
        // All passes contribute to one merged findings list, used to redact the
        // payload once; the redacted text propagates — the original is dropped.
        let text = action_scan_text(action);

        let packs = match Self::document_locale_packs(policy.data.as_ref()) {
            Ok(packs) => packs,
            Err(e) => return Self::detection_unavailable_deny(&e),
        };
        let cascade_state = self.cascade.load();
        let scanner_pass = detection::BuiltinScannerPass::new(&self.scanner);
        let regex_pass = detection::CompiledRegexPass::new(&cascade_state.compiled_patterns);
        let pack_passes: Vec<detection::LocalePackPass> =
            packs.into_iter().map(detection::LocalePackPass::new).collect();

        let detected = if pack_passes.is_empty() {
            // The pass list on the default path is a stack array, so configuring
            // no locale pack costs no heap allocation *here*. (Under `cfg(test)`
            // `detection::run` still builds a vector to splice in a test double;
            // that allocation does not exist in a production build.)
            Self::run_detection(text, &[&scanner_pass as &dyn detection::DetectionPass, &regex_pass])
        } else {
            let mut passes: Vec<&dyn detection::DetectionPass> = vec![&scanner_pass, &regex_pass];
            passes.extend(pack_passes.iter().map(|p| p as &dyn detection::DetectionPass));
            Self::run_detection(text, &passes)
        };
        let (all_findings, canonical, canonical_only) = match detected {
            Ok(parts) => parts,
            Err(e) => return Self::detection_unavailable_deny(&e),
        };

        let credential_action = policy.data.as_ref().map(|d| d.credential_action).unwrap_or_default();

        let (redacted_payload, credential_findings, canonical_findings) =
            match Self::apply_credential_scan(text, all_findings, canonical, canonical_only, credential_action) {
                CredentialScanOutcome::Block(result) => return result,
                CredentialScanOutcome::Continue(payload, findings, canonical) => (payload, findings, canonical),
            };

        // Stage 7 — Budget check (monthly first, then daily).
        if let Some(bp) = &policy.budget {
            let deny_action = Self::budget_deny_action(bp);
            if let Some(reason) = self.budget_exceeded_reason(bp, &ctx.agent_id) {
                return EvaluationResult::deny_with(
                    reason,
                    redacted_payload,
                    credential_findings,
                    canonical_findings,
                    deny_action,
                );
            }
        }

        // AAASM-5100 / ADR-0018 item A — the action was permitted; record whether
        // an in-force allow-list scoped it down (`narrow`) vs. a default allow.
        let narrowed = policy
            .capabilities
            .as_ref()
            .is_some_and(|caps| Self::capability_narrowed(caps, action));

        EvaluationResult {
            decision: aa_core::PolicyResult::Allow,
            redacted_payload,
            credential_findings,
            canonical_findings,
            deny_action: None,
            policy_doc_id: None,
            narrowed,
        }
    }

    /// Cascade capability guard: deny when the merged capability set (folded
    /// across the whole cascade) blocks the action — either the capability is in
    /// the merged deny set, or a non-empty merged allow set omits it. This
    /// catches the cross-doc intersection case that per-doc checks miss
    /// (AAASM-1046). `None` when the action is permitted.
    fn cascade_capability_guard(
        cascade: &[Arc<PolicyDocument>],
        action: &aa_core::GovernanceAction,
    ) -> Option<EvaluationResult> {
        let merged_caps = Self::collect_merged_capabilities(cascade);
        Self::capability_guard(&merged_caps, action)
    }

    /// Capability authorization gate shared by BOTH the primary
    /// (`evaluate_primary`) and cascade (`cascade_capability_guard`) paths: deny
    /// when `caps.deny` blocks the action's capability, or when an allow-list
    /// restriction is in force (`CapabilitySet::allow_is_restricted`) and
    /// `caps.allow` omits it. `None` when the action maps to no capability or is
    /// permitted.
    ///
    /// The restriction check keys off `allow_is_restricted()` rather than
    /// `!allow.is_empty()` so a disjoint multi-tier cascade that intersects two
    /// whitelists down to an empty `allow` fails *closed* (deny-all) instead of
    /// reading empty as "no allow-list" and permitting everything (AAASM-4154).
    ///
    /// Extracted so the single-file and directory-cascade paths can never
    /// diverge again (AAASM-4123): the primary path previously ran every stage
    /// EXCEPT this one, silently permitting capability-denied actions on the
    /// single-file surface (`aasm policy simulate`, aa-api, single-file
    /// gateway). This is the same fail-open-by-omission class closed for the
    /// network stage via a shared helper (AAASM-3728). `capability_is_denied`
    /// carries the write-deny⇒delete-deny defense-in-depth rule, so both paths
    /// inherit it identically.
    fn capability_guard(caps: &aa_core::CapabilitySet, action: &aa_core::GovernanceAction) -> Option<EvaluationResult> {
        let cap = aa_core::action_to_capability(action)?;
        if aa_core::capability_is_denied(&caps.deny, &cap) {
            return Some(EvaluationResult::deny("capability denied by policy"));
        }
        // Fail closed when a restriction is in force: an empty merged allow-list
        // that carries `allow_restricted` means a disjoint cascade collapsed two
        // whitelists to nothing — deny everything, never allow-all (AAASM-4154).
        if caps.allow_is_restricted() && !caps.allow.contains(&cap) {
            return Some(EvaluationResult::deny("capability not in allow list"));
        }
        None
    }

    /// AAASM-5100 / ADR-0018 item A — `true` when `caps` **permits** the action
    /// but only because it fell inside an in-force allow-list restriction, i.e.
    /// a policy scoped the action down rather than blocking it.
    ///
    /// This is the `narrow` runtime-verdict signal: the action's capability is
    /// present in a *restricted* merged allow-list (`allow_is_restricted()` — an
    /// explicit whitelist is in force, not the empty "no restriction" default),
    /// so it was admitted by a scoping match rather than by default-allow.
    /// Returns `false` when the action maps to no capability, when no allow-list
    /// restriction is in force, or when the action would be denied — the caller
    /// only consults this on a permitted (`capability_guard` → `None`) action.
    fn capability_narrowed(caps: &aa_core::CapabilitySet, action: &aa_core::GovernanceAction) -> bool {
        let Some(cap) = aa_core::action_to_capability(action) else {
            return false;
        };
        caps.allow_is_restricted() && caps.allow.contains(&cap)
    }

    /// Stage 4 across a cascade: apply the most restrictive (minimum)
    /// `limit_per_hour` found for the tool across all cascade docs. Returns a
    /// deny when the shared bucket is exhausted; `None` otherwise.
    fn cascade_rate_limit(
        &self,
        cascade: &[Arc<PolicyDocument>],
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> Option<EvaluationResult> {
        let aa_core::GovernanceAction::ToolCall { name, .. } = action else {
            return None;
        };
        // AAASM-4164: within each doc the exact per-tool entry wins, falling back
        // to that doc's `"*"` wildcard, so a `tools: { "*": { limit_per_hour: N } }`
        // scope rate-limits unlisted tools instead of leaving them uncapped —
        // mirroring `stage_tool_allow`'s wildcard fallback.
        let min_limit = cascade
            .iter()
            .filter_map(|doc| doc.tools.get(name).or_else(|| doc.tools.get("*")))
            .filter_map(|tp| tp.limit_per_hour)
            .min()?;
        if !self.try_consume_rate(&self.rate_scope(ctx), name, min_limit) {
            return Some(EvaluationResult::deny("rate limit exceeded"));
        }
        None
    }

    /// AAASM-3995(c) — whether any `requires_approval_if` in the cascade
    /// references live runtime context (registry graph / budget state). Such
    /// verdicts must not be served from the decision cache, whose key omits the
    /// live context, or a context-dependent approval could be frozen for the
    /// cache TTL.
    fn cascade_has_live_context_approval(cascade: &[Arc<PolicyDocument>]) -> bool {
        cascade.iter().any(|doc| {
            doc.tools.values().any(|tp| {
                tp.requires_approval_if
                    .as_deref()
                    .is_some_and(crate::policy::expr::references_live_context)
            })
        })
    }

    /// Compute the most restrictive credential action across the cascade.
    ///
    /// Ranks by protection level: Block > RedactOnly > AlertAndRedact > AlertOnly.
    fn cascade_credential_action(cascade: &[Arc<PolicyDocument>]) -> CredentialAction {
        cascade
            .iter()
            .filter_map(|d| d.data.as_ref().map(|dp| dp.credential_action))
            .max_by_key(|a| match a {
                CredentialAction::Block => 3,
                CredentialAction::RedactOnly => 2,
                CredentialAction::AlertAndRedact => 1,
                CredentialAction::AlertOnly => 0,
            })
            .unwrap_or_default()
    }

    /// The union of every locale pack any document in the cascade names.
    ///
    /// A union rather than an intersection, for the same reason
    /// [`Self::cascade_credential_action`] takes the *most* restrictive action:
    /// a narrower-scoped document that asks for a detector must not have that
    /// request cancelled by a broader one that is silent about it.
    ///
    /// # Errors
    ///
    /// [`detection::DetectionError::UnknownLocalePack`] if any document names a
    /// pack this build does not contain — failing closed rather than quietly
    /// dropping a detector an operator asked for.
    fn cascade_locale_packs(
        cascade: &[Arc<PolicyDocument>],
    ) -> Result<Vec<detection::LocalePack>, detection::DetectionError> {
        let mut packs: Vec<detection::LocalePack> = Vec::new();
        for doc in cascade {
            for pack in Self::document_locale_packs(doc.data.as_ref())? {
                if !packs.contains(&pack) {
                    packs.push(pack);
                }
            }
        }
        Ok(packs)
    }

    /// Check budget constraints across the cascade, returning an early deny if exceeded.
    fn check_cascade_budget(
        &self,
        cascade: &[Arc<PolicyDocument>],
        agent_id: &aa_core::identity::AgentId,
        redacted_payload: Option<String>,
        credential_findings: Vec<aa_security::CredentialFinding>,
        canonical_findings: Vec<aa_security::canonical::CanonicalFinding>,
    ) -> Option<EvaluationResult> {
        for doc in cascade {
            if let Some(bp) = &doc.budget {
                let da = Self::budget_deny_action(bp);
                if let Some(reason) = self.budget_exceeded_reason(bp, agent_id) {
                    return Some(EvaluationResult::deny_with(
                        reason,
                        redacted_payload,
                        credential_findings,
                        canonical_findings,
                        da,
                    ));
                }
            }
        }
        None
    }

    /// Resolve the merge verdict, using cache when appropriate (AAASM-3995(c)).
    fn resolve_merge_verdict(
        &self,
        cascade: &[Arc<PolicyDocument>],
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
        cache_key: CacheKey,
        pctx_dyn: Option<&dyn crate::policy::context::PolicyContext>,
    ) -> (PolicyDecision, Option<String>) {
        let context_dependent = Self::cascade_has_live_context_approval(cascade);
        if context_dependent {
            // ADR 0015 §4: surface any graph-context resolution failures for audit
            // on the fresh-evaluation path (context-dependent verdicts are never
            // cached, so this is the only place they can arise).
            let mut failures = Vec::new();
            // AAASM-5107 — attribute the verdict to the deciding document's digest.
            let v = decision::merge_decisions_attributed(cascade, ctx, action, pctx_dyn, &mut failures);
            Self::emit_resolution_failures(&failures);
            v
        } else if let Some(cached) = self.decision_cache.get(&cache_key) {
            cached
        } else {
            let mut failures = Vec::new();
            let v = decision::merge_decisions_attributed(cascade, ctx, action, pctx_dyn, &mut failures);
            self.decision_cache.insert(cache_key, v.clone());
            v
        }
    }

    /// Cascade evaluation path: runs `merge_decisions` across all scoped policies,
    /// then applies rate-limit (stage 4), budget (stage 7), and credential scan
    /// (stage 6) at the engine level.
    ///
    /// AAASM-5440 — wraps the pipeline for the same reason
    /// [`Self::evaluate_primary`] does: this path has six early returns after
    /// Stage 6's scan, and a per-exit call site would be six chances to add a
    /// seventh that records nothing.
    ///
    /// This is the **second, independent** seam. It is wired separately rather
    /// than by hoisting the call into [`Self::evaluate`] because the two paths
    /// are separately reachable (`simulate_against` reaches only the primary
    /// one) and because a single hoisted call site cannot be falsified per
    /// path — one mutation would kill every test and prove neither seam.
    fn evaluate_with_cascade(
        &self,
        cascade: Vec<Arc<PolicyDocument>>,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> EvaluationResult {
        let result = self.evaluate_with_cascade_inner(cascade, ctx, action);
        self.project_sensitive_data(ctx, action, &result);
        result
    }

    fn evaluate_with_cascade_inner(
        &self,
        cascade: Vec<Arc<PolicyDocument>>,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> EvaluationResult {
        // Stage 1 — Schedule: time-dependent, evaluated FRESH on every request.
        if let Some(PolicyDecision::Deny { reason, .. }) = decision::evaluate_schedule_cascade(&cascade) {
            return EvaluationResult {
                decision: aa_core::PolicyResult::Deny { reason },
                redacted_payload: None,
                credential_findings: vec![],
                canonical_findings: vec![],
                deny_action: None,
                policy_doc_id: None,
                narrowed: false,
            };
        }

        // Cache setup for stateless stages.
        let epoch = self.policy_epoch.load(Ordering::Relaxed);
        let cache_key = CacheKey::new(ctx.agent_id.as_bytes(), epoch, action);
        let now_secs = chrono::Utc::now().timestamp() as u64;
        let pctx = self.registry.as_ref().map(|reg| {
            crate::policy::context::ProductionPolicyContext::new(
                reg.as_ref(),
                self.budget.as_ref(),
                *ctx.agent_id.as_bytes(),
                ctx.team_id.clone(),
                now_secs,
            )
        });
        let pctx_dyn: Option<&dyn crate::policy::context::PolicyContext> = pctx.as_ref().map(|c| c as _);

        let (verdict, policy_doc_id) = self.resolve_merge_verdict(&cascade, ctx, action, cache_key, pctx_dyn);

        // If already denied, return immediately.
        if let PolicyDecision::Deny { reason, .. } = verdict {
            return EvaluationResult {
                decision: aa_core::PolicyResult::Deny { reason },
                redacted_payload: None,
                credential_findings: vec![],
                canonical_findings: vec![],
                deny_action: None,
                policy_doc_id,
                narrowed: false,
            };
        }

        // Cascade capability guard (cross-doc merged allow/deny set).
        if let Some(result) = Self::cascade_capability_guard(&cascade, action) {
            return result;
        }

        // Stage 4 — Rate limiting across the cascade.
        if let Some(result) = self.cascade_rate_limit(&cascade, ctx, action) {
            return result;
        }

        // Stage 6 — Credential scan, through the same canonical detection port
        // the single-policy path uses (AAASM-5354). Pass 2 here spans every
        // document in the resolved cascade, not just the Global one.
        let text = action_scan_text(action);

        let packs = match Self::cascade_locale_packs(&cascade) {
            Ok(packs) => packs,
            Err(e) => return Self::detection_unavailable_deny(&e),
        };
        let scanner_pass = detection::BuiltinScannerPass::new(&self.scanner);
        let regex_pass = detection::CascadeRegexPass::new(&cascade);
        let pack_passes: Vec<detection::LocalePackPass> =
            packs.into_iter().map(detection::LocalePackPass::new).collect();

        let detected = if pack_passes.is_empty() {
            Self::run_detection(text, &[&scanner_pass as &dyn detection::DetectionPass, &regex_pass])
        } else {
            let mut passes: Vec<&dyn detection::DetectionPass> = vec![&scanner_pass, &regex_pass];
            passes.extend(pack_passes.iter().map(|p| p as &dyn detection::DetectionPass));
            Self::run_detection(text, &passes)
        };
        let (all_findings, canonical, canonical_only) = match detected {
            Ok(parts) => parts,
            Err(e) => return Self::detection_unavailable_deny(&e),
        };

        let credential_action = Self::cascade_credential_action(&cascade);
        let (redacted_payload, credential_findings, canonical_findings) =
            match Self::apply_credential_scan(text, all_findings, canonical, canonical_only, credential_action) {
                CredentialScanOutcome::Block(result) => return result,
                CredentialScanOutcome::Continue(payload, findings, canonical) => (payload, findings, canonical),
            };

        // Stage 7 — Budget check.
        if let Some(result) = self.check_cascade_budget(
            &cascade,
            &ctx.agent_id,
            redacted_payload.clone(),
            credential_findings.clone(),
            canonical_findings.clone(),
        ) {
            return result;
        }

        // Extract deny_action from budget policies (if any).
        let deny_action = cascade
            .iter()
            .filter_map(|doc| doc.budget.as_ref().and_then(Self::budget_deny_action))
            .next_back();

        // AAASM-5100 / ADR-0018 item A — an allowed action was `narrow`ed when the
        // merged cascade allow-list scoped it down rather than blocking it. Only
        // an Allow verdict can be narrowed; a surviving RequireApproval is
        // `pending`, not `narrow`.
        let decision = verdict.into_policy_result();
        let narrowed = matches!(decision, aa_core::PolicyResult::Allow)
            && Self::capability_narrowed(&Self::collect_merged_capabilities(&cascade), action);

        EvaluationResult {
            decision,
            redacted_payload,
            credential_findings,
            canonical_findings,
            deny_action,
            policy_doc_id,
            narrowed,
        }
    }

    /// Build the merged `CapabilitySet` for the given cascade by folding
    /// `merge_capabilities` left-to-right (Global → Org → Team → Agent).
    ///
    /// Returns an empty `CapabilitySet` (no restrictions) when no policy in the
    /// cascade defines a `capabilities` block.
    pub fn collect_merged_capabilities(cascade: &[std::sync::Arc<PolicyDocument>]) -> aa_core::CapabilitySet {
        cascade.iter().fold(aa_core::CapabilitySet::default(), |acc, doc| {
            if let Some(caps) = &doc.capabilities {
                aa_core::merge_capabilities(&acc, caps)
            } else {
                acc
            }
        })
    }

    /// Compute the effective permission set for a single agent, with cascade
    /// provenance.
    ///
    /// Walks the agent's cascade (`Global → Org → Team → Agent → Tool`) and
    /// returns:
    /// - `merged`: the result of folding `merge_capabilities` over every doc
    ///   in the cascade that declares a `capabilities` block;
    /// - `sources`: one `PermissionSource` per cascade doc that declares
    ///   capabilities, in cascade order, with the scope's wire-format label
    ///   plus that doc's own `allow` / `deny` sets.
    ///
    /// Sources with no `capabilities` block are omitted from `sources` so the
    /// CLI / dashboard only display rows that actually contribute. If no doc
    /// in the cascade declares capabilities, `sources` is empty and `merged`
    /// equals `CapabilitySet::default()` (no allow-list restriction).
    pub fn effective_permissions(&self, agent_id: &aa_core::identity::AgentId) -> aa_core::EffectivePermissions {
        let cascade = self.collect_cascade(agent_id);
        let merged = Self::collect_merged_capabilities(&cascade);
        let sources = cascade
            .iter()
            .filter_map(|doc| {
                doc.capabilities.as_ref().map(|caps| aa_core::PermissionSource {
                    scope: doc.scope.to_string(),
                    allow: caps.allow.clone(),
                    deny: caps.deny.clone(),
                })
            })
            .collect();
        aa_core::EffectivePermissions { merged, sources }
    }

    /// Record a spend amount for an agent after an action completes.
    ///
    /// Converts the `f64` amount to `Decimal` and delegates to the advanced
    /// tracker's `record_raw_spend`, which fires 80%/95% threshold alerts.
    pub fn record_spend(&self, ctx: &aa_core::AgentContext, amount_usd: f64) {
        if let Ok(amount) = rust_decimal::Decimal::try_from(amount_usd) {
            // AAASM-3138 — the budget tenancy key (team_id / org_id) must be the
            // agent's *registered* owner, not the values the client put in the
            // request. Trusting the client-supplied tenancy lets one tenant
            // charge spend against — or exhaust the budget of — another tenant
            // they don't own. Resolve from the registry by agent_id; the
            // client-supplied ctx values are used only as a fallback when no
            // registry is attached or the agent is unregistered.
            // AAASM-2022 — `org_id` still rolls the spend up into the Org tier.
            let (team_id, org_id) = self.authoritative_tenancy(ctx);
            self.budget
                .record_raw_spend(ctx.agent_id, team_id.as_deref(), org_id.as_deref(), amount);
        }
    }

    /// AAASM-3986 — atomically reserve LLM-call spend against the agent's (and
    /// its ancestors') budget under the tracker's per-ancestor lock, so the
    /// budget check and the spend commit cannot interleave across concurrent
    /// requests.
    ///
    /// Replaces the previous "read spend at Stage 7, then `record_spend` after
    /// the response was built" split, which let N concurrent checks for one
    /// tenant all observe under-limit before any recorded (bounded overspend ∝
    /// in-flight concurrency).
    ///
    /// Returns `Some(reason)` when the projected spend would exceed a configured
    /// daily / monthly limit — the caller must DENY the call and record nothing
    /// (the reservation committed nothing). Returns `None` when the spend was
    /// committed within budget. Tenancy is resolved from the agent's *registered*
    /// owner (AAASM-3138) so spend is never billed to a client-forged tenant.
    pub fn check_and_accrue_llm_spend(&self, ctx: &aa_core::AgentContext, amount_usd: f64) -> Option<&'static str> {
        let amount = match rust_decimal::Decimal::try_from(amount_usd) {
            Ok(a) if a > rust_decimal::Decimal::ZERO => a,
            _ => return None,
        };
        let (team_id, org_id) = self.authoritative_tenancy(ctx);
        let ancestors = self
            .registry
            .as_ref()
            .map(|r| r.ancestors_of(ctx.agent_id.as_bytes()))
            .unwrap_or_default();
        match self
            .budget
            .reserve_spend(ctx.agent_id, &ancestors, team_id.as_deref(), org_id.as_deref(), amount)
        {
            Ok(()) => None,
            Err(err) => {
                use crate::budget::types::{BudgetError, BudgetKind};
                let kind = match err {
                    BudgetError::SelfBudgetExhausted { kind } => kind,
                    BudgetError::AncestorBudgetExhausted { kind, .. } => kind,
                    BudgetError::TenantBudgetExhausted { kind, .. } => kind,
                };
                Some(match kind {
                    BudgetKind::Monthly => "monthly budget exceeded",
                    _ => "daily budget exceeded",
                })
            }
        }
    }

    /// Price a completed LLM call in USD using the budget pricing table.
    ///
    /// AAASM-3353 — the live `CheckAction` proto carries only the model name
    /// string and a prompt-token estimate (no provider, no output tokens).
    /// The `(Provider, Model)` pair is inferred from the model name via
    /// [`crate::budget::types::Model::infer_from_name`]; output tokens are
    /// treated as `0` because the pre-execution check has no completion yet.
    ///
    /// AAASM-4069 — an unrecognised model name is priced at the conservative
    /// fallback rate (the costliest known model), NOT `0.0`. Returning `0.0`
    /// previously made the `cost <= 0.0` accrual short-circuit skip the budget
    /// reservation, so an agent could pick any model outside the built-in table
    /// (o1/o3, gemini-*, llama-*, "gpt-5", …) for unlimited unmetered spend.
    /// Fail closed instead: unknown-model spend still accrues and the cap
    /// engages. The model name is attacker-controlled — this must not panic.
    pub fn llm_call_cost_usd(&self, model_name: &str, input_tokens: u64, output_tokens: u64) -> f64 {
        use rust_decimal::prelude::ToPrimitive;
        let pricing = self.budget.pricing();
        let cost = match crate::budget::types::Model::infer_from_name(model_name) {
            Some((provider, model)) => pricing.cost_usd(provider, model, input_tokens, output_tokens),
            None => pricing.fallback_cost_usd(input_tokens, output_tokens),
        };
        cost.to_f64().unwrap_or(0.0)
    }

    /// Attach the durable sensitive-data projection (AAASM-5440).
    ///
    /// Without a sink the engine writes no projection at all, which is the
    /// default state and the pre-AAASM-5440 behaviour. The sink is a channel
    /// handle, so attaching it costs one `try_send` per action that carried a
    /// finding and nothing at all for an action that did not.
    #[must_use]
    pub fn with_sensitive_data_sink(mut self, sink: sensitive_data::SensitiveDataProjectionSink) -> Self {
        self.sensitive_data = Some(sink);
        self
    }

    /// Project one evaluation into the durable sensitive-data tier (AAASM-5440).
    ///
    /// Called from both enforcement seams with the decision **already
    /// computed**, which is the whole of AC3: nothing here is read by the
    /// pipeline, so no value this function produces — and no failure it hits —
    /// can move a policy outcome. It takes `&EvaluationResult` rather than
    /// owning it for the same reason.
    ///
    /// Does nothing when the action produced no canonical findings. An action
    /// with nothing sensitive in it is not a sensitive-data decision, and writing
    /// a zero-finding event for every governed call would drown the tier the
    /// dashboards read in rows about nothing.
    fn project_sensitive_data(
        &self,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
        result: &EvaluationResult,
    ) {
        let Some(sink) = self.sensitive_data.as_ref() else {
            return;
        };
        if result.canonical_findings.is_empty() {
            return;
        }

        // The same authoritative resolution the cascade selection uses — the
        // registered owner, never the client-asserted lineage (AAASM-3729). A
        // projection scoped by a forgeable tenancy would file one tenant's
        // findings under another's dashboard.
        let lineage = self.authoritative_lineage(ctx);
        let mode = self
            .registry
            .as_ref()
            .and_then(|registry| registry.get(ctx.agent_id.as_bytes()))
            .and_then(|record| record.enforcement_mode)
            .unwrap_or(aa_core::EnforcementMode::Enforce);
        // Minted here rather than derived from the action so two identical
        // actions are two events: the projection's idempotency key is the event
        // id, and a derived one would silently collapse a repeated leak into a
        // single row under first-write-wins.
        let event_id = format!("{:032x}", rand::random::<u128>());

        match sensitive_data::project_decision(
            ctx,
            action,
            &lineage,
            mode,
            result,
            aa_core::time::Timestamp::from(std::time::SystemTime::now()),
            &event_id,
        ) {
            Ok(decision) => sink.record(decision),
            Err(refusal) => sink.refuse(refusal),
        }
    }

    /// Resolve the budget tenancy (`team_id`, `org_id`) for `ctx` from the
    /// authoritative agent registry, falling back to the client-supplied
    /// `ctx` values only when no registry is attached or the agent is not
    /// registered.
    ///
    /// AAASM-3138: the registered owner is the trust anchor for budget keying —
    /// a client must not be able to bill spend against a tenant it does not own
    /// by forging `team_id` / `org_id` in the request.
    fn authoritative_tenancy(&self, ctx: &aa_core::AgentContext) -> (Option<String>, Option<String>) {
        if let Some(registry) = self.registry.as_ref() {
            if let Some(record) = registry.get(ctx.agent_id.as_bytes()) {
                return (record.team_id, record.org_id);
            }
        }
        let team_id = ctx.team_id.clone();
        let org_id = ctx.metadata.get("org_id").cloned();
        (team_id, org_id)
    }

    /// Resolve the policy-cascade lineage (`org_id` / `team_id` + delegation
    /// chain) for `ctx` from the authoritative agent registry, falling back to
    /// the client-supplied `ctx` lineage only when no registry is attached or
    /// the agent is not registered.
    ///
    /// AAASM-3729: the registered owner is the trust anchor for cascade
    /// *selection* — a client must not be able to point evaluation at a more
    /// permissive tenant's policy by forging `org_id` / `team_id` in the
    /// request context. Mirrors [`Self::authoritative_tenancy`] (AAASM-3138),
    /// which already keys budget spend on the registered owner.
    fn authoritative_lineage(&self, ctx: &aa_core::AgentContext) -> crate::registry::Lineage {
        if let Some(registry) = self.registry.as_ref() {
            if let Some(lineage) = registry.lineage(ctx.agent_id.as_bytes()) {
                return lineage;
            }
        }
        crate::registry::Lineage {
            org_id: ctx.metadata.get("org_id").cloned(),
            team_id: ctx.team_id.clone().or_else(|| ctx.metadata.get("team_id").cloned()),
            ..Default::default()
        }
    }

    /// Check whether an agent is within both daily and monthly budget limits.
    ///
    /// Returns `true` if the agent has not exceeded any configured budget limit
    /// (or if no budget limits are configured). Used by the heartbeat handler to
    /// determine whether a budget-suspended agent can be auto-resumed.
    pub fn is_within_budget(&self, agent_id_bytes: &[u8; 16]) -> bool {
        let agent_id = aa_core::identity::AgentId::from_bytes(*agent_id_bytes);
        let policy = self.policy.load();
        let bp = match &policy.budget {
            Some(bp) => bp,
            None => return true,
        };
        if let Some(limit) = bp.daily_limit_usd {
            if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                if self.budget.check_daily(&agent_id, limit_dec) {
                    return false;
                }
            }
        }
        if let Some(limit) = bp.monthly_limit_usd {
            if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                if self.budget.check_monthly(&agent_id, limit_dec) {
                    return false;
                }
            }
        }
        true
    }

    /// Returns a clone of the `Arc<BudgetTracker>` for shared ownership.
    ///
    /// Used by the persistence layer to spawn the background writer and
    /// to perform the final save on graceful shutdown.
    /// Return a lightweight summary of the currently active policy.
    pub fn active_policy_info(&self) -> ActivePolicyInfo {
        let doc = self.policy.load();
        ActivePolicyInfo {
            name: doc.name.clone(),
            policy_version: doc.policy_version.clone(),
            rule_count: doc.tools.len(),
        }
    }

    pub fn budget_tracker(&self) -> Arc<BudgetTracker> {
        Arc::clone(&self.budget)
    }

    /// Return the primary policy's network allowlist (bare hosts).
    ///
    /// Used by the anomaly detector's unknown-external-connection check
    /// (AAASM-3378) so it can flag `NetworkRequest`s to hosts outside the
    /// configured allowlist. An empty result means no allowlist is configured
    /// (open network policy) and the detector treats every host as allowed.
    pub fn network_allowlist(&self) -> Vec<String> {
        self.policy
            .load()
            .network
            .as_ref()
            .map(|np| np.allowlist.clone())
            .unwrap_or_default()
    }

    /// Return per-policy approval escalation overrides from the primary policy.
    ///
    /// Returns `(escalation_timeout_seconds_override, escalation_role_override)`.
    /// Both are `None` when the primary policy has no `approval` section or when
    /// the respective field is absent.
    pub fn approval_escalation_overrides(&self) -> (Option<u64>, Option<String>) {
        let doc = self.policy.load();
        match &doc.approval_policy {
            Some(ap) => (ap.timeout_seconds.map(u64::from), ap.escalation_role.clone()),
            None => (None, None),
        }
    }

    /// Cumulative cascade decision cache hits since engine construction.
    pub fn cache_hits(&self) -> u64 {
        self.decision_cache.cache_hits()
    }

    /// Cumulative cascade decision cache misses since engine construction.
    pub fn cache_misses(&self) -> u64 {
        self.decision_cache.cache_misses()
    }

    // ── F92 Phase B (AAASM-951): scope-keyed policy index ──────────────────

    /// Register `doc` in the scope-keyed index and return the freshly
    /// allocated [`scope_index::PolicyId`].
    ///
    /// Distinct from the [`aa_core::PolicyEvaluator::load_policy`] trait
    /// method (which is a stub on this type — see `impl PolicyEvaluator`
    /// below): this inherent method takes the gateway's own
    /// [`PolicyDocument`] and returns an id rather than a `Result<()>`.
    ///
    /// Phase B does not yet have the cascading evaluator consult this
    /// index — that wiring lands in F93 (AAASM-220). For now `load_policy`
    /// is purely about populating the index for backward-compat tests
    /// and so consumers can prepare scoped policies in advance.
    ///
    /// The cascade lives behind an [`ArcSwap`] (AAASM-3497), so this clones
    /// the current state, inserts into the clone, and swaps it in. Cheap
    /// enough for the test-prep / pre-load use it serves — not a hot path.
    pub fn load_policy(&mut self, doc: PolicyDocument) -> scope_index::PolicyId {
        self.policy_epoch.fetch_add(1, Ordering::Relaxed);
        let mut state = (**self.cascade.load()).clone();
        let id = state.scope_index.insert(doc);
        self.cascade.store(Arc::new(state));
        id
    }

    /// Drop a previously-registered policy by id, keeping `by_scope`
    /// consistent. Returns the dropped `Arc<PolicyDocument>` if the id
    /// was present, or `None` if it had already been removed.
    pub fn remove_policy(&mut self, id: scope_index::PolicyId) -> Option<Arc<PolicyDocument>> {
        let mut state = (**self.cascade.load()).clone();
        let removed = state.scope_index.remove(id);
        if removed.is_some() {
            self.cascade.store(Arc::new(state));
        }
        removed
    }

    /// Return the [`scope_index::PolicyId`]s registered under `scope`,
    /// in load order. Returns an empty `Vec` when no policy has ever
    /// been registered under that scope (or all of them have been
    /// removed).
    ///
    /// Returns an owned `Vec` rather than a borrow because the scope index
    /// lives behind an [`ArcSwap`] (AAASM-3497) and the loaded guard cannot
    /// outlive the call.
    pub fn policies_for_scope(&self, scope: &crate::policy::PolicyScope) -> Vec<scope_index::PolicyId> {
        self.cascade.load().scope_index.policies_for_scope(scope).to_vec()
    }

    /// Whether this engine actually carries a policy cascade — i.e. its
    /// `scope_index` holds at least one scoped document.
    ///
    /// This is the *loaded / unavailable* signal for cascade-derived **reporting
    /// projections** (AAASM-5106): the capability matrix, the topology permission
    /// chain, and the Teams active-policies list all read the cascade, and when it
    /// is empty they would otherwise render a confident but false answer (an
    /// all-`allow` grid, a zero-policy chain, "no policy is in force") that the
    /// enforcement path — which falls back to the primary policy slot — does not
    /// agree with. `false` here means those projections must render
    /// *Unknown / Unconfigured / Not evaluated* rather than inferring permission
    /// from the absence of cascade data. This never changes enforcement: it only
    /// tells a read-only projection whether the cascade slot it is about to
    /// summarise carries anything. See ADR 0024.
    ///
    /// Returns an owned `bool` computed under the [`ArcSwap`] guard; the guard
    /// cannot outlive the call.
    pub fn cascade_loaded(&self) -> bool {
        !self.cascade.load().scope_index.is_empty()
    }

    /// Look up a policy previously registered via [`Self::load_policy`]
    /// by its [`scope_index::PolicyId`].
    ///
    /// Returns `None` if the id was never issued, or if the policy
    /// has since been removed via [`Self::remove_policy`]. Returns an
    /// owned `Arc` clone because the index lives behind an [`ArcSwap`]
    /// (AAASM-3497) and the loaded guard cannot outlive the call.
    pub fn policy(&self, id: scope_index::PolicyId) -> Option<Arc<PolicyDocument>> {
        self.cascade.load().scope_index.policy(id).map(Arc::clone)
    }

    /// Collect all policies applicable to `agent_id` in cascade walk order:
    /// `Global → Org → Team → Agent`.
    ///
    /// Lineage (org, team) is resolved from the attached `AgentRegistry`.
    /// If no registry is wired, or the agent is not registered, only `Global`
    /// and `Agent`-scoped policies are collected.
    ///
    /// Returns a `Vec<Arc<PolicyDocument>>` ordered from broadest scope to
    /// narrowest. Policies within the same scope appear in their load order
    /// (insertion order in `ScopeIndex`).
    pub fn collect_cascade(&self, agent_id: &aa_core::identity::AgentId) -> Vec<Arc<PolicyDocument>> {
        let lineage = self
            .registry
            .as_ref()
            .and_then(|r| r.lineage(agent_id.as_bytes()))
            .unwrap_or_default();
        self.collect_cascade_with_lineage(agent_id, &lineage)
    }

    /// AAASM-2023 — variant of [`Self::collect_cascade`] that takes a
    /// pre-resolved [`crate::registry::Lineage`] hint instead of looking
    /// it up via the attached registry.
    ///
    /// Used by [`Self::evaluate`] which can resolve the lineage from the
    /// `AgentContext` (where convert.rs already deposits `org_id` /
    /// `team_id` in `metadata`) without needing the registry to be
    /// queryable by `ctx.agent_id` — a key shape that doesn't match the
    /// registry's composite `{org_id, team_id, agent_id}` hash today.
    pub fn collect_cascade_with_lineage(
        &self,
        agent_id: &aa_core::identity::AgentId,
        lineage: &crate::registry::Lineage,
    ) -> Vec<Arc<PolicyDocument>> {
        use crate::policy::scope::PolicyScope;

        let mut cascade = Vec::new();

        // Broadest → narrowest scope.
        self.push_scope_policies(&PolicyScope::Global, &mut cascade);
        if let Some(ref org_id) = lineage.org_id {
            self.push_scope_policies(&PolicyScope::Org(org_id.clone()), &mut cascade);
        }
        if let Some(ref team_id) = lineage.team_id {
            self.push_scope_policies(&PolicyScope::Team(team_id.clone()), &mut cascade);
        }
        self.push_scope_policies(&PolicyScope::Agent(*agent_id), &mut cascade);

        cascade
    }

    /// Append all policy documents registered for `scope` to `cascade`,
    /// preserving the scope index's order.
    fn push_scope_policies(&self, scope: &crate::policy::scope::PolicyScope, cascade: &mut Vec<Arc<PolicyDocument>>) {
        let state = self.cascade.load();
        for &id in state.scope_index.policies_for_scope(scope) {
            if let Some(doc) = state.scope_index.policy(id) {
                cascade.push(Arc::clone(doc));
            }
        }
    }
}

/// Resolve the tool identity an action targets, for selecting the `tool:`-scoped
/// cascade tier (AAASM-3981). Only tool-invocation actions carry a tool name:
/// `ToolCall` and `ToolResult`. Every other variant (file, network, process,
/// message) has no tool identity, so returns `None` and the caller skips the
/// Tool tier rather than fabricating one.
fn action_tool_name(action: &aa_core::GovernanceAction) -> Option<&str> {
    match action {
        aa_core::GovernanceAction::ToolCall { name, .. } => Some(name.as_str()),
        aa_core::GovernanceAction::ToolResult { tool_name, .. } => Some(tool_name.as_str()),
        aa_core::GovernanceAction::FileAccess { .. }
        | aa_core::GovernanceAction::NetworkRequest { .. }
        | aa_core::GovernanceAction::ProcessExec { .. }
        | aa_core::GovernanceAction::SendMessage { .. } => None,
    }
}

/// Extract the text payload an action contributes to the credential scan.
/// `SendMessage` carries no scannable text and maps to the empty string.
fn action_scan_text(action: &aa_core::GovernanceAction) -> &str {
    match action {
        aa_core::GovernanceAction::ToolCall { args, .. } => args.as_str(),
        aa_core::GovernanceAction::ToolResult { result, .. } => result.as_str(),
        aa_core::GovernanceAction::FileAccess { path, .. } => path.as_str(),
        aa_core::GovernanceAction::NetworkRequest { url, .. } => url.as_str(),
        aa_core::GovernanceAction::ProcessExec { command } => command.as_str(),
        aa_core::GovernanceAction::SendMessage { .. } => "",
    }
}

/// Implement the `aa_core::PolicyEvaluator` trait so `PolicyEngine` can be used
/// as `dyn PolicyEvaluator` wherever a pluggable evaluation backend is expected.
///
/// `load_policy` and `validate_policy` are not meaningful for `PolicyEngine` because
/// it uses a richer YAML-based policy document (not the `aa_core::PolicyDocument` stub).
/// Both methods return `Err(PolicyError::InvalidDocument)` to make the limitation explicit.
/// Use [`PolicyEngine::load_from_file`] to construct and reload a live engine.
impl aa_core::PolicyEvaluator for PolicyEngine {
    fn evaluate(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> aa_core::PolicyResult {
        PolicyEngine::evaluate(self, ctx, action).decision
    }

    fn load_policy(&mut self, _policy: &aa_core::PolicyDocument) -> Result<(), aa_core::PolicyError> {
        Err(aa_core::PolicyError::InvalidDocument)
    }

    fn validate_policy(&self, _policy: &aa_core::PolicyDocument) -> Result<(), Vec<aa_core::PolicyError>> {
        Err(vec![aa_core::PolicyError::InvalidDocument])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::document::{
        ActionOnExceed, ActiveHours, BudgetPolicy, CredentialAction, DataPolicy, NetworkPolicy, PolicyDocument,
        SchedulePolicy, ToolPolicy,
    };
    use aa_core::{
        identity::{AgentId, SessionId},
        time::Timestamp,
        AgentContext, GovernanceAction, PolicyResult,
    };
    use std::collections::{BTreeMap, HashMap};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_ctx() -> AgentContext {
        AgentContext {
            agent_id: AgentId::from_bytes([1u8; 16]),
            session_id: SessionId::from_bytes([2u8; 16]),
            pid: 1,
            started_at: Timestamp::from_nanos(0),
            metadata: BTreeMap::new(),
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        }
    }

    fn make_ctx_in_team(agent_byte: u8, team: &str) -> AgentContext {
        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([agent_byte; 16]);
        ctx.team_id = Some(team.to_string());
        ctx
    }

    fn empty_doc() -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: crate::policy::scope::PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: None,
            filesystem: None,
            syscall_allowlist: None,
        }
    }

    fn make_engine(doc: PolicyDocument) -> PolicyEngine {
        let compiled_patterns = doc
            .data
            .as_ref()
            .map(|dp| {
                dp.sensitive_patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let daily_limit = doc
            .budget
            .as_ref()
            .and_then(|bp| bp.daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let monthly_limit = doc
            .budget
            .as_ref()
            .and_then(|bp| bp.monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        PolicyEngine {
            policy: Arc::new(ArcSwap::new(Arc::new(doc))),
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new(
                crate::budget::PricingTable::default_table(),
                daily_limit,
                monthly_limit,
                chrono_tz::UTC,
            )),
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState {
                scope_index: ScopeIndex::new(),
                compiled_patterns,
            })),
            _cascade_watcher: None,
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(1_024),
        }
    }

    fn tool_call(name: &str, args: &str) -> GovernanceAction {
        GovernanceAction::ToolCall {
            name: name.to_string(),
            args: args.to_string(),
        }
    }

    fn network_req(url: &str) -> GovernanceAction {
        GovernanceAction::NetworkRequest {
            url: url.to_string(),
            method: "GET".to_string(),
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    // ── AAASM-5354: the canonical detection port on the production path ──────

    use crate::engine::detection::test_double::{self, FixedPass};

    /// A doc whose `data` section carries only the given locale-pack tags.
    fn doc_with_locale_packs(tags: &[&str]) -> PolicyDocument {
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![],
            credential_action: CredentialAction::default(),
            locale_packs: tags.iter().map(|t| t.to_string()).collect(),
        });
        doc
    }

    /// A 2021-form 居留證 built by AAASM-5353's own fixture generator (see
    /// `conformance/vectors/zh_tw_detection/id_arc_2021.json`): synthetic, and
    /// checksum-valid so the recognizer that exists is the one under test.
    const ZH_TW_ARC_TEXT: &str = "居留證統一證號 A800000005 於系統中建檔。";

    /// **The production-path test.** The real engine's `evaluate` must reach the
    /// port — not a unit-test adapter calling `detection::run` directly.
    ///
    /// Falsification: this fails if the seam is disconnected. Removing the
    /// `Self::run_detection` call from `evaluate_primary` (or reverting Stage 6
    /// to the pre-port open-coded loops) leaves the installed pass unrun and
    /// `canonical_findings` empty, and the assertion below fires. Confirmed by
    /// making that edit and watching this test fail before it was committed.
    #[test]
    fn evaluate_invokes_the_detection_port_on_the_production_path() {
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "the payload contains SENTINEL somewhere");

        let result = test_double::with(FixedPass::reporting("SENTINEL"), || engine.evaluate(&ctx, &action));

        let recognizers: Vec<_> = result
            .canonical_findings
            .iter()
            .map(|f| (f.provenance().recognizer, f.provenance().version))
            .collect();
        assert!(
            recognizers.contains(&(aa_security::canonical::Recognizer::ZhTwLocalePack, "test-double")),
            "the engine did not run the installed pass — the seam is disconnected. got {recognizers:?}"
        );
    }

    /// The same seam, seen from the enforcement tier: a pass that produces a
    /// `CredentialFinding` must have it reach `credential_findings` and the
    /// redaction, not merely the canonical projection.
    #[test]
    fn a_port_finding_reaches_the_enforcement_tier_and_the_redaction() {
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "value=SENTINEL trailing");

        let result = test_double::with(FixedPass::enforceable("SENTINEL"), || engine.evaluate(&ctx, &action));

        assert_eq!(result.decision, PolicyResult::Allow);
        assert_eq!(
            result.credential_findings.len(),
            1,
            "the port's enforcement-tier finding did not reach credential_findings"
        );
        let redacted = result.redacted_payload.expect("a finding must produce a redaction");
        assert!(!redacted.contains("SENTINEL"), "the flagged span survived: {redacted}");
    }

    /// Fail closed. A pass that cannot run must deny, never continue with an
    /// empty findings list — this is the synchronous pre-action path, so
    /// "no findings" would forward a payload nothing inspected.
    #[test]
    fn a_failing_detection_pass_denies_instead_of_allowing_with_no_findings() {
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "anything at all");

        // Control: without the failure the same action is allowed, so the deny
        // below is caused by the failure and not by the fixture.
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);

        let result = test_double::with(
            FixedPass::failing(detection::DetectionError::UnknownLocalePack { tag: "ja-JP".into() }),
            || engine.evaluate(&ctx, &action),
        );

        match result.decision {
            PolicyResult::Deny { ref reason } => {
                assert!(reason.contains("detection unavailable"), "unexpected reason: {reason}");
                assert!(
                    reason.contains("ja-JP"),
                    "the reason must name the failing pack: {reason}"
                );
            }
            other => panic!("a failed detection pass must deny, got {other:?}"),
        }
        assert!(result.redacted_payload.is_none());
    }

    /// A policy naming a pack this build lacks denies rather than running with
    /// that detector silently absent. Reached by constructing the document
    /// directly, which is how `aa-api`, the simulation surface and tests build
    /// one; `PolicyValidator` rejects the same tag at load time.
    #[test]
    fn an_unknown_locale_pack_denies_rather_than_scanning_without_it() {
        let engine = make_engine(doc_with_locale_packs(&["ja-JP"]));
        let ctx = make_ctx();
        let result = engine.evaluate(&ctx, &tool_call("any", "harmless text"));
        match result.decision {
            PolicyResult::Deny { ref reason } => assert!(reason.contains("ja-JP"), "{reason}"),
            other => panic!("an unknown pack must deny, got {other:?}"),
        }
    }

    /// Confidence is evidence, never an authorisation input (ADR 0002; ADR 0032
    /// §4). Two runs differing *only* in the band a pass reports must produce
    /// the same decision, the same redaction and the same finding count.
    #[test]
    fn a_findings_confidence_band_does_not_move_the_decision() {
        use aa_security::canonical::ConfidenceBand;
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![],
            credential_action: CredentialAction::Block,
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "carrying SENTINEL here");

        let high = test_double::with(
            FixedPass::reporting("SENTINEL").with_confidence(ConfidenceBand::High),
            || engine.evaluate(&ctx, &action),
        );
        let low = test_double::with(
            FixedPass::reporting("SENTINEL").with_confidence(ConfidenceBand::Low),
            || engine.evaluate(&ctx, &action),
        );

        // Guard against the comparison passing because neither fired.
        assert!(matches!(high.decision, PolicyResult::Deny { .. }), "fixture must block");
        assert_eq!(high.decision, low.decision);
        assert_eq!(high.redacted_payload, low.redacted_payload);
        assert_eq!(high.canonical_findings.len(), low.canonical_findings.len());
        assert_ne!(
            high.canonical_findings[0].confidence(),
            low.canonical_findings[0].confidence(),
            "the two runs must actually differ in the band, or this test compares identical inputs"
        );
    }

    // ── AAASM-5354: the zh-TW gate, off by default ──────────────────────────

    /// Default off. The pack is compiled in and reachable, and a policy that
    /// does not ask for it gets exactly the pre-port behaviour.
    #[test]
    fn zh_tw_findings_do_not_appear_unless_the_policy_asks_for_the_pack() {
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let result = engine.evaluate(&ctx, &tool_call("any", ZH_TW_ARC_TEXT));

        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(result.credential_findings.is_empty());
        assert!(
            result.canonical_findings.is_empty(),
            "the zh-TW pack ran without being configured: {:?}",
            result.canonical_findings
        );
        assert!(result.redacted_payload.is_none());
    }

    /// With the gate on the same input is detected and the identifier removed.
    #[test]
    fn the_zh_tw_gate_detects_and_redacts_when_enabled() {
        let engine = make_engine(doc_with_locale_packs(&["zh-TW"]));
        let ctx = make_ctx();
        let result = engine.evaluate(&ctx, &tool_call("any", ZH_TW_ARC_TEXT));

        assert_eq!(result.decision, PolicyResult::Allow);
        assert_eq!(result.canonical_findings.len(), 1, "{:?}", result.canonical_findings);
        let finding = result.canonical_findings[0];
        assert_eq!(
            finding.provenance().recognizer,
            aa_security::canonical::Recognizer::ZhTwLocalePack
        );
        assert_eq!(finding.category().to_string(), "NATIONAL_ID[zh-TW/arc_new]");
        assert!(
            result.credential_findings.is_empty(),
            "a locale finding must not fabricate a CredentialKind"
        );
        let redacted = result.redacted_payload.expect("a finding must redact");
        assert!(!redacted.contains("A800000005"), "the identifier survived: {redacted}");
        assert_eq!(redacted, "居留證統一證號 [REDACTED] 於系統中建檔。");
    }

    /// A locale finding has no enforcement-tier counterpart, so a `block`
    /// policy that only consulted `credential_findings` would forward it. It
    /// must deny.
    #[test]
    fn the_zh_tw_gate_blocks_under_credential_action_block() {
        let mut doc = doc_with_locale_packs(&["zh-TW"]);
        doc.data.as_mut().unwrap().credential_action = CredentialAction::Block;
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let result = engine.evaluate(&ctx, &tool_call("any", ZH_TW_ARC_TEXT));

        assert!(
            matches!(result.decision, PolicyResult::Deny { .. }),
            "a locale finding must reach the block path, got {:?}",
            result.decision
        );
        assert!(result.redacted_payload.is_none(), "a blocked payload is not forwarded");
    }

    /// The false-positive side, which is the defect this Epic exists to fix:
    /// ordinary numerically-dense Traditional-Chinese prose must produce
    /// nothing even with the pack running. Corpus taken from AAASM-5353's
    /// `clean_prose_negative` vector.
    #[test]
    fn the_zh_tw_gate_is_silent_on_ordinary_numeric_prose() {
        let engine = make_engine(doc_with_locale_packs(&["zh-TW"]));
        let ctx = make_ctx();
        let text = "本文件對應版本 v0.0.1-rc.7，最後更新於 2026-08-01。閘道器預設監聽 50051 埠，\
                    儀表板使用 3000 埠。第一季共處理 1,250,000 次決策請求，其中 3,412 次被拒絕。\
                    稽核事件保留 365 天，每批最多 5000 筆。會議記錄編號 20260715，與會者 12 人。";
        let result = engine.evaluate(&ctx, &tool_call("any", text));

        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(
            result.canonical_findings.is_empty(),
            "clean prose produced findings: {:?}",
            result.canonical_findings
        );
        assert!(result.redacted_payload.is_none(), "clean prose must not be rewritten");
    }

    /// A checksum near-miss: one digit off a valid identity number. The
    /// recognizer is arithmetic, so this must not fire.
    #[test]
    fn the_zh_tw_gate_rejects_a_checksum_near_miss() {
        let engine = make_engine(doc_with_locale_packs(&["zh-TW"]));
        let ctx = make_ctx();
        // A800000005 is valid; A800000004 differs only in the check digit.
        let result = engine.evaluate(&ctx, &tool_call("any", "居留證統一證號 A800000004 於系統中建檔。"));

        assert!(
            result.canonical_findings.is_empty(),
            "a checksum-invalid identifier fired: {:?}",
            result.canonical_findings
        );
    }

    /// Mixed-language payload: the built-in scanner and the locale pack must
    /// both fire, and both spans must be removed from one redaction.
    #[test]
    fn the_zh_tw_gate_composes_with_the_built_in_scanner_on_mixed_text() {
        let engine = make_engine(doc_with_locale_packs(&["zh-TW"]));
        let ctx = make_ctx();
        let raw_key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let text = format!("token={raw_key}，居留證統一證號 A800000005 已建檔。");
        let result = engine.evaluate(&ctx, &tool_call("any", &text));

        let recognizers: Vec<_> = result
            .canonical_findings
            .iter()
            .map(|f| f.provenance().recognizer)
            .collect();
        assert!(
            recognizers.contains(&aa_security::canonical::Recognizer::BuiltinScanner),
            "the built-in scanner did not fire on mixed text: {recognizers:?}"
        );
        assert!(
            recognizers.contains(&aa_security::canonical::Recognizer::ZhTwLocalePack),
            "the locale pack did not fire on mixed text: {recognizers:?}"
        );
        let redacted = result.redacted_payload.expect("both findings must redact");
        assert!(!redacted.contains(raw_key), "the token survived: {redacted}");
        assert!(!redacted.contains("A800000005"), "the identifier survived: {redacted}");
    }

    // ── AAASM-5354: the cascade path is a second enforcement path ────────────
    //
    // `PolicyEngine::evaluate` has two Stage 6 implementations, not one: it
    // delegates to `evaluate_primary` while the scope index is empty and to
    // `evaluate_with_cascade` once any scoped document is registered. Both are
    // production enforcement paths. A test that only exercised the first would
    // pass with the second still running an un-ported detector — which is the
    // shape of wrong-reason pass this Epic keeps producing — so every property
    // proved of the primary path above is proved again here.

    /// A cascade engine: registering a scoped document makes `evaluate` route
    /// through `evaluate_with_cascade` rather than `evaluate_primary`.
    fn make_cascade_engine(docs: Vec<PolicyDocument>) -> PolicyEngine {
        let mut engine = make_engine(empty_doc());
        for doc in docs {
            engine.load_policy(doc);
        }
        engine
    }

    fn scoped(scope: crate::policy::scope::PolicyScope, data: Option<DataPolicy>) -> PolicyDocument {
        let mut doc = empty_doc();
        doc.scope = scope;
        doc.data = data;
        doc
    }

    /// Guards every cascade test below: if `evaluate` ever stopped routing to
    /// `evaluate_with_cascade` for a scope-indexed engine, those tests would be
    /// re-proving the primary path and silently testing nothing new.
    #[test]
    fn a_scope_indexed_engine_really_routes_through_the_cascade_path() {
        use crate::policy::scope::PolicyScope;
        // `policy_doc_id` is attributed only by the cascade path; the primary
        // path documents that it returns `None` because no cascade document
        // decided.
        let engine = make_cascade_engine(vec![scoped(PolicyScope::Global, None)]);
        let result = engine.evaluate(&make_ctx(), &tool_call("any", "harmless"));
        assert!(
            result.policy_doc_id.is_some(),
            "this engine did not take the cascade path, so the cascade tests below prove nothing"
        );
        assert!(make_engine(empty_doc())
            .evaluate(&make_ctx(), &tool_call("any", "harmless"))
            .policy_doc_id
            .is_none());
    }

    /// **The cascade production-path test.** Falsification: reverting
    /// `evaluate_with_cascade`'s Stage 6 to the pre-port
    /// `collect_cascade_custom_findings` merge makes this fail while every
    /// primary-path test stays green.
    #[test]
    fn evaluate_with_cascade_invokes_the_detection_port_on_the_production_path() {
        use crate::policy::scope::PolicyScope;
        let engine = make_cascade_engine(vec![scoped(PolicyScope::Global, None)]);
        let action = tool_call("any", "the payload contains SENTINEL somewhere");

        let result = test_double::with(FixedPass::reporting("SENTINEL"), || {
            engine.evaluate(&make_ctx(), &action)
        });

        let recognizers: Vec<_> = result
            .canonical_findings
            .iter()
            .map(|f| (f.provenance().recognizer, f.provenance().version))
            .collect();
        assert!(
            recognizers.contains(&(aa_security::canonical::Recognizer::ZhTwLocalePack, "test-double")),
            "the cascade path did not run the installed pass — its seam is disconnected. got {recognizers:?}"
        );
    }

    /// Fail-closed on the cascade path too.
    #[test]
    fn a_failing_detection_pass_denies_on_the_cascade_path() {
        use crate::policy::scope::PolicyScope;
        let engine = make_cascade_engine(vec![scoped(PolicyScope::Global, None)]);
        let action = tool_call("any", "anything at all");
        assert_eq!(engine.evaluate(&make_ctx(), &action).decision, PolicyResult::Allow);

        let result = test_double::with(
            FixedPass::failing(detection::DetectionError::UnknownLocalePack { tag: "ja-JP".into() }),
            || engine.evaluate(&make_ctx(), &action),
        );
        match result.decision {
            PolicyResult::Deny { ref reason } => assert!(reason.contains("ja-JP"), "{reason}"),
            other => panic!("the cascade path must deny on a failed pass, got {other:?}"),
        }
    }

    /// Behaviour identity for the cascade path, whose pass 2 spans every
    /// document in the resolved cascade rather than only the Global one.
    /// Compared against a transcription of `collect_cascade_custom_findings`
    /// as it stood at 3e8cb4955.
    #[test]
    fn the_cascade_merge_is_identical_to_the_pre_port_cascade_merge() {
        use crate::policy::scope::PolicyScope;
        let agent = aa_core::identity::AgentId::from_bytes([1u8; 16]);
        let global_pattern = r"api_key=[A-Za-z0-9]+";
        let agent_pattern = r"secret-\w+";

        let engine = make_cascade_engine(vec![
            scoped(
                PolicyScope::Global,
                Some(DataPolicy {
                    sensitive_patterns: vec![global_pattern.to_string()],
                    credential_action: CredentialAction::default(),
                    locale_packs: vec![],
                }),
            ),
            scoped(
                PolicyScope::Agent(agent),
                Some(DataPolicy {
                    sensitive_patterns: vec![agent_pattern.to_string()],
                    credential_action: CredentialAction::default(),
                    locale_packs: vec![],
                }),
            ),
        ]);

        let text = "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 api_key=abc123 secret-zzz";
        let result = engine.evaluate(&make_ctx(), &tool_call("any", text));

        // The pre-port merge: built-in scan, then every cascade doc's patterns
        // in cascade order, then a stable sort by offset.
        let scanner = aa_security::CredentialScanner::new();
        let mut expected = scanner.scan(text).findings;
        for pattern in [global_pattern, agent_pattern] {
            let re = regex::Regex::new(pattern).unwrap();
            for m in re.find_iter(text) {
                expected.push(aa_security::CredentialFinding::from_regex_match(m.start(), m.end()));
            }
        }
        expected.sort_by_key(|f| f.offset);

        assert_eq!(result.credential_findings, expected, "cascade merge differs");
        assert_eq!(
            result.redacted_payload,
            Some(
                aa_security::ScanResult {
                    findings: expected.clone()
                }
                .redact(text)
            ),
            "cascade redaction differs"
        );
        // Guard: both passes and both documents must actually have contributed,
        // or the equality above is between two short lists that agree trivially.
        assert!(
            expected.len() >= 3
                && expected
                    .iter()
                    .filter(|f| f.kind == aa_security::CredentialKind::Custom)
                    .count()
                    == 2,
            "the cascade fixture stopped exercising both documents' patterns: {expected:?}"
        );
    }

    /// A locale pack named by *any* document in the cascade runs, so a
    /// narrow-scoped policy asking for a detector is not cancelled by a broader
    /// one that is silent about it.
    #[test]
    fn a_locale_pack_named_by_one_cascade_document_runs_for_that_agent() {
        use crate::policy::scope::PolicyScope;
        let agent = aa_core::identity::AgentId::from_bytes([1u8; 16]);
        let engine = make_cascade_engine(vec![
            scoped(PolicyScope::Global, None),
            scoped(
                PolicyScope::Agent(agent),
                Some(DataPolicy {
                    sensitive_patterns: vec![],
                    credential_action: CredentialAction::default(),
                    locale_packs: vec!["zh-TW".to_string()],
                }),
            ),
        ]);

        let result = engine.evaluate(&make_ctx(), &tool_call("any", ZH_TW_ARC_TEXT));
        assert_eq!(
            result.canonical_findings.len(),
            1,
            "the cascade path did not run the pack the agent-scoped document asked for: {:?}",
            result.canonical_findings
        );
        assert_eq!(
            result.canonical_findings[0].provenance().recognizer,
            aa_security::canonical::Recognizer::ZhTwLocalePack
        );
        let redacted = result.redacted_payload.expect("a finding must redact");
        assert!(!redacted.contains("A800000005"), "the identifier survived: {redacted}");
    }

    /// And the same default: a cascade in which no document names a pack does
    /// not run one.
    #[test]
    fn the_cascade_path_runs_no_locale_pack_unless_a_document_names_one() {
        use crate::policy::scope::PolicyScope;
        let engine = make_cascade_engine(vec![scoped(PolicyScope::Global, None)]);
        let result = engine.evaluate(&make_ctx(), &tool_call("any", ZH_TW_ARC_TEXT));
        assert!(
            result.canonical_findings.is_empty(),
            "the cascade path ran the zh-TW pack unasked: {:?}",
            result.canonical_findings
        );
        assert!(result.redacted_payload.is_none());
    }

    // ── AAASM-5354: behaviour identity of the ungated merge ──────────────────

    /// The pre-port Stage 6 merge, transcribed from `engine/mod.rs` at
    /// `3e8cb4955`. The "before" side of the identity comparison below.
    fn pre_port_stage6(patterns: &[regex::Regex], text: &str) -> Vec<aa_security::CredentialFinding> {
        let scanner = aa_security::CredentialScanner::new();
        let mut all_findings = scanner.scan(text).findings;
        for re in patterns {
            for m in re.find_iter(text) {
                all_findings.push(aa_security::CredentialFinding::from_regex_match(m.start(), m.end()));
            }
        }
        all_findings.sort_by_key(|f| f.offset);
        all_findings
    }

    /// End-to-end behaviour identity: for every fixture, the findings the real
    /// engine reports and the payload it redacts are exactly what the pre-port
    /// code produced — identical lists, not merely both non-empty.
    ///
    /// The counters at the end guard the guard: without them this whole loop
    /// would pass on a corpus that had stopped producing findings.
    #[test]
    fn the_ungated_engine_merge_is_identical_to_the_pre_port_merge() {
        let fixtures: Vec<(&str, Vec<&str>)> = vec![
            ("list files in /home/user", vec![]),
            ("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", vec![]),
            ("config: api_key=supersecret123", vec![r"api_key=[A-Za-z0-9]+"]),
            (
                "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 and api_key=supersecret123",
                vec![r"api_key=[A-Za-z0-9]+"],
            ),
            (
                "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
                vec![r"ghp_[A-Za-z0-9]+", r"ghp_[A-Z]{4}"],
            ),
            ("aaaa-bbbb-cccc", vec![r"a+-b+", r"b+-c+"]),
            ("使用者的 api_key=秘密 已外洩", vec![r"api_key=\S+"]),
            ("abc", vec![r"x*"]),
            (ZH_TW_ARC_TEXT, vec![]),
            ("AKIAIOSFODNN7EXAMPLE and postgres://u:p@h/db", vec![]),
        ];

        let ctx = make_ctx();
        let mut fixtures_with_findings = 0usize;
        let mut total_findings = 0usize;
        let mut fixtures_redacted = 0usize;

        for (text, patterns) in fixtures {
            let mut doc = empty_doc();
            doc.data = Some(DataPolicy {
                sensitive_patterns: patterns.iter().map(|p| p.to_string()).collect(),
                credential_action: CredentialAction::default(),
                locale_packs: vec![],
            });
            let engine = make_engine(doc);
            let result = engine.evaluate(&ctx, &tool_call("any", text));

            let compiled: Vec<regex::Regex> = patterns.iter().map(|p| regex::Regex::new(p).unwrap()).collect();
            let expected = pre_port_stage6(&compiled, text);

            assert_eq!(
                result.credential_findings, expected,
                "merged findings differ for fixture {text:?}"
            );

            let expected_redaction = if expected.is_empty() {
                None
            } else {
                Some(
                    aa_security::ScanResult {
                        findings: expected.clone(),
                    }
                    .redact(text),
                )
            };
            assert_eq!(
                result.redacted_payload, expected_redaction,
                "redaction differs for fixture {text:?}"
            );

            total_findings += expected.len();
            if !expected.is_empty() {
                fixtures_with_findings += 1;
            }
            if expected_redaction.is_some() {
                fixtures_redacted += 1;
            }
        }

        assert!(
            fixtures_with_findings >= 7 && total_findings >= 12 && fixtures_redacted >= 7,
            "the identity corpus stopped exercising the merge: {fixtures_with_findings} fixtures with \
             findings, {total_findings} findings, {fixtures_redacted} redactions"
        );
    }

    /// Every AAASM-5353 conformance vector, replayed through the real engine
    /// with the gate on. Reuses the committed fixtures rather than restating
    /// the detection logic.
    #[test]
    fn the_zh_tw_conformance_vectors_replay_through_the_engine() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../conformance/vectors/zh_tw_detection");
        let engine = make_engine(doc_with_locale_packs(&["zh-TW"]));
        let ctx = make_ctx();

        let mut checked = 0usize;
        let mut positive = 0usize;
        for entry in std::fs::read_dir(&dir).expect("the AAASM-5353 vector directory must exist") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let vector: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let text = vector["input_text"].as_str().unwrap();
            let expected: Vec<String> = vector["expected_findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["category"].as_str().unwrap().to_string())
                .collect();

            let result = engine.evaluate(&ctx, &tool_call("any", text));
            let actual: Vec<String> = result
                .canonical_findings
                .iter()
                .filter(|f| f.provenance().recognizer == aa_security::canonical::Recognizer::ZhTwLocalePack)
                .map(|f| f.category().to_string())
                .collect();

            assert_eq!(
                actual,
                expected,
                "vector {} replayed differently through the engine",
                path.display()
            );
            checked += 1;
            if !expected.is_empty() {
                positive += 1;
            }
        }

        // Without this the test passes on an empty directory, and passes on a
        // pack that detects nothing at all (every vector's expectation would
        // then be the empty list only for the negatives).
        assert!(
            checked >= 19 && positive >= 8,
            "expected the full AAASM-5353 vector set: {checked} replayed, {positive} with findings"
        );
    }

    #[test]
    fn evaluate_allows_when_no_policy_sections() {
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn schedule_denies_outside_active_hours() {
        // A window of 00:00–00:01 will almost certainly be outside the current time.
        let mut doc = empty_doc();
        doc.schedule = Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: "00:00".to_string(),
                end: "00:01".to_string(),
                timezone: "UTC".to_string(),
            }),
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "");
        let result = engine.evaluate(&ctx, &action);
        // This window is 1 minute wide; unless tests run exactly at midnight, it's Deny.
        // Accept either Deny or Allow (if tests run in the 00:00–00:01 window).
        match result.decision {
            PolicyResult::Deny { reason } => {
                assert_eq!(reason, "outside active hours");
            }
            PolicyResult::Allow => {
                // Rare but possible if test runs exactly at midnight UTC.
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn schedule_omitted_allows_at_any_time() {
        // AAASM-5933: this test previously configured `active_hours`
        // `"00:00"`–`"23:59"` and asserted Allow, on the assumption that
        // covers the full day. It doesn't — `end` is documented exclusive
        // (`docs/src/policy-reference.md` § schedule), so that window denies
        // its own last minute, and the test failed deterministically
        // whenever CI happened to run during it. The schema has no `24:00`
        // sentinel, so no `active_hours` window can express "every instant of
        // the day" — the documented way to get unrestricted scheduling is to
        // omit `schedule` entirely, which `empty_doc()` already does. That
        // needs no clock at all, so this is deterministic rather than merely
        // "correct at the instant it happens to run" like the window version
        // was.
        let doc = empty_doc();
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn schedule_wide_active_hours_window_allows_through_the_full_pipeline() {
        // Independent review of AAASM-5933 (PR #2218) flagged that the fix
        // above removed the only `engine::evaluate()`-level test exercising a
        // *real* (non-`None`) `active_hours` window through the production
        // live-clock path and asserting Allow — every remaining
        // `ActiveHours { .. }` case in this file asserts Deny. `evaluate()`
        // has no seam to inject a fixed instant (unlike `stage_schedule_at`
        // in `decision.rs`, added by the same PR, which only covers the
        // stage-level comparison, not dispatch/caching — the thing AAASM-3893
        // cares about: a cached verdict computed inside active-hours must not
        // outlive the window).
        //
        // A live-clock window test necessarily keeps *some* wall-clock
        // dependence, which is exactly what AAASM-5933 exists to eliminate —
        // so this deliberately follows `schedule_denies_outside_active_hours`
        // above's already-established, already-accepted pattern for that
        // trade-off (tolerate the near-certain case, name the rare one)
        // rather than inventing a new one. Unlike the original bug, this
        // window's excluded minutes (`23:58`, `23:59`) are far from its
        // `start` and stated purpose is "wide", so an `Allow` failure here
        // names the actual gap instead of masking it as "flaky".
        let mut doc = empty_doc();
        doc.schedule = Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: "00:00".to_string(),
                end: "23:58".to_string(),
                timezone: "UTC".to_string(),
            }),
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "");
        let result = engine.evaluate(&ctx, &action);
        match result.decision {
            PolicyResult::Allow => {}
            PolicyResult::Deny { reason } => {
                // Only expected in the 2 minutes/day this window excludes.
                assert_eq!(reason, "outside active hours");
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn schedule_invalid_timezone_fails_closed() {
        // AAASM-3847: an unparseable tz on the single-policy `evaluate_primary`
        // path must DENY, not silently fall back to UTC. The window is the full
        // day, so the only reason to deny is the invalid timezone — proving the
        // fail-closed behaviour rather than a coincidental out-of-window deny.
        let mut doc = empty_doc();
        doc.schedule = Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: "00:00".to_string(),
                end: "23:59".to_string(),
                timezone: "Not/AZone".to_string(),
            }),
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "");
        match engine.evaluate(&ctx, &action).decision {
            PolicyResult::Deny { reason } => {
                assert!(
                    reason.contains("invalid schedule timezone"),
                    "expected invalid-timezone deny, got: {reason}"
                );
            }
            other => panic!("expected fail-closed Deny, got: {other:?}"),
        }
    }

    #[test]
    fn network_denies_unlisted_host() {
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = network_req("https://evil.com/path");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "host not in network allowlist".into()
            }
        );
    }

    #[test]
    fn network_allows_listed_host() {
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = network_req("https://api.openai.com/v1");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn network_allows_listed_host_with_port() {
        // AAASM-3350: `convert.rs` emits `proto://host:port`, so the live
        // `evaluate`/`eval_network_stage` path must strip the `:port` before the
        // bare-host allowlist compare. An allowlisted host with a port must Allow.
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = network_req("https://api.openai.com:443/v1");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn network_denies_unlisted_host_with_port() {
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy {
            allowlist: vec!["api.openai.com".to_string()],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = network_req("https://evil.attacker.net:8443/x");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "host not in network allowlist".into()
            }
        );
    }

    #[test]
    fn network_empty_allowlist_denies_all_egress() {
        // AAASM-3728: the single-file path failed OPEN on an empty allowlist
        // (returned None ⇒ allow-all). A configured `network:` clause with an
        // empty allowlist must deny ALL egress (fail-closed).
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy { allowlist: vec![] });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = network_req("https://api.openai.com/v1");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "host not in network allowlist".into()
            },
            "empty allowlist must deny all egress, not allow it"
        );
    }

    #[test]
    fn network_wildcard_allows_subdomain_on_single_file_path() {
        // AAASM-3728: the single-file path used exact-match only (`entry ==
        // host`), so a `*.openai.com` allowlist entry never matched and denied
        // traffic the operator believed allowed. It must now honour the
        // wildcard-aware shared matcher, like the cascade path.
        let mut doc = empty_doc();
        doc.network = Some(NetworkPolicy {
            allowlist: vec!["*.openai.com".to_string()],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        assert_eq!(
            engine
                .evaluate(&ctx, &network_req("https://chat.openai.com/v1"))
                .decision,
            PolicyResult::Allow,
            "wildcard *.openai.com must match chat.openai.com"
        );
        assert_eq!(
            engine
                .evaluate(&ctx, &network_req("https://evil.attacker.net/x"))
                .decision,
            PolicyResult::Deny {
                reason: "host not in network allowlist".into()
            },
            "a non-matching host must still be denied"
        );
    }

    #[test]
    fn tool_deny_blocks_call() {
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("ls", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            }
        );
    }

    #[test]
    fn simulate_allows_permitted_tool() {
        // AAASM-5037: the dry-run path returns the same verdict as `evaluate`.
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        assert_eq!(
            engine.simulate(&ctx, &tool_call("ls", "")).decision,
            PolicyResult::Allow
        );
    }

    #[test]
    fn simulate_denies_denied_tool() {
        // AAASM-5037: a denied tool dry-runs to the same deny verdict + reason.
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        assert_eq!(
            engine.simulate(&ctx, &tool_call("ls", "")).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            }
        );
    }

    #[test]
    fn simulate_does_not_consume_rate_limit_token() {
        // AAASM-5037 core invariant: the dry-run must have NO state side effect.
        // A rate-limited tool (limit_per_hour = 1) grants exactly one live token;
        // simulating any number of times must consume none, leaving the live
        // budget fully intact for the first real `evaluate`.
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: Some(1),
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("ls", "");

        // Repeated simulation always allows and consumes nothing.
        for _ in 0..5 {
            assert_eq!(engine.simulate(&ctx, &action).decision, PolicyResult::Allow);
        }

        // The live token bucket is still full: the first real call allows...
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
        // ...and only after that real consumption does the next real call deny.
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            }
        );
    }

    #[test]
    fn tool_allow_passes_call() {
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("ls", "");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn tool_wildcard_deny_blocks_unlisted_tool() {
        // AAASM-4152: the single-file `evaluate_primary` path must honour the
        // `"*"` wildcard so `tools: { "*": { allow: false }, read_file: allow }`
        // denies an unlisted tool. Previously the exact-only lookup let it fall
        // through to allow-by-default — the behaviourally-proven fail-open.
        let mut doc = empty_doc();
        doc.tools.insert(
            "*".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        doc.tools.insert(
            "read_file".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        // Explicitly-allowed tool passes.
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("read_file", "")).decision,
            PolicyResult::Allow
        );
        // Unlisted tool falls back to the `"*"` deny.
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("exfiltrate_secrets", "")).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            }
        );
    }

    #[test]
    fn tool_wildcard_rate_limit_caps_unlisted_tool() {
        // AAASM-4164: a `"*"` wildcard carrying `limit_per_hour` must rate-limit
        // an unlisted tool on the single-file path (stage 4), not leave it
        // uncapped. An explicit per-tool entry still takes precedence: a tool
        // with its own entry (no limit) is never capped by the wildcard.
        let mut doc = empty_doc();
        doc.tools.insert(
            "*".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: Some(1),
                requires_approval_if: None,
            },
        );
        doc.tools.insert(
            "read_file".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();

        // Unlisted tool falls back to the `"*"` cap: first call passes, second denies.
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("search", "")).decision,
            PolicyResult::Allow
        );
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("search", "")).decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            }
        );
        // Explicit entry (no limit) wins over the wildcard — never rate-limited.
        for _ in 0..3 {
            assert_eq!(
                engine.evaluate(&ctx, &tool_call("read_file", "")).decision,
                PolicyResult::Allow
            );
        }
    }

    #[test]
    fn rate_limit_bucket_is_isolated_per_team() {
        // AAASM-4173: the stage-4 rate-limit bucket must be keyed by tenant
        // scope (team) + tool name, not tool name alone. A `limit_per_hour` is
        // per-team — like budgets — so one team exhausting its bucket must NOT
        // deny another team, while two agents in the SAME team SHARE one bucket
        // (the limit is enforced within a team, across its agents). With the old
        // name-only key, team A's calls consumed team B's allowance (a global
        // bucket per tool name shared across every tenant).
        let mut doc = empty_doc();
        doc.tools.insert(
            "search".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: Some(1),
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);

        let team_a_agent1 = make_ctx_in_team(1, "team-a");
        let team_a_agent2 = make_ctx_in_team(2, "team-a");
        let team_b_agent1 = make_ctx_in_team(3, "team-b");

        // Team A consumes its single token.
        assert_eq!(
            engine.evaluate(&team_a_agent1, &tool_call("search", "")).decision,
            PolicyResult::Allow
        );
        // A different agent in the SAME team shares the bucket — now exhausted.
        // (If the key were per-agent, agent2 would get a fresh bucket and pass.)
        assert_eq!(
            engine.evaluate(&team_a_agent2, &tool_call("search", "")).decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            },
            "same team + same tool must share one bucket (limit enforced per team)"
        );
        // Team B has its OWN bucket — team A's exhaustion must not deny team B.
        assert_eq!(
            engine.evaluate(&team_b_agent1, &tool_call("search", "")).decision,
            PolicyResult::Allow,
            "a different team must not share team A's bucket (cross-tenant isolation)"
        );
        // Team B's own bucket still enforces the limit within team B.
        assert_eq!(
            engine.evaluate(&team_b_agent1, &tool_call("search", "")).decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            },
            "team B's own bucket still enforces the per-team limit"
        );
    }

    #[test]
    fn tool_wildcard_approval_gates_unlisted_tool() {
        // AAASM-4164: a `"*"` wildcard carrying `requires_approval_if` must gate
        // an unlisted tool on the single-file path (stage 5), not skip approval.
        // An explicit per-tool entry (no approval guard) still takes precedence.
        let mut doc = empty_doc();
        doc.tools.insert(
            "*".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                // Always true for any real tool name — proves the wildcard guard
                // is consulted regardless of the unlisted tool's name.
                requires_approval_if: Some(r#"tool != "__never_matches__""#.to_string()),
            },
        );
        doc.tools.insert(
            "read_file".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();

        // Unlisted tool falls back to the `"*"` approval guard.
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("exfiltrate_secrets", "")).decision,
            PolicyResult::RequiresApproval { timeout_secs: 300 }
        );
        // Explicit entry (no guard) wins over the wildcard — allowed outright.
        assert_eq!(
            engine.evaluate(&ctx, &tool_call("read_file", "")).decision,
            PolicyResult::Allow
        );
    }

    #[test]
    fn cascade_wildcard_rate_limit_caps_unlisted_tool() {
        // AAASM-4164: the cascade path's `cascade_rate_limit` must honour a
        // `"*"` wildcard `limit_per_hour` for an unlisted tool (stage 4), the
        // twin of the single-file fix. Explicit entries still take precedence.
        let mut doc = empty_doc();
        doc.tools.insert(
            "*".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: Some(1),
                requires_approval_if: None,
            },
        );
        doc.tools.insert(
            "read_file".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let cascade = vec![Arc::new(doc)];

        assert_eq!(
            engine
                .evaluate_with_cascade(cascade.clone(), &ctx, &tool_call("search", ""))
                .decision,
            PolicyResult::Allow
        );
        assert_eq!(
            engine
                .evaluate_with_cascade(cascade.clone(), &ctx, &tool_call("search", ""))
                .decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            }
        );
        // Explicit entry (no limit) wins over the wildcard.
        for _ in 0..3 {
            assert_eq!(
                engine
                    .evaluate_with_cascade(cascade.clone(), &ctx, &tool_call("read_file", ""))
                    .decision,
                PolicyResult::Allow
            );
        }
    }

    #[test]
    fn cascade_wildcard_approval_gates_unlisted_tool() {
        // AAASM-4164: the cascade path's `stage_approval` must honour a `"*"`
        // wildcard `requires_approval_if` for an unlisted tool (stage 5), the
        // twin of the single-file fix. Explicit entries still take precedence.
        let mut doc = empty_doc();
        doc.tools.insert(
            "*".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: Some(r#"tool != "__never_matches__""#.to_string()),
            },
        );
        doc.tools.insert(
            "read_file".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let cascade = vec![Arc::new(doc)];

        assert_eq!(
            engine
                .evaluate_with_cascade(cascade.clone(), &ctx, &tool_call("exfiltrate_secrets", ""))
                .decision,
            PolicyResult::RequiresApproval { timeout_secs: 300 }
        );
        // Explicit entry (no guard) wins over the wildcard.
        assert_eq!(
            engine
                .evaluate_with_cascade(cascade, &ctx, &tool_call("read_file", ""))
                .decision,
            PolicyResult::Allow
        );
    }

    #[test]
    fn rate_limit_denies_after_capacity_exhausted() {
        let mut doc = empty_doc();
        doc.tools.insert(
            "search".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: Some(1),
                requires_approval_if: None,
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("search", "");

        // First call should succeed.
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
        // Second call should be rate-limited.
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "rate limit exceeded".into()
            }
        );
    }

    #[test]
    fn approval_condition_triggers_requires_approval() {
        let mut doc = empty_doc();
        doc.tools.insert(
            "search".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: Some(r#"tool == "search""#.to_string()),
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("search", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::RequiresApproval { timeout_secs: 300 }
        );
    }

    #[test]
    fn approval_condition_uses_custom_timeout() {
        let mut doc = empty_doc();
        doc.approval_timeout_secs = 600;
        doc.tools.insert(
            "deploy".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: Some(r#"tool == "deploy""#.to_string()),
            },
        );
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("deploy", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::RequiresApproval { timeout_secs: 600 }
        );
    }

    #[test]
    fn cached_allow_not_served_for_dangerous_args_through_cascade() {
        // AAASM-3787 regression: the cascade decision cache must key on the
        // action args. A benign `transfer {amount:1}` evaluates to Allow and is
        // cached; a subsequent `transfer {amount:1000000}` within the TTL — same
        // agent, epoch, and tool name but different args — must NOT be served
        // the cached Allow. It must re-evaluate and trip the stage-5
        // `requires_approval_if` predicate (`args.amount > 100`).
        let mut doc = empty_doc();
        doc.tools.insert(
            "transfer".to_string(),
            ToolPolicy {
                allow: true,
                limit_per_hour: None,
                requires_approval_if: Some("args.amount > 100".to_string()),
            },
        );
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let cascade = vec![Arc::new(doc)];

        let benign = tool_call("transfer", r#"{"amount":1}"#);
        assert_eq!(
            engine.evaluate_with_cascade(cascade.clone(), &ctx, &benign).decision,
            PolicyResult::Allow,
        );

        let dangerous = tool_call("transfer", r#"{"amount":1000000}"#);
        assert_eq!(
            engine.evaluate_with_cascade(cascade, &ctx, &dangerous).decision,
            PolicyResult::RequiresApproval { timeout_secs: 300 },
        );
    }

    #[test]
    fn cascade_schedule_denies_despite_stale_cached_allow() {
        // AAASM-3893 regression: the schedule stage is time-dependent and must
        // be evaluated FRESH on every cascade request. A decision cached while
        // the active-hours window was open must NOT be served once the window
        // has closed. We pre-seed the cache with the stale Allow a prior
        // in-window evaluation would have stored, then evaluate against a
        // now-closed window: the request must be DENIED, not served the cached
        // Allow.
        let mut doc = empty_doc();
        doc.schedule = Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: "00:00".to_string(),
                // An empty window (start == end == "00:00"): `current >= end`
                // is always true, so this window is closed at every wall-clock
                // time — the test is deterministic regardless of when it runs.
                end: "00:00".to_string(),
                timezone: "UTC".to_string(),
            }),
        });
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "");

        // Pre-seed the cache with the stale Allow a prior in-window eval stored.
        let epoch = engine.policy_epoch.load(Ordering::Relaxed);
        let key = CacheKey::new(ctx.agent_id.as_bytes(), epoch, &action);
        engine.decision_cache.insert(key, (PolicyDecision::Allow, None));

        let cascade = vec![Arc::new(doc)];
        assert_eq!(
            engine.evaluate_with_cascade(cascade, &ctx, &action).decision,
            PolicyResult::Deny {
                reason: "outside active hours".into()
            },
            "a cached Allow must not survive the active-hours window closing",
        );
    }

    #[test]
    fn data_pattern_redacts_on_custom_match() {
        // Stage 6 no longer denies — it redacts in-memory and sets credential_findings.
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"password=\w+".to_string()],
            credential_action: CredentialAction::default(),
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "password=secret");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(!result.credential_findings.is_empty());
        assert!(result.redacted_payload.is_some());
        // Raw value must not appear in the redacted payload.
        let redacted = result.redacted_payload.unwrap();
        assert!(!redacted.contains("secret"), "raw secret leaked into redacted payload");
        assert!(redacted.contains("[REDACTED:Custom]"));
    }

    #[test]
    fn data_pattern_blocks_when_credential_action_is_block() {
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"password=\w+".to_string()],
            credential_action: CredentialAction::Block,
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "password=secret");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(
            result.decision,
            PolicyResult::Deny {
                reason: "credential detected".into(),
            }
        );
        assert!(!result.credential_findings.is_empty());
        // Block must never produce a redacted form — the payload is rejected outright.
        assert!(result.redacted_payload.is_none());
    }

    #[test]
    fn data_pattern_forwards_when_credential_action_is_alert_only() {
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"password=\w+".to_string()],
            credential_action: CredentialAction::AlertOnly,
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "password=secret");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(!result.credential_findings.is_empty());
        // Alert-only mode forwards the payload unmodified — no redacted form is set.
        assert!(result.redacted_payload.is_none());
    }

    #[test]
    fn data_pattern_redacts_when_credential_action_is_alert_and_redact() {
        // AAASM-3137: alert_and_redact must still redact the payload — the raw
        // secret must NOT be forwarded even though an alert is raised.
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"password=\w+".to_string()],
            credential_action: CredentialAction::AlertAndRedact,
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "password=secret");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(!result.credential_findings.is_empty());
        // A redacted form IS set, and the raw secret is gone.
        let redacted = result
            .redacted_payload
            .expect("alert_and_redact must produce a redacted payload");
        assert!(
            !redacted.contains("secret"),
            "raw secret leaked in alert_and_redact mode"
        );
    }

    #[test]
    fn budget_denies_when_exceeded() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        engine.record_spend(&ctx, 1.0);

        let action = tool_call("any", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "daily budget exceeded".into()
            }
        );
    }

    #[test]
    fn check_and_accrue_llm_spend_commits_within_budget() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(10.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        // Calls are allowed while the agent is under its limit, then denied once
        // it reaches it — the same decision semantics as the Stage-7 read-check.
        assert_eq!(engine.check_and_accrue_llm_spend(&ctx, 5.0), None); // spent 0 → 5
        assert_eq!(engine.check_and_accrue_llm_spend(&ctx, 5.0), None); // spent 5 → 10
                                                                        // Now spent == limit, so the next reservation is rejected atomically.
        assert_eq!(
            engine.check_and_accrue_llm_spend(&ctx, 1.0),
            Some("daily budget exceeded")
        );

        let state = engine.budget.agent_state(&ctx.agent_id).expect("agent has spend");
        assert_eq!(state.spent_usd, rust_decimal::Decimal::try_from(10.0).unwrap());
    }

    #[test]
    fn unknown_model_accrues_fallback_spend_and_engages_budget_cap() {
        // AAASM-4069 regression: a model outside the built-in pricing table
        // (here "o3-mini") must NOT price to $0. Previously it did, and the
        // `cost <= 0.0` accrual short-circuit skipped the budget reservation
        // entirely — an agent could pick any current model for unlimited
        // unmetered spend. It must now fail closed: cost > 0, spend accrues,
        // and the daily cap engages just like a known model.
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        // An unrecognized model with a non-empty prompt is priced at the
        // conservative fallback rate, never $0.
        let cost = engine.llm_call_cost_usd("o3-mini", 10_000, 0);
        assert!(cost > 0.0, "unknown model must not price to zero (was {cost})");

        // The priced spend actually reserves against the budget, so repeated
        // unknown-model calls exhaust the $1 daily cap and are then denied —
        // proving the reservation is reachable, not bypassed.
        let mut denied = false;
        for _ in 0..1_000 {
            if engine.check_and_accrue_llm_spend(&ctx, cost).is_some() {
                denied = true;
                break;
            }
        }
        assert!(denied, "unknown-model spend must eventually hit the daily cap");
    }

    #[test]
    fn check_and_accrue_llm_spend_no_overspend_under_parallel_checks() {
        // AAASM-3986: the atomic check+commit must never let concurrent
        // reservations for one tenant overspend the daily limit. With a $10
        // limit and $1 per call, at most 10 of N parallel reservations may
        // commit and the recorded total must be exactly $10 — never more.
        use std::sync::Arc;

        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(10.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = Arc::new(make_engine(doc));

        let threads = 64;
        let allowed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let engine = Arc::clone(&engine);
                let allowed = Arc::clone(&allowed);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let ctx = make_ctx();
                    barrier.wait();
                    if engine.check_and_accrue_llm_spend(&ctx, 1.0).is_none() {
                        allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let ctx = make_ctx();
        let spent = engine
            .budget
            .agent_state(&ctx.agent_id)
            .expect("agent has spend")
            .spent_usd;
        assert_eq!(
            allowed.load(std::sync::atomic::Ordering::Relaxed),
            10,
            "exactly 10 of the parallel $1 reservations may commit against a $10 limit"
        );
        assert_eq!(
            spent,
            rust_decimal::Decimal::try_from(10.0).unwrap(),
            "recorded spend must never exceed the $10 daily limit"
        );
    }

    #[test]
    fn monthly_budget_denies_when_exceeded() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: None,
            monthly_limit_usd: Some(5.0),
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        engine.record_spend(&ctx, 5.0);

        let action = tool_call("any", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "monthly budget exceeded".into()
            }
        );
    }

    #[test]
    fn monthly_budget_within_limit_allows() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: None,
            monthly_limit_usd: Some(10.0),
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        engine.record_spend(&ctx, 1.0);

        let action = tool_call("any", "");
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
    }

    #[test]
    fn monthly_denies_before_daily_when_both_exceeded() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(2.0),
            monthly_limit_usd: Some(5.0),
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        engine.record_spend(&ctx, 5.0);

        let action = tool_call("any", "");
        // Monthly check comes first in the pipeline
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "monthly budget exceeded".into()
            }
        );
    }

    #[test]
    fn budget_exceed_with_action_deny_returns_no_deny_action() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::Deny,
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        engine.record_spend(&ctx, 1.0);

        let result = engine.evaluate(&ctx, &tool_call("any", ""));
        assert_eq!(
            result.decision,
            PolicyResult::Deny {
                reason: "daily budget exceeded".into()
            }
        );
        assert_eq!(result.deny_action, None);
    }

    #[test]
    fn budget_exceed_with_action_suspend_returns_suspend_agent() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::Suspend,
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        engine.record_spend(&ctx, 1.0);

        let result = engine.evaluate(&ctx, &tool_call("any", ""));
        assert_eq!(
            result.decision,
            PolicyResult::Deny {
                reason: "daily budget exceeded".into()
            }
        );
        assert_eq!(result.deny_action, Some(DenyAction::SuspendAgent));
    }

    #[test]
    fn monthly_budget_exceed_with_suspend_returns_suspend_agent() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: None,
            monthly_limit_usd: Some(5.0),
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::Suspend,
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        engine.record_spend(&ctx, 5.0);

        let result = engine.evaluate(&ctx, &tool_call("any", ""));
        assert_eq!(
            result.decision,
            PolicyResult::Deny {
                reason: "monthly budget exceeded".into()
            }
        );
        assert_eq!(result.deny_action, Some(DenyAction::SuspendAgent));
    }

    #[test]
    fn action_deny_within_budget_allows_normally() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(10.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::Deny,
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        engine.record_spend(&ctx, 1.0);

        let result = engine.evaluate(&ctx, &tool_call("any", ""));
        assert_eq!(result.decision, PolicyResult::Allow);
        assert_eq!(result.deny_action, None);
    }

    #[test]
    fn short_circuit_stops_at_first_deny() {
        // Tool deny (Stage 3) fires before the credential scan (Stage 6).
        let mut doc = empty_doc();
        doc.tools.insert(
            "ls".to_string(),
            ToolPolicy {
                allow: false,
                limit_per_hour: None,
                requires_approval_if: None,
            },
        );
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![".*".to_string()],
            credential_action: CredentialAction::default(),
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("ls", "anything");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            }
        );
    }

    #[test]
    fn load_from_file_returns_engine() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "version: \"1\"\ntools:\n  search:\n    allow: true\n").unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(64);
        let result = PolicyEngine::load_from_file(tmp.path(), alert_tx);
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
    }

    // ── budget timezone fail-closed (AAASM-3875) ──────────────────────────────

    #[test]
    fn parse_budget_tz_none_defaults_to_utc() {
        // No timezone configured is a deliberate default, not a misconfig —
        // keep the documented UTC fallback.
        assert_eq!(parse_budget_tz(None).unwrap(), chrono_tz::UTC);
    }

    #[test]
    fn parse_budget_tz_valid_string_parses() {
        assert_eq!(parse_budget_tz(Some("Asia/Tokyo")).unwrap(), chrono_tz::Asia::Tokyo);
    }

    #[test]
    fn parse_budget_tz_invalid_fails_closed() {
        // AAASM-3875: an unparseable budget timezone must NOT silently fall back
        // to UTC (which would shift the daily/monthly reset boundaries). It is a
        // hard configuration error, mirroring the schedule fix (AAASM-3847).
        match parse_budget_tz(Some("Not/AZone")) {
            Err(PolicyLoadError::Validation(errs)) => {
                assert!(
                    errs.iter().any(|e| e.field == "budget.timezone"),
                    "expected a budget.timezone validation error, got: {errs:?}"
                );
            }
            other => panic!("expected fail-closed Validation error, got: {other:?}"),
        }
    }

    #[test]
    fn load_from_file_invalid_budget_tz_fails_closed() {
        // AAASM-3875: loading a policy whose budget timezone does not parse must
        // abort the load rather than degrade silently to UTC.
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmp,
            "version: \"1\"\nbudget:\n  daily_limit_usd: 10.0\n  timezone: \"Not/AZone\"\n"
        )
        .unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(64);
        let result = PolicyEngine::load_from_file(tmp.path(), alert_tx);
        assert!(
            matches!(result, Err(PolicyLoadError::Validation(_))),
            "expected fail-closed Validation error, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn load_from_file_nested_unknown_key_fails_closed() {
        // AAASM-4330: a typo INSIDE a section (`capabilities.dney` for `deny`)
        // drops the intended restriction. The engine load path must abort
        // rather than enforce a weaker policy than the author wrote.
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "capabilities:\n  dney:\n    - file_delete\n").unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(64);
        let result = PolicyEngine::load_from_file(tmp.path(), alert_tx);
        assert!(
            matches!(result, Err(PolicyLoadError::Validation(_))),
            "expected fail-closed Validation error, got: {:?}",
            result.err()
        );
    }

    // ── PolicyEvaluator trait impl ────────────────────────────────────────────

    #[test]
    fn trait_evaluate_delegates_to_inherent_method() {
        use aa_core::PolicyEvaluator;
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "");
        // Trait returns aa_core::PolicyResult; inherent returns EvaluationResult.
        // Both must agree on the decision for clean payloads.
        let via_trait = <PolicyEngine as PolicyEvaluator>::evaluate(&engine, &ctx, &action);
        let via_inherent = engine.evaluate(&ctx, &action).decision;
        assert_eq!(via_trait, via_inherent);
    }

    #[test]
    fn trait_load_policy_returns_invalid_document() {
        use aa_core::PolicyEvaluator;
        let mut engine = make_engine(empty_doc());
        let stub = aa_core::PolicyDocument {
            version: 1,
            name: "stub".to_string(),
            rules: vec![],
            enforcement_mode: aa_core::EnforcementMode::default(),
        };
        // PolicyEngine now also exposes an inherent `load_policy` that
        // returns a `PolicyId` (AAASM-951). Use fully-qualified syntax so
        // method resolution picks the trait stub under test rather than
        // the inherent method, mirroring the trait-vs-inherent disambiguation
        // already used for `evaluate` above.
        let result = <PolicyEngine as PolicyEvaluator>::load_policy(&mut engine, &stub);
        assert_eq!(result, Err(aa_core::PolicyError::InvalidDocument));
    }

    #[test]
    fn trait_validate_policy_returns_invalid_document() {
        use aa_core::PolicyEvaluator;
        let engine = make_engine(empty_doc());
        let stub = aa_core::PolicyDocument {
            version: 1,
            name: "stub".to_string(),
            rules: vec![],
            enforcement_mode: aa_core::EnforcementMode::default(),
        };
        let result = engine.validate_policy(&stub);
        assert_eq!(result, Err(vec![aa_core::PolicyError::InvalidDocument]));
    }

    // ── Stage 6 scanner integration tests ────────────────────────────────────

    #[test]
    fn stage6_builtin_openai_key_redacted_not_denied() {
        // A payload containing an OpenAI API key must be redacted, not denied.
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "call openai with key sk-abc123xyz");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(!result.credential_findings.is_empty());
        let kinds: Vec<_> = result.credential_findings.iter().map(|f| f.kind.clone()).collect();
        assert!(
            kinds.contains(&aa_security::CredentialKind::OpenAiKey),
            "expected OpenAiKey finding, got: {:?}",
            kinds
        );
        let redacted = result.redacted_payload.expect("redacted_payload must be Some");
        assert!(
            !redacted.contains("sk-abc123xyz"),
            "raw key leaked into redacted payload"
        );
        assert!(redacted.contains("[REDACTED:OpenAiKey]"));
    }

    #[test]
    fn stage6_builtin_findings_not_in_redacted_payload() {
        // Raw secret must be absent from the payload that propagates downstream.
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let raw_key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        let action = tool_call("any", &format!("token={raw_key}"));
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        let redacted = result.redacted_payload.expect("redacted_payload must be Some");
        assert!(!redacted.contains(raw_key), "raw token leaked into redacted payload");
        assert!(redacted.contains("[REDACTED:GitHubPat]"));
    }

    #[test]
    fn stage6_custom_pattern_produces_custom_finding() {
        // A policy-defined regex pattern must produce a CredentialKind::Custom finding.
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"api_key=[A-Za-z0-9]+".to_string()],
            credential_action: CredentialAction::default(),
            locale_packs: vec![],
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "config: api_key=supersecret123");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        let kinds: Vec<_> = result.credential_findings.iter().map(|f| f.kind.clone()).collect();
        assert!(
            kinds.contains(&aa_security::CredentialKind::Custom),
            "expected Custom finding, got: {:?}",
            kinds
        );
        let redacted = result.redacted_payload.expect("redacted_payload must be Some");
        assert!(
            !redacted.contains("supersecret123"),
            "raw value leaked into redacted payload"
        );
    }

    #[test]
    fn stage6_clean_payload_has_no_findings() {
        // A payload with no credentials must produce empty findings and None redacted_payload.
        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        let action = tool_call("any", "list files in /home/user");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(result.credential_findings.is_empty());
        assert!(result.redacted_payload.is_none());
    }

    #[test]
    fn scan_100kb_payload_within_ci_time_bound() {
        // Ticket AC (Technical Details): "scanning must not add > 2ms to the hot path for
        // payloads < 100KB". The 2ms budget is enforced on release builds; debug builds use a
        // looser bound because the Aho-Corasick automaton is not optimised in debug mode.
        use std::time::Instant;

        // AAASM-6016: 50ms wasn't generous enough — `cargo nextest run --workspace`
        // runs 8000+ tests concurrently on a shared, resource-constrained CI runner,
        // and that contention alone pushed this well past 50ms with no change to the
        // scan itself (confirmed: passes in 0.18s in isolation, both locally and on a
        // clean main-branch CI run). Widened for contention headroom, not because the
        // debug-mode scan got slower — this bound was never a perf gate.
        #[cfg(debug_assertions)]
        let budget_ms: u128 = 500; // debug: correctness only, not a perf gate
        #[cfg(not(debug_assertions))]
        let budget_ms: u128 = 2; // release: enforces the AC

        let engine = make_engine(empty_doc());
        let ctx = make_ctx();
        // Build a ~100 KB payload of benign repeated text (no credentials).
        let payload = "the quick brown fox jumps over the lazy dog ".repeat(2_500); // ~110 KB
        let action = tool_call("any", &payload);

        let start = Instant::now();
        let result = engine.evaluate(&ctx, &action);
        let elapsed = start.elapsed();

        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(result.credential_findings.is_empty());
        assert!(
            elapsed.as_millis() < budget_ms,
            "scan took {}ms — exceeds {}ms budget",
            elapsed.as_millis(),
            budget_ms,
        );
    }

    // ── apply_yaml integration ──────────────────────────────────────────────

    #[tokio::test]
    async fn apply_yaml_swaps_policy_and_saves_history() {
        use crate::policy::history::{FsHistoryStore, HistoryConfig, PolicyHistoryStore};
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(HistoryConfig {
            history_dir: tmp.path().to_path_buf(),
            max_versions: 50,
        });

        let engine = make_engine(empty_doc());
        let yaml = "tools:\n  bash:\n    allow: false\n";

        let meta = engine.apply_yaml(yaml, Some("tester"), &store).await.unwrap();

        // History entry was created
        assert!(!meta.sha256.is_empty());
        assert_eq!(meta.applied_by.as_deref(), Some("tester"));

        // Live policy was swapped
        let live = engine.policy.load();
        assert!(!live.tools["bash"].allow);

        // History store has the entry
        let list = store.list(10).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn apply_yaml_rejects_invalid_yaml() {
        use crate::policy::history::{FsHistoryStore, HistoryConfig};
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(HistoryConfig {
            history_dir: tmp.path().to_path_buf(),
            max_versions: 50,
        });

        let engine = make_engine(empty_doc());
        let result = engine.apply_yaml(":\n  [[[bad", None, &store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn apply_yaml_broadcasts_invalidation_within_100ms() {
        use crate::invalidation::InvalidationHub;
        use crate::policy::history::{FsHistoryStore, HistoryConfig};
        use aa_proto::assembly::gateway::v1::invalidation_event::Payload;

        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(HistoryConfig {
            history_dir: tmp.path().to_path_buf(),
            max_versions: 50,
        });

        // A subscriber connected before the mutation should be notified.
        let hub = InvalidationHub::new();
        let mut handle = hub.subscribe("asm-itest", None, 0).expect("subscribe succeeds");
        let engine = make_engine(empty_doc()).with_invalidation_hub(Arc::clone(&hub));

        let start = std::time::Instant::now();
        engine
            .apply_yaml("tools:\n  bash:\n    allow: false\n", Some("tester"), &store)
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), handle.receiver.recv())
            .await
            .expect("invalidation delivered within 100 ms")
            .expect("channel open");
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
        match event.payload.expect("payload set") {
            Payload::PolicyInvalidated(p) => assert_eq!(p.policy_version, 1),
            Payload::ApprovalResolved(_) => panic!("expected PolicyInvalidated"),
        }
    }

    // ── Budget alert integration ────────────────────────────────────────

    fn make_engine_with_alert_sender(
        doc: PolicyDocument,
        alert_tx: tokio::sync::broadcast::Sender<crate::budget::BudgetAlert>,
    ) -> PolicyEngine {
        let compiled_patterns = doc
            .data
            .as_ref()
            .map(|dp| {
                dp.sensitive_patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect()
            })
            .unwrap_or_default();
        let daily_limit = doc
            .budget
            .as_ref()
            .and_then(|bp| bp.daily_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        let monthly_limit = doc
            .budget
            .as_ref()
            .and_then(|bp| bp.monthly_limit_usd)
            .and_then(|v| rust_decimal::Decimal::try_from(v).ok());
        PolicyEngine {
            policy: Arc::new(ArcSwap::new(Arc::new(doc))),
            scanner: aa_security::CredentialScanner::new(),
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new_with_alert_sender(
                crate::budget::PricingTable::default_table(),
                daily_limit,
                monthly_limit,
                chrono_tz::UTC,
                alert_tx,
            )),
            cascade: Arc::new(ArcSwap::from_pointee(CascadeState {
                scope_index: ScopeIndex::new(),
                compiled_patterns,
            })),
            _cascade_watcher: None,
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            invalidation_hub: None,
            sensitive_data: None,
            decision_cache: DecisionCache::new(1_024),
        }
    }

    #[test]
    fn record_spend_fires_alert_on_external_channel() {
        let (alert_tx, mut alert_rx) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(64);
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(10.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine_with_alert_sender(doc, alert_tx);
        let ctx = make_ctx();

        // Record spend at exactly 80% of daily limit
        engine.record_spend(&ctx, 8.0);

        let alert = alert_rx.try_recv().expect("expected 80% threshold alert");
        assert_eq!(alert.threshold_pct, 80);
        assert!((alert.spent_usd - 8.0).abs() < 0.01);
        assert!((alert.limit_usd - 10.0).abs() < 0.01);
    }

    #[test]
    fn budget_deny_still_works_after_migration() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            team_daily_limit_usd: None,
            team_monthly_limit_usd: None,
            org_daily_limit_usd: None,
            org_monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
            window: None,
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();

        engine.record_spend(&ctx, 1.0);

        let action = tool_call("any", "");
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "daily budget exceeded".into()
            }
        );
    }

    // ── Cascade capability guard tests ────────────────────────────────────────

    fn scoped_doc(scope: crate::policy::scope::PolicyScope, caps: Option<aa_core::CapabilitySet>) -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: caps,
            filesystem: None,
            syscall_allowlist: None,
        }
    }

    fn cap_set_cascade(allow: &[aa_core::Capability], deny: &[aa_core::Capability]) -> aa_core::CapabilitySet {
        use std::collections::BTreeSet;
        aa_core::CapabilitySet {
            allow: allow.iter().cloned().collect::<BTreeSet<_>>(),
            deny: deny.iter().cloned().collect::<BTreeSet<_>>(),
            allow_restricted: false,
        }
    }

    #[test]
    fn cascade_capability_deny_from_global_blocks_narrower_allow() {
        // Global deny = {FileWrite}; Agent allow = {FileRead, FileWrite} — global deny wins.
        let mut engine = make_engine(empty_doc());
        let global_caps = cap_set_cascade(&[], &[aa_core::Capability::FileWrite]);
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Global, Some(global_caps)));
        let agent_id = AgentId::from_bytes([1u8; 16]);
        let agent_caps = cap_set_cascade(&[aa_core::Capability::FileRead, aa_core::Capability::FileWrite], &[]);
        engine.load_policy(scoped_doc(
            crate::policy::scope::PolicyScope::Agent(agent_id),
            Some(agent_caps),
        ));

        let ctx = make_ctx();
        let action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Write,
        };
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );
    }

    #[test]
    fn cascade_capability_merged_allow_list_is_intersection() {
        // Global allow = {FileRead, FileWrite}; Agent allow = {FileRead}.
        // After merge: allow is narrowed to {FileRead}. FileWrite should be denied.
        // Uses Global + Agent scopes because collect_cascade walks those without a registry.
        let agent_id = AgentId::from_bytes([1u8; 16]);
        let mut engine = make_engine(empty_doc());
        let global_caps = cap_set_cascade(&[aa_core::Capability::FileRead, aa_core::Capability::FileWrite], &[]);
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Global, Some(global_caps)));
        let agent_caps = cap_set_cascade(&[aa_core::Capability::FileRead], &[]);
        engine.load_policy(scoped_doc(
            crate::policy::scope::PolicyScope::Agent(agent_id),
            Some(agent_caps),
        ));

        let ctx = make_ctx();

        // FileWrite must be denied (not in merged allow list)
        let write_action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Write,
        };
        assert_eq!(
            engine.evaluate(&ctx, &write_action).decision,
            PolicyResult::Deny {
                reason: "capability not in allow list".into()
            }
        );

        // FileRead must be allowed (in merged allow list)
        let read_action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Read,
        };
        assert_ne!(
            engine.evaluate(&ctx, &read_action).decision,
            PolicyResult::Deny {
                reason: "capability not in allow list".into()
            }
        );
    }

    #[test]
    fn cascade_no_capabilities_configured_allows_all_actions() {
        // No capabilities blocks in any cascade doc → capability guard is no-op.
        let mut engine = make_engine(empty_doc());
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Global, None));
        let agent_id = AgentId::from_bytes([1u8; 16]);
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Agent(agent_id), None));

        let ctx = make_ctx();
        let action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Write,
        };
        assert_ne!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );
        assert_ne!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Deny {
                reason: "capability not in allow list".into()
            }
        );
    }

    // ── narrowed flag (AAASM-5100 / ADR-0018 item A) ──────────────────────────

    #[test]
    fn allow_admitted_by_restricted_allowlist_sets_narrowed() {
        // An in-force allow-list (Global {FileRead,FileWrite} ∩ Agent {FileRead})
        // permits FileRead only because it fell inside the scoped whitelist — a
        // narrowing, not a default allow. The result must flag `narrowed = true`
        // so the audit write can render the `narrow` runtime verdict.
        let agent_id = AgentId::from_bytes([1u8; 16]);
        let mut engine = make_engine(empty_doc());
        let global_caps = cap_set_cascade(&[aa_core::Capability::FileRead, aa_core::Capability::FileWrite], &[]);
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Global, Some(global_caps)));
        let agent_caps = cap_set_cascade(&[aa_core::Capability::FileRead], &[]);
        engine.load_policy(scoped_doc(
            crate::policy::scope::PolicyScope::Agent(agent_id),
            Some(agent_caps),
        ));

        let ctx = make_ctx();
        let read_action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Read,
        };
        let result = engine.evaluate(&ctx, &read_action);
        assert_eq!(
            result.decision,
            PolicyResult::Allow,
            "FileRead is inside the allow-list"
        );
        assert!(result.narrowed, "a scoped allow-list match must flag narrowed");
    }

    #[test]
    fn default_allow_with_no_capability_restriction_is_not_narrowed() {
        // No capabilities block anywhere → the action is permitted by default,
        // not scoped by any allow-list, so it must NOT be flagged as narrowed.
        let mut engine = make_engine(empty_doc());
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Global, None));
        let agent_id = AgentId::from_bytes([1u8; 16]);
        engine.load_policy(scoped_doc(crate::policy::scope::PolicyScope::Agent(agent_id), None));

        let ctx = make_ctx();
        let action = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: aa_core::FileMode::Write,
        };
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        assert!(!result.narrowed, "a default allow must not be flagged narrowed");
    }

    // ── Primary-path capability stage regression (AAASM-4123) ─────────────────

    /// Load a single-file policy via the same public loader `aasm policy
    /// simulate` / aa-api use, so `evaluate` takes the primary path (empty
    /// `scope_index`).
    fn load_single_file_engine(yaml: &str) -> PolicyEngine {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{yaml}").unwrap();
        tmp.flush().unwrap();
        let (alert_tx, _) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(64);
        PolicyEngine::load_from_file(tmp.path(), alert_tx).expect("policy should load")
    }

    #[test]
    fn single_file_strict_policy_enforces_capability_stage() {
        // AAASM-4123: before the fix the primary path skipped the capability
        // stage entirely, so a single-file strict policy (deny terminal_exec +
        // file_write) silently ALLOWED process-exec / file-write / file-delete
        // even though the network stage correctly denied. Mirrors the shipped
        // policy-examples/strict.yaml capability floor.
        let engine = load_single_file_engine(
            "version: \"1\"\n\
             network:\n  allowlist:\n    - api.openai.com\n\
             capabilities:\n  deny:\n    - terminal_exec\n    - file_write\n\
             tools:\n  read_file:\n    allow: true\n",
        );
        let ctx = make_ctx();

        // Proof the primary path actually runs: a non-allowlisted GET is denied
        // by the network stage.
        let net = aa_core::GovernanceAction::NetworkRequest {
            url: "https://evil.example.com/".into(),
            method: "GET".into(),
        };
        assert_eq!(
            engine.evaluate(&ctx, &net).decision,
            PolicyResult::Deny {
                reason: "host not in network allowlist".into()
            }
        );

        // terminal_exec deny ⇒ ProcessExec denied.
        let exec = aa_core::GovernanceAction::ProcessExec { command: "id".into() };
        assert_eq!(
            engine.evaluate(&ctx, &exec).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );

        // file_write deny ⇒ FileAccess::Write denied.
        let write = aa_core::GovernanceAction::FileAccess {
            path: "/etc/passwd".into(),
            mode: aa_core::FileMode::Write,
        };
        assert_eq!(
            engine.evaluate(&ctx, &write).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );

        // file_write deny ⇒ FileAccess::Delete denied too (defense-in-depth:
        // a pre-file_delete write-deny must keep blocking delete, AAASM-4103).
        let delete = aa_core::GovernanceAction::FileAccess {
            path: "/etc/passwd".into(),
            mode: aa_core::FileMode::Delete,
        };
        assert_eq!(
            engine.evaluate(&ctx, &delete).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );

        // file_read is not denied and the allow list is empty ⇒ read is not
        // blocked by the capability stage.
        let read = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/ok".into(),
            mode: aa_core::FileMode::Read,
        };
        assert_ne!(
            engine.evaluate(&ctx, &read).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );
    }

    #[test]
    fn single_file_file_delete_deny_blocks_delete_on_primary_path() {
        // AAASM-4123 + AAASM-4103: delete is a first-class verb. A single-file
        // policy that denies only file_delete must block delete on the primary
        // path while still permitting writes (delete-deny ≠ write-deny).
        let engine = load_single_file_engine("version: \"1\"\ncapabilities:\n  deny:\n    - file_delete\n");
        let ctx = make_ctx();

        let delete = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/x".into(),
            mode: aa_core::FileMode::Delete,
        };
        assert_eq!(
            engine.evaluate(&ctx, &delete).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );

        // A write is NOT denied by a delete-only deny.
        let write = aa_core::GovernanceAction::FileAccess {
            path: "/tmp/x".into(),
            mode: aa_core::FileMode::Write,
        };
        assert_ne!(
            engine.evaluate(&ctx, &write).decision,
            PolicyResult::Deny {
                reason: "capability denied by policy".into()
            }
        );
    }

    // ── Directory-cascade binary-loader regression (AAASM-3499) ───────────────

    /// Build a `ctx` for a distinct agent (`agent_byte`) whose lineage
    /// `org_id` is `org`, mirroring the metadata `convert.rs` deposits on the
    /// live gRPC path. Distinct agent ids matter: the decision cache is keyed
    /// by `agent_id` (different orgs run different agents in production), so a
    /// test must not reuse one agent id across two orgs.
    fn make_ctx_in_org(agent_byte: u8, org: &str) -> AgentContext {
        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([agent_byte; 16]);
        ctx.metadata.insert("org_id".to_string(), org.to_string());
        ctx
    }

    /// AAASM-3499 — the directory cascade must be reachable through the loader
    /// the shipped `aa-gateway` binary calls (`load_cascade_from_dir_with_budget`),
    /// not just the test-only `load_cascade_from_dir`. Mirrors the ST-org-4 QA
    /// fixtures: a Global allow-all baseline plus an org-alpha-scoped `bash`
    /// deny. The narrower org-scoped deny must override the Global allow for an
    /// org-alpha agent, while an org-beta agent falls through to the allow.
    #[test]
    fn binary_loader_cascades_org_scoped_deny_over_global_allow() {
        let tmp = tempfile::tempdir().unwrap();
        // Global baseline — empty tools = allow-by-default.
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: reg-global-allow-all\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        // Org-alpha-scoped deny of `bash`. `scope:` lives INSIDE `spec:`.
        std::fs::write(
            tmp.path().join("100-org-alpha-deny-bash.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: reg-org-alpha-deny-bash\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        let (alert_tx, _alert_rx) = tokio::sync::broadcast::channel::<crate::budget::BudgetAlert>(8);
        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        // The binary path: a pre-built tracker is adopted, scope_index populated.
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget)
            .expect("cascade directory loads via the binary loader");
        let _ = alert_tx; // budget alerts unused in this assertion

        let bash = tool_call("bash", "");

        // org-alpha → the org-scoped deny fires and overrides the Global allow.
        assert_eq!(
            engine.evaluate(&make_ctx_in_org(0xaa, "org-alpha"), &bash).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            },
            "org-alpha bash must be denied by the narrower org-scoped document"
        );

        // org-beta → the org-alpha doc is filtered out; falls through to allow.
        assert_eq!(
            engine.evaluate(&make_ctx_in_org(0xbb, "org-beta"), &bash).decision,
            PolicyResult::Allow,
            "org-beta bash must pass through to the Global allow-all default"
        );
    }

    /// The single-file loader must keep the same `scope_index`-empty,
    /// primary-only behaviour (back-compat) — a directory and a file are not
    /// interchangeable through the same loader, but routing on
    /// `path.is_dir()` (in `server::load_policy_engine`) is what selects them.
    #[test]
    fn binary_loader_cascade_populates_scope_index() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: reg-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("100-org.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: reg-org\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:acme\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("loads");
        // A populated scope_index is what routes evaluate() through the cascade.
        assert!(
            !engine.cascade.load().scope_index.is_empty(),
            "directory loader must populate the scope_index (cascade active)"
        );
    }

    /// AAASM-5106 — `cascade_loaded()` is the loaded/unavailable signal the
    /// reporting projections read to tell "the engine carries no cascade" apart
    /// from "this agent/team genuinely has no policy". A primary-only engine
    /// (`load_from_file` semantics, which every shipped aa-api deployment uses)
    /// reports `false`; a directory-loaded cascade reports `true`.
    #[test]
    fn cascade_loaded_reflects_scope_index_population() {
        // Primary-only engine: empty scope_index, so the cascade is not loaded.
        let primary_only = make_engine(empty_doc());
        assert!(
            !primary_only.cascade_loaded(),
            "a primary-only engine carries no cascade — cascade_loaded() must be false"
        );

        // Directory-loaded engine: a populated scope_index means a live cascade.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: reg-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let cascade_engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("loads");
        assert!(
            cascade_engine.cascade_loaded(),
            "a directory-loaded engine carries a cascade — cascade_loaded() must be true"
        );
    }

    // ── Directory-cascade hot-reload (AAASM-3497) ─────────────────────────────

    /// Poll `engine.evaluate(ctx, action)` until its decision equals `want`,
    /// or fail after `timeout`. Used instead of a fixed sleep so the test is
    /// deterministic across slow/fast filesystems: it succeeds as soon as the
    /// directory watcher has applied the on-disk change, and only fails if the
    /// re-evaluation never lands within the (generous) budget.
    fn poll_until_decision(
        engine: &PolicyEngine,
        ctx: &AgentContext,
        action: &GovernanceAction,
        want: &PolicyResult,
        timeout: std::time::Duration,
    ) -> PolicyResult {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let got = engine.evaluate(ctx, action).decision;
            if &got == want {
                return got;
            }
            if std::time::Instant::now() >= deadline {
                return got;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    /// Modifying a `*.yaml` in the policy directory must re-evaluate the
    /// cascade on the running engine. A Global allow-all baseline plus an
    /// org-alpha doc that initially allows `bash`; once the org doc on disk is
    /// rewritten to deny `bash`, an org-alpha agent's `bash` call flips from
    /// Allow to Deny without reloading the engine.
    #[test]
    fn cascade_hot_reload_modify_file_re_evaluates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-global-allow-all\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        let org_doc = tmp.path().join("100-org-alpha.yaml");
        // Initially org-alpha explicitly *allows* bash.
        std::fs::write(
            &org_doc,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-org-alpha\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: true\n",
        )
        .unwrap();

        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("cascade loads");

        let ctx = make_ctx_in_org(0xaa, "org-alpha");
        let bash = tool_call("bash", "");

        // Baseline: bash is allowed before any edit.
        assert_eq!(
            engine.evaluate(&ctx, &bash).decision,
            PolicyResult::Allow,
            "org-alpha bash must start allowed"
        );

        // Strengthen the org doc to DENY bash. Truncate+rewrite mirrors how an
        // operator edits a policy file in place.
        std::fs::write(
            &org_doc,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-org-alpha\n  version: \"0.2.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        let want = PolicyResult::Deny {
            reason: "tool denied by policy".into(),
        };
        let got = poll_until_decision(&engine, &ctx, &bash, &want, std::time::Duration::from_secs(10));
        assert_eq!(
            got, want,
            "modifying the org doc on disk must hot-reload the cascade and deny bash"
        );
    }

    /// Adding a brand-new scoped `*.yaml` to the policy directory must register
    /// in the cascade on the running engine. Starting from a Global allow-all
    /// with no org doc, dropping in an org-alpha `bash` deny flips an org-alpha
    /// agent's `bash` call from Allow to Deny.
    #[test]
    fn cascade_hot_reload_add_scoped_file_re_evaluates() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-add-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();

        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("cascade loads");

        let ctx = make_ctx_in_org(0xcc, "org-alpha");
        let bash = tool_call("bash", "");

        // Baseline: only Global allow-all loaded → bash allowed.
        assert_eq!(
            engine.evaluate(&ctx, &bash).decision,
            PolicyResult::Allow,
            "org-alpha bash must start allowed with no org doc present"
        );

        // Add a new org-scoped deny document to the directory.
        std::fs::write(
            tmp.path().join("100-org-alpha-deny-bash.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-add-org-alpha\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        let want = PolicyResult::Deny {
            reason: "tool denied by policy".into(),
        };
        let got = poll_until_decision(&engine, &ctx, &bash, &want, std::time::Duration::from_secs(10));
        assert_eq!(
            got, want,
            "adding a new org-scoped deny doc must hot-reload the cascade and deny bash"
        );
    }

    /// A read/parse failure during a hot-reload must preserve the current
    /// cascade — a broken mid-edit file must never degrade the running gateway
    /// to allow-all. Writing invalid YAML over the org-alpha *deny* doc must
    /// leave bash denied, not silently re-allowed.
    #[test]
    fn cascade_hot_reload_invalid_yaml_preserves_cascade() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-inv-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        let org_doc = tmp.path().join("100-org-alpha-deny-bash.yaml");
        std::fs::write(
            &org_doc,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: hr-inv-org\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("cascade loads");

        let ctx = make_ctx_in_org(0xdd, "org-alpha");
        let bash = tool_call("bash", "");
        let deny = PolicyResult::Deny {
            reason: "tool denied by policy".into(),
        };
        assert_eq!(
            engine.evaluate(&ctx, &bash).decision,
            deny,
            "org-alpha bash starts denied"
        );

        // Corrupt the org doc. The reload must fail-safe and keep the deny.
        std::fs::write(&org_doc, "this: is: not: valid: yaml: [[[").unwrap();

        // Give the watcher ample time to observe + reject the bad edit, then
        // assert the deny is still in force (the cascade was preserved).
        std::thread::sleep(std::time::Duration::from_millis(500));
        assert_eq!(
            engine.evaluate(&ctx, &bash).decision,
            deny,
            "an invalid mid-edit file must not degrade the cascade to allow-all"
        );
    }

    /// A directory re-read must fail-CLOSED on an *empty* (whitespace-only)
    /// `*.yaml`. On Linux (inotify), a truncate+write overwrite emits a Modify
    /// event for the 0-byte file before the new content lands; an empty YAML
    /// otherwise parses as a valid Global-scoped allow-all document. Without a
    /// guard, `rebuild_cascade_state` would return `Ok` with a degraded cascade
    /// and the watcher would silently drop a deny doc — a fail-OPEN. This
    /// drives the rebuild directly so the assertion is deterministic (no
    /// filesystem-watcher timing). (AAASM-3561)
    #[test]
    fn rebuild_cascade_state_fails_closed_on_empty_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: empty-global\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        let org_doc = tmp.path().join("100-org-alpha-deny-bash.yaml");
        std::fs::write(
            &org_doc,
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: empty-org\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:org-alpha\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();

        // Healthy directory rebuilds cleanly.
        assert!(
            PolicyEngine::rebuild_cascade_state(tmp.path()).is_ok(),
            "a well-formed cascade must rebuild"
        );

        // Mid-truncation: the deny doc is observed at 0 bytes. The rebuild must
        // reject it rather than silently producing an allow-all cascade.
        std::fs::write(&org_doc, "").unwrap();
        assert!(
            PolicyEngine::rebuild_cascade_state(tmp.path()).is_err(),
            "an empty mid-edit document must fail closed, not degrade the cascade to allow-all"
        );

        // Whitespace-only content is treated identically.
        std::fs::write(&org_doc, "   \n\t\n").unwrap();
        assert!(
            PolicyEngine::rebuild_cascade_state(tmp.path()).is_err(),
            "a whitespace-only mid-edit document must fail closed"
        );
    }

    // ── approval_escalation_overrides tests ───────────────────────────────────

    #[test]
    fn approval_escalation_overrides_returns_none_when_no_approval_policy() {
        let engine = make_engine(empty_doc());
        assert_eq!(engine.approval_escalation_overrides(), (None, None));
    }

    #[test]
    fn approval_escalation_overrides_returns_values_when_approval_policy_set() {
        use crate::policy::document::ApprovalPolicy;
        let mut doc = empty_doc();
        doc.approval_policy = Some(ApprovalPolicy {
            timeout_seconds: Some(120),
            escalation_role: Some("org-admin".to_string()),
        });
        let engine = make_engine(doc);
        let (timeout, role) = engine.approval_escalation_overrides();
        assert_eq!(timeout, Some(120u64));
        assert_eq!(role, Some("org-admin".to_string()));
    }

    // ── observe-mode transform (AAASM-1556) ──────────────────────────────────

    fn allow_result() -> EvaluationResult {
        EvaluationResult {
            decision: PolicyResult::Allow,
            redacted_payload: None,
            credential_findings: vec![],
            canonical_findings: vec![],
            deny_action: None,
            policy_doc_id: None,
            narrowed: false,
        }
    }

    #[test]
    fn observe_mode_passes_allow_through_with_no_shadow_event() {
        // An Allow decision is already a no-op for enforcement — observe mode
        // must NOT fabricate a shadow event for it (otherwise audit log
        // sandbox-event volume would be 1:1 with all traffic, not 1:1 with
        // would-be violations).
        let (out, shadow) = transform_for_observe_mode(allow_result(), aa_core::EnforcementMode::Observe);
        assert_eq!(out.decision, PolicyResult::Allow);
        assert!(shadow.is_none(), "no shadow event for Allow decisions");
    }

    fn deny_result(reason: &str) -> EvaluationResult {
        EvaluationResult {
            decision: PolicyResult::Deny {
                reason: reason.to_string(),
            },
            redacted_payload: None,
            credential_findings: vec![],
            canonical_findings: vec![],
            deny_action: Some(DenyAction::Block),
            policy_doc_id: None,
            narrowed: false,
        }
    }

    #[test]
    fn enforce_mode_leaves_deny_unchanged_and_emits_no_shadow_event() {
        // Backward-compat guard: pre-feature behaviour for every existing
        // caller must be 100% preserved when enforcement_mode = Enforce.
        let original = deny_result("tool denied by policy");
        let (out, shadow) = transform_for_observe_mode(original, aa_core::EnforcementMode::Enforce);
        match out.decision {
            PolicyResult::Deny { reason } => assert_eq!(reason, "tool denied by policy"),
            other => panic!("Enforce mode must preserve Deny; got {other:?}"),
        }
        assert_eq!(out.deny_action, Some(DenyAction::Block));
        assert!(shadow.is_none(), "Enforce mode produces no shadow events");
    }

    #[test]
    fn observe_mode_converts_requires_approval_to_allow_with_pending_shadow() {
        // A RequiresApproval decision in Observe mode must NOT halt execution
        // — the agent proceeds, and shadow_decision = "pending" is recorded.
        let pending = EvaluationResult {
            decision: PolicyResult::RequiresApproval { timeout_secs: 600 },
            redacted_payload: None,
            credential_findings: vec![],
            canonical_findings: vec![],
            deny_action: None,
            policy_doc_id: None,
            narrowed: false,
        };
        let (out, shadow) = transform_for_observe_mode(pending, aa_core::EnforcementMode::Observe);
        assert_eq!(out.decision, PolicyResult::Allow);
        let shadow = shadow.expect("shadow event for RequiresApproval in Observe mode");
        assert_eq!(shadow.shadow_decision, "pending");
    }

    #[test]
    fn observe_mode_converts_deny_to_allow_and_emits_shadow_event() {
        // The core observe-mode contract: a Deny decision is rewritten to
        // Allow, the deny_action side-effect is dropped, and a ShadowEvent
        // with shadow_decision = "deny" is produced for the audit sink.
        let original = deny_result("tool denied by policy");
        let (out, shadow) = transform_for_observe_mode(original, aa_core::EnforcementMode::Observe);
        assert_eq!(out.decision, PolicyResult::Allow);
        assert!(out.deny_action.is_none(), "deny side-effect must be dropped");
        let shadow = shadow.expect("shadow event for Deny in Observe mode");
        assert_eq!(shadow.shadow_decision, "deny");
        assert_eq!(shadow.reason, "tool denied by policy");
    }

    // ── enforcement-mode resolution (AAASM-1557) ─────────────────────────────

    #[test]
    fn resolve_isolates_two_agents_under_the_same_policy() {
        // AAASM-1557 AC: two agents share a policy, one registers in Observe,
        // the other inherits the policy default (Enforce) — each must resolve
        // to its own mode independently. Regression guard for any future
        // refactor that accidentally shares state across resolve() calls.
        let policy = aa_core::EnforcementMode::Enforce; // trusted-team policy
        let trusted_agent = resolve_enforcement_mode(None, policy);
        let experimental_agent = resolve_enforcement_mode(Some(aa_core::EnforcementMode::Observe), policy);
        assert_eq!(trusted_agent, aa_core::EnforcementMode::Enforce);
        assert_eq!(experimental_agent, aa_core::EnforcementMode::Observe);
    }

    #[test]
    fn resolve_prefers_agent_override_over_policy_default() {
        // Per-agent override is the whole point of this subtask — it must
        // win over the policy-level default. Covers all four override values
        // crossed with each policy default, so a regression that swaps the
        // priority would be caught by at least one assertion.
        for agent in [
            aa_core::EnforcementMode::Enforce,
            aa_core::EnforcementMode::Observe,
            aa_core::EnforcementMode::Disabled,
        ] {
            for policy in [
                aa_core::EnforcementMode::Enforce,
                aa_core::EnforcementMode::Observe,
                aa_core::EnforcementMode::Disabled,
            ] {
                assert_eq!(resolve_enforcement_mode(Some(agent), policy), agent);
            }
        }
    }

    #[test]
    fn resolve_falls_back_to_policy_default_when_agent_override_is_none() {
        // An agent that registered without setting enforcement_mode inherits
        // the policy document's posture. Most production agents take this path.
        let resolved = resolve_enforcement_mode(None, aa_core::EnforcementMode::Observe);
        assert_eq!(resolved, aa_core::EnforcementMode::Observe);

        let resolved = resolve_enforcement_mode(None, aa_core::EnforcementMode::Enforce);
        assert_eq!(resolved, aa_core::EnforcementMode::Enforce);
    }

    // ── AAASM-3138: budget tenancy keyed by registered owner ────────────────

    /// Build a minimal registry record for `agent_id` owned by `team`.
    fn registry_record(agent_id: [u8; 16], team: &str, org: Option<&str>) -> crate::registry::store::AgentRecord {
        crate::registry::store::AgentRecord {
            agent_id,
            name: "demo".to_string(),
            framework: "test".to_string(),
            version: "0".to_string(),
            risk_tier: 0,
            tool_names: Vec::new(),
            public_key: String::new(),
            credential_token: String::new(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: crate::registry::AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            active_sessions: Vec::new(),
            recent_events: std::collections::VecDeque::new(),
            recent_traces: Vec::new(),
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: Some(team.to_string()),
            org_id: org.map(str::to_string),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(agent_id),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
            enforcement_mode_expires_at: None,
        }
    }

    #[test]
    fn record_spend_keys_budget_by_registered_team_not_client_supplied() {
        // AAASM-3138: a client must not be able to bill spend against a tenant
        // it does not own by forging team_id in the request context. The budget
        // must key on the agent's *registered* owner.
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        registry
            .register(registry_record([1u8; 16], "owner-team", Some("owner-org")))
            .expect("register");

        let engine = make_engine(empty_doc()).with_registry(registry);

        // ctx carries a forged team_id / org_id that the agent does NOT own.
        let mut ctx = make_ctx(); // agent_id = [1u8; 16]
        ctx.team_id = Some("victim-team".to_string());
        ctx.metadata.insert("org_id".to_string(), "victim-org".to_string());

        engine.record_spend(&ctx, 7.0);

        // Spend landed under the registered owner, not the forged tenant.
        assert!(
            engine.budget.team_state("owner-team").is_some(),
            "spend must be attributed to the registered team"
        );
        assert!(
            engine.budget.team_state("victim-team").is_none(),
            "spend must NOT be attributed to the client-forged team"
        );
    }

    #[test]
    fn record_spend_falls_back_to_ctx_when_agent_unregistered() {
        // With no registry attached, the legacy ctx-supplied tenancy is used —
        // preserving behaviour for untenanted / pre-registry deployments.
        let engine = make_engine(empty_doc());
        let mut ctx = make_ctx();
        ctx.team_id = Some("ctx-team".to_string());

        engine.record_spend(&ctx, 3.0);

        assert!(engine.budget.team_state("ctx-team").is_some());
    }

    // ── AAASM-3729: cascade selected by registered owner, not client claim ───

    /// Build a cascade engine: a Global allow-all baseline plus an
    /// `org:owner-org`-scoped deny of `bash`.
    ///
    /// Returns the owning [`tempfile::TempDir`] alongside the engine: the
    /// directory MUST outlive the engine. `load_cascade_from_dir_with_budget`
    /// starts a live filesystem watcher on the directory, and dropping the
    /// `TempDir` deletes those `*.yaml` files. If the guard were dropped at the
    /// helper boundary, the watcher would race to re-read the now-empty
    /// directory and atomically swap in an empty (allow-all) cascade — making
    /// `evaluate` nondeterministically see Allow instead of the org-scoped Deny
    /// under CI parallelism (AAASM-3729 follow-up).
    fn cascade_engine_owner_org_denies_bash() -> (PolicyEngine, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global-allow-all.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: t-global-allow\n  version: \"0.1.0\"\n\
             spec:\n  tools: {}\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("100-org-owner-deny-bash.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: t-owner-deny-bash\n  version: \"0.1.0\"\n\
             spec:\n  scope: org:owner-org\n  tools:\n    bash:\n      allow: false\n",
        )
        .unwrap();
        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget).expect("cascade loads");
        (engine, tmp)
    }

    #[test]
    fn cascade_uses_registered_org_not_client_forged_org() {
        // AAASM-3729: an agent registered in `owner-org` (which denies `bash`)
        // must not escape that policy by forging a different, more permissive
        // org_id in the request context. The cascade must select the registered
        // owner's org-scoped deny.
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        registry
            .register(registry_record([0xaa; 16], "owner-team", Some("owner-org")))
            .expect("register");
        // `_tmp` keeps the cascade directory alive for the whole test so the
        // live watcher never re-reads a deleted dir mid-evaluate (AAASM-3729).
        let (engine, _tmp) = cascade_engine_owner_org_denies_bash();
        let engine = engine.with_registry(registry);

        // ctx carries a forged org_id pointing at an org with no deny rules.
        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([0xaa; 16]);
        ctx.metadata.insert("org_id".to_string(), "permissive-org".to_string());

        assert_eq!(
            engine.evaluate(&ctx, &tool_call("bash", "")).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            },
            "registered owner-org deny must apply despite the client-forged org_id"
        );
    }

    #[test]
    fn cascade_falls_back_to_ctx_org_when_agent_unregistered() {
        // With no registry record for the agent, the ctx-supplied lineage is
        // used (untenanted / convert.rs path). An agent claiming owner-org sees
        // that org's deny; this preserves the pre-registry behaviour.
        // `_tmp` keeps the cascade directory alive for the whole test so the
        // live watcher never re-reads a deleted dir mid-evaluate (AAASM-3729).
        let (engine, _tmp) = cascade_engine_owner_org_denies_bash();
        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([0xcc; 16]);
        ctx.metadata.insert("org_id".to_string(), "owner-org".to_string());

        assert_eq!(
            engine.evaluate(&ctx, &tool_call("bash", "")).decision,
            PolicyResult::Deny {
                reason: "tool denied by policy".into()
            },
            "unregistered agent falls back to ctx-supplied org lineage"
        );
    }

    #[test]
    fn cascade_context_dependent_approval_is_not_frozen_by_decision_cache() {
        // AAASM-3995(c): a `requires_approval_if` referencing live context
        // (team.active_agents) must be re-evaluated as that context changes —
        // not served stale from the decision cache, which keys only on
        // (agent, epoch, action).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("000-global.yaml"),
            "apiVersion: agent-assembly.dev/v1alpha1\n\
             kind: GovernancePolicy\n\
             metadata:\n  name: t-approval\n  version: \"0.1.0\"\n\
             spec:\n  tools:\n    spawn:\n      allow: true\n      requires_approval_if: \"team.active_agents > 1\"\n",
        )
        .unwrap();
        let budget = Arc::new(BudgetTracker::new(
            crate::budget::PricingTable::default_table(),
            None,
            None,
            chrono_tz::UTC,
        ));
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        registry
            .register(registry_record([0x01; 16], "t", Some("o")))
            .expect("register first member");
        let engine = PolicyEngine::load_cascade_from_dir_with_budget(tmp.path(), budget)
            .expect("cascade loads")
            .with_registry(Arc::clone(&registry));

        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([0x01; 16]);
        ctx.team_id = Some("t".to_string());
        let action = tool_call("spawn", "");

        // One team member: `1 > 1` is false → Allow (evaluated fresh).
        assert_eq!(
            engine.evaluate(&ctx, &action).decision,
            PolicyResult::Allow,
            "one team member is under the approval threshold"
        );

        // A second team member joins; live context now crosses the threshold.
        registry
            .register(registry_record([0x02; 16], "t", Some("o")))
            .expect("register second member");

        // Two members: `2 > 1` is true → RequiresApproval. A cache that froze the
        // earlier Allow (same agent/epoch/action) would wrongly still allow.
        assert!(
            matches!(
                engine.evaluate(&ctx, &action).decision,
                PolicyResult::RequiresApproval { .. }
            ),
            "context-dependent approval must reflect the updated team size, not a stale cached Allow"
        );

        drop(tmp);
    }

    // ── AAASM-4190: rate-limit scope for anonymous callers ────────────────────

    #[test]
    fn rate_scope_unregistered_agents_share_anon_bucket() {
        // AAASM-4190: unregistered/anonymous agents must share a single "anon"
        // bucket. Rotating the client-supplied agent_id must NOT mint a fresh
        // bucket (that would bypass the rate limit).
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        let engine = make_engine(empty_doc()).with_registry(registry);

        // Two different agent_ids that are NOT in the registry.
        let mut ctx_a = make_ctx();
        ctx_a.agent_id = AgentId::from_bytes([0xAA; 16]);
        ctx_a.team_id = None;

        let mut ctx_b = make_ctx();
        ctx_b.agent_id = AgentId::from_bytes([0xBB; 16]);
        ctx_b.team_id = None;

        // Both should resolve to the same "anon" scope.
        let scope_a = engine.rate_scope(&ctx_a);
        let scope_b = engine.rate_scope(&ctx_b);

        assert_eq!(scope_a, "anon", "unregistered agent should use 'anon' scope");
        assert_eq!(scope_b, "anon", "unregistered agent should use 'anon' scope");
        assert_eq!(scope_a, scope_b, "rotating agent_id must not change the scope");
    }

    #[test]
    fn rate_scope_registered_teamless_agent_gets_isolated_bucket() {
        // AAASM-4190: a registered but teamless agent uses its authenticated
        // agent_id for isolation — distinct from the shared "anon" bucket.
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        // Register agent without a team.
        let mut record = registry_record([0xCC; 16], "placeholder", None);
        record.team_id = None; // explicitly teamless
        registry.register(record).expect("register");

        let engine = make_engine(empty_doc()).with_registry(registry);

        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([0xCC; 16]);
        ctx.team_id = None;

        let scope = engine.rate_scope(&ctx);
        // Hex-encoded agent_id for [0xCC; 16] = "cccccccc..." (32 chars).
        assert!(
            scope.starts_with("agent:"),
            "registered teamless agent should use 'agent:<hex>' scope, got: {scope}"
        );
        assert_ne!(scope, "anon", "registered agent must not share the anon bucket");
    }

    #[test]
    fn rate_scope_registered_with_team_uses_team_scope() {
        // Sanity check: registered agent with a team uses team scope.
        let registry = Arc::new(crate::registry::AgentRegistry::new());
        registry
            .register(registry_record([0xDD; 16], "my-team", None))
            .expect("register");

        let engine = make_engine(empty_doc()).with_registry(registry);

        let mut ctx = make_ctx();
        ctx.agent_id = AgentId::from_bytes([0xDD; 16]);
        // Note: ctx.team_id is client-supplied and should be ignored.
        ctx.team_id = Some("forged-team".to_string());

        let scope = engine.rate_scope(&ctx);
        assert_eq!(scope, "team:my-team", "should use registered team, not client-supplied");
    }
}
