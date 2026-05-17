//! Policy engine implementation.
//!
//! Core rate limiting and enforcement mechanisms for the Agent Assembly policy engine.

pub mod cache;
pub mod decision;
pub(crate) mod rate_limit;
pub mod scope_index;
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

use crate::engine::decision::{merge_decisions, PolicyDecision};
use crate::engine::scope_index::ScopeIndex;
use crate::policy::document::ActionOnExceed;
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
    pub credential_findings: Vec<aa_core::CredentialFinding>,
    /// Optional side-effect action for the service layer when the decision is `Deny`.
    /// `None` means no side-effect beyond denying the request.
    pub deny_action: Option<DenyAction>,
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
    /// Built once at construction time from [`aa_core::CredentialScanner`].
    /// Always active — scans every action payload regardless of policy data section.
    scanner: aa_core::CredentialScanner,
    /// Pre-compiled regex patterns from the policy's `data.sensitive_patterns`.
    ///
    /// Compiled once at load time to avoid re-compiling on every `evaluate()` call.
    // TODO: recompile on hot-reload — currently these patterns reflect the policy at engine
    // construction time and will not update when the watcher swaps in a new policy document.
    compiled_patterns: Vec<regex::Regex>,
    rate_state: DashMap<String, Mutex<crate::engine::rate_limit::TokenBucket>>,
    budget: Arc<BudgetTracker>,
    /// Scope-keyed index of additionally-loaded policies (AAASM-951).
    ///
    /// Populated via [`PolicyEngine::load_policy`]. The single primary
    /// policy held in `policy` (above) is unaffected — F93 (AAASM-220)
    /// will migrate the evaluator to consult this index for cascading
    /// most-restrictive-wins resolution.
    scope_index: ScopeIndex,
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
        let budget_tz = output
            .document
            .budget
            .as_ref()
            .and_then(|bp| bp.timezone.as_deref())
            .and_then(|s| s.parse::<chrono_tz::Tz>().ok())
            .unwrap_or(chrono_tz::UTC);
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
        let budget = Arc::new(BudgetTracker::new_with_alert_sender(
            crate::budget::PricingTable::default_table(),
            daily_limit,
            monthly_limit,
            budget_tz,
            budget_alert_tx,
        ));
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(output.document)));
        let watcher = crate::engine::watcher::start_watcher(path, policy_arc.clone()).ok();
        Ok(PolicyEngine {
            policy: policy_arc,
            scanner: aa_core::CredentialScanner::new(),
            compiled_patterns,
            rate_state: DashMap::new(),
            budget,
            scope_index: ScopeIndex::new(),
            _watcher: watcher,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
            decision_cache: DecisionCache::new(100_000),
        })
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
            scanner: aa_core::CredentialScanner::new(),
            compiled_patterns,
            rate_state: DashMap::new(),
            budget,
            scope_index: ScopeIndex::new(),
            _watcher: watcher,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
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
        };
        let policy_arc = Arc::new(ArcSwap::new(Arc::new(doc)));
        PolicyEngine {
            policy: policy_arc,
            scanner: aa_core::CredentialScanner::new(),
            compiled_patterns: vec![],
            rate_state: DashMap::new(),
            budget,
            scope_index: ScopeIndex::new(),
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
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
        self.policy_epoch.fetch_add(1, Ordering::Relaxed);

        Ok(meta)
    }

    /// Evaluate a governance action through the 7-step pipeline.
    ///
    /// When scoped policies are loaded in the `scope_index`, delegates to the
    /// cascade path (`evaluate_with_cascade`). Falls back to the original
    /// single-policy pipeline (`evaluate_primary`) when no scoped policies are
    /// present, preserving full backward compatibility.
    pub fn evaluate(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> EvaluationResult {
        let cascade = self.collect_cascade(&ctx.agent_id);

        // Backward-compat: no scoped policies loaded → use primary policy only.
        if cascade.is_empty() {
            return self.evaluate_primary(ctx, action);
        }

        self.evaluate_with_cascade(cascade, ctx, action)
    }

    /// Single-policy evaluation path: used when no scoped policies are registered.
    ///
    /// This is the original 7-stage pipeline from before AAASM-220. When the
    /// `scope_index` is empty, `evaluate` delegates here for full backward compat.
    fn evaluate_primary(&self, ctx: &aa_core::AgentContext, action: &aa_core::GovernanceAction) -> EvaluationResult {
        let policy = self.policy.load();

        // Stage 1 — Schedule: check active hours window.
        if let Some(schedule) = &policy.schedule {
            if let Some(ah) = &schedule.active_hours {
                use chrono::Timelike;
                let tz: chrono_tz::Tz = ah.timezone.parse().unwrap_or(chrono_tz::UTC);
                let now = chrono::Utc::now().with_timezone(&tz);
                let current_hhmm = format!("{:02}:{:02}", now.hour(), now.minute());
                if current_hhmm < ah.start || current_hhmm >= ah.end {
                    return EvaluationResult {
                        decision: aa_core::PolicyResult::Deny {
                            reason: "outside active hours".into(),
                        },
                        redacted_payload: None,
                        credential_findings: vec![],
                        deny_action: None,
                    };
                }
            }
        }

        // Stage 2 — Network allowlist: only for NetworkRequest actions.
        if let aa_core::GovernanceAction::NetworkRequest { url, .. } = action {
            if let Some(np) = &policy.network {
                if !np.allowlist.is_empty() {
                    let host = url
                        .split_once("://")
                        .map(|x| x.1)
                        .unwrap_or("")
                        .split('/')
                        .next()
                        .unwrap_or("");
                    if !np.allowlist.iter().any(|entry| entry == host) {
                        return EvaluationResult {
                            decision: aa_core::PolicyResult::Deny {
                                reason: "host not in network allowlist".into(),
                            },
                            redacted_payload: None,
                            credential_findings: vec![],
                            deny_action: None,
                        };
                    }
                }
            }
        }

        // Stage 3 — Tool allow/deny.
        if let aa_core::GovernanceAction::ToolCall { name, .. } = action {
            if let Some(tp) = policy.tools.get(name) {
                if !tp.allow {
                    return EvaluationResult {
                        decision: aa_core::PolicyResult::Deny {
                            reason: "tool denied by policy".into(),
                        },
                        redacted_payload: None,
                        credential_findings: vec![],
                        deny_action: None,
                    };
                }
            }
        }

        // Stage 4 — Tool rate limit.
        if let aa_core::GovernanceAction::ToolCall { name, .. } = action {
            if let Some(tp) = policy.tools.get(name) {
                if let Some(limit) = tp.limit_per_hour {
                    let entry = self
                        .rate_state
                        .entry(name.clone())
                        .or_insert_with(|| Mutex::new(rate_limit::TokenBucket::new(limit)));
                    let mut bucket = entry.lock().unwrap_or_else(|e| e.into_inner());
                    if !bucket.try_consume() {
                        return EvaluationResult {
                            decision: aa_core::PolicyResult::Deny {
                                reason: "rate limit exceeded".into(),
                            },
                            redacted_payload: None,
                            credential_findings: vec![],
                            deny_action: None,
                        };
                    }
                }
            }
        }

        // Stage 5 — Approval condition.
        if let aa_core::GovernanceAction::ToolCall { name, .. } = action {
            if let Some(tp) = policy.tools.get(name) {
                if let Some(expr) = &tp.requires_approval_if {
                    if !expr.is_empty() {
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
                        let pctx_dyn: Option<&dyn crate::policy::context::PolicyContext> =
                            pctx.as_ref().map(|c| c as _);
                        if crate::policy::expr::evaluate(expr, action, Some(ctx.governance_level), pctx_dyn) {
                            return EvaluationResult {
                                decision: aa_core::PolicyResult::RequiresApproval {
                                    timeout_secs: policy.approval_timeout_secs,
                                },
                                redacted_payload: None,
                                credential_findings: vec![],
                                deny_action: None,
                            };
                        }
                    }
                }
            }
        }

        // Stage 5b — Approval condition for SendMessage (channel policy).
        if let aa_core::GovernanceAction::SendMessage { .. } = action {
            if let Some(tp) = policy.tools.get("message") {
                if let Some(expr) = &tp.requires_approval_if {
                    if !expr.is_empty() {
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
                        let pctx_dyn: Option<&dyn crate::policy::context::PolicyContext> =
                            pctx.as_ref().map(|c| c as _);
                        if crate::policy::expr::evaluate(expr, action, Some(ctx.governance_level), pctx_dyn) {
                            return EvaluationResult {
                                decision: aa_core::PolicyResult::RequiresApproval {
                                    timeout_secs: policy.approval_timeout_secs,
                                },
                                redacted_payload: None,
                                credential_findings: vec![],
                                deny_action: None,
                            };
                        }
                    }
                }
            }
        }

        // Stage 6 — Credential scan + custom pattern scan: redact in-memory, never deny.
        //
        // Pass 1: Aho-Corasick built-in scan (18+ patterns via aa-core::CredentialScanner).
        // Pass 2: Policy-defined regex patterns from data.sensitive_patterns.
        // Both passes contribute to the same findings list. The merged ScanResult is used
        // to redact the payload once; the redacted text propagates — the original is dropped.
        let text = match action {
            aa_core::GovernanceAction::ToolCall { args, .. } => args.as_str(),
            aa_core::GovernanceAction::FileAccess { path, .. } => path.as_str(),
            aa_core::GovernanceAction::NetworkRequest { url, .. } => url.as_str(),
            aa_core::GovernanceAction::ProcessExec { command } => command.as_str(),
            aa_core::GovernanceAction::SendMessage { .. } => "",
        };

        let scan = self.scanner.scan(text);
        let mut all_findings = scan.findings;

        // Pass 2: policy-defined regex patterns.
        for re in &self.compiled_patterns {
            for m in re.find_iter(text) {
                all_findings.push(aa_core::CredentialFinding::from_regex_match(m.start(), m.end()));
            }
        }

        let (redacted_payload, credential_findings) = if all_findings.is_empty() {
            (None, vec![])
        } else {
            // Sort by offset for deterministic redaction order.
            all_findings.sort_by_key(|f| f.offset);
            let merged = aa_core::ScanResult {
                findings: all_findings.clone(),
            };
            let redacted = merged.redact(text);
            // TODO(AAASM-31): wrap in EnrichedEvent::DataLeak(DataLeakEvent { ... }) and
            // send on the broadcast_tx once AAASM-31 adds the DataLeak variant to EnrichedEvent.
            // DataLeakEvent fields are available here:
            //   agent_id:         ctx.agent_id
            //   session_id:       ctx.session_id
            //   timestamp_ns:     <now>
            //   finding_count:    all_findings.len()
            //   credential_kinds: all_findings.iter().map(|f| f.kind.as_str())
            //   policy_name:      policy.version.as_deref().unwrap_or("unknown")
            tracing::warn!(
                finding_count = all_findings.len(),
                "DataLeakEvent emission pending AAASM-31 EnrichedEvent::DataLeak variant"
            );
            (Some(redacted), all_findings)
        };

        // Stage 7 — Budget check (monthly first, then daily).
        if let Some(bp) = &policy.budget {
            let deny_action = match bp.action_on_exceed {
                ActionOnExceed::Suspend => Some(DenyAction::SuspendAgent),
                ActionOnExceed::Deny => None,
            };
            if let Some(limit) = bp.monthly_limit_usd {
                if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                    if self.budget.check_monthly(&ctx.agent_id, limit_dec) {
                        return EvaluationResult {
                            decision: aa_core::PolicyResult::Deny {
                                reason: "monthly budget exceeded".into(),
                            },
                            redacted_payload,
                            credential_findings,
                            deny_action,
                        };
                    }
                }
            }
            if let Some(limit) = bp.daily_limit_usd {
                if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                    if self.budget.check_daily(&ctx.agent_id, limit_dec) {
                        return EvaluationResult {
                            decision: aa_core::PolicyResult::Deny {
                                reason: "daily budget exceeded".into(),
                            },
                            redacted_payload,
                            credential_findings,
                            deny_action,
                        };
                    }
                }
            }
        }

        EvaluationResult {
            decision: aa_core::PolicyResult::Allow,
            redacted_payload,
            credential_findings,
            deny_action: None,
        }
    }

    /// Cascade evaluation path: runs `merge_decisions` across all scoped policies,
    /// then applies rate-limit (stage 4), budget (stage 7), and credential scan
    /// (stage 6) at the engine level.
    fn evaluate_with_cascade(
        &self,
        cascade: Vec<Arc<PolicyDocument>>,
        ctx: &aa_core::AgentContext,
        action: &aa_core::GovernanceAction,
    ) -> EvaluationResult {
        // Cache lookup: stateless stages only (1–3, 5). Stateful stages (4, 7),
        // the capability guard, and the credential scan always run.
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

        let verdict = if let Some(cached) = self.decision_cache.get(&cache_key) {
            cached
        } else {
            // Stages 1–3 and 5: stateless per-doc rules merged across cascade.
            let v = merge_decisions(&cascade, ctx, action, pctx_dyn);
            self.decision_cache.insert(cache_key, v.clone());
            v
        };

        // If already denied, return immediately — no need for scan or budget check.
        if let PolicyDecision::Deny { reason, .. } = verdict {
            return EvaluationResult {
                decision: aa_core::PolicyResult::Deny { reason },
                redacted_payload: None,
                credential_findings: vec![],
                deny_action: None,
            };
        }

        // Cascade capability guard: checks the allow-list intersection case where no single
        // doc denies the capability but the merged allow-list (after merge_capabilities)
        // does not contain it. Per-doc stage 3.5 handles intra-doc denials; this guard
        // handles cross-doc scenarios. The merged set is also used for dev-tool wiring
        // (AAASM-1046).
        let merged_caps = Self::collect_merged_capabilities(&cascade);
        if let Some(cap) = aa_core::action_to_capability(action) {
            if merged_caps.deny.contains(&cap) {
                return EvaluationResult {
                    decision: aa_core::PolicyResult::Deny {
                        reason: "capability denied by policy".into(),
                    },
                    redacted_payload: None,
                    credential_findings: vec![],
                    deny_action: None,
                };
            }
            if !merged_caps.allow.is_empty() && !merged_caps.allow.contains(&cap) {
                return EvaluationResult {
                    decision: aa_core::PolicyResult::Deny {
                        reason: "capability not in allow list".into(),
                    },
                    redacted_payload: None,
                    credential_findings: vec![],
                    deny_action: None,
                };
            }
        }

        // Stage 4 — Rate limiting: use the most restrictive (minimum) limit_per_hour
        // found across all cascade policies for the requested tool.
        if let aa_core::GovernanceAction::ToolCall { name, .. } = action {
            let min_limit = cascade
                .iter()
                .filter_map(|doc| doc.tools.get(name))
                .filter_map(|tp| tp.limit_per_hour)
                .min();

            if let Some(limit) = min_limit {
                let entry = self
                    .rate_state
                    .entry(name.clone())
                    .or_insert_with(|| Mutex::new(rate_limit::TokenBucket::new(limit)));
                let mut bucket = entry.lock().unwrap_or_else(|e| e.into_inner());
                if !bucket.try_consume() {
                    return EvaluationResult {
                        decision: aa_core::PolicyResult::Deny {
                            reason: "rate limit exceeded".into(),
                        },
                        redacted_payload: None,
                        credential_findings: vec![],
                        deny_action: None,
                    };
                }
            }
        }

        // Stage 6 — Credential scan: accumulate custom patterns from all cascade docs.
        let text = match action {
            aa_core::GovernanceAction::ToolCall { args, .. } => args.as_str(),
            aa_core::GovernanceAction::FileAccess { path, .. } => path.as_str(),
            aa_core::GovernanceAction::NetworkRequest { url, .. } => url.as_str(),
            aa_core::GovernanceAction::ProcessExec { command } => command.as_str(),
            aa_core::GovernanceAction::SendMessage { .. } => "",
        };
        let scan = self.scanner.scan(text);
        let mut all_findings = scan.findings;
        for doc in &cascade {
            if let Some(dp) = &doc.data {
                for pattern in &dp.sensitive_patterns {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        for m in re.find_iter(text) {
                            all_findings.push(aa_core::CredentialFinding::from_regex_match(m.start(), m.end()));
                        }
                    }
                }
            }
        }
        let (redacted_payload, credential_findings) = if all_findings.is_empty() {
            (None, vec![])
        } else {
            all_findings.sort_by_key(|f| f.offset);
            let merged = aa_core::ScanResult {
                findings: all_findings.clone(),
            };
            let redacted = merged.redact(text);
            tracing::warn!(
                finding_count = all_findings.len(),
                "DataLeakEvent emission pending AAASM-31 EnrichedEvent::DataLeak variant"
            );
            (Some(redacted), all_findings)
        };

        // Stage 7 — Budget: check against all cascade docs' budget configs.
        // Take the most restrictive (lowest) limit across all policies.
        let mut deny_action = None;
        for doc in &cascade {
            if let Some(bp) = &doc.budget {
                let da = match bp.action_on_exceed {
                    ActionOnExceed::Suspend => Some(DenyAction::SuspendAgent),
                    ActionOnExceed::Deny => None,
                };
                if let Some(limit) = bp.monthly_limit_usd {
                    if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                        if self.budget.check_monthly(&ctx.agent_id, limit_dec) {
                            return EvaluationResult {
                                decision: aa_core::PolicyResult::Deny {
                                    reason: "monthly budget exceeded".into(),
                                },
                                redacted_payload,
                                credential_findings,
                                deny_action: da,
                            };
                        }
                    }
                }
                if let Some(limit) = bp.daily_limit_usd {
                    if let Ok(limit_dec) = rust_decimal::Decimal::try_from(limit) {
                        if self.budget.check_daily(&ctx.agent_id, limit_dec) {
                            return EvaluationResult {
                                decision: aa_core::PolicyResult::Deny {
                                    reason: "daily budget exceeded".into(),
                                },
                                redacted_payload,
                                credential_findings,
                                deny_action: da,
                            };
                        }
                    }
                }
                deny_action = da;
            }
        }

        // Convert the merge verdict to PolicyResult.
        EvaluationResult {
            decision: verdict.into_policy_result(),
            redacted_payload,
            credential_findings,
            deny_action,
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
            self.budget
                .record_raw_spend(ctx.agent_id, ctx.team_id.as_deref(), amount);
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
    pub fn load_policy(&mut self, doc: PolicyDocument) -> scope_index::PolicyId {
        self.policy_epoch.fetch_add(1, Ordering::Relaxed);
        self.scope_index.insert(doc)
    }

    /// Drop a previously-registered policy by id, keeping `by_scope`
    /// consistent. Returns the dropped `Arc<PolicyDocument>` if the id
    /// was present, or `None` if it had already been removed.
    pub fn remove_policy(&mut self, id: scope_index::PolicyId) -> Option<Arc<PolicyDocument>> {
        self.scope_index.remove(id)
    }

    /// Return the [`scope_index::PolicyId`]s registered under `scope`,
    /// in load order. Returns an empty slice when no policy has ever
    /// been registered under that scope (or all of them have been
    /// removed).
    pub fn policies_for_scope(&self, scope: &crate::policy::PolicyScope) -> &[scope_index::PolicyId] {
        self.scope_index.policies_for_scope(scope)
    }

    /// Look up a policy previously registered via [`Self::load_policy`]
    /// by its [`scope_index::PolicyId`].
    ///
    /// Returns `None` if the id was never issued, or if the policy
    /// has since been removed via [`Self::remove_policy`]. Cheap —
    /// backed by a `HashMap` lookup with no allocation.
    ///
    /// F93 (AAASM-220) will use this to materialise the cascading
    /// chain of `(scope, doc)` pairs once it consults
    /// [`Self::policies_for_scope`].
    pub fn policy(&self, id: scope_index::PolicyId) -> Option<&Arc<PolicyDocument>> {
        self.scope_index.policy(id)
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
        use crate::policy::scope::PolicyScope;

        let lineage = self
            .registry
            .as_ref()
            .and_then(|r| r.lineage(agent_id.as_bytes()))
            .unwrap_or_default();

        let mut cascade = Vec::new();

        // Global — broadest scope
        for &id in self.scope_index.policies_for_scope(&PolicyScope::Global) {
            if let Some(doc) = self.scope_index.policy(id) {
                cascade.push(Arc::clone(doc));
            }
        }

        // Org — if agent has an org
        if let Some(ref org_id) = lineage.org_id {
            for &id in self.scope_index.policies_for_scope(&PolicyScope::Org(org_id.clone())) {
                if let Some(doc) = self.scope_index.policy(id) {
                    cascade.push(Arc::clone(doc));
                }
            }
        }

        // Team — if agent has a team
        if let Some(ref team_id) = lineage.team_id {
            for &id in self.scope_index.policies_for_scope(&PolicyScope::Team(team_id.clone())) {
                if let Some(doc) = self.scope_index.policy(id) {
                    cascade.push(Arc::clone(doc));
                }
            }
        }

        // Agent — narrowest scope
        for &id in self.scope_index.policies_for_scope(&PolicyScope::Agent(*agent_id)) {
            if let Some(doc) = self.scope_index.policy(id) {
                cascade.push(Arc::clone(doc));
            }
        }

        cascade
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
        ActionOnExceed, ActiveHours, BudgetPolicy, DataPolicy, NetworkPolicy, PolicyDocument, SchedulePolicy,
        ToolPolicy,
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
            scanner: aa_core::CredentialScanner::new(),
            compiled_patterns,
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new(
                crate::budget::PricingTable::default_table(),
                daily_limit,
                monthly_limit,
                chrono_tz::UTC,
            )),
            scope_index: ScopeIndex::new(),
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
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
    fn schedule_allows_full_day_window() {
        let mut doc = empty_doc();
        doc.schedule = Some(SchedulePolicy {
            active_hours: Some(ActiveHours {
                start: "00:00".to_string(),
                end: "23:59".to_string(),
                timezone: "UTC".to_string(),
            }),
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "");
        // 00:00–23:59 covers almost the whole day — should Allow.
        assert_eq!(engine.evaluate(&ctx, &action).decision, PolicyResult::Allow);
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
    fn data_pattern_redacts_on_custom_match() {
        // Stage 6 no longer denies — it redacts in-memory and sets credential_findings.
        let mut doc = empty_doc();
        doc.data = Some(DataPolicy {
            sensitive_patterns: vec![r"password=\w+".to_string()],
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
    fn budget_denies_when_exceeded() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: Some(1.0),
            monthly_limit_usd: None,
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
    fn monthly_budget_denies_when_exceeded() {
        let mut doc = empty_doc();
        doc.budget = Some(BudgetPolicy {
            daily_limit_usd: None,
            monthly_limit_usd: Some(5.0),
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
            timezone: None,
            action_on_exceed: ActionOnExceed::Deny,
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
            timezone: None,
            action_on_exceed: ActionOnExceed::Suspend,
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
            timezone: None,
            action_on_exceed: ActionOnExceed::Suspend,
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
            timezone: None,
            action_on_exceed: ActionOnExceed::Deny,
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
            kinds.contains(&aa_core::CredentialKind::OpenAiKey),
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
        });
        let engine = make_engine(doc);
        let ctx = make_ctx();
        let action = tool_call("any", "config: api_key=supersecret123");
        let result = engine.evaluate(&ctx, &action);
        assert_eq!(result.decision, PolicyResult::Allow);
        let kinds: Vec<_> = result.credential_findings.iter().map(|f| f.kind.clone()).collect();
        assert!(
            kinds.contains(&aa_core::CredentialKind::Custom),
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

        #[cfg(debug_assertions)]
        let budget_ms: u128 = 50; // debug: correctness only, not a perf gate
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
            scanner: aa_core::CredentialScanner::new(),
            compiled_patterns,
            rate_state: DashMap::new(),
            budget: Arc::new(BudgetTracker::new_with_alert_sender(
                crate::budget::PricingTable::default_table(),
                daily_limit,
                monthly_limit,
                chrono_tz::UTC,
                alert_tx,
            )),
            scope_index: ScopeIndex::new(),
            _watcher: None,
            registry: None,
            policy_epoch: Arc::new(AtomicU64::new(0)),
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
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
            timezone: None,
            action_on_exceed: ActionOnExceed::default(),
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
        }
    }

    fn cap_set_cascade(allow: &[aa_core::Capability], deny: &[aa_core::Capability]) -> aa_core::CapabilitySet {
        use std::collections::BTreeSet;
        aa_core::CapabilitySet {
            allow: allow.iter().cloned().collect::<BTreeSet<_>>(),
            deny: deny.iter().cloned().collect::<BTreeSet<_>>(),
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
}
