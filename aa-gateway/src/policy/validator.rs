//! Policy YAML validator: deserializes raw YAML then validates into typed structs.

use std::collections::HashMap;

use crate::policy::{
    document::{
        ActionOnExceed, ActiveHours, ApprovalPolicy, BudgetPolicy, CredentialAction, DataPolicy, NetworkPolicy,
        PolicyDocument, SchedulePolicy, ToolPolicy,
    },
    error::{ValidationError, ValidationWarning},
    raw::{GovernancePolicyEnvelope, RawPolicyDocument},
    scope::PolicyScope,
};

/// Result of a successful parse+validate pass.
#[derive(Debug)]
pub struct PolicyValidatorOutput {
    /// The fully-validated policy document.
    pub document: PolicyDocument,
    /// Non-fatal warnings (unknown keys, etc.).
    pub warnings: Vec<ValidationWarning>,
}

/// Parses and validates a policy YAML document.
pub struct PolicyValidator;

impl PolicyValidator {
    /// Parse `yaml_str`, validate every section, and return a typed
    /// [`PolicyDocument`] together with any [`ValidationWarning`]s.
    ///
    /// Returns `Err` with accumulated [`ValidationError`]s when at least one
    /// hard constraint is violated, or when the YAML cannot be parsed.
    pub fn from_yaml(yaml_str: &str) -> Result<PolicyValidatorOutput, Vec<ValidationError>> {
        // Step 1 — try envelope format first (apiVersion/kind/metadata/spec)
        let (raw, metadata) = Self::parse_yaml(yaml_str)?;

        let mut errors: Vec<ValidationError> = Vec::new();
        let mut warnings: Vec<ValidationWarning> = Vec::new();

        // Step 2 — collect top-level unknown keys.
        //
        // AAASM-3351: a top-level `rules:` key signals a rule-list /
        // `GovernancePolicy`-style schema that the section-based engine does
        // NOT honor. Previously this was treated as an unknown key (warning
        // only), so the document validated into an empty allow-all policy —
        // a fail-OPEN on a misformatted/legacy policy. Fail closed instead:
        // refuse to load the document rather than silently allowing
        // everything. (Full multi-schema support is a follow-up.)
        //
        // AAASM-4191: extend fail-closed to ALL unknown top-level keys, not
        // just `rules`. A typo'd section key (e.g. `capabilties` instead of
        // `capabilities`) was silently dropped, allowing restrictions to
        // vanish without any error. Now every unknown top-level key is a
        // hard validation error — consistent with the product's fail-closed
        // posture everywhere else.
        for key in raw.unknown.keys() {
            if key == "rules" {
                errors.push(ValidationError::new(
                    "rules",
                    "unsupported rule-list policy schema (top-level 'rules:'); the gateway uses a \
                     section-based schema (network/schedule/budget/data/tools/capabilities) and \
                     refuses to load this document to avoid an allow-all fallback",
                ));
            } else {
                errors.push(ValidationError::new(
                    key,
                    format!(
                        "unknown top-level key '{}'; valid keys are: version, scope, network, \
                         schedule, budget, data, tools, capabilities, approval_timeout_secs, approval",
                        key
                    ),
                ));
            }
        }

        // Step 3 — validate each section
        let network = Self::validate_network(raw.network, &mut errors, &mut warnings);
        let schedule = Self::validate_schedule(raw.schedule, &mut errors, &mut warnings);
        let budget = Self::validate_budget(raw.budget, &mut errors);
        let data = Self::validate_data(raw.data, &mut errors);
        let tools = Self::validate_tools(raw.tools, &mut errors, &mut warnings);
        let capabilities = Self::validate_capabilities(raw.capabilities, &mut errors, &mut warnings);
        let approval_policy = Self::validate_approval_policy(raw.approval, &mut errors, &mut warnings);

        let approval_timeout_secs = match raw.approval_timeout_secs {
            Some(0) => {
                errors.push(ValidationError::new("approval_timeout_secs", "must be greater than 0"));
                300
            }
            Some(v) => v,
            None => 300,
        };

        if !errors.is_empty() {
            return Err(errors);
        }

        let (meta_name, meta_version) = match metadata {
            Some(m) => (m.name, m.version),
            None => (None, None),
        };

        Ok(PolicyValidatorOutput {
            document: PolicyDocument {
                name: meta_name,
                policy_version: meta_version,
                version: raw.version,
                scope: raw.scope.unwrap_or(PolicyScope::Global),
                network,
                schedule,
                budget,
                data,
                approval_timeout_secs,
                approval_policy,
                tools,
                capabilities,
            },
            warnings,
        })
    }

    /// Parse YAML string, detecting envelope vs flat format.
    ///
    /// Returns the parsed `RawPolicyDocument` and optional metadata extracted
    /// from the envelope wrapper.
    fn parse_yaml(
        yaml_str: &str,
    ) -> Result<(RawPolicyDocument, Option<crate::policy::raw::RawMetadata>), Vec<ValidationError>> {
        let make_parse_error = |e: serde_yaml::Error| {
            let line = e.location().map(|l| l.line() as u32);
            let mut err = ValidationError::new("(document)", format!("YAML parse error: {}", e));
            if let Some(l) = line {
                err = err.with_line(l);
            }
            vec![err]
        };

        // Try envelope format: if it has a `spec` key, treat it as wrapped.
        if let Ok(envelope) = serde_yaml::from_str::<GovernancePolicyEnvelope>(yaml_str) {
            if let Some(spec_value) = envelope.spec {
                let raw: RawPolicyDocument = serde_yaml::from_value(spec_value).map_err(make_parse_error)?;
                return Ok((raw, envelope.metadata));
            }
        }

        // Fall back to flat format (no envelope).
        let raw: RawPolicyDocument = serde_yaml::from_str(yaml_str).map_err(make_parse_error)?;
        Ok((raw, None))
    }

    // ── Section validators ──────────────────────────────────────────────────

    fn validate_network(
        raw: Option<crate::policy::raw::RawNetworkPolicy>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Option<NetworkPolicy> {
        let raw = raw?;

        for key in raw.unknown.keys() {
            warnings.push(ValidationWarning::unknown_key(format!("network.{}", key)));
        }

        let allowlist = raw.allowlist.unwrap_or_default();
        for (i, entry) in allowlist.iter().enumerate() {
            if entry.trim().is_empty() {
                errors.push(ValidationError::new(
                    format!("network.allowlist[{}]", i),
                    "allowlist entry must not be empty",
                ));
            }
        }

        Some(NetworkPolicy { allowlist })
    }

    fn validate_schedule(
        raw: Option<crate::policy::raw::RawSchedulePolicy>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Option<SchedulePolicy> {
        let raw = raw?;

        for key in raw.unknown.keys() {
            warnings.push(ValidationWarning::unknown_key(format!("schedule.{}", key)));
        }

        let active_hours = raw
            .active_hours
            .and_then(|ah| Self::validate_active_hours(ah, errors, warnings));

        Some(SchedulePolicy { active_hours })
    }

    fn validate_active_hours(
        raw: crate::policy::raw::RawActiveHours,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Option<ActiveHours> {
        for key in raw.unknown.keys() {
            warnings.push(ValidationWarning::unknown_key(format!("schedule.active_hours.{}", key)));
        }

        let start = match raw.start {
            Some(s) => {
                if !is_hhmm(&s) {
                    errors.push(ValidationError::new(
                        "schedule.active_hours.start",
                        "must be in HH:MM 24-hour format",
                    ));
                    return None;
                }
                s
            }
            None => {
                errors.push(ValidationError::new(
                    "schedule.active_hours.start",
                    "required when active_hours is present",
                ));
                return None;
            }
        };

        let end = match raw.end {
            Some(e) => {
                if !is_hhmm(&e) {
                    errors.push(ValidationError::new(
                        "schedule.active_hours.end",
                        "must be in HH:MM 24-hour format",
                    ));
                    return None;
                }
                e
            }
            None => {
                errors.push(ValidationError::new(
                    "schedule.active_hours.end",
                    "required when active_hours is present",
                ));
                return None;
            }
        };

        if start >= end {
            errors.push(ValidationError::new(
                "schedule.active_hours",
                "start must be earlier than end",
            ));
            return None;
        }

        let timezone = match raw.timezone {
            Some(tz) => tz,
            None => {
                errors.push(ValidationError::new(
                    "schedule.active_hours.timezone",
                    "required when active_hours is present",
                ));
                return None;
            }
        };

        // AAASM-3133: reject an unparseable IANA timezone at load time. The
        // engine fails closed on a bad tz at evaluation, but catching it here
        // gives the operator an immediate, actionable error instead of a policy
        // that silently denies every action once deployed.
        if timezone.parse::<chrono_tz::Tz>().is_err() {
            errors.push(ValidationError::new(
                "schedule.active_hours.timezone",
                "must be a valid IANA timezone (e.g. America/New_York)",
            ));
            return None;
        }

        Some(ActiveHours { start, end, timezone })
    }

    fn validate_budget(
        raw: Option<crate::policy::raw::RawBudgetPolicy>,
        errors: &mut Vec<ValidationError>,
    ) -> Option<BudgetPolicy> {
        let raw = raw?;

        validate_budget_limit_pair(
            raw.daily_limit_usd,
            raw.monthly_limit_usd,
            "budget.daily_limit_usd",
            "budget.monthly_limit_usd",
            errors,
        );

        // AAASM-2022 — Per-org limits use the same validation rules as the
        // global limits: positive, and monthly >= daily.
        validate_budget_limit_pair(
            raw.org_daily_limit_usd,
            raw.org_monthly_limit_usd,
            "budget.org_daily_limit_usd",
            "budget.org_monthly_limit_usd",
            errors,
        );

        // Validate timezone string if provided
        if let Some(tz_str) = &raw.timezone {
            if tz_str.parse::<chrono_tz::Tz>().is_err() {
                errors.push(ValidationError::new(
                    "budget.timezone",
                    format!("'{}' is not a valid IANA timezone name", tz_str),
                ));
            }
        }

        // Validate action_on_exceed if provided
        let action_on_exceed = match raw.action_on_exceed.as_deref() {
            Some("deny") | None => ActionOnExceed::Deny,
            Some("suspend") => ActionOnExceed::Suspend,
            Some(other) => {
                errors.push(ValidationError::new(
                    "budget.action_on_exceed",
                    format!("must be 'deny' or 'suspend', got '{}'", other),
                ));
                ActionOnExceed::Deny
            }
        };

        // Validate sub-day window if provided (AAASM-1600). Parses
        // humantime strings; rejects zero-or-negative or unparseable values.
        let window = match raw.window.as_deref() {
            None => None,
            Some(s) => match humantime::parse_duration(s) {
                Ok(d) if d.is_zero() => {
                    errors.push(ValidationError::new(
                        "budget.window",
                        "must be a positive duration (e.g. '5s', '30m', '1h')",
                    ));
                    None
                }
                Ok(d) => Some(d),
                Err(e) => {
                    errors.push(ValidationError::new(
                        "budget.window",
                        format!("'{s}' is not a valid humantime duration: {e}"),
                    ));
                    None
                }
            },
        };

        Some(BudgetPolicy {
            daily_limit_usd: raw.daily_limit_usd,
            monthly_limit_usd: raw.monthly_limit_usd,
            org_daily_limit_usd: raw.org_daily_limit_usd,
            org_monthly_limit_usd: raw.org_monthly_limit_usd,
            timezone: raw.timezone,
            action_on_exceed,
            window,
        })
    }

    fn validate_data(
        raw: Option<crate::policy::raw::RawDataPolicy>,
        errors: &mut Vec<ValidationError>,
    ) -> Option<DataPolicy> {
        let raw = raw?;

        let patterns = raw.sensitive_patterns.unwrap_or_default();
        for (i, pattern) in patterns.iter().enumerate() {
            if regex::Regex::new(pattern).is_err() {
                errors.push(ValidationError::new(
                    format!("data.sensitive_patterns[{}]", i),
                    format!("invalid regex: {}", pattern),
                ));
            }
        }

        let credential_action = match raw.credential_action.as_deref() {
            None | Some("redact_only") => CredentialAction::RedactOnly,
            Some("block") => CredentialAction::Block,
            Some("alert_only") => CredentialAction::AlertOnly,
            // AAASM-3137: safe alerting mode — alert AND redact on forward.
            Some("alert_and_redact") => CredentialAction::AlertAndRedact,
            Some(other) => {
                errors.push(ValidationError::new(
                    "data.credential_action",
                    format!(
                        "must be 'block', 'redact_only', 'alert_only', or 'alert_and_redact', got '{}'",
                        other
                    ),
                ));
                CredentialAction::RedactOnly
            }
        };

        Some(DataPolicy {
            sensitive_patterns: patterns,
            credential_action,
        })
    }

    fn validate_capabilities(
        raw: Option<crate::policy::raw::RawCapabilitySet>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Option<aa_core::CapabilitySet> {
        let raw = raw?;

        for key in raw.unknown.keys() {
            warnings.push(ValidationWarning::unknown_key(format!("capabilities.{}", key)));
        }

        let mut allow = std::collections::BTreeSet::new();
        for (i, s) in raw.allow.unwrap_or_default().iter().enumerate() {
            match s.parse::<aa_core::Capability>() {
                Ok(cap) => {
                    // AAASM-4099: warn loudly when a capability has no governance
                    // action routing to it — the allow/deny would be silently inert.
                    if !cap.is_enforceable() {
                        warnings.push(ValidationWarning::inert_capability(
                            format!("capabilities.allow[{}]", i),
                            &cap,
                        ));
                    }
                    allow.insert(cap);
                }
                Err(msg) => errors.push(ValidationError::new(format!("capabilities.allow[{}]", i), msg)),
            }
        }

        let mut deny = std::collections::BTreeSet::new();
        for (i, s) in raw.deny.unwrap_or_default().iter().enumerate() {
            match s.parse::<aa_core::Capability>() {
                Ok(cap) => {
                    // AAASM-4099: a declared deny on an unenforceable capability
                    // is the dangerous case — the operator believes they blocked
                    // it. Surface it loudly.
                    if !cap.is_enforceable() {
                        warnings.push(ValidationWarning::inert_capability(
                            format!("capabilities.deny[{}]", i),
                            &cap,
                        ));
                    }
                    deny.insert(cap);
                }
                Err(msg) => errors.push(ValidationError::new(format!("capabilities.deny[{}]", i), msg)),
            }
        }

        // A non-empty allow-list at this scope is itself a restriction; record it
        // so a later disjoint cascade merge cannot silently drop it (AAASM-4154).
        let allow_restricted = !allow.is_empty();
        Some(aa_core::CapabilitySet {
            allow,
            deny,
            allow_restricted,
        })
    }

    fn validate_tools(
        raw: Option<HashMap<String, crate::policy::raw::RawToolPolicy>>,
        errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> HashMap<String, ToolPolicy> {
        let raw = match raw {
            Some(m) => m,
            None => return HashMap::new(),
        };

        let mut tools = HashMap::new();
        for (name, rt) in raw {
            for key in rt.unknown.keys() {
                warnings.push(ValidationWarning::unknown_key(format!("tools.{}.{}", name, key)));
            }

            if let Some(expr) = &rt.requires_approval_if {
                if expr.trim().is_empty() {
                    errors.push(ValidationError::new(
                        format!("tools.{}.requires_approval_if", name),
                        "CEL expression must not be empty",
                    ));
                } else if let Err(msg) = super::expr::validate_governance_levels(expr) {
                    errors.push(ValidationError::new(
                        format!("tools.{}.requires_approval_if", name),
                        msg,
                    ));
                } else if let Err(e) = super::expr::validate_variables(expr) {
                    errors.push(ValidationError::new(
                        format!("tools.{}.requires_approval_if", name),
                        e.to_string(),
                    ));
                }
            }

            tools.insert(
                name,
                ToolPolicy {
                    // AAASM-3134: a tool entry that omits `allow` defaults to
                    // DENY, not allow. A policy typo (e.g. `alow: true`) or a
                    // half-written rule previously failed permissive — the tool
                    // was allowed by default — which is the opposite of what a
                    // governance control should do. Fail closed: an explicit
                    // `allow: true` is required to permit a listed tool.
                    allow: rt.allow.unwrap_or(false),
                    limit_per_hour: rt.limit_per_hour,
                    requires_approval_if: rt.requires_approval_if,
                },
            );
        }
        tools
    }

    fn validate_approval_policy(
        raw: Option<crate::policy::raw::RawApprovalPolicy>,
        _errors: &mut Vec<ValidationError>,
        warnings: &mut Vec<ValidationWarning>,
    ) -> Option<ApprovalPolicy> {
        let raw = raw?;

        for key in raw.unknown.keys() {
            warnings.push(ValidationWarning::unknown_key(format!("approval.{}", key)));
        }

        Some(ApprovalPolicy {
            timeout_seconds: raw.timeout_seconds,
            escalation_role: raw.escalation_role,
        })
    }
}

/// Validate a daily/monthly budget limit pair: each must be positive when
/// present, and `monthly` must be >= `daily`. `daily_field` / `monthly_field`
/// are the dotted field paths used in [`ValidationError`] messages.
fn validate_budget_limit_pair(
    daily: Option<f64>,
    monthly: Option<f64>,
    daily_field: &'static str,
    monthly_field: &'static str,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(limit) = daily {
        if limit <= 0.0 {
            errors.push(ValidationError::new(daily_field, "must be greater than 0"));
        }
    }
    if let Some(limit) = monthly {
        if limit <= 0.0 {
            errors.push(ValidationError::new(monthly_field, "must be greater than 0"));
        }
        if let Some(daily) = daily {
            if limit < daily {
                // Cross-message references the daily field by its leaf name.
                let daily_leaf = daily_field.rsplit('.').next().unwrap_or(daily_field);
                errors.push(ValidationError::new(monthly_field, format!("must be >= {daily_leaf}")));
            }
        }
    }
}

/// Returns `true` if `s` matches `HH:MM` with valid 24-hour values.
fn is_hhmm(s: &str) -> bool {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }
    match (parts[0].parse::<u8>(), parts[1].parse::<u8>()) {
        (Ok(h), Ok(m)) => h < 24 && m < 60 && parts[0].len() == 2 && parts[1].len() == 2,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unknown key errors (AAASM-4191: fail-closed on unknown top-level keys) ─

    #[test]
    fn top_level_unknown_key_is_validation_error() {
        // AAASM-4191: unknown top-level keys must fail closed (error), not
        // silently vanish with a warning. A typo'd section (e.g. `capabilties`)
        // would otherwise drop the restriction entirely.
        let yaml = "risk_tier: high\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "unknown top-level key must be rejected");
        let errs = result.unwrap_err();
        assert!(
            errs.iter().any(|e| e.field == "risk_tier"),
            "expected error on 'risk_tier' field, got: {:?}",
            errs,
        );
    }

    #[test]
    fn misspelled_capabilities_section_is_validation_error() {
        // AAASM-4191: a typo'd section key must not silently drop the restriction.
        let yaml = "capabilties:\n  deny:\n    - file_delete\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "misspelled section key must be rejected");
        let errs = result.unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.field == "capabilties" && e.message.contains("unknown")),
            "expected error mentioning 'capabilties', got: {:?}",
            errs,
        );
    }

    #[test]
    fn rule_list_schema_is_a_validation_error_not_an_allow_all_warning() {
        // AAASM-3351: a rule-list / GovernancePolicy-style document (top-level
        // `rules:`) is not honored by the section-based engine. It must fail
        // closed with a hard validation error, NOT validate into an empty
        // allow-all policy with only a warning.
        let yaml = "rules:\n  - id: deny-all\n    action: deny\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "rule-list schema must be rejected, not allow-all");
        let errs = result.unwrap_err();
        assert!(
            errs.iter().any(|e| e.field == "rules"),
            "expected a hard error on the 'rules' field, got: {:?}",
            errs,
        );
    }

    #[test]
    fn network_unknown_key_produces_warning() {
        let yaml = "network:\n  allowlist:\n    - api.openai.com\n  blocklist:\n    - \"*\"\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.warnings.iter().any(|w| w.field == "network.blocklist"));
    }

    #[test]
    fn tool_unknown_key_produces_warning() {
        let yaml = "tools:\n  bash:\n    allow: true\n    constraint: read-only\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.warnings.iter().any(|w| w.field == "tools.bash.constraint"));
    }

    // ── Network allowlist validation ────────────────────────────────────────

    #[test]
    fn network_empty_allowlist_entry_is_an_error() {
        let yaml = "network:\n  allowlist:\n    - \"\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "network.allowlist[0]"));
    }

    #[test]
    fn network_valid_allowlist_round_trips() {
        let yaml = "network:\n  allowlist:\n    - api.openai.com\n    - slack.com\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let np = out.document.network.unwrap();
        assert_eq!(np.allowlist, vec!["api.openai.com", "slack.com"]);
    }

    // ── Tool validation ─────────────────────────────────────────────────────

    #[test]
    fn tool_empty_requires_approval_if_is_an_error() {
        let yaml = "tools:\n  bash:\n    allow: true\n    requires_approval_if: \"   \"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "tools.bash.requires_approval_if"));
    }

    #[test]
    fn parser_rejects_unknown_governance_level() {
        // A condition referencing `L4` (or any non-L0..L3 level) must be
        // rejected at validation time with the spec-mandated message.
        let yaml = "tools:\n  bash:\n    allow: true\n    requires_approval_if: \"governance_level >= L4\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        let err = errs
            .iter()
            .find(|e| e.field == "tools.bash.requires_approval_if")
            .expect("validator should flag the unknown level on the requires_approval_if field");
        assert_eq!(
            err.message,
            "unknown governance level: L4; valid values: L0, L1, L2, L3"
        );
    }

    #[test]
    fn validator_accepts_all_known_governance_levels() {
        // Backward-compat sanity: valid L0..L3 conditions pass validation.
        for lvl in ["L0", "L1", "L2", "L3"] {
            let yaml =
                format!("tools:\n  bash:\n    allow: true\n    requires_approval_if: \"governance_level == {lvl}\"\n",);
            assert!(
                PolicyValidator::from_yaml(&yaml).is_ok(),
                "validator unexpectedly rejected condition with {lvl}",
            );
        }
    }

    #[test]
    fn tool_allow_defaults_to_false_when_absent() {
        // AAASM-3134: a tool entry without an explicit `allow` must fail closed
        // (deny), so a policy typo cannot silently permit a tool.
        let yaml = "tools:\n  bash:\n    limit_per_hour: 5\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(!out.document.tools["bash"].allow);
    }

    #[test]
    fn tool_allow_true_is_honoured_when_explicit() {
        let yaml = "tools:\n  bash:\n    allow: true\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.document.tools["bash"].allow);
    }

    #[test]
    fn tool_limit_per_hour_round_trips() {
        let yaml = "tools:\n  bash:\n    allow: true\n    limit_per_hour: 10\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.tools["bash"].limit_per_hour, Some(10));
    }

    // ── Data sensitive_patterns validation ─────────────────────────────────

    #[test]
    fn data_invalid_regex_pattern_is_an_error() {
        let yaml = "data:\n  sensitive_patterns:\n    - \"[unclosed\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "data.sensitive_patterns[0]"));
    }

    #[test]
    fn data_valid_regex_patterns_round_trip() {
        let yaml = "data:\n  sensitive_patterns:\n    - \"sk-[a-zA-Z0-9]{48}\"\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let dp = out.document.data.unwrap();
        assert_eq!(dp.sensitive_patterns.len(), 1);
    }

    #[test]
    fn data_credential_action_block_parses() {
        let yaml = "data:\n  credential_action: block\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let dp = out.document.data.unwrap();
        assert_eq!(dp.credential_action, CredentialAction::Block);
    }

    #[test]
    fn data_credential_action_alert_only_parses() {
        let yaml = "data:\n  credential_action: alert_only\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let dp = out.document.data.unwrap();
        assert_eq!(dp.credential_action, CredentialAction::AlertOnly);
    }

    #[test]
    fn data_credential_action_alert_and_redact_parses() {
        let yaml = "data:\n  credential_action: alert_and_redact\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let dp = out.document.data.unwrap();
        assert_eq!(dp.credential_action, CredentialAction::AlertAndRedact);
    }

    #[test]
    fn data_credential_action_invalid_value_is_an_error() {
        let yaml = "data:\n  credential_action: not_a_real_mode\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "data.credential_action"));
    }

    // ── Budget validation ───────────────────────────────────────────────────

    #[test]
    fn budget_zero_daily_limit_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 0.0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.daily_limit_usd"));
    }

    #[test]
    fn budget_negative_daily_limit_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: -1.0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.daily_limit_usd"));
    }

    #[test]
    fn budget_valid_daily_limit_round_trips() {
        let yaml = "budget:\n  daily_limit_usd: 50.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.daily_limit_usd, Some(50.0));
    }

    #[test]
    fn budget_timezone_valid_string_round_trips() {
        let yaml = "budget:\n  daily_limit_usd: 10.0\n  timezone: \"Asia/Tokyo\"\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.timezone, Some("Asia/Tokyo".to_string()));
    }

    #[test]
    fn budget_timezone_invalid_string_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 10.0\n  timezone: \"Not/AValidZone\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "expected validation error for invalid timezone");
        let errors = result.unwrap_err();
        assert!(
            errors.iter().any(|e| e.field == "budget.timezone"),
            "expected error mentioning budget.timezone, got: {:?}",
            errors
        );
    }

    // ── Monthly budget validation ─────────────────────────────────────────

    #[test]
    fn budget_valid_monthly_limit_round_trips() {
        let yaml = "budget:\n  monthly_limit_usd: 500.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.monthly_limit_usd, Some(500.0));
    }

    #[test]
    fn budget_negative_monthly_limit_is_an_error() {
        let yaml = "budget:\n  monthly_limit_usd: -10.0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.monthly_limit_usd"));
    }

    #[test]
    fn budget_zero_monthly_limit_is_an_error() {
        let yaml = "budget:\n  monthly_limit_usd: 0.0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.monthly_limit_usd"));
    }

    #[test]
    fn budget_monthly_less_than_daily_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 100.0\n  monthly_limit_usd: 50.0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs
            .iter()
            .any(|e| e.field == "budget.monthly_limit_usd" && e.message.contains(">= daily_limit_usd")));
    }

    #[test]
    fn budget_monthly_equal_to_daily_is_valid() {
        let yaml = "budget:\n  daily_limit_usd: 100.0\n  monthly_limit_usd: 100.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.monthly_limit_usd, Some(100.0));
        assert_eq!(bp.daily_limit_usd, Some(100.0));
    }

    #[test]
    fn budget_monthly_without_daily_is_valid() {
        let yaml = "budget:\n  monthly_limit_usd: 1000.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.monthly_limit_usd, Some(1000.0));
        assert!(bp.daily_limit_usd.is_none());
    }

    // ── action_on_exceed validation ────────────────────────────────────────

    #[test]
    fn budget_action_on_exceed_deny_round_trips() {
        let yaml = "budget:\n  daily_limit_usd: 50.0\n  action_on_exceed: deny\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.action_on_exceed, ActionOnExceed::Deny);
    }

    #[test]
    fn budget_action_on_exceed_suspend_round_trips() {
        let yaml = "budget:\n  daily_limit_usd: 50.0\n  action_on_exceed: suspend\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.action_on_exceed, ActionOnExceed::Suspend);
    }

    #[test]
    fn budget_action_on_exceed_invalid_value_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 50.0\n  action_on_exceed: quarantine\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.action_on_exceed"));
    }

    #[test]
    fn budget_action_on_exceed_absent_defaults_to_deny() {
        let yaml = "budget:\n  daily_limit_usd: 50.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.action_on_exceed, ActionOnExceed::Deny);
    }

    // ── Schedule active_hours validation ───────────────────────────────────

    #[test]
    fn schedule_invalid_start_format_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    start: \"9:00\"\n    end: \"18:00\"\n    timezone: \"UTC\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.start"));
    }

    #[test]
    fn schedule_end_not_after_start_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    start: \"18:00\"\n    end: \"09:00\"\n    timezone: \"UTC\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours"));
    }

    #[test]
    fn schedule_valid_active_hours_round_trips() {
        let yaml =
            "schedule:\n  active_hours:\n    start: \"09:00\"\n    end: \"18:00\"\n    timezone: \"Asia/Taipei\"\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let sp = out.document.schedule.unwrap();
        let ah = sp.active_hours.unwrap();
        assert_eq!(ah.start, "09:00");
        assert_eq!(ah.end, "18:00");
        assert_eq!(ah.timezone, "Asia/Taipei");
    }

    #[test]
    fn schedule_invalid_timezone_is_an_error() {
        // AAASM-3133: a bogus IANA timezone must be rejected at load time, not
        // silently accepted (and later fall back to UTC at evaluation).
        let yaml =
            "schedule:\n  active_hours:\n    start: \"09:00\"\n    end: \"18:00\"\n    timezone: \"Mars/Phobos\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "invalid timezone must be a validation error");
    }

    // ── Capabilities validation ─────────────────────────────────────────────

    #[test]
    fn capabilities_valid_round_trips() {
        let yaml = "capabilities:\n  allow:\n    - file_read\n    - mcp_tool:bash\n  deny:\n    - terminal_exec\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let caps = out.document.capabilities.as_ref().unwrap();
        assert!(caps.allow.contains(&aa_core::Capability::FileRead));
        assert!(caps.allow.contains(&aa_core::Capability::McpTool("bash".to_string())));
        assert!(caps.deny.contains(&aa_core::Capability::TerminalExec));
    }

    #[test]
    fn capabilities_absent_is_none() {
        let yaml = "{}\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.document.capabilities.is_none());
    }

    #[test]
    fn capabilities_unknown_string_is_validation_error() {
        let yaml = "capabilities:\n  allow:\n    - unknown_thing\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "capabilities.allow[0]"));
    }

    #[test]
    fn capabilities_mcp_tool_no_name_is_error() {
        let yaml = "capabilities:\n  allow:\n    - \"mcp_tool:\"\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "capabilities.allow[0]"));
    }

    #[test]
    fn capabilities_unknown_key_produces_warning() {
        let yaml = "capabilities:\n  allow: []\n  extra_key: true\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.warnings.iter().any(|w| w.field == "capabilities.extra_key"));
    }

    #[test]
    fn capabilities_inert_deny_parses_but_warns_loudly() {
        // AAASM-4099: network_inbound / agent_spawn / model:* have no governance
        // action, so a declared deny is silently inert. Loading must still
        // succeed (shipped strict.yaml relies on it) but MUST warn loudly.
        for cap in ["network_inbound", "agent_spawn", "model:gpt-4o"] {
            let yaml = format!("capabilities:\n  deny:\n    - {cap}\n");
            let out = PolicyValidator::from_yaml(&yaml)
                .unwrap_or_else(|e| panic!("inert cap {cap} must not be a hard error: {e:?}"));
            let warning = out
                .warnings
                .iter()
                .find(|w| w.field == "capabilities.deny[0]")
                .unwrap_or_else(|| panic!("expected inert-capability warning for {cap}"));
            assert!(
                warning.message.contains("NOT enforced") && warning.message.contains("inert"),
                "warning for {cap} must be loud about non-enforcement: {}",
                warning.message
            );
        }
    }

    #[test]
    fn capabilities_inert_allow_warns_loudly() {
        let yaml = "capabilities:\n  allow:\n    - agent_spawn\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out
            .warnings
            .iter()
            .any(|w| w.field == "capabilities.allow[0]" && w.message.contains("NOT enforced")));
    }

    #[test]
    fn capabilities_enforceable_caps_produce_no_inert_warning() {
        let yaml = "capabilities:\n  deny:\n    - terminal_exec\n    - file_write\n    - network_outbound\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(
            !out.warnings.iter().any(|w| w.message.contains("NOT enforced")),
            "action-backed capabilities must not emit an inert warning"
        );
    }

    // ── Full-policy integration ─────────────────────────────────────────────

    #[test]
    fn full_policy_document_validates_successfully() {
        let yaml = r#"
version: "1.0"
network:
  allowlist:
    - api.openai.com
    - slack.com
schedule:
  active_hours:
    start: "09:00"
    end: "18:00"
    timezone: "Asia/Taipei"
budget:
  daily_limit_usd: 25.0
data:
  sensitive_patterns:
    - "sk-[a-zA-Z0-9]{48}"
tools:
  bash:
    allow: true
    limit_per_hour: 10
    requires_approval_if: "agent.depth > 1"
  file_write:
    allow: false
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let doc = &out.document;

        assert_eq!(doc.version, Some("1.0".to_string()));

        let np = doc.network.as_ref().unwrap();
        assert_eq!(np.allowlist.len(), 2);

        let sp = doc.schedule.as_ref().unwrap();
        let ah = sp.active_hours.as_ref().unwrap();
        assert_eq!(ah.timezone, "Asia/Taipei");

        let bp = doc.budget.as_ref().unwrap();
        assert_eq!(bp.daily_limit_usd, Some(25.0));

        let dp = doc.data.as_ref().unwrap();
        assert_eq!(dp.sensitive_patterns.len(), 1);

        assert!(doc.tools["bash"].allow);
        assert_eq!(doc.tools["bash"].limit_per_hour, Some(10));
        assert!(!doc.tools["file_write"].allow);

        assert!(out.warnings.is_empty());
    }

    #[test]
    fn full_policy_with_multiple_errors_collects_all() {
        let yaml = r#"
network:
  allowlist:
    - ""
budget:
  daily_limit_usd: 0.0
data:
  sensitive_patterns:
    - "[bad"
"#;
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "network.allowlist[0]"));
        assert!(errs.iter().any(|e| e.field == "budget.daily_limit_usd"));
        assert!(errs.iter().any(|e| e.field == "data.sensitive_patterns[0]"));
    }

    // ── Malformed YAML ──────────────────────────────────────────────────────

    #[test]
    fn malformed_yaml_returns_parse_error() {
        let yaml = ":\n  bad: [unclosed\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert_eq!(errs[0].field, "(document)");
        assert!(errs[0].message.contains("YAML parse error"));
    }

    #[test]
    fn malformed_yaml_error_includes_line_number() {
        // serde_yaml reports location for parse errors when available.
        let yaml = "network:\n  allowlist:\n    - [unclosed\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs[0].line.is_some(), "expected line number in parse error");
    }

    #[test]
    fn empty_document_is_valid_with_no_errors() {
        let yaml = "{}\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert!(out.warnings.is_empty());
        assert!(out.document.network.is_none());
    }

    // ── Scope field (F92) ───────────────────────────────────────────────────

    #[test]
    fn scope_absent_defaults_to_global_for_backward_compatibility() {
        let yaml = "{}\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.scope, PolicyScope::Global);
    }

    #[test]
    fn scope_team_field_round_trips_through_validator() {
        let yaml = "scope: team:platform\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.scope, PolicyScope::Team("platform".to_owned()));
    }

    #[test]
    fn scope_org_field_round_trips_through_validator() {
        let yaml = "scope: org:acme\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.scope, PolicyScope::Org("acme".to_owned()));
    }

    #[test]
    fn scope_global_field_is_accepted() {
        let yaml = "scope: global\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.scope, PolicyScope::Global);
    }

    #[test]
    fn malformed_scope_field_is_rejected_at_parse_time() {
        let yaml = "scope: project:foo\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err(), "expected validation error for unknown scope kind");
        let errs = result.unwrap_err();
        assert!(
            errs.iter().any(|e| e.message.contains("invalid policy scope")),
            "expected error message mentioning invalid scope, got {:?}",
            errs,
        );
    }

    /// Parameterised coverage for every malformed-scope shape the validator
    /// must reject. Each row is `(quoted YAML scalar, substring expected in
    /// the diagnostic)`. The substring lets the test stay robust against
    /// minor wording changes in `PolicyParseError::Display`.
    #[test]
    fn every_malformed_scope_form_is_rejected_with_useful_diagnostic() {
        let cases: &[(&str, &str)] = &[
            // Empty quoted string — neither `global` nor `<kind>:<id>`.
            ("\"\"", "expected `global`"),
            // No colon and not `global`.
            ("acme", "expected `global`"),
            // Empty identifier after the colon.
            ("\"team:\"", "must not be empty"),
            // Empty identifier on the Tool variant (AAASM-1008 AC).
            ("\"tool:\"", "must not be empty"),
            // Unknown scope kind.
            ("project:foo", "unknown scope kind"),
            // Agent variant with a non-UUID identifier.
            ("agent:not-a-uuid", "valid UUID"),
        ];

        for (yaml_scalar, expected_substring) in cases {
            let yaml = format!("scope: {}\n", yaml_scalar);
            let result = PolicyValidator::from_yaml(&yaml);
            assert!(result.is_err(), "expected error for malformed scope {:?}", yaml_scalar,);
            let errs = result.unwrap_err();
            assert!(
                errs.iter().any(|e| e.message.contains(expected_substring)),
                "for scope {:?} expected diagnostic containing {:?}, got {:?}",
                yaml_scalar,
                expected_substring,
                errs,
            );
        }
    }

    // ── Approval timeout validation ──────────────────────────────────────────

    #[test]
    fn approval_timeout_valid_value_round_trips() {
        let yaml = "approval_timeout_secs: 600\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.approval_timeout_secs, 600);
    }

    #[test]
    fn approval_timeout_absent_defaults_to_300() {
        let yaml = "{}\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.approval_timeout_secs, 300);
    }

    #[test]
    fn approval_timeout_zero_is_an_error() {
        let yaml = "approval_timeout_secs: 0\n";
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "approval_timeout_secs"));
    }

    // ── Envelope vs flat format ────────────────────────────────────────────

    #[test]
    fn envelope_format_extracts_metadata_name_and_version() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: my-policy
  version: "2.0.0"
spec:
  budget:
    daily_limit_usd: 10.0
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.name, Some("my-policy".to_string()));
        assert_eq!(out.document.policy_version, Some("2.0.0".to_string()));
        assert_eq!(out.document.budget.unwrap().daily_limit_usd, Some(10.0));
    }

    #[test]
    fn envelope_format_with_tools_parses_spec_correctly() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: test-policy
  version: "1.0.0"
spec:
  tools:
    bash:
      allow: true
      limit_per_hour: 5
    file_write:
      allow: false
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert_eq!(out.document.name, Some("test-policy".to_string()));
        assert_eq!(out.document.tools.len(), 2);
        assert!(out.document.tools["bash"].allow);
        assert!(!out.document.tools["file_write"].allow);
    }

    #[test]
    fn flat_format_has_no_metadata() {
        let yaml = "budget:\n  daily_limit_usd: 25.0\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.document.name.is_none());
        assert!(out.document.policy_version.is_none());
        assert_eq!(out.document.budget.unwrap().daily_limit_usd, Some(25.0));
    }

    #[test]
    fn envelope_format_without_metadata_section() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
spec:
  budget:
    daily_limit_usd: 5.0
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(out.document.name.is_none());
        assert!(out.document.policy_version.is_none());
        assert_eq!(out.document.budget.unwrap().daily_limit_usd, Some(5.0));
    }

    #[test]
    fn envelope_format_validation_errors_propagate() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: bad-policy
spec:
  budget:
    daily_limit_usd: -1.0
"#;
        let result = PolicyValidator::from_yaml(yaml);
        assert!(result.is_err());
        let errs = result.unwrap_err();
        assert!(errs.iter().any(|e| e.field == "budget.daily_limit_usd"));
    }

    // ── approval policy validation ─────────────────────────────────────────────

    #[test]
    fn approval_policy_parses_timeout_and_role() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: escalation-test
spec:
  scope: global
  approval:
    timeout_seconds: 600
    escalation_role: org-admin
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let ap = out.document.approval_policy.expect("approval_policy must be Some");
        assert_eq!(ap.timeout_seconds, Some(600));
        assert_eq!(ap.escalation_role, Some("org-admin".to_string()));
    }

    #[test]
    fn approval_policy_absent_yields_none() {
        let out = PolicyValidator::from_yaml("version: \"1\"\n").unwrap();
        assert!(out.document.approval_policy.is_none());
    }

    #[test]
    fn approval_policy_unknown_key_produces_warning() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: warn-test
spec:
  scope: global
  approval:
    timeout_seconds: 300
    unknown_field: surprise
"#;
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.field.contains("unknown_field")),
            "expected warning for unknown approval field, got: {:?}",
            out.warnings,
        );
    }

    // ── Schedule active_hours missing/unknown fields ────────────────────────

    #[test]
    fn schedule_unknown_key_produces_warning() {
        let yaml = "schedule:\n  surprise: 1\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.field == "schedule.surprise"),
            "expected warning for unknown schedule key, got: {:?}",
            out.warnings,
        );
    }

    #[test]
    fn schedule_active_hours_unknown_key_produces_warning() {
        let yaml = "schedule:\n  active_hours:\n    start: \"09:00\"\n    end: \"18:00\"\n    timezone: \"UTC\"\n    surprise: 1\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        assert!(
            out.warnings.iter().any(|w| w.field == "schedule.active_hours.surprise"),
            "expected warning for unknown active_hours key, got: {:?}",
            out.warnings,
        );
    }

    #[test]
    fn schedule_missing_start_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    end: \"18:00\"\n    timezone: \"UTC\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.start"));
    }

    #[test]
    fn schedule_invalid_end_format_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    start: \"09:00\"\n    end: \"6pm\"\n    timezone: \"UTC\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.end"));
    }

    #[test]
    fn schedule_missing_end_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    start: \"09:00\"\n    timezone: \"UTC\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.end"));
    }

    #[test]
    fn schedule_missing_timezone_is_an_error() {
        let yaml = "schedule:\n  active_hours:\n    start: \"09:00\"\n    end: \"18:00\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.timezone"));
    }

    #[test]
    fn schedule_start_without_colon_is_rejected() {
        // is_hhmm must reject a value with no ':' separator (e.g. "0900").
        let yaml = "schedule:\n  active_hours:\n    start: \"0900\"\n    end: \"18:00\"\n    timezone: \"UTC\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.start"));
    }

    #[test]
    fn schedule_start_with_non_numeric_components_is_rejected() {
        // is_hhmm must reject non-numeric HH/MM components (e.g. "ab:cd").
        let yaml = "schedule:\n  active_hours:\n    start: \"ab:cd\"\n    end: \"18:00\"\n    timezone: \"UTC\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(errs.iter().any(|e| e.field == "schedule.active_hours.start"));
    }

    // ── Budget sub-day window (AAASM-1600) ──────────────────────────────────

    #[test]
    fn budget_window_valid_humantime_round_trips() {
        let yaml = "budget:\n  daily_limit_usd: 10.0\n  window: \"30m\"\n";
        let out = PolicyValidator::from_yaml(yaml).unwrap();
        let bp = out.document.budget.unwrap();
        assert_eq!(bp.window, Some(std::time::Duration::from_secs(30 * 60)));
    }

    #[test]
    fn budget_window_zero_duration_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 10.0\n  window: \"0s\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(
            errs.iter().any(|e| e.field == "budget.window"),
            "zero window must be rejected, got: {errs:?}"
        );
    }

    #[test]
    fn budget_window_unparseable_is_an_error() {
        let yaml = "budget:\n  daily_limit_usd: 10.0\n  window: \"not-a-duration\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(
            errs.iter().any(|e| e.field == "budget.window"),
            "unparseable window must be rejected, got: {errs:?}"
        );
    }

    // ── Capabilities deny-list validation ───────────────────────────────────

    #[test]
    fn capabilities_invalid_deny_entry_is_an_error() {
        let yaml = "capabilities:\n  deny:\n    - \"not::a::capability\"\n";
        let errs = PolicyValidator::from_yaml(yaml).unwrap_err();
        assert!(
            errs.iter().any(|e| e.field == "capabilities.deny[0]"),
            "invalid deny capability must be rejected, got: {errs:?}"
        );
    }
}
