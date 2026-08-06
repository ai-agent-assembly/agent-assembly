//! Turning one model into either of the two renderings (AAASM-5280).
//!
//! # The contract this file enforces
//!
//! [`Report`] requires `Serialize` *and* `render_human`. A command therefore
//! cannot produce a human table from one value and JSON from another: both come
//! out of [`emit`], which takes a single `&impl Report`. The invariant "human
//! and machine output derive from the same response model" is enforced by the
//! type system rather than by a review comment.
//!
//! # What is never printed
//!
//! Nothing here can print a capability token, a rendered settings body or a
//! policy document, because [`super::model`] has no field able to hold one and
//! these functions read only from those models. Fingerprints and key *names*
//! are printed; values never are.

use chrono::{DateTime, Local, Utc};
use serde::Serialize;

use crate::output::OutputFormat;

use super::model::{
    EvidenceRow, InstallReport, LevelAvailability, PlanReport, RemoveReport, RepairReport, StatusReport, StepRow,
    ToolListReport, VerifyReport,
};

/// A command result that can be rendered for a person and for a script, from
/// one value.
pub trait Report: Serialize {
    /// The human rendering.
    fn render_human(&self) -> String;
}

/// Write `report` in the requested format to stdout.
///
/// Notices, warnings and prompts go to stderr elsewhere, so stdout carries the
/// report and nothing else — `aasm integrations status x --output json | jq`
/// works even when the runtime had to be started first.
pub fn emit(report: &impl Report, output: OutputFormat) {
    match output {
        OutputFormat::Json => match serde_json::to_string_pretty(report) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("error: could not serialize the report: {e}"),
        },
        OutputFormat::Yaml => match serde_yaml::to_string(report) {
            Ok(yaml) => print!("{yaml}"),
            Err(e) => eprintln!("error: could not serialize the report: {e}"),
        },
        OutputFormat::Table => print!("{}", report.render_human()),
    }
}

/// The operator-facing name of an integration state.
///
/// The DI-API's four tokens are `ladder | drifted | degraded | incompatible`,
/// and `ladder` means "on the ordinary ladder — nothing anomalous". Printed
/// verbatim it is decodable only by a reader who already knows the other three
/// and can infer that this one is the good case (AAASM-5635). The separation
/// itself is load-bearing and stays: only the word a person reads changes, and
/// the wire token `--output json` publishes is untouched.
///
/// A token this build does not know is named as unrecognized rather than
/// forwarded. Passing it through is how `ladder` reached a user in the first
/// place, and this client is not entitled to translate a word it has never
/// seen — reporting it, unread, is.
fn human_state(token: &str) -> String {
    match token {
        "ladder" => "ok".to_string(),
        "drifted" | "degraded" | "incompatible" => token.to_string(),
        other => format!("unrecognized ({other})"),
    }
}

/// A moment a person can read, and how old it is.
///
/// Every timestamp the DI-API carries is seconds since the epoch, and printing
/// that integer asks the reader to go and convert it before they can act on it
/// (AAASM-5636). Both halves are rendered because both are asked: the absolute
/// local time answers *when*, and the age answers *how stale is this reading* —
/// which is the operative question here, since `partially_integrated` is the
/// resting state of a verification that fell outside its window.
///
/// `--output json` still publishes the integer, untouched. This is the human
/// half only.
fn timestamp(unix_secs: u64) -> String {
    timestamp_at(unix_secs, Utc::now())
}

/// The clock-free half, so the wording is testable without one.
fn timestamp_at(unix_secs: u64, now: DateTime<Utc>) -> String {
    let Some(at) = i64::try_from(unix_secs)
        .ok()
        .and_then(|s| DateTime::from_timestamp(s, 0))
    else {
        // No calendar date exists for this value. Reporting the integer and
        // saying why is the only honest option left; inventing a date is not.
        return format!("{unix_secs} (unix; outside the representable range)");
    };
    format!(
        "{} ({})",
        at.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S %:z"),
        age(now.timestamp() - at.timestamp())
    )
}

/// `4 minutes ago`, coarse on purpose: freshness is a judgement about whether a
/// reading still stands, not a stopwatch value.
///
/// A negative delta is rendered as a future time rather than clamped, because a
/// reading dated ahead of this host's clock is a disagreement worth seeing.
fn age(delta_secs: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;

    let elapsed = delta_secs.abs();
    if elapsed < 5 {
        return "just now".to_string();
    }
    let (count, unit) = match elapsed {
        s if s < MINUTE => (s, "second"),
        s if s < HOUR => (s / MINUTE, "minute"),
        s if s < DAY => (s / HOUR, "hour"),
        s => (s / DAY, "day"),
    };
    let plural = if count == 1 { "" } else { "s" };
    if delta_secs < 0 {
        format!("{count} {unit}{plural} from now")
    } else {
        format!("{count} {unit}{plural} ago")
    }
}

fn tick(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn bullets(out: &mut String, heading: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{heading}:\n"));
    for item in items {
        out.push_str(&format!("  - {item}\n"));
    }
}

fn render_evidence(out: &mut String, heading: &str, rows: &[EvidenceRow], empty_note: &str) {
    out.push_str(&format!("\n{heading}:\n"));
    if rows.is_empty() {
        out.push_str(&format!("  ({empty_note})\n"));
        return;
    }
    for row in rows {
        out.push_str(&format!(
            "  - {} [{}] at {}: {}\n",
            row.mechanism,
            row.outcome,
            timestamp(row.observed_at_unix_secs),
            row.detail
        ));
    }
}

fn render_steps(out: &mut String, steps: &[StepRow]) {
    if steps.is_empty() {
        out.push_str("  (no steps)\n");
        return;
    }
    for (index, step) in steps.iter().enumerate() {
        out.push_str(&format!(
            "  {}. [{}{}] {} — {}\n",
            index + 1,
            step.requirement,
            if step.privilege == "privileged_host" {
                ",privileged-host"
            } else {
                ""
            },
            step.action_kind,
            step.summary
        ));
        if let Some(scope) = &step.settings_scope {
            out.push_str(&format!("       surface: {scope}\n"));
        }
        if !step.managed_keys.is_empty() {
            out.push_str(&format!("       keys:    {}\n", step.managed_keys.join(", ")));
        }
        for path in &step.artifact_paths {
            out.push_str(&format!("       file:    {path}\n"));
        }
        if let Some(digest) = &step.content_sha256 {
            out.push_str(&format!("       sha256:  {digest}\n"));
        }
        out.push_str(&format!("       reversible: {}\n", tick(step.reversible)));
        if let Some(prompt) = &step.consent_prompt {
            out.push_str(&format!("       CONSENT REQUIRED: {prompt}\n"));
        }
    }
}

impl Report for ToolListReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Agent Assembly core {} (DI-API v{})\n\n",
            self.runtime.core_version, self.runtime.di_api_version
        ));
        out.push_str(&format!(
            "{:<16} {:<12} {:<12} {:<14} {}\n",
            "TOOL", "VERSION", "COMPAT", "STATE", "PROTECTION"
        ));
        for tool in &self.tools {
            out.push_str(&format!(
                "{:<16} {:<12} {:<12} {:<14} {}\n",
                tool.tool_id,
                tool.detected_version.as_deref().unwrap_or("-"),
                tool.compatibility,
                // `None` is this CLI's own "no status could be read", not one
                // of the service's state tokens, so it does not go through the
                // rename.
                tool.integration_state
                    .as_deref()
                    .map_or_else(|| "not_integrated".to_string(), human_state),
                tool.achieved_level.as_deref().unwrap_or("-"),
            ));
            for warning in &tool.warnings {
                out.push_str(&format!("{:<16} ! {warning}\n", ""));
            }
        }
        out.push_str("\nRun `aasm integrations status <tool>` for the evidence behind a protection level.\n");
        out
    }
}

impl Report for PlanReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("Plan {} for {}\n", self.plan_id, self.tool_id));
        out.push_str(&format!("  profile:         {}\n", self.profile));
        out.push_str(&format!("  settings scope:  {}\n", self.settings_scope));
        out.push_str(&format!("  planned level:   {}\n", self.planned_level));
        out.push_str(&format!("  adapter ceiling: {}\n", self.adapter_ceiling));
        if let Some(profile) = &self.policy_profile {
            out.push_str(&format!(
                "  policy profile:  {} ({}, digest {})\n",
                profile.display_name, profile.id, profile.digest
            ));
        }
        out.push_str("\nMaterial changes:\n");
        render_steps(&mut out, &self.steps);

        out.push_str("\nPermissions required:\n");
        if self.required_permissions.is_empty() {
            out.push_str("  (none — no step changes host state)\n");
        } else {
            for prompt in &self.required_permissions {
                out.push_str(&format!("  - {prompt}\n"));
            }
        }

        if !self.unsupported.is_empty() {
            out.push_str("\nNot available for this tool:\n");
            for row in &self.unsupported {
                out.push_str(&format!("  - {}: {}\n", row.capability, row.reason));
            }
        }
        bullets(&mut out, "Warnings", &self.warnings);
        if !self.applied {
            out.push_str("\nNothing has been changed. Run `aasm integrations install <tool>` to apply.\n");
        }
        out
    }
}

impl Report for InstallReport {
    fn render_human(&self) -> String {
        let mut out = self.plan.render_human();
        out.push_str(&format!("\nApplied as receipt {}\n", self.receipt_id));
        out.push_str(&format!(
            "  at:              {}\n",
            timestamp(self.applied_at_unix_secs)
        ));
        out.push_str(&format!("  planned level:   {}\n", self.planned_level));
        out.push_str(&format!("  achieved level:  {}\n", self.achieved_level));
        out.push_str("\nStep outcomes:\n");
        for step in &self.steps {
            out.push_str(&format!(
                "  - {}: {}{}\n",
                step.step_id,
                step.outcome,
                step.fingerprint.as_ref().map(|f| format!(" ({f})")).unwrap_or_default()
            ));
        }
        out.push_str(
            "\nInstalling is idempotent: re-running it leaves a target that already matches the plan \
             exactly as it is.\n\nInstalling configures the tool. It does not by itself prove anything is \
             protected — run `aasm integrations verify <tool>`.\n",
        );
        out
    }
}

impl Report for StatusReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{} — {}\n", self.tool_id, self.achieved_level));
        out.push_str(&format!(
            "  observed at:     {}\n",
            timestamp(self.observed_at_unix_secs)
        ));
        out.push_str(&format!("  lifecycle phase: {}\n", self.phase));
        out.push_str(&format!("  state:           {}\n", human_state(&self.state)));
        out.push_str(&format!("  planned level:   {}\n", self.planned_level));
        out.push_str(&format!("  compatibility:   {}\n", self.compatibility));
        out.push_str(&format!("  adapter ceiling: {}\n", self.adapter_ceiling));

        out.push_str("\nRuntime:\n");
        out.push_str(&format!(
            "  core {} over DI-API v{}{}\n",
            self.runtime.core_version,
            self.runtime.di_api_version,
            if self.runtime.degraded { " (degraded)" } else { "" }
        ));
        if let Some(verified) = self.last_verified_at_unix_secs {
            out.push_str(&format!("  last verification: {}\n", timestamp(verified)));
        } else {
            out.push_str("  last verification: never\n");
        }

        // Rendered as its own block, not folded into the ladder above. The
        // protection level and the policy are independent: an integration can
        // be `Gateway Protected` while a governed launch would be refused for
        // want of a policy, and a reader who saw one number would assume the
        // other.
        out.push_str("\nPolicy for the next governed launch:\n");
        out.push_str(&format!("  state:  {}\n", self.policy.state));
        match self.policy.refuses_launch {
            Some(true) => out.push_str("  launch: REFUSED — `aasm run` will not start a tool in this state\n"),
            Some(false) => out.push_str("  launch: permitted\n"),
            // Never rendered as "permitted". An unanswerable question is not a
            // yes, and printing one would be the over-claim this whole command
            // is written to avoid.
            None => out.push_str("  launch: not established by this reading\n"),
        }
        if let Some(source) = &self.policy.source {
            out.push_str(&format!("  source: {source}\n"));
        }
        out.push_str(&format!("  detail: {}\n", self.policy.detail));

        out.push_str("\nProtection levels:\n");
        for level in &self.levels {
            // Three marks for three states, and none of them is a sentence
            // this client made up about the host. "The adapter says this
            // platform cannot" and "nobody said anything" used to share the
            // mark `unavailable on this platform`, which is how a supported
            // mechanism came to be reported as impossible (AAASM-5454). A
            // platform claim, when there is one, is the adapter's and arrives
            // on the limitation line below.
            let mark = match (level.achieved, level.availability) {
                (true, _) => "active",
                (false, LevelAvailability::Available) => "not active",
                (false, LevelAvailability::Unsupported) => "unsupported by this integration",
                (false, LevelAvailability::Unmeasured) => "not established by this reading",
            };
            out.push_str(&format!("  {:<20} {}\n", level.level, mark));
            out.push_str(&format!("  {:<20}   {}\n", "", level.limitation));
        }
        if let Some(next) = &self.next_level {
            out.push_str(&format!("\nNext level up: {} — {}\n", next.level, next.limitation));
        }

        render_evidence(
            &mut out,
            "Exercised evidence (traffic was produced and adjudicated)",
            &self.exercised_evidence,
            "none — nothing about traffic has been demonstrated",
        );
        render_evidence(
            &mut out,
            "Read-back evidence (configuration was compared to the receipt)",
            &self.read_back_evidence,
            "none",
        );
        if !self.absent_evidence.is_empty() {
            render_evidence(&mut out, "Checks that could not be made", &self.absent_evidence, "none");
        }

        if let Some(reason) = &self.state_reason {
            out.push_str(&format!("\nWhy: {reason}\n"));
        }
        if let Some(remediation) = &self.state_remediation {
            out.push_str(&format!("Fix: {remediation}\n"));
        }
        bullets(&mut out, "Drifted artifacts", &self.drift_mismatched);
        if self.repair_available {
            out.push_str("\nRun `aasm integrations repair ");
            out.push_str(&self.tool_id);
            out.push_str("` to restore the AASM-owned state above.\n");
        }
        if !self.unsupported.is_empty() {
            out.push_str("\nMechanisms this tool cannot use:\n");
            for row in &self.unsupported {
                out.push_str(&format!("  - {}: {}\n", row.capability, row.reason));
            }
        }
        out
    }
}

impl Report for VerifyReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{} — verification {}\n", self.tool_id, self.outcome));
        out.push_str(&format!(
            "  ran at:               {}\n",
            timestamp(self.verified_at_unix_secs)
        ));
        out.push_str(&format!(
            "  protected path exercised: {}\n",
            tick(self.protected_path_exercised)
        ));

        out.push_str("\nAssertions:\n");
        for assertion in &self.assertions {
            out.push_str(&format!(
                "  [{}] {:<38} {}\n",
                if assertion.holds { "ok" } else { "--" },
                assertion.id,
                assertion.detail
            ));
        }

        render_evidence(&mut out, "Evidence", &self.evidence, "none");
        bullets(&mut out, "Not established", &self.missing);
        if let Some(reason) = &self.reason {
            out.push_str(&format!("\nWhy: {reason}\n"));
        }
        if !self.established_protection() {
            out.push_str(
                "\nThis is NOT a protection measurement. Configuration that exists is not evidence \
                 that anything was protected; the protected path must be exercised and adjudicated.\n",
            );
        }
        out
    }
}

impl Report for RepairReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        // The outcome rides on the one line that is always printed. Every block
        // below it is conditional, so a reader who does not already know which
        // ones are optional cannot tell a repair that restored nothing from one
        // that had nothing to restore — which is the whole of AAASM-5455.
        out.push_str(&format!(
            "{} — {}{}\n",
            self.tool_id,
            if self.dry_run { "repair preview" } else { "repair" },
            if self.nothing_to_repair.is_some() {
                " (nothing to repair)"
            } else {
                ""
            }
        ));
        bullets(&mut out, "Drifted", &self.drifted);
        if let Some(reason) = &self.nothing_to_repair {
            // Unconditional for this case, and phrased as a fact about the
            // host rather than about the command, so it reads the same way
            // `remove` states its own no-op.
            out.push_str(&format!("\nNothing was repaired: {reason}.\n"));
        }
        if self.dry_run {
            out.push_str("\nNothing has been changed. Re-run without --dry-run to restore the AASM-owned state.\n");
        } else {
            bullets(&mut out, "Restored", &self.repaired);
        }
        if !self.unresolved.is_empty() {
            out.push_str("\nLeft alone (not AASM's to change, or not repairable):\n");
            for row in &self.unresolved {
                out.push_str(&format!("  - {}: {}\n", row.capability, row.reason));
            }
            out.push_str(
                "  Protection is degraded while these stand; `aasm integrations status` shows what \
                 the evidence currently supports.\n",
            );
        }
        if let Some(status) = &self.status {
            out.push('\n');
            out.push_str(&status.render_human());
        }
        out
    }
}

impl Report for RemoveReport {
    fn render_human(&self) -> String {
        let mut out = String::new();
        // The plan identity rides on the one line that is always printed, so a
        // reader never has to work out which of the conditional blocks below
        // would have carried it. A run that authored no plan says so here in
        // the same shape `repair` states its own no-op (AAASM-5629).
        out.push_str(&format!(
            "{} — {} ({})\n",
            self.tool_id,
            if self.dry_run { "removal preview" } else { "removal" },
            match &self.plan_id {
                Some(id) => format!("plan {id}"),
                None => "nothing to remove".to_string(),
            }
        ));
        out.push_str("\nRestoration actions:\n");
        render_steps(&mut out, &self.steps);
        bullets(&mut out, "Left behind", &self.residual);
        bullets(&mut out, "Warnings", &self.warnings);
        if self.dry_run {
            out.push_str("\nNothing has been changed. Re-run without --dry-run to remove the integration.\n");
        } else {
            out.push_str("\nConfiguration Agent Assembly did not write has been left untouched.\n");
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::integrations::model::{Assertion, EvidenceRow, RuntimeInfo, VerifyReport};

    fn runtime() -> RuntimeInfo {
        RuntimeInfo {
            di_api_version: 2,
            core_version: "0.0.1".to_string(),
            degraded: false,
            unavailable_verbs: Vec::new(),
            started_by_this_command: false,
        }
    }

    fn vacuous() -> VerifyReport {
        VerifyReport {
            runtime: runtime(),
            tool_id: "claude-code".to_string(),
            verified_at_unix_secs: 1,
            outcome: "passed".to_string(),
            missing: Vec::new(),
            reason: None,
            protected_path_exercised: false,
            assertions: vec![Assertion {
                id: "protected_path_exercised".to_string(),
                holds: false,
                detail: "nothing protective was observed".to_string(),
            }],
            evidence: vec![EvidenceRow {
                mechanism: "managed_settings".to_string(),
                kind: "read_back".to_string(),
                outcome: "matched".to_string(),
                observed_at_unix_secs: 1,
                detail: "the managed keys match".to_string(),
            }],
        }
    }

    /// The human rendering must not let a vacuous pass read as a success. A
    /// user who sees "verification passed" and nothing else has been told
    /// something untrue.
    #[test]
    fn a_vacuous_pass_says_so_in_the_human_rendering() {
        let rendered = vacuous().render_human();
        assert!(rendered.contains("NOT a protection measurement"), "{rendered}");
        assert!(rendered.contains("protected path exercised: no"), "{rendered}");
    }

    /// A status whose adapter declared `support` about host enforcement, or
    /// declared nothing at all when `support` is `None`.
    fn status_declaring(support: Option<&str>) -> StatusReport {
        use aa_proto::assembly::devint::v1 as wire;

        let view = wire::StatusView {
            tool_id: "claude-code".to_string(),
            phase: "installed".to_string(),
            state: "ladder".to_string(),
            achieved_level: "gateway_protected".to_string(),
            planned_level: "gateway_protected".to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            compatibility: "compatible".to_string(),
            evidence: Vec::new(),
            next_level: None,
            observed_at_unix_secs: 1,
            drift_mismatched: Vec::new(),
            state_reason: String::new(),
            state_remediation: String::new(),
            policy: None,
        };
        let summary = support.map(|support| wire::ToolSummary {
            tool_id: "claude-code".to_string(),
            display_name: "Claude Code".to_string(),
            detected: true,
            detected_version: "2.1.220".to_string(),
            compatibility: "compatible".to_string(),
            capabilities: vec![wire::CapabilityView {
                capability: "host_enforcement".to_string(),
                support: support.to_string(),
                reason: String::new(),
            }],
            adapter_ceiling: "l2_enforce".to_string(),
        });
        StatusReport::from_view(runtime(), &view, summary.as_ref())
    }

    fn host_mark(report: &StatusReport) -> String {
        report
            .render_human()
            .lines()
            .find_map(|line| line.trim_start().strip_prefix("host_enforced"))
            .expect("the ladder must name host_enforced")
            .trim()
            .to_string()
    }

    /// Three availability states, three marks (AAASM-5454).
    ///
    /// Collapsing any two is the defect: "the adapter says this platform
    /// cannot" and "nobody declared anything" shared one mark, so a mechanism
    /// nobody had asked about was reported as impossible. A state this client
    /// did not establish must not borrow the wording of one it did.
    #[test]
    fn the_three_availability_states_render_as_three_distinct_marks() {
        let available = host_mark(&status_declaring(Some("supported")));
        let unsupported = host_mark(&status_declaring(Some("unsupported")));
        let unmeasured = host_mark(&status_declaring(None));

        assert_ne!(available, unsupported);
        assert_ne!(available, unmeasured);
        assert_ne!(
            unsupported, unmeasured,
            "a declared refusal and an absent declaration read as the same thing"
        );
        for mark in [&available, &unsupported, &unmeasured] {
            assert!(
                !mark.to_ascii_lowercase().contains("platform"),
                "the CLI made a claim about the host: {mark}"
            );
        }
    }

    /// Availability is a claim about a path; `active` is a claim about a
    /// measurement. Becoming available must never promote a rung to active.
    #[test]
    fn an_available_rung_never_renders_as_active() {
        let report = status_declaring(Some("supported"));
        assert_eq!(host_mark(&report), "not active");
        assert!(
            report.levels.iter().any(|l| l.level == "host_enforced" && l.available),
            "the rung under test was not the available one"
        );
    }

    /// Every field a person can read must be readable by a script, because both
    /// come out of one struct. Asserted on the JSON so a future `render_human`
    /// that computed something extra locally would show up here as a field the
    /// JSON does not have.
    #[test]
    fn the_json_and_the_human_rendering_agree_on_the_facts() {
        let report = vacuous();
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["protected_path_exercised"], serde_json::json!(false));
        assert_eq!(json["outcome"], serde_json::json!("passed"));
        assert_eq!(json["assertions"][0]["holds"], serde_json::json!(false));
        assert!(report.render_human().contains("passed"));
    }

    // ---- AAASM-5635: the integration state is wire vocabulary ----------------

    fn tool_list(state: Option<&str>) -> ToolListReport {
        use crate::commands::integrations::model::ToolRow;

        ToolListReport {
            runtime: runtime(),
            tools: vec![ToolRow {
                tool_id: "claude-code".to_string(),
                display_name: "Claude Code".to_string(),
                detected: true,
                detected_version: Some("2.1.220".to_string()),
                compatibility: "compatible".to_string(),
                adapter_ceiling: "l2_enforce".to_string(),
                capabilities: Vec::new(),
                lifecycle_phase: Some("detected_not_integrated".to_string()),
                integration_state: state.map(str::to_string),
                achieved_level: Some("detected_not_integrated".to_string()),
                warnings: Vec::new(),
            }],
        }
    }

    /// The `STATE` cell of the single row `tool_list` builds.
    fn state_cell(report: &ToolListReport) -> String {
        let rendered = report.render_human();
        let row = rendered
            .lines()
            .find(|line| line.starts_with("claude-code"))
            .expect("the listing must carry the row")
            .to_string();
        // TOOL(16) VERSION(12) COMPAT(12) then STATE(14), space-separated.
        row.split_whitespace()
            .nth(3)
            .expect("the row must have a STATE cell")
            .to_string()
    }

    /// `ladder` is the DI-API's token for "on the normal ladder — nothing
    /// anomalous". Printing it makes the reader infer the good case from the
    /// three bad ones they would have to already know (AAASM-5635).
    #[test]
    fn the_listing_never_prints_the_ladder_discriminator() {
        let rendered = tool_list(Some("ladder")).render_human();
        assert!(
            !rendered.contains("ladder"),
            "the internal state token reached the user: {rendered}"
        );
    }

    /// The value is correct and the separation is load-bearing: the three
    /// overriding states must stay distinguishable from the ordinary one and
    /// from each other after the rename.
    #[test]
    fn the_four_integration_states_stay_four_distinct_words() {
        let marks: Vec<String> = ["ladder", "drifted", "degraded", "incompatible"]
            .iter()
            .map(|state| state_cell(&tool_list(Some(state))))
            .collect();
        for (i, a) in marks.iter().enumerate() {
            for b in marks.iter().skip(i + 1) {
                assert_ne!(a, b, "two states collapsed onto one word: {marks:?}");
            }
        }
    }

    /// A token this build does not know must not be forwarded verbatim — that
    /// is how `ladder` reached a user in the first place. Naming it as
    /// unrecognized reports what the runtime said without pretending to read it.
    #[test]
    fn an_unknown_state_token_is_not_printed_verbatim() {
        let cell = state_cell(&tool_list(Some("quantum_entangled")));
        assert_ne!(cell, "quantum_entangled");
        let rendered = tool_list(Some("quantum_entangled")).render_human();
        assert!(rendered.contains("unrecognized"), "{rendered}");
        assert!(
            rendered.contains("quantum_entangled"),
            "the token itself must still be reported: {rendered}"
        );
    }

    /// The wire/JSON token is a public contract. Renaming what a person reads
    /// must not rename what a script branches on.
    #[test]
    fn the_listing_json_still_carries_the_wire_state_token() {
        let json = serde_json::to_value(tool_list(Some("ladder"))).expect("serialize");
        assert_eq!(json["tools"][0]["integration_state"], serde_json::json!("ladder"));
    }

    /// `status` prints the same discriminator on its own `state:` line.
    #[test]
    fn the_status_rendering_never_prints_the_ladder_discriminator() {
        let report = status_declaring(Some("supported"));
        assert_eq!(report.state, "ladder", "the fixture under test changed");
        let rendered = report.render_human();
        assert!(!rendered.contains("ladder"), "{rendered}");
    }

    /// And its JSON keeps the token, for the same reason.
    #[test]
    fn the_status_json_still_carries_the_wire_state_token() {
        let json = serde_json::to_value(status_declaring(Some("supported"))).expect("serialize");
        assert_eq!(json["state"], serde_json::json!("ladder"));
    }
}
