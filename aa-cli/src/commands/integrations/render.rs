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
    EvidenceRow, InstallReport, LevelAvailability, PlanReport, RemoveReport, RepairReport, RuntimeInfo, StatusReport,
    StepRow, ToolListReport, VerifyReport,
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

/// The one-line build identity under `list`'s banner (AAASM-5628).
///
/// The banner said only `core <version> (DI-API vN)`, which two checkouts share
/// — so a whole campaign was measured against the wrong build without anything
/// on screen disagreeing. The commit and the pid are what tell them apart.
fn runtime_identity_line(runtime: &RuntimeInfo) -> String {
    let provenance = &runtime.provenance;
    match (&provenance.build_sha, provenance.pid) {
        (Some(sha), Some(pid)) => format!(
            "  build {} · pid {pid} · {}{}",
            aa_runtime::devint::provenance::short_sha(sha),
            // The standing rides on the same line as the identity, so a reader
            // cannot take in the commit without taking in what it proves. A
            // build with no identity prints `unknown · unverifiable`, which is
            // the honest reading; printing only `unknown` would look like a
            // cosmetic gap rather than the absence of a guarantee.
            provenance.standing,
            if provenance.reachable_runtimes > 1 {
                format!(" · {} runtimes reachable", provenance.reachable_runtimes)
            } else {
                String::new()
            }
        ),
        // A runtime too old to say is named as such, never left blank: a blank
        // line reads as "nothing to report" rather than "it cannot tell you".
        _ => format!("  build unidentified ({})", provenance.verdict),
    }
}

/// The provenance block under `status`'s `Runtime:` heading.
fn render_runtime_provenance(out: &mut String, runtime: &RuntimeInfo) {
    let provenance = &runtime.provenance;
    match (&provenance.build_sha, provenance.pid) {
        (Some(sha), Some(pid)) => {
            out.push_str(&format!(
                "  build {sha}{}\n",
                match &provenance.build_id_source {
                    Some(source) => format!(" (via {source})"),
                    None => String::new(),
                }
            ));
            // Labelled `provenance:`, never `verified:`. The label used to be
            // the latter, which put the word "verified" beside every verdict
            // including the ones that are not — the exact shape AAASM-5628
            // forbids, since `verified: unverifiable` is read by eye as
            // "verified".
            out.push_str(&format!(
                "  pid {pid}, provenance: {} ({})\n",
                provenance.standing, provenance.verdict
            ));
            // Which facts were absent, matched or disagreed. Printed only when
            // there is something to explain, so a clean run stays quiet.
            if provenance.standing != "verified" {
                for field in &provenance.fields {
                    out.push_str(&format!(
                        "    {}: {} (this aasm {:?}, runtime {:?})\n",
                        field.field, field.status, field.expected, field.reported
                    ));
                }
            }
            if let Some(path) = &provenance.executable_path {
                out.push_str(&format!(
                    "  executable: {path}{}\n",
                    match provenance.executable_present {
                        Some(false) => " (DELETED)",
                        _ => "",
                    }
                ));
            }
            if let Some(source) = provenance.source_path.as_ref().filter(|s| !s.is_empty()) {
                out.push_str(&format!("  built from: {source}\n"));
            }
            if let Some(started) = provenance.started_at_unix_secs {
                // Uses the shared human timestamp (AAASM-5636); a provenance
                // block is no more entitled to print a bare epoch than any
                // other reading a person has to act on.
                out.push_str(&format!("  started at: {}\n", timestamp(started)));
            }
        }
        _ => out.push_str(&format!("  build unidentified ({})\n", provenance.verdict)),
    }
    if provenance.reachable_runtimes > 1 {
        out.push_str(&format!(
            "  ! {} runtimes are reachable — this result names the one above, not the others\n",
            provenance.reachable_runtimes
        ));
    }
}

/// The standing of the runtime that produced a report, stated on **stdout**
/// above the claims a reader is about to believe (AAASM-5628).
///
/// # Why every rendering needs this, not just `status`
///
/// `status` carried a caveat from the start and the other four renderings did
/// not, so `aasm integrations plan` — which is read-only and therefore
/// *proceeds* under an unverifiable standing — printed `planned level:
/// host_enforced` with nothing beside it, and the only disagreement was a line
/// on stderr. That is precisely the shape `session::guard_provenance`'s own doc
/// comment refuses to ship: "a warning on stderr beside a confident answer on
/// stdout is exactly the shape that got mistaken for a regression".
///
/// `verify` was the sharpest case. Under `--allow-unverified-runtime` a
/// **refuted** runtime — one shown to be a different build — produced
/// `verification passed`, `[ok] protected_path_exercised` and exit 0, with
/// nothing on stdout saying which build had been measured.
///
/// It is also what makes the documented promise true. `IntegrationsArgs`'
/// `--allow-unverified-runtime` help and the CLI reference both say the flag
/// "changes whether the command proceeds, never what it reports" — true of
/// `--output json`, which carries the standing on every report, and false of
/// the table rendering until this function existed.
///
/// `subject` names what the caveat is about, so each command says what its own
/// output is ("this plan", "this verification"). Quiet when the standing is
/// `verified`, so an ordinary run is not hedged.
fn render_provenance_caveat(out: &mut String, runtime: &RuntimeInfo, subject: &str) {
    let provenance = &runtime.provenance;
    if provenance.standing == "verified" {
        return;
    }
    out.push_str(&format!(
        "\n! The Agent Assembly runtime that produced {subject} is {} ({}), so none of it is \
         attributable to this build — read it as reported, not established.\n  {}\n",
        provenance.standing, provenance.verdict, provenance.detail
    ));
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
            "Agent Assembly core {} (DI-API v{})\n{}\n\n",
            self.runtime.core_version,
            self.runtime.di_api_version,
            runtime_identity_line(&self.runtime)
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
        // `plan` is read-only, so it proceeds under an unverifiable standing —
        // which means `planned level:` below is a claim about whatever host the
        // answering runtime is on. Stated before the block rather than after it.
        // Skipped when the plan has been applied: `InstallReport` embeds this
        // rendering and states the caveat once, against the installation.
        if !self.applied {
            render_provenance_caveat(&mut out, &self.runtime, "this plan");
        }
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
        // `achieved level:` below is the strongest claim this command makes, and
        // an install only reaches an unidentified runtime through
        // `--allow-unverified-runtime` — so the standing is stated once here,
        // against the installation, rather than twice via the embedded plan.
        render_provenance_caveat(&mut out, &self.plan.runtime, "this installation");
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
        render_runtime_provenance(&mut out, &self.runtime);
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

        // AAASM-5628: `status` is read-only, so it answers even when the runtime
        // that produced these levels could not be identified. What it must not
        // do is let `host_enforced  active` stand as an *established* claim
        // about this host — every line below describes whatever host that
        // runtime is on. Naming it here, immediately above the ladder, rather
        // than only in the `Runtime:` block a reader may have scrolled past.
        render_provenance_caveat(&mut out, &self.runtime, "the reading below");
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
        // Immediately under the outcome word, because `verification passed`
        // followed by `[ok] protected_path_exercised` is the most confident
        // thing this family prints — and under `--allow-unverified-runtime` it
        // was printed for a runtime shown to be a *different build*, with the
        // only contradiction on stderr.
        render_provenance_caveat(&mut out, &self.runtime, "this verification");
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
        // `repair` states what it restored on this host, so the standing rides
        // above that claim. Stated even when a `StatusReport` is embedded below
        // — that one is a nested report carrying its own caveat above its own
        // ladder, and it is not always present (a runtime that answers the
        // repair verb without a status view leaves it `None`).
        render_provenance_caveat(&mut out, &self.runtime, "this repair");
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
        // The restoration actions below describe the host the answering runtime
        // is on, and removal reaches an unidentified runtime only through
        // `--allow-unverified-runtime`.
        render_provenance_caveat(&mut out, &self.runtime, "this removal plan");
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
    use crate::commands::integrations::model::{
        Assertion, EvidenceRow, RuntimeInfo, RuntimeProvenanceInfo, VerifyReport,
    };

    fn runtime() -> RuntimeInfo {
        RuntimeInfo {
            di_api_version: 2,
            core_version: "0.0.1".to_string(),
            degraded: false,
            unavailable_verbs: Vec::new(),
            started_by_this_command: false,
            provenance: RuntimeProvenanceInfo {
                standing: "verified".to_string(),
                verdict: "verified".to_string(),
                build_id_source: Some("checkout".to_string()),
                fields: Vec::new(),
                detail: "the Agent Assembly runtime answering is 0.0.1 (abcdef012345) (pid 4242)".to_string(),
                build_sha: Some("abcdef0123456789".to_string()),
                pid: Some(4242),
                executable_path: Some("/build/target/debug/aa-runtime".to_string()),
                executable_present: Some(true),
                source_path: Some("/build".to_string()),
                started_at_unix_secs: Some(1_700_000_000),
                reachable_runtimes: 1,
            },
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
        status_declaring_on(runtime(), support)
    }

    /// [`status_declaring`] against a chosen runtime, so the provenance tests
    /// can vary the standing without a second fixture.
    fn status_declaring_on(runtime: RuntimeInfo, support: Option<&str>) -> StatusReport {
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
        StatusReport::from_view(runtime, &view, summary.as_ref())
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
        tool_list_on(runtime(), state)
    }

    /// [`tool_list`] against a chosen runtime.
    fn tool_list_on(runtime: RuntimeInfo, state: Option<&str>) -> ToolListReport {
        use crate::commands::integrations::model::ToolRow;

        ToolListReport {
            runtime,
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

    // ---- AAASM-5636: bare unix epochs in the human rendering -----------------

    /// Seconds since the epoch, `age` seconds ago.
    fn secs_ago(age: u64) -> u64 {
        u64::try_from(chrono::Utc::now().timestamp()).expect("a clock before 1970") - age
    }

    /// The text after `label:` on the first line carrying it.
    fn labelled(rendered: &str, label: &str) -> String {
        rendered
            .lines()
            .find_map(|line| line.trim_start().strip_prefix(label))
            .unwrap_or_else(|| panic!("no `{label}` line in:\n{rendered}"))
            .trim()
            .to_string()
    }

    /// A rendering a person can date without a converter: absolute local time,
    /// and how old the reading is.
    fn assert_reads_as_a_time(value: &str) {
        assert!(
            value
                .split_whitespace()
                .next()
                .is_some_and(|first| first.parse::<u64>().is_err()),
            "a bare epoch integer reached the user: {value}"
        );
        assert!(!value.contains("(unix)"), "still labelled as a unix epoch: {value}");
        assert!(
            value.contains('-') && value.contains(':'),
            "no absolute time in: {value}"
        );
        assert!(
            value.contains("ago") || value.contains("just now") || value.contains("from now"),
            "no relative age in: {value}"
        );
    }

    /// A status whose reading and evidence are four minutes old.
    fn status_observed_at(observed: u64) -> StatusReport {
        use aa_proto::assembly::devint::v1 as wire;

        let view = wire::StatusView {
            tool_id: "claude-code".to_string(),
            phase: "installed".to_string(),
            state: "ladder".to_string(),
            achieved_level: "partially_integrated".to_string(),
            planned_level: "gateway_protected".to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            compatibility: "compatible".to_string(),
            evidence: vec![wire::EvidenceView {
                mechanism: "managed_settings".to_string(),
                kind: "read_back".to_string(),
                outcome: "matched".to_string(),
                observed_at_unix_secs: observed,
                detail: "the managed keys match".to_string(),
            }],
            next_level: None,
            observed_at_unix_secs: observed,
            drift_mismatched: Vec::new(),
            state_reason: String::new(),
            state_remediation: String::new(),
            policy: None,
        };
        StatusReport::from_view(runtime(), &view, None)
    }

    /// `observed at: 1785983102 (unix)` is a number a person has to go and
    /// convert. Freshness is the question this command exists to answer, so the
    /// age must be on the line too (AAASM-5636).
    #[test]
    fn the_status_reading_is_dated_in_local_time_with_its_age() {
        let rendered = status_observed_at(secs_ago(4 * 60)).render_human();
        let observed = labelled(&rendered, "observed at:");
        assert_reads_as_a_time(&observed);
        assert!(observed.contains("4 minutes ago"), "{observed}");
    }

    /// Every timestamp in the family, not just the one the bug named.
    #[test]
    fn the_last_verification_and_the_evidence_rows_are_dated_the_same_way() {
        let rendered = status_observed_at(secs_ago(90 * 60)).render_human();
        assert_reads_as_a_time(&labelled(&rendered, "last verification:"));

        let evidence = rendered
            .lines()
            .find(|line| line.contains("managed_settings"))
            .expect("the read-back row must be rendered");
        assert!(
            !evidence.contains(" at 1"),
            "an epoch integer survived on the evidence row: {evidence}"
        );
        assert!(
            evidence.contains("hour"),
            "no relative age on the evidence row: {evidence}"
        );
    }

    /// `verify` dates its run the same way.
    #[test]
    fn a_verification_run_is_dated_in_local_time_with_its_age() {
        let mut report = vacuous();
        report.verified_at_unix_secs = secs_ago(30);
        report.evidence[0].observed_at_unix_secs = report.verified_at_unix_secs;
        let rendered = report.render_human();
        assert_reads_as_a_time(&labelled(&rendered, "ran at:"));
    }

    /// The relative half is what a reader acts on, so its wording is asserted
    /// against a fixed clock rather than the machine's.
    #[test]
    fn the_age_is_worded_from_the_distance_to_now() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("a representable now");
        for (observed, expected) in [
            (1_700_000_000_u64, "just now"),
            (1_699_999_760, "4 minutes ago"),
            (1_699_996_400, "1 hour ago"),
            (1_699_913_600, "1 day ago"),
            (1_700_000_600, "10 minutes from now"),
        ] {
            let rendered = timestamp_at(observed, now);
            assert!(rendered.ends_with(&format!("({expected})")), "{observed}: {rendered}");
        }
    }

    /// A value no calendar can name says so rather than being given a date.
    #[test]
    fn a_timestamp_with_no_calendar_date_is_reported_not_guessed() {
        let now = DateTime::from_timestamp(1_700_000_000, 0).expect("a representable now");
        let rendered = timestamp_at(u64::MAX, now);
        assert!(rendered.contains("outside the representable range"), "{rendered}");
    }

    // ---- AAASM-5628: every rendering states which build produced it ---------

    /// A runtime shown to be a *different* build — the `refuted` standing.
    fn refuted_runtime() -> RuntimeInfo {
        RuntimeInfo {
            provenance: RuntimeProvenanceInfo {
                standing: "refuted".to_string(),
                verdict: "mismatch".to_string(),
                detail: "the Agent Assembly runtime answering (pid 87718) is 0.0.1 (111111111111 via checkout), \
                         not the 0.0.1 (abcdef012345 via checkout) this aasm was built with"
                    .to_string(),
                build_sha: Some("1111111111111111".to_string()),
                pid: Some(87_718),
                ..runtime().provenance
            },
            ..runtime()
        }
    }

    fn plan_report(runtime: RuntimeInfo, applied: bool) -> PlanReport {
        PlanReport {
            runtime,
            schema_version: 1,
            plan_id: "plan-1".to_string(),
            tool_id: "claude-code".to_string(),
            profile: "recommended".to_string(),
            settings_scope: "managed".to_string(),
            policy_profile: None,
            planned_level: "host_enforced".to_string(),
            adapter_ceiling: "l2_enforce".to_string(),
            steps: Vec::new(),
            unsupported: Vec::new(),
            warnings: Vec::new(),
            required_permissions: Vec::new(),
            applied,
        }
    }

    fn install_report(runtime: RuntimeInfo) -> InstallReport {
        InstallReport {
            plan: plan_report(runtime, true),
            receipt_id: "receipt-1".to_string(),
            applied_at_unix_secs: 1,
            steps: Vec::new(),
            planned_level: "host_enforced".to_string(),
            achieved_level: "host_enforced".to_string(),
        }
    }

    fn remove_report(runtime: RuntimeInfo) -> RemoveReport {
        RemoveReport {
            runtime,
            tool_id: "claude-code".to_string(),
            dry_run: false,
            plan_id: Some("removal-1".to_string()),
            steps: Vec::new(),
            residual: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn repair_report(runtime: RuntimeInfo) -> RepairReport {
        RepairReport {
            runtime,
            tool_id: "claude-code".to_string(),
            dry_run: false,
            drifted: Vec::new(),
            repaired: Vec::new(),
            unresolved: Vec::new(),
            nothing_to_repair: Some("no receipt accounts for this tool".to_string()),
            status: None,
        }
    }

    /// A verification that passed **and** exercised the protected path — the
    /// most confident output this family produces.
    fn confident_pass(runtime: RuntimeInfo) -> VerifyReport {
        VerifyReport {
            runtime,
            protected_path_exercised: true,
            assertions: vec![Assertion {
                id: "protected_path_exercised".to_string(),
                holds: true,
                detail: "the synthetic secret was redacted".to_string(),
            }],
            ..vacuous()
        }
    }

    /// Every rendering, on a refuted runtime, keyed by what a user would type.
    fn every_rendering(runtime: &RuntimeInfo) -> Vec<(&'static str, String)> {
        vec![
            ("plan", plan_report(runtime.clone(), false).render_human()),
            ("install", install_report(runtime.clone()).render_human()),
            ("verify", confident_pass(runtime.clone()).render_human()),
            ("repair", repair_report(runtime.clone()).render_human()),
            ("remove", remove_report(runtime.clone()).render_human()),
            (
                "status",
                status_declaring_on(runtime.clone(), Some("supported")).render_human(),
            ),
            ("list", tool_list_on(runtime.clone(), Some("ladder")).render_human()),
        ]
    }

    /// The defect: only `list` and `status` said which build had answered, so
    /// `plan`, `install`, `verify`, `repair` and `remove` printed a confident
    /// answer on stdout with the contradiction only on stderr.
    #[test]
    fn every_human_rendering_names_the_standing_of_the_runtime_that_produced_it() {
        let runtime = refuted_runtime();
        for (command, rendered) in every_rendering(&runtime) {
            assert!(
                rendered.contains("refuted"),
                "`{command}` printed a result without saying the runtime was refuted:\n{rendered}"
            );
        }
    }

    /// …and a verified runtime is not hedged, so the caveat stays a signal.
    #[test]
    fn a_verified_runtime_adds_no_caveat_to_any_rendering() {
        for (command, rendered) in every_rendering(&runtime()) {
            assert!(
                !rendered.contains("attributable to this build"),
                "`{command}` hedged a verified result:\n{rendered}"
            );
        }
    }

    /// The index of `needle` in `rendered`, or a panic naming the whole output.
    fn at(rendered: &str, needle: &str) -> usize {
        rendered
            .find(needle)
            .unwrap_or_else(|| panic!("{needle:?} is not in:\n{rendered}"))
    }

    /// `plan` is read-only, so it *proceeds* under an unverifiable standing and
    /// prints `planned level: host_enforced` — a claim about whatever host the
    /// answering runtime is on. The caveat has to come first, or the reader has
    /// already believed it.
    #[test]
    fn a_plan_states_the_standing_above_its_planned_level() {
        let rendered = plan_report(refuted_runtime(), false).render_human();
        assert!(
            at(&rendered, "attributable to this build") < at(&rendered, "planned level:"),
            "{rendered}"
        );
    }

    /// The sharpest case in the ticket: under `--allow-unverified-runtime`,
    /// `verify` against a runtime shown to be a **different build** printed
    /// `verification passed`, `[ok] protected_path_exercised` and exit 0, with
    /// nothing on stdout saying so.
    ///
    /// The pass is still reported — the flag is documented as changing whether
    /// the command proceeds, not what it concludes — but it can no longer be
    /// read without the standing.
    #[test]
    fn a_pass_against_a_refuted_runtime_says_which_build_was_measured() {
        let rendered = confident_pass(refuted_runtime()).render_human();
        assert!(rendered.contains("verification passed"), "{rendered}");
        assert!(
            rendered.contains("[ok] protected_path_exercised"),
            "the fixture must be the confident one, or this test proves nothing: {rendered}"
        );
        assert!(
            at(&rendered, "refuted") < at(&rendered, "[ok] protected_path_exercised"),
            "the standing must precede the assertion a reader acts on: {rendered}"
        );
        assert!(
            rendered.contains("87718"),
            "the answering process must be nameable from stdout alone: {rendered}"
        );
    }

    /// `install` and `remove` change host state; the standing rides above the
    /// levels and the actions they report.
    #[test]
    fn install_and_remove_state_the_standing_above_what_they_claim_to_have_done() {
        let install = install_report(refuted_runtime()).render_human();
        assert!(
            at(&install, "attributable to this build") < at(&install, "achieved level:"),
            "{install}"
        );

        let remove = remove_report(refuted_runtime()).render_human();
        assert!(
            at(&remove, "attributable to this build") < at(&remove, "Restoration actions:"),
            "{remove}"
        );
    }

    /// The integers are the contract `--output json` publishes. A human-side
    /// rename must leave every one of them exactly as it was.
    #[test]
    fn the_json_timestamps_stay_integers() {
        let observed = secs_ago(4 * 60);
        let json = serde_json::to_value(status_observed_at(observed)).expect("serialize");
        assert_eq!(json["observed_at_unix_secs"], serde_json::json!(observed));
        assert_eq!(json["last_verified_at_unix_secs"], serde_json::json!(observed));
        assert_eq!(
            json["read_back_evidence"][0]["observed_at_unix_secs"],
            serde_json::json!(observed)
        );

        let verify = serde_json::to_value(vacuous()).expect("serialize");
        assert_eq!(verify["verified_at_unix_secs"], serde_json::json!(1));
        assert_eq!(verify["evidence"][0]["observed_at_unix_secs"], serde_json::json!(1));
    }
}
