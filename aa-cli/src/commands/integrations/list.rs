//! `aasm integrations list` — what is here, and what is protecting it.
//!
//! Two DI-API reads per tool, deliberately: `list_tools` answers "what does
//! this build know about, and what did it find", and `status` answers "and what
//! is currently true". A list that showed only the first would tell a user
//! their tool is supported while saying nothing about whether it is protected,
//! which is the question they actually came with.

use std::process::ExitCode;

use clap::Args;

use crate::output::OutputFormat;

use super::model::{Capability, RuntimeInfo, ToolListReport, ToolRow};
use super::render::emit;
use super::session::SessionOptions;
use super::target::Target;
use super::{exit::Outcome, open, run_blocking, verb_failure};

/// `aasm integrations list` arguments.
#[derive(Args)]
pub struct ListArgs {
    /// Show every declared mechanism per tool, not just the summary row.
    #[arg(long)]
    pub capabilities: bool,
}

/// Run `aasm integrations list`.
pub fn run(args: ListArgs, options: SessionOptions, output: OutputFormat) -> ExitCode {
    run_blocking(async move {
        let mut session = open(options).await?;
        let target = Target::here()?;
        let runtime = RuntimeInfo::from_session(&session);
        let tools = session.client.list_tools().await.map_err(verb_failure)?;

        let mut rows = Vec::with_capacity(tools.tools.len());
        let mut any_drift = false;
        for summary in &tools.tools {
            // A status read can legitimately fail for a tool nothing has been
            // applied to, and that is not a reason to fail the whole listing —
            // the row simply carries no integration state.
            let status = session.client.status(&summary.tool_id, target.as_request()).await.ok();
            let warnings = collect_tool_warnings(summary, status.as_ref(), &mut any_drift);
            rows.push(build_tool_row(summary, status.as_ref(), warnings, args.capabilities));
        }

        emit(&ToolListReport { runtime, tools: rows }, output);
        // Drift is reported, not hidden behind a zero exit: a listing that
        // exits 0 while something has drifted trains a script to ignore it.
        Ok(if any_drift { Outcome::Drifted } else { Outcome::Success })
    })
}

/// Warnings a single tool's row should carry, derived from its status read and
/// the summary's compatibility. Sets `any_drift` when a drifted status is seen.
fn collect_tool_warnings(
    summary: &aa_proto::assembly::devint::v1::ToolSummary,
    status: Option<&aa_proto::assembly::devint::v1::StatusView>,
    any_drift: &mut bool,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(status) = status {
        if status.state == "drifted" {
            *any_drift = true;
            warnings.push(format!(
                "drifted: {} — run `aasm integrations repair {}`",
                status.drift_mismatched.join(", "),
                summary.tool_id
            ));
        }
        if status.state == "degraded" && !status.state_reason.is_empty() {
            warnings.push(format!("degraded: {}", status.state_reason));
        }
        if status.state == "incompatible" && !status.state_reason.is_empty() {
            warnings.push(format!("incompatible: {}", status.state_reason));
        }
    }
    if summary.compatibility == "incompatible" {
        warnings.push("the detected version is outside the adapter's supported range".to_string());
    }
    if summary.compatibility == "unknown" && summary.detected {
        warnings.push("the tool's version could not be read, so compatibility is unresolved".to_string());
    }
    warnings
}

/// Assemble the [`ToolRow`] for one tool from its summary, optional status, and
/// pre-collected warnings.
fn build_tool_row(
    summary: &aa_proto::assembly::devint::v1::ToolSummary,
    status: Option<&aa_proto::assembly::devint::v1::StatusView>,
    warnings: Vec<String>,
    with_capabilities: bool,
) -> ToolRow {
    ToolRow {
        tool_id: summary.tool_id.clone(),
        display_name: summary.display_name.clone(),
        detected: summary.detected,
        detected_version: (!summary.detected_version.is_empty()).then(|| summary.detected_version.clone()),
        compatibility: summary.compatibility.clone(),
        adapter_ceiling: summary.adapter_ceiling.clone(),
        capabilities: if with_capabilities {
            summary.capabilities.iter().map(Capability::from).collect()
        } else {
            // Kept out of the default listing rather than out of the
            // model: `--capabilities` widens what is shown, and JSON
            // consumers ask for it explicitly rather than paying for
            // twelve rows per tool they did not want.
            Vec::new()
        },
        lifecycle_phase: status.map(|s| s.phase.clone()),
        integration_state: status.map(|s| s.state.clone()),
        achieved_level: status.map(|s| s.achieved_level.clone()),
        warnings,
    }
}
