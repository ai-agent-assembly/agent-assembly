//! `aasm receipt inspect` — forensic reconstruction surfaces over a stored
//! execution receipt (AAASM-6172, parent Epic AAASM-6159).
//!
//! This module starts with the renderer alone: pure functions over an
//! already-sealed [`ReceiptEnvelope`] and an already-computed defect list,
//! with no opinion yet on *when* they're safe to call — that gate lands in a
//! later commit (see this module's doc comment there for the full Gate
//! A/Gate B design).
//!
//! # The `workspace.diff_digest` correctness fix
//!
//! [`super::project::workspace_binding`] computes `diff_digest` from
//! `outcome.sorted_changes` unconditionally — and
//! `run_workspace_tx::settle`'s own refused/discarded branches always
//! construct `sorted_changes: Vec::new()` (never populated from a real
//! change set unless `commit()` succeeds), so every receipt whose
//! transaction did not commit carries the *same* digest: the digest of an
//! empty list. Rendering that value unlabeled would misrepresent a constant
//! as if it meant something about this specific run. [`render_workspace`]
//! and [`suppress_diff_digest_if_not_committed`] both withhold it whenever
//! `workspace.committed != Some(true)`.
use super::host;
use super::schema::{ReceiptEnvelope, WorkspaceBinding};
use super::text::ReceiptText;
use super::validate::ReceiptDefect;

fn text_or_withheld(t: &ReceiptText) -> String {
    t.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "<withheld>".to_string())
}

fn opt_text_or(t: Option<&ReceiptText>, absent: &str) -> String {
    t.map(text_or_withheld).unwrap_or_else(|| absent.to_string())
}

fn join_texts(items: &[ReceiptText]) -> String {
    if items.is_empty() {
        return "(none)".to_string();
    }
    items.iter().map(text_or_withheld).collect::<Vec<_>>().join(",")
}

/// Render a receipt's full body as the `[section]`-grouped `key=value` text
/// report. `findings` (Gate B's output) appears as its own top-level section
/// immediately after the seal/schema line — never a footnote.
fn render_text(envelope: &ReceiptEnvelope, defects: &[ReceiptDefect]) -> String {
    let body = &envelope.body;
    let mut out = String::new();

    out.push_str(&format!("schema={}\n", envelope.schema));
    out.push_str("seal=holds\n");
    if defects.is_empty() {
        out.push_str("findings: none\n");
    } else {
        out.push_str("findings:\n");
        for d in defects {
            out.push_str(&format!("  - {d}\n"));
        }
    }

    out.push_str(&format!("\nrun_id={}\n", body.run_id));
    out.push_str(&format!("trace_id={}\n", body.trace_id));
    out.push_str(&format!("recorded_at_unix_secs={}\n", body.recorded_at_unix_secs));
    out.push_str(&format!("posture={}\n", body.posture()));
    out.push_str(&format!("elapsed_secs={}\n", body.elapsed_secs()));
    out.push_str(&format!("is_least_authority={}\n", body.is_least_authority()));

    out.push_str("\n[identity]\n");
    out.push_str(&format!(
        "agent_id={}\n",
        text_or_withheld(&body.asserted_identity.agent_id)
    ));
    out.push_str(&format!(
        "team_id={}\n",
        opt_text_or(body.asserted_identity.team_id.as_ref(), "<none>")
    ));
    out.push_str(&format!("depth={}\n", body.asserted_identity.depth));
    out.push_str(&format!("lineage={}\n", join_texts(&body.asserted_identity.lineage)));

    out.push_str("\n[producer]\n");
    out.push_str(&format!("component={}\n", text_or_withheld(&body.producer.component)));
    out.push_str(&format!("release={}\n", text_or_withheld(&body.producer.release)));
    out.push_str(&format!(
        "source_revision={}\n",
        opt_text_or(
            body.producer.source_revision.as_ref(),
            "<unavailable: no build script records one>"
        )
    ));

    out.push_str("\n[policy]\n");
    out.push_str(&format!(
        "canonical_digest={}\n",
        body.policy
            .canonical_digest
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<unavailable>".to_string())
    ));
    out.push_str(&format!(
        "source={}\n",
        opt_text_or(body.policy.source.as_ref(), "<unavailable>")
    ));
    out.push_str(&format!("resolution={}\n", text_or_withheld(&body.policy.resolution)));
    out.push_str(&format!("unmapped={}\n", join_texts(&body.policy.unmapped)));

    out.push_str("\n[spec]\n");
    out.push_str(&format!("digest={}\n", body.spec.digest));
    out.push_str(&format!("program={}\n", text_or_withheld(&body.spec.program)));
    out.push_str(&format!("arg_count={}\n", body.spec.arg_count));
    out.push_str(&format!("argv_digest={}\n", body.spec.argv_digest));
    out.push_str(&format!(
        "working_dir_digest={}\n",
        body.spec
            .working_dir_digest
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<unavailable: no working directory was set>".to_string())
    ));
    out.push_str(&format!("required_count={}\n", body.spec.required_count));
    out.push_str(&format!("optional_count={}\n", body.spec.optional_count));
    out.push_str(&format!(
        "degrade_if_unavailable_count={}\n",
        body.spec.degrade_if_unavailable_count
    ));

    out.push_str("\n[backend]\n");
    match &body.backend {
        Some(b) => {
            out.push_str(&format!("id={}\n", text_or_withheld(&b.id)));
            out.push_str(&format!("version={}\n", text_or_withheld(&b.version)));
            out.push_str(&format!(
                "provenance_source={}\n",
                text_or_withheld(&b.provenance_source)
            ));
            out.push_str(&format!(
                "provenance_license={}\n",
                text_or_withheld(&b.provenance_license)
            ));
            out.push_str(&format!("provenance_modified={}\n", b.provenance_modified));
            out.push_str(&format!(
                "platform_boundary={}\n",
                text_or_withheld(&b.platform_boundary)
            ));
            out.push_str(&format!(
                "selection_mode={}\n",
                opt_text_or(b.selection_mode.as_ref(), "<unavailable: no automatic selection ran>")
            ));
            for c in &b.considered {
                out.push_str(&format!(
                    "considered: id={} verdict={} unmet_domains={}\n",
                    text_or_withheld(&c.id),
                    text_or_withheld(&c.verdict),
                    join_texts(&c.unmet_domains)
                ));
            }
        }
        None => out.push_str("<unavailable: no execution-isolation boundary ran>\n"),
    }

    out.push_str("\n[host]\n");
    for f in &body.host {
        out.push_str(&format!("{}: {}\n", host_fact_name_token(f.name), host_fact_render(f)));
    }

    out.push_str("\n[runtime_image]\n");
    match &body.runtime_image {
        Some(d) => out.push_str(&format!("{d}\n")),
        None => out.push_str("<not recorded: no backend computes a guest/runtime-image digest today>\n"),
    }

    out.push_str("\n[leases]\n");
    if body.leases.is_empty() {
        out.push_str("(none)\n");
    } else {
        for l in &body.leases {
            out.push_str(&format!(
                "- lease_id={} domain={} digest={} derived_from_lease_id={} inheritance_mode={}\n",
                text_or_withheld(&l.lease_id),
                text_or_withheld(&l.domain),
                l.digest,
                opt_text_or(l.derived_from_lease_id.as_ref(), "<none>"),
                opt_text_or(l.inheritance_mode.as_ref(), "<none>"),
            ));
        }
    }

    out.push_str("\n[domains]\n");
    for d in &body.domains {
        out.push_str(&format!(
            "- domain={} requested={} state={} claim={} evidence_basis={} prevention_supported={} \
             independently_verified={}\n",
            text_or_withheld(&d.domain),
            text_or_withheld(&d.requested),
            text_or_withheld(&d.state),
            text_or_withheld(&d.claim),
            text_or_withheld(&d.evidence_basis),
            d.prevention_supported,
            d.independently_verified,
        ));
    }

    out.push_str("\n[credentials]\n");
    out.push_str(&format!("removed={}\n", join_texts(&body.credentials.removed)));
    out.push_str(&format!("delegated={}\n", join_texts(&body.credentials.delegated)));
    out.push_str(&format!(
        "ambient_unremoved={}\n",
        join_texts(&body.credentials.ambient_unremoved)
    ));

    out.push_str("\n[workspace]\n");
    render_workspace(&mut out, body.workspace.as_ref());

    out.push_str("\n[host_capability]\n");
    match &body.host_capability {
        Some(hc) => {
            out.push_str(&format!("posture={}\n", text_or_withheld(&hc.posture)));
            out.push_str(&format!("broker_available={}\n", hc.broker_available));
            out.push_str(&format!("toolchain={}\n", join_texts(&hc.toolchain)));
            out.push_str(&format!("requested={}\n", join_texts(&hc.requested)));
            for a in &hc.achieved {
                out.push_str(&format!(
                    "achieved: kind={} exit_code={} argv_digest={} output_truncated={}\n",
                    text_or_withheld(&a.kind),
                    a.exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "<unavailable>".to_string()),
                    a.argv_digest,
                    a.output_truncated
                ));
            }
            out.push_str(&format!("refused={}\n", join_texts(&hc.refused)));
        }
        None => out.push_str("<not recorded: no host-capability contract applied to this run>\n"),
    }

    out.push_str("\n[execution]\n");
    out.push_str(&format!(
        "started_at_unix_secs={}\n",
        body.execution.started_at_unix_secs
    ));
    out.push_str(&format!("ended_at_unix_secs={}\n", body.execution.ended_at_unix_secs));
    out.push_str(&format!(
        "exit_code={}\n",
        body.execution
            .exit_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "<unavailable: see TerminationRecord — None does not mean failure>".to_string())
    ));
    out.push_str(&format!(
        "no_code_detail={}\n",
        opt_text_or(body.execution.no_code_detail.as_ref(), "<none>")
    ));
    out.push_str(&format!("termination={:?}\n", body.execution.termination));

    out.push_str("\n[degraded]\n");
    if body.degraded.is_empty() {
        out.push_str("(none)\n");
    } else {
        for d in &body.degraded {
            out.push_str(&format!(
                "- domain={} kind={:?} detail={}\n",
                opt_text_or(d.domain.as_ref(), "<run>"),
                d.kind,
                text_or_withheld(&d.detail)
            ));
        }
    }

    out.push_str("\n[withheld_fields]\n");
    if body.withheld_fields.is_empty() {
        out.push_str("(none)\n");
    } else {
        out.push_str(&format!(
            "{}\n",
            body.withheld_fields
                .iter()
                .map(|f| format!("{f:?}"))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }

    out.push_str("\n[evidence_refs]\n");
    if body.evidence_refs.is_empty() {
        out.push_str("(none)\n");
    } else {
        for e in &body.evidence_refs {
            out.push_str(&format!(
                "- kind={} domain={} claim={} detail_digest={}\n",
                text_or_withheld(&e.kind),
                opt_text_or(e.domain.as_ref(), "<none>"),
                text_or_withheld(&e.claim),
                e.detail_digest
            ));
        }
    }

    out
}

/// Render `[workspace]`. The load-bearing correctness fix: `diff_digest` (and
/// `result_digest`) are suppressed with an explicit "not meaningful" label
/// whenever `committed != Some(true)` — see this module's doc comment for
/// why the stored value would otherwise be the same constant on every
/// non-committed receipt.
fn render_workspace(out: &mut String, workspace: Option<&WorkspaceBinding>) {
    let Some(w) = workspace else {
        out.push_str("<not recorded: --workspace-tx was not passed>\n");
        return;
    };

    out.push_str(&format!(
        "committed={}\n",
        w.committed
            .map(|b| b.to_string())
            .unwrap_or_else(|| "<unavailable: the transaction never reached a settle decision>".to_string())
    ));
    out.push_str(&format!(
        "refusal_kind={}\n",
        opt_text_or(w.refusal_kind.as_ref(), "<none>")
    ));
    out.push_str(&format!(
        "base_digest={}\n",
        w.base_digest
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<unavailable>".to_string())
    ));

    if w.committed == Some(true) {
        out.push_str(&format!(
            "result_digest={}\n",
            w.result_digest
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<unavailable>".to_string())
        ));
        out.push_str(&format!(
            "diff_digest={}\n",
            w.diff_digest
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "<unavailable>".to_string())
        ));
    } else {
        out.push_str("result_digest=<not meaningful: transaction did not commit>\n");
        out.push_str(
            "diff_digest=<not meaningful: transaction did not commit — the stored value is the constant digest of \
             an empty change set, not a diff of this run>\n",
        );
    }

    out.push_str(&format!("added_count={}\n", w.added_count));
    out.push_str(&format!("modified_count={}\n", w.modified_count));
    out.push_str(&format!("deleted_count={}\n", w.deleted_count));
    out.push_str(&format!("surface_excluded_count={}\n", w.surface_excluded_count));
    out.push_str(&format!("protected_selector_count={}\n", w.protected_selector_count));
    out.push_str(&format!("approval_presented={}\n", w.approval_presented));
    out.push_str(&format!(
        "not_transactional={}\n",
        w.not_transactional
            .iter()
            .filter_map(ReceiptText::as_str)
            .collect::<Vec<_>>()
            .join(",")
    ));
}

fn host_fact_name_token(name: host::FactName) -> &'static str {
    use host::FactName::*;
    match name {
        BuildTargetArch => "build_target_arch",
        BuildTargetOs => "build_target_os",
        HostArch => "host_arch",
        KernelRelease => "kernel_release",
        GuestKernelRelease => "guest_kernel_release",
        GuestArch => "guest_arch",
        PlatformBoundary => "platform_boundary",
        AbiFloor => "abi_floor",
    }
}

fn host_fact_render(f: &host::MeasuredFact) -> String {
    match &f.basis {
        host::FactBasis::Measured { .. } => format!(
            "{} (measured)",
            f.value
                .as_ref()
                .map(text_or_withheld)
                .unwrap_or_else(|| "<withheld>".to_string())
        ),
        host::FactBasis::Asserted { .. } => format!(
            "{} (asserted)",
            f.value
                .as_ref()
                .map(text_or_withheld)
                .unwrap_or_else(|| "<withheld>".to_string())
        ),
        host::FactBasis::Unmeasured { reason, detail } => format!(
            "<unmeasured: {}{}>",
            text_or_withheld(reason),
            detail
                .as_ref()
                .map(|d| format!(" — {}", text_or_withheld(d)))
                .unwrap_or_default()
        ),
    }
}

// ---------------------------------------------------------------------------
// JSON rendering
// ---------------------------------------------------------------------------

fn json_report(envelope: &ReceiptEnvelope, defects: &[ReceiptDefect]) -> serde_json::Value {
    let mut body_value = serde_json::to_value(&envelope.body).unwrap_or(serde_json::Value::Null);
    suppress_diff_digest_if_not_committed(&mut body_value);
    serde_json::json!({
        "schema": envelope.schema,
        "seal": "holds",
        "findings": defects.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "posture": envelope.body.posture(),
        "elapsed_secs": envelope.body.elapsed_secs(),
        "is_least_authority": envelope.body.is_least_authority(),
        "body": body_value,
    })
}

/// The JSON-rendering twin of [`render_workspace`]'s digest suppression —
/// see this module's doc comment for why.
fn suppress_diff_digest_if_not_committed(body_value: &mut serde_json::Value) {
    let Some(workspace) = body_value.get_mut("workspace") else {
        return;
    };
    let Some(obj) = workspace.as_object_mut() else {
        return;
    };
    let committed = obj.get("committed") == Some(&serde_json::json!(true));
    if committed {
        return;
    }
    let not_meaningful = serde_json::json!(
        "not_meaningful: transaction did not commit — the stored value is the constant digest of an empty change \
         set, not a diff of this run"
    );
    if obj.contains_key("diff_digest") {
        obj.insert("diff_digest".to_string(), not_meaningful.clone());
    }
    if obj.contains_key("result_digest") {
        obj.insert(
            "result_digest".to_string(),
            serde_json::json!("not_meaningful: transaction did not commit"),
        );
    }
}
