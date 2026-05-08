//! Generates `docs/src/policy-rbac.md` from the PolicyMutationRequiredRole table.
//!
//! Run from the workspace root:
//!
//! ```bash
//! cargo run -p aa-api --bin generate_policy_rbac_doc
//! ```
//!
//! CI verifies the committed file is in sync with the generated output via
//! `.ci/check-policy-rbac-doc.sh`.

use std::fmt::Write;

use aa_gateway::policy::rbac::{required_role_for, CallerRole, MutationKind, PolicyScopeKind};
use aa_gateway::policy::scope::PolicyScope;

fn main() {
    let doc = generate_doc();

    let out_path = std::path::Path::new("docs/src/policy-rbac.md");
    std::fs::write(out_path, &doc).expect("failed to write docs/src/policy-rbac.md");
    eprintln!("wrote {}", out_path.display());
}

/// Build the full Markdown document from the role table.
pub fn generate_doc() -> String {
    let scopes: &[(PolicyScopeKind, PolicyScope)] = &[
        (PolicyScopeKind::Global, PolicyScope::Global),
        (PolicyScopeKind::Org, PolicyScope::Org("*".into())),
        (PolicyScopeKind::Team, PolicyScope::Team("*".into())),
        (
            PolicyScopeKind::Agent,
            PolicyScope::Agent(aa_core::identity::AgentId::from_bytes([0u8; 16])),
        ),
        (PolicyScopeKind::Tool, PolicyScope::Tool("*".into())),
    ];

    let mutations = [MutationKind::Create, MutationKind::Update, MutationKind::Delete];

    let mut out = String::new();

    writeln!(out, "# Policy RBAC Role Matrix").unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "Auto-generated from the `PolicyMutationRequiredRole` table in \
         `aa-gateway/src/policy/rbac.rs`. Do not edit by hand — run \
         `cargo run -p aa-api --bin generate_policy_rbac_doc` to regenerate."
    )
    .unwrap();
    writeln!(out).unwrap();
    writeln!(
        out,
        "The 5 canonical RBAC roles in privilege order (highest → lowest):\n\
         `OrgAdmin > TeamAdmin > Developer > Viewer > Auditor`\n\
         `Auditor` may never mutate policies — all write attempts are denied."
    )
    .unwrap();
    writeln!(out).unwrap();

    // Header row
    write!(out, "| Scope | ").unwrap();
    for m in mutations {
        write!(out, "{m} | ").unwrap();
    }
    writeln!(out).unwrap();

    // Separator row
    write!(out, "|---| ").unwrap();
    for _ in mutations {
        write!(out, "--- | ").unwrap();
    }
    writeln!(out).unwrap();

    // Data rows
    for (kind, scope) in scopes {
        write!(out, "| `{kind}` | ").unwrap();
        for mutation in mutations {
            let role = required_role_for(scope, mutation);
            write!(out, "`{role}` | ").unwrap();
        }
        writeln!(out).unwrap();
    }

    writeln!(out).unwrap();
    writeln!(out, "## Role Descriptions").unwrap();
    writeln!(out).unwrap();

    for (role, desc) in &[
        (CallerRole::OrgAdmin, "Full policy mutation rights across all scopes."),
        (
            CallerRole::TeamAdmin,
            "Can mutate team-scoped policies and below (Agent, Tool).",
        ),
        (
            CallerRole::Developer,
            "Can mutate agent- and tool-scoped policies only.",
        ),
        (CallerRole::Viewer, "Read-only access — no writes permitted."),
        (
            CallerRole::Auditor,
            "Read-only audit access — all write attempts denied regardless of scope.",
        ),
    ] {
        writeln!(out, "- **`{role}`** — {desc}").unwrap();
    }

    out
}
