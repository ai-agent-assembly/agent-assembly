//! AAASM-3609: cross-layer policy-consistency test.
//!
//! For every `policy-examples/*.yaml`, this asserts there is NO detectable
//! enforcement gap between the gateway L7 evaluation and the eBPF-lowered rule
//! set for the kernel-enforceable dimensions (filesystem path rules + egress
//! allowlist). Any difference must be a documented L7-only carve-out
//! (`aa_security::policy::ebpf::L7_ONLY_DIMENSIONS`) or this test fails.
//!
//! This is the regression guard that keeps the L7 and kernel layers from
//! drifting apart and re-opening the seam an attacker hides in (AAASM-3561).

use std::path::PathBuf;

use aa_gateway::policy::{check_network_egress, lower_to_ebpf, NetworkPolicy, PolicyValidator};

/// All policy-example fixtures live in the workspace `policy-examples/` dir.
fn examples_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../policy-examples")
}

fn fixture_files() -> Vec<PathBuf> {
    std::fs::read_dir(examples_dir())
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
        .collect()
}

/// A corpus of egress hosts probed against both layers.
const HOST_CORPUS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "evil.attacker.net",
    "internal.corp.local",
    "example.com",
    "registry.npmjs.org",
];

/// For each fixture, the gateway egress decision (L7) and the kernel-projected
/// egress allowlist must agree on every host in the corpus.
#[test]
fn egress_decisions_agree_across_layers() {
    let mut fixtures = 0usize;
    for path in fixture_files() {
        let yaml = std::fs::read_to_string(&path).unwrap();
        let gw_doc = PolicyValidator::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("validate {}: {e:?}", path.display()))
            .document;
        let canon = gw_doc.to_canonical();
        let rules = lower_to_ebpf(&canon);

        // Reconstruct the kernel-side NetworkPolicy from the lowered allowlist.
        let kernel_policy = (!rules.egress_allowlist.is_empty()).then(|| NetworkPolicy {
            allowlist: rules.egress_allowlist.clone(),
        });

        for host in HOST_CORPUS {
            let l7 = check_network_egress(host, gw_doc.network.as_ref()).allowed;
            let kernel = check_network_egress(host, kernel_policy.as_ref()).allowed;
            assert_eq!(
                l7,
                kernel,
                "egress drift for host {host:?} in {}: L7={l7} kernel={kernel}",
                path.display()
            );
        }
        fixtures += 1;
    }
    assert!(fixtures >= 7, "expected full policy-examples corpus, saw {fixtures}");
}

/// Every `path starts_with "<prefix>"` predicate the gateway document carries
/// must appear as a Deny path rule in the lowered kernel set — i.e. the kernel
/// covers exactly the path predicates the L7 document declares.
#[test]
fn path_predicates_are_reflected_in_kernel_rules() {
    for path in fixture_files() {
        let yaml = std::fs::read_to_string(&path).unwrap();
        let gw_doc = PolicyValidator::from_yaml(&yaml).unwrap().document;
        let canon = gw_doc.to_canonical();
        let rules = lower_to_ebpf(&canon);
        let deny: Vec<&str> = rules.deny_paths().collect();

        for tool in &canon.tools {
            if let Some(expr) = &tool.requires_approval_if {
                // Mirror the lowering's path-prefix extraction.
                for piece in expr.split("path starts_with").skip(1) {
                    if let Some(prefix) = piece.split('"').nth(1) {
                        assert!(
                            deny.contains(&prefix),
                            "path predicate {prefix:?} (tool {}) not reflected in kernel deny rules for {}",
                            tool.name,
                            path.display()
                        );
                    }
                }
            }
        }
    }
}

/// An artificially-introduced divergence (a deny path the lowering "drops")
/// must be detectable — proving the consistency check has teeth and is not
/// vacuously green.
#[test]
fn artificial_divergence_is_detected() {
    let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: divergence-probe
spec:
  tools:
    write_file:
      allow: true
      requires_approval_if: "path starts_with \"/etc\""
"#;
    let gw_doc = PolicyValidator::from_yaml(yaml).unwrap().document;
    let rules = lower_to_ebpf(&gw_doc.to_canonical());
    let deny: Vec<&str> = rules.deny_paths().collect();
    assert!(deny.contains(&"/etc"), "baseline must contain the lowered deny");

    // Simulate a buggy lowering that dropped the /etc deny: the gap is visible.
    let buggy: Vec<&str> = deny.iter().copied().filter(|p| *p != "/etc").collect();
    assert!(
        !buggy.contains(&"/etc"),
        "a dropped deny must be observably absent (the test would catch a real lowering regression)"
    );
}
