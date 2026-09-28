//! AAASM-419 — every policy document printed in the concepts documentation must
//! be one the validator actually accepts.
//!
//! The pages these fences live on previously documented a rule-list schema
//! (`spec.tier` plus a list of `spec.rules`) that `PolicyValidator` refuses
//! outright, so a reader following the docs got a document the gateway would not
//! load. Prose alone cannot hold that line: the only thing that keeps a printed
//! example honest is running it through the same parser the product uses.
//!
//! The fixture is the documentation itself, so a future page cannot introduce an
//! unloadable example without reddening this test.

use std::{fs, path::PathBuf};

use aa_policy::PolicyValidator;

/// Resolve `docs/src/concepts/` relative to this crate, the way
/// `aa-security/tests/policy_examples_parse.rs` resolves `policy-examples/`.
fn concepts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../docs/src/concepts")
}

/// Extract the body of every ```` ```yaml ```` fence in `md`.
fn yaml_fences(md: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in md.lines() {
        match current.as_mut() {
            None => {
                if line.trim_start().starts_with("```yaml") {
                    current = Some(String::new());
                }
            }
            Some(buf) => {
                if line.trim_start().starts_with("```") {
                    blocks.push(std::mem::take(buf));
                    current = None;
                } else {
                    buf.push_str(line);
                    buf.push('\n');
                }
            }
        }
    }
    blocks
}

/// A fence is a policy document if it declares the envelope `kind: Policy`.
/// Anything else on a concepts page (a routing config, a fragment) is not this
/// test's business.
fn is_policy_document(yaml: &str) -> bool {
    yaml.lines().any(|l| l.trim() == "kind: Policy")
}

#[test]
fn every_documented_policy_document_validates() {
    let dir = concepts_dir();
    let entries = fs::read_dir(&dir).unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()));

    let mut checked = 0usize;
    for entry in entries {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let md = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        for (idx, block) in yaml_fences(&md).into_iter().enumerate() {
            if !is_policy_document(&block) {
                continue;
            }
            match PolicyValidator::from_yaml(&block) {
                Ok(_) => checked += 1,
                Err(errors) => panic!(
                    "{} yaml fence #{} is a policy document the validator refuses: {:?}\n--- document ---\n{}",
                    path.display(),
                    idx,
                    errors,
                    block
                ),
            }
        }
    }

    // Anti-vacuity: a fence extractor that silently matched nothing would make
    // the loop above pass over an empty set. The concepts pages carry a policy
    // document on `policy.md` and another on `approval.md`, so anything below
    // two means the extraction broke, not that the docs are clean.
    assert!(
        checked >= 2,
        "expected at least 2 documented policy documents under {}, found {checked} — \
         the yaml-fence extraction is not matching",
        dir.display()
    );
}

/// The negative control for the test above: prove the validator it calls really
/// does refuse the schema the documentation used to print. Without this, a
/// validator that accepted everything would make
/// `every_documented_policy_document_validates` pass vacuously.
#[test]
fn the_rule_list_schema_the_docs_used_to_print_is_still_refused() {
    let removed = "\
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: medium-risk-approval-gate
spec:
  tier: medium
  rules:
    - id: require-approval-for-writes
      match:
        actions: [\"fs:write\"]
      effect: require_approval
";
    let errors = PolicyValidator::from_yaml(removed)
        .err()
        .expect("a tier/rules document must not validate");
    let rendered = format!("{errors:?}");
    assert!(
        rendered.contains("rules"),
        "expected the dedicated rule-list refusal, got {rendered}"
    );
    assert!(
        rendered.contains("tier"),
        "expected `tier` to be rejected as an unknown top-level key, got {rendered}"
    );
}
