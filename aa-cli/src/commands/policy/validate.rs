//! `aasm policy validate` — local-only policy YAML validation.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;

/// Arguments for `aasm policy validate`.
#[derive(Args)]
pub struct ValidateArgs {
    /// Path to the policy YAML file to validate.
    pub file: PathBuf,
}

/// Execute the `aasm policy validate` command.
///
/// Validates the policy YAML file locally using `aa_gateway::policy::PolicyValidator::from_yaml`.
/// Exits 0 if valid, 1 if invalid with error details printed to stderr.
pub fn run(args: ValidateArgs) -> ExitCode {
    let yaml = match std::fs::read_to_string(&args.file) {
        Ok(y) => y,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", args.file.display());
            return ExitCode::FAILURE;
        }
    };

    match aa_gateway::policy::PolicyValidator::from_yaml(&yaml) {
        Ok(output) => {
            for w in &output.warnings {
                eprintln!("warning: {w}");
            }
            println!("Policy is valid: {}", args.file.display());
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for e in &errors {
                eprintln!("error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    #[test]
    fn valid_policy_exits_success() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: test-policy
spec:
  budget:
    daily_limit_usd: 100.0"#
        )
        .unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::SUCCESS);
    }

    #[test]
    fn invalid_yaml_exits_failure() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not: valid: yaml: [[[").unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn missing_file_exits_failure() {
        let args = ValidateArgs {
            file: PathBuf::from("/tmp/nonexistent-policy-file-that-does-not-exist.yaml"),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn unknown_top_level_key_exits_failure() {
        // AAASM-4191: unknown top-level keys must fail closed (exit 1), not
        // silently pass with a warning. A typo'd section would otherwise drop
        // the restriction entirely.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "risk_tier: high").unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn misspelled_section_key_exits_failure() {
        // AAASM-4191: a typo'd section (e.g. `capabilties`) must fail closed.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "capabilties:\n  deny:\n    - file_delete").unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn nested_unknown_key_exits_failure() {
        // AAASM-4330: a typo INSIDE a section (e.g. `capabilities.dney` for
        // `deny`) must fail closed at the CLI (exit 1), not pass with a warning
        // while silently dropping the restriction.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "capabilities:\n  dney:\n    - file_delete").unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }

    #[test]
    fn valid_nested_policy_exits_success() {
        // AAASM-4330 over-rejection guard: a policy whose nested keys are all
        // spelled correctly must still validate (exit 0).
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            "capabilities:\n  deny:\n    - file_delete\ntools:\n  bash:\n    allow: true\n    limit_per_hour: 5"
        )
        .unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::SUCCESS);
    }

    #[test]
    fn multiple_errors_all_reported() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            tmp,
            r#"network:
  allowlist:
    - ""
budget:
  daily_limit_usd: 0.0
data:
  sensitive_patterns:
    - "[bad""#
        )
        .unwrap();

        let args = ValidateArgs {
            file: tmp.path().to_path_buf(),
        };
        assert_eq!(run(args), ExitCode::FAILURE);
    }
}
