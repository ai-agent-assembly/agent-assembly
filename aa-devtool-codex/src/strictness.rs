//! Never-relax rule for the user's own Codex `config.toml` (AAASM-6327).
//!
//! Codex's `sandbox_mode` / `approval_policy` are the user's security
//! settings. AA may tighten them but must not lower one: since AAASM-6319 the
//! values AA writes are ones Codex actually loads, so a blind "AA wins" merge
//! would persistently replace a user's `read-only` with `workspace-write`.
//!
//! Rule: a managed key is written only when AA's value ranks at least as strict
//! as the existing one. A key that is absent ranks strictest (Codex's default
//! depends on context, so a permissive value must not land on an empty key),
//! and a value that cannot be ranked (`never`, a granular table, `untrusted`,
//! unknown strings) is never overwritten: `never` and granular tables can only
//! auto-reject prompts, so replacing them could only relax.
//!
//! Only top-level keys are compared; `[profiles.*]` is user-owned and untouched.

/// A managed key that was not written, and why.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub key: &'static str,
    pub existing: String,
    /// `true` when the existing value has no rank (kept as-is); `false` when
    /// AA's value would have been less strict.
    pub unrankable: bool,
    /// `true` when the key was unset in the user's config, so nothing of theirs
    /// was lowered; the managed value was dropped because it was not the
    /// strictest one AA can write. `existing` is empty then.
    pub absent: bool,
}

const SANDBOX: &str = "sandbox_mode";
const APPROVAL: &str = "approval_policy";
type Rank = fn(&toml::Value) -> Option<u8>;

fn sandbox_rank(v: &toml::Value) -> Option<u8> {
    match v.as_str()? {
        "danger-full-access" => Some(0),
        // AA's own pre-AAASM-6319 spellings, so update/repair of an older
        // install still compares: full-auto wrote workspace-write semantics.
        "workspace-write" | "full-auto" => Some(1),
        "read-only" | "suggest" | "ask" => Some(2),
        _ => None,
    }
}

fn approval_rank(v: &toml::Value) -> Option<u8> {
    match v {
        toml::Value::String(s) => match s.as_str() {
            "on-failure" => Some(0),
            "on-request" => Some(1),
            _ => None,
        },
        // AA's own pre-AAASM-6319 per-category table; any non-`auto` category
        // asked for a prompt.
        toml::Value::Table(t) => {
            const KEYS: [&str; 4] = ["file_writes", "shell_exec", "network", "mcp_calls"];
            let legacy = t.len() == KEYS.len() && KEYS.iter().all(|k| t.contains_key(*k));
            if !legacy {
                return None;
            }
            Some(if t.values().any(|l| l.as_str() != Some("auto")) {
                1
            } else {
                0
            })
        }
        _ => None,
    }
}

/// The line `aasm run` prints when it leaves a managed key alone.
pub(crate) fn warning(w: &Withheld) -> String {
    if w.absent {
        format!(
            "warning: not setting `{}` in your Codex config: it is unset there and the managed value is not the strictest Agent Assembly can write, so it is left unset",
            w.key
        )
    } else if w.unrankable {
        format!(
            "warning: not changing `{}` in your Codex config: its value `{}` is not one Agent Assembly can compare, so it is left as you set it",
            w.key, w.existing
        )
    } else {
        format!(
            "warning: not changing `{}` in your Codex config: the managed value would be less strict than your `{}`, so it is left as you set it",
            w.key, w.existing
        )
    }
}

/// Writes one [`warning`] line per withheld key, so a skipped relaxation is
/// never silent.
pub(crate) fn report(withheld: &[Withheld], out: &mut impl std::io::Write) -> std::io::Result<()> {
    withheld.iter().try_for_each(|w| writeln!(out, "{}", warning(w)))
}

fn describe(v: &toml::Value) -> String {
    match v.as_str() {
        Some(s) => s.to_string(),
        None => v.to_string(),
    }
}

/// Removes from `managed` every key whose write would relax `existing` or
/// overwrite a value that cannot be ranked. Other keys are left alone.
pub(crate) fn withhold_relaxations(existing: &toml::Table, managed: &mut toml::Table) -> Vec<Withheld> {
    let mut withheld = Vec::new();
    let checks: [(&'static str, Rank); 2] = [(SANDBOX, sandbox_rank), (APPROVAL, approval_rank)];
    for (key, rank) in checks {
        let Some(aa) = managed.get(key) else { continue };
        let Some(current) = existing.get(key) else {
            // Absent ranks strictest: only the strictest AA value may land.
            if !rank(aa).is_some_and(|r| r >= strictest(key)) {
                withheld.push(Withheld {
                    key,
                    existing: String::new(),
                    unrankable: false,
                    absent: true,
                });
                managed.remove(key);
            }
            continue;
        };
        match (rank(aa), rank(current)) {
            (Some(a), Some(c)) if a >= c => {}
            (_, Some(_)) => {
                withheld.push(Withheld {
                    key,
                    existing: describe(current),
                    unrankable: false,
                    absent: false,
                });
                managed.remove(key);
            }
            (_, None) => {
                withheld.push(Withheld {
                    key,
                    existing: describe(current),
                    unrankable: true,
                    absent: false,
                });
                managed.remove(key);
            }
        }
    }
    withheld
}

fn strictest(key: &str) -> u8 {
    if key == SANDBOX {
        2
    } else {
        // `on-request` is the strictest value AA can write.
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tbl(s: &str) -> toml::Table {
        toml::from_str(s).unwrap()
    }

    /// Returns what survives in `managed` after the rule runs.
    fn run(existing: &str, managed: &str) -> (toml::Table, Vec<Withheld>) {
        let mut m = tbl(managed);
        let w = withhold_relaxations(&tbl(existing), &mut m);
        (m, w)
    }

    #[test]
    fn sandbox_is_never_lowered_but_may_be_raised_or_kept() {
        let ladder = ["danger-full-access", "workspace-write", "read-only"];
        for (ei, existing) in ladder.iter().enumerate() {
            for (ai, aa) in ladder.iter().enumerate() {
                let (m, _) = run(
                    &format!("sandbox_mode = \"{existing}\""),
                    &format!("sandbox_mode = \"{aa}\""),
                );
                assert_eq!(m.contains_key("sandbox_mode"), ai >= ei, "existing={existing} aa={aa}");
            }
        }
    }

    #[test]
    fn approval_is_never_lowered_but_may_be_raised_or_kept() {
        for (existing, aa, written) in [
            ("on-request", "on-failure", false),
            ("on-request", "on-request", true),
            ("on-failure", "on-request", true),
            ("on-failure", "on-failure", true),
        ] {
            let (m, _) = run(
                &format!("approval_policy = \"{existing}\""),
                &format!("approval_policy = \"{aa}\""),
            );
            assert_eq!(
                m.contains_key("approval_policy"),
                written,
                "existing={existing} aa={aa}"
            );
        }
    }

    #[test]
    fn absent_key_ranks_strictest_so_a_permissive_value_does_not_land() {
        let (m, w) = run(
            "",
            "sandbox_mode = \"workspace-write\"\napproval_policy = \"on-failure\"",
        );
        assert!(m.is_empty(), "{m:?}");
        // The drop is reported (AAASM-6361), once per key, as an absent key.
        assert_eq!(w.iter().filter(|x| x.absent).count(), 2, "{w:?}");
        assert!(w.iter().all(|x| !x.unrankable && x.existing.is_empty()));
        let (m, w) = run("", "sandbox_mode = \"read-only\"\napproval_policy = \"on-request\"");
        assert_eq!(m.len(), 2);
        assert!(w.is_empty(), "the strictest value lands and says nothing: {w:?}");
    }

    #[test]
    fn unrankable_existing_values_are_never_overwritten() {
        for existing in [
            "approval_policy = \"never\"",
            "approval_policy = \"untrusted\"",
            "approval_policy = \"bogus\"",
            "approval_policy = 3",
            "[approval_policy]\nreject = true",
            "[approval_policy.granular]\nsandbox_approval = true",
        ] {
            let (m, w) = run(existing, "approval_policy = \"on-request\"");
            assert!(!m.contains_key("approval_policy"), "{existing}");
            assert!(w.iter().any(|x| x.unrankable), "{existing}");
        }
        let (m, w) = run("sandbox_mode = \"bogus\"", "sandbox_mode = \"read-only\"");
        assert!(m.is_empty() && w[0].unrankable);
    }

    #[test]
    fn aas_own_retired_spellings_still_rank() {
        // An older AA install wrote these; update/repair must still compare.
        let (m, _) = run("sandbox_mode = \"suggest\"", "sandbox_mode = \"read-only\"");
        assert!(m.contains_key("sandbox_mode"));
        let (m, _) = run("sandbox_mode = \"suggest\"", "sandbox_mode = \"workspace-write\"");
        assert!(!m.contains_key("sandbox_mode"));
        let legacy = "[approval_policy]\nfile_writes = \"auto\"\nshell_exec = \"prompt\"\nnetwork = \"auto\"\nmcp_calls = \"auto\"";
        let (m, _) = run(legacy, "approval_policy = \"on-request\"");
        assert!(m.contains_key("approval_policy"));
        let (m, _) = run(legacy, "approval_policy = \"on-failure\"");
        assert!(!m.contains_key("approval_policy"));
    }

    #[test]
    fn warning_names_the_key_and_the_value_left_alone() {
        let (_, w) = run("approval_policy = \"never\"", "approval_policy = \"on-request\"");
        let line = warning(&w[0]);
        assert!(line.contains("approval_policy") && line.contains("never"), "{line}");
    }

    #[test]
    fn other_managed_keys_pass_through() {
        let (m, _) = run(
            "sandbox_mode = \"read-only\"",
            "sandbox_mode = \"workspace-write\"\nsome_other_key = [\"a\"]",
        );
        assert!(!m.contains_key("sandbox_mode"));
        assert!(m.contains_key("some_other_key"));
    }

    /// Ranking pin. Checked against codex-cli 0.163.0 with a private
    /// `CODEX_HOME` (no auth read, no prompt observed):
    /// - `codex --help` lists `--ask-for-approval` values `on-request` ("The
    ///   model decides when to ask the user for approval") and `never`; it does
    ///   NOT list or describe `on-failure`.
    /// - A `config.toml` with `approval_policy` = `on-failure` or `on-request`
    ///   loads (`codex mcp list` succeeds); `untrusted` fails with "is no longer
    ///   supported"; an unknown value fails listing `untrusted`, `on-failure`,
    ///   `on-request`, `granular`, `never`.
    ///
    /// So 0.163.0 confirms both strings are accepted and defines `on-request`
    /// as can-prompt-before-acting, but gives no definition of `on-failure`.
    /// The order below (`on-failure` asks only after a sandboxed command fails)
    /// is therefore a reading, not something this binary states; this pins it
    /// so changing it has to be deliberate.
    #[test]
    fn on_request_outranks_on_failure_per_codex_0_163_0() {
        let rank = |s: &str| approval_rank(&toml::Value::String(s.into())).unwrap();
        assert!(rank("on-request") > rank("on-failure"));
    }

    #[test]
    fn warning_for_a_relaxation_says_the_value_would_be_less_strict() {
        let (_, w) = run("approval_policy = \"on-request\"", "approval_policy = \"on-failure\"");
        assert!(!w[0].unrankable);
        let line = warning(&w[0]);
        assert!(
            line.contains("approval_policy") && line.contains("on-request") && line.contains("less strict"),
            "{line}"
        );
    }

    #[test]
    fn a_withheld_relaxation_is_reported_and_a_tightening_is_not() {
        // Negative control: relaxation withheld AND reported.
        let (m, w) = run("approval_policy = \"on-request\"", "approval_policy = \"on-failure\"");
        assert!(!m.contains_key("approval_policy"));
        let mut out = Vec::new();
        report(&w, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(
            text.contains("approval_policy") && text.contains("on-request"),
            "{text}"
        );
        // Positive control: a genuine tightening is applied and says nothing.
        let (m, w) = run("approval_policy = \"on-failure\"", "approval_policy = \"on-request\"");
        assert!(m.contains_key("approval_policy"));
        let mut out = Vec::new();
        report(&w, &mut out).unwrap();
        assert!(out.is_empty());
    }
}
