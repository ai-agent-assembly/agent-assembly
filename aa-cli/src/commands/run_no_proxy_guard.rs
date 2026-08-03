//! When `--no-proxy` may be used, and when it may not (AAASM-5350 AC 1).
//!
//! # The two authoritative refusal sources, and why only these two
//!
//! `--no-proxy` launches a tool with **no interception, no egress policy and
//! nothing inspected**. That is a legitimate thing to want on an unmanaged
//! machine, and it stays available there. It is not legitimate where someone
//! other than the invoking user has already decided this host runs managed.
//!
//! Two artifacts express that decision, and both are things a party *other than
//! the flag's user* wrote:
//!
//! * **(a)** the integration receipt records [`ProtectionProfile::Strict`] — an
//!   install-time choice, integrity-checked by the receipt store;
//! * **(b)** a valid endpoint managed-settings file exists at the canonical
//!   system path, root-owned — which takes administrator authorization to
//!   create.
//!
//! **"A required protection level" is deliberately absent.** No runtime artifact
//! expresses one, and a refusal inferred from local conditions with no
//! authoritative representation would be this programme's own failure mode: a
//! claim with nothing behind it. If such a requirement is introduced later, this
//! contract is extended through that feature's work rather than anticipated
//! here.
//!
//! # What a refusal never does
//!
//! It never silently downgrades. A launch under either source is refused
//! outright, before anything starts — the alternative, quietly proceeding
//! unprotected, is exactly what AC 1 exists to prevent.
//!
//! A permitted `--no-proxy` launch is still **Unprotected** and must never be
//! reported as `Gateway Protected` or `Host Enforced`; that is AC 2 and AC 3,
//! enforced elsewhere.

use std::fmt;
use std::path::PathBuf;

use aa_core::dev_tool::DevToolKind;
use aa_core::integration::plan::ProtectionProfile;
use aa_core::integration::step::SettingsScope;

/// The authoritative source that refuses this `--no-proxy` launch.
///
/// Named individually because the operator's next step differs: a profile is
/// something they chose and can re-install, a managed file is something an
/// administrator installed and they may not be able to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalSource {
    /// (a) The integration receipt records a `Strict` profile.
    StrictProfile {
        /// The tool whose receipt says so.
        tool: String,
        /// The scope the receipt was read from.
        scope: SettingsScope,
    },
    /// (b) A valid, root-owned managed-settings file is installed.
    ManagedSettingsInstalled {
        /// The canonical path it was found at.
        path: PathBuf,
    },
}

impl fmt::Display for RefusalSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrictProfile { tool, scope } => write!(
                f,
                "refusing --no-proxy: the {tool} integration is installed with the strict profile \
                 ({scope:?} scope), and strict exists precisely to say that this tool does not run \
                 unprotected on this host.\n\
                 \n\
                 To run without interception, re-install the integration with a profile that permits \
                 it:\n\
                 \x20 aasm integrations install {tool} --profile recommended\n\
                 Or run it without --no-proxy, which is what strict expects:\n\
                 \x20 aasm proxy start && aasm run {tool}"
            ),
            Self::ManagedSettingsInstalled { path } => write!(
                f,
                "refusing --no-proxy: an endpoint managed-settings file is installed at {}, which \
                 takes administrator authorization to create. Someone other than you decided this \
                 host runs managed, and a per-launch flag does not override that.\n\
                 \n\
                 Run the tool through the managed path instead:\n\
                 \x20 aasm proxy start && aasm run <tool>\n\
                 If this host should no longer be managed, that is an administrator action — removing \
                 the file requires the same authorization installing it did.",
                path.display()
            ),
        }
    }
}

/// Decide whether `--no-proxy` may be used for `tool`.
///
/// `receipt_profile` is the profile recorded in the authoritative integration
/// receipt, or `None` when no receipt exists — an un-integrated tool is not a
/// managed one.
///
/// Checked in order (a) then (b), and the **first** match is reported rather
/// than a list: AC 1 requires naming the exact triggering condition, and "one of
/// these two things" is not a condition an operator can act on.
pub fn refusal_for(
    tool: &DevToolKind,
    scope: SettingsScope,
    receipt_profile: Option<ProtectionProfile>,
    managed_evidence: Option<PathBuf>,
) -> Option<RefusalSource> {
    if receipt_profile == Some(ProtectionProfile::Strict) {
        return Some(RefusalSource::StrictProfile {
            tool: tool_id(tool),
            scope,
        });
    }
    managed_evidence.map(|path| RefusalSource::ManagedSettingsInstalled { path })
}

fn tool_id(tool: &DevToolKind) -> String {
    match tool {
        DevToolKind::Custom(name) => name.clone(),
        other => format!("{other:?}").to_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claude() -> DevToolKind {
        DevToolKind::ClaudeCode
    }

    /// Strict is the install-time statement that this tool does not run
    /// unprotected here, so the flag cannot override it.
    #[test]
    fn strict_profile_refuses() {
        let refusal = refusal_for(&claude(), SettingsScope::User, Some(ProtectionProfile::Strict), None);
        assert!(matches!(refusal, Some(RefusalSource::StrictProfile { .. })));
    }

    /// Recommended is guidance, not a mandate. `--no-proxy` stays available, and
    /// narrowing that would remove a documented capability the AC preserves.
    #[test]
    fn recommended_permits() {
        assert_eq!(
            refusal_for(
                &claude(),
                SettingsScope::User,
                Some(ProtectionProfile::Recommended),
                None
            ),
            None
        );
    }

    /// Observe-only applies no decision at all; refusing under it would be
    /// stricter than the profile itself.
    #[test]
    fn observe_only_permits() {
        assert_eq!(
            refusal_for(
                &claude(),
                SettingsScope::User,
                Some(ProtectionProfile::ObserveOnly),
                None
            ),
            None
        );
    }

    /// An un-integrated tool on an unmanaged host is the ordinary local case.
    #[test]
    fn no_receipt_and_no_managed_file_permits() {
        assert_eq!(refusal_for(&claude(), SettingsScope::User, None, None), None);
    }

    /// A managed installation refuses even with no receipt at all: the
    /// administrator's decision does not depend on this tool being integrated.
    #[test]
    fn managed_settings_refuse_without_any_receipt() {
        let refusal = refusal_for(
            &claude(),
            SettingsScope::User,
            None,
            Some(PathBuf::from(
                "/Library/Application Support/ClaudeCode/managed-settings.json",
            )),
        );
        assert!(matches!(refusal, Some(RefusalSource::ManagedSettingsInstalled { .. })));
    }

    /// Both sources in force must name exactly one — the profile, checked first.
    /// AC 1 requires the *exact* triggering condition, and a diagnostic listing
    /// both leaves the operator guessing which to act on.
    #[test]
    fn both_sources_name_exactly_one_condition() {
        let refusal = refusal_for(
            &claude(),
            SettingsScope::User,
            Some(ProtectionProfile::Strict),
            Some(PathBuf::from("/some/managed.json")),
        )
        .expect("refused");
        assert!(matches!(refusal, RefusalSource::StrictProfile { .. }));
        let text = refusal.to_string();
        assert!(
            !text.contains("/some/managed.json"),
            "must name one condition, not both"
        );
    }

    /// The diagnostic has to be actionable: it names the condition and what the
    /// operator can do, or it is just a denial.
    #[test]
    fn each_diagnostic_names_the_condition_and_a_way_forward() {
        let strict = RefusalSource::StrictProfile {
            tool: "claude-code".into(),
            scope: SettingsScope::User,
        }
        .to_string();
        assert!(strict.contains("strict profile"), "names the condition: {strict}");
        assert!(
            strict.contains("aasm integrations install"),
            "offers a way forward: {strict}"
        );

        let managed = RefusalSource::ManagedSettingsInstalled {
            path: PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json"),
        }
        .to_string();
        assert!(managed.contains("managed-settings"), "names the condition: {managed}");
        assert!(managed.contains("administrator"), "says who can change it: {managed}");
        assert!(
            managed.contains("/Library/Application Support/ClaudeCode/managed-settings.json"),
            "names the exact path: {managed}"
        );
    }
}
