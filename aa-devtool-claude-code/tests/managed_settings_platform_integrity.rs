//! Whether *this* platform has a managed-settings integrity model at all
//! (AAASM-5465).
//!
//! # The gap this closes
//!
//! The endpoint managed-settings file is the only surface that can carry a
//! bypass-resistance claim, and the claim rests on three properties of the file
//! as found on disk: **root-owned**, **not writable by group or other**, and
//! **not a symlink**. All three are asked through Unix ownership, Unix mode bits
//! and `O_NOFOLLOW`, so every one of them — and the entire unit-test module that
//! pins them, `managed_evidence_tests` — is behind `#[cfg(unix)]`.
//!
//! On a non-Unix host the model does not degrade, it *vanishes*: the test module
//! compiles to nothing, `managed_installation_evidence_at` becomes a stub that
//! returns `NotInstalled`, and the suite reports green having asserted nothing
//! about integrity. Nothing in the tree said so. That is the same defect as a
//! `SKIP` that reads as a pass, one layer down — the compiler doing the skipping
//! instead of a runtime guard, which makes it *less* visible rather than more.
//!
//! # What this file does, and deliberately does not, do
//!
//! It does not restate the rejections; `managed_evidence_tests` already pins
//! each one against a crafted file, and duplicating them here would mean two
//! places to update and no more evidence. It answers the question that module
//! cannot ask about itself: *does this build have the integrity model?*
//!
//! * On Unix it takes one live measurement through the **public** installer —
//!   the ownership check and the permission check both refusing — so "the model
//!   is present on this platform" is asserted rather than assumed from the fact
//!   that some `#[cfg(unix)]` code exists.
//! * On any other platform it **fails**, naming the three properties that have
//!   no implementation and what one would require. There is no Windows CI lane
//!   in this repository today, so this cannot turn anything red now; the point
//!   is that the day someone adds `windows-latest` to a matrix, the lane reports
//!   the absence instead of a green run that measured no integrity at all.
//!
//! # Why the absence is reported rather than implemented
//!
//! A genuine Windows equivalent is not a port of this file, it is a product
//! decision with a different shape: the canonical path
//! (`/Library/Application Support/ClaudeCode/managed-settings.json`) is a macOS
//! constant, Windows has no uid to compare against, and "not writable by anyone
//! but an administrator" is a DACL question needing a Win32 security-descriptor
//! dependency and a definition of which SIDs count as authoritative. Choosing
//! those is expanding what the product claims to enforce, on a platform the
//! repository does not build or test today — so this ticket records the gap
//! where it is impossible to miss and leaves the decision to the ticket that
//! owns Windows support.

/// The evidence ledger (AAASM-5465), shared verbatim with every other suite that
/// can decline to measure, so one CI summary covers all of them.
///
/// The module is dependency-free by design, which is what lets a third crate
/// include it without a new dev-dependency.
#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

/// The ledger name for this platform question.
const SCENARIO: &str = "managed-settings-integrity-model-on-this-platform";

/// The three properties the managed-settings claim rests on, named once so the
/// Unix and non-Unix arms cannot drift apart in what they say is covered.
const INTEGRITY_PROPERTIES: [&str; 3] = ["root-owned", "not writable by group or other", "not a symlink"];

#[cfg(unix)]
mod present {
    use super::{evidence, INTEGRITY_PROPERTIES, SCENARIO};

    use aa_devtool_claude_code::managed_settings::testing::FakeAuthority;
    use aa_devtool_claude_code::managed_settings::{
        managed_settings_document, ManagedSettingsError, ManagedSettingsInstaller,
    };
    use aa_devtool_contract::ProtectionProfile;

    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    /// The uid this process writes files as, read off a file it just created so
    /// the fixture needs neither `libc` nor `unsafe`.
    fn current_uid(dir: &std::path::Path) -> u32 {
        let probe = dir.join(".uid-probe");
        std::fs::write(&probe, b"").expect("probe file");
        let uid = std::fs::metadata(&probe).expect("probe metadata").uid();
        std::fs::remove_file(&probe).expect("probe cleanup");
        uid
    }

    /// Two of the three integrity properties, measured through the public
    /// installer against a redirected target.
    ///
    /// `MacOsAdminAuthority` refuses any target that is not the canonical system
    /// path and is not used here at all: the authority is `FakeAuthority`, whose
    /// "elevation" is an ordinary unprivileged copy into a temp directory. No
    /// authorization prompt is reachable from this test.
    ///
    /// The third property (`O_NOFOLLOW`, no symlink) is only reachable through a
    /// crate-private entry point and is pinned by `managed_evidence_tests`; it is
    /// named in the failure message below rather than re-measured.
    #[test]
    fn the_integrity_model_is_present_and_enforcing_on_this_platform() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("ClaudeCode").join("managed-settings.json");
        let work = dir.path().join("state");
        std::fs::create_dir_all(&work).expect("work dir");
        let document = managed_settings_document(ProtectionProfile::Recommended).expect("managed document");

        // ── root-owned ─────────────────────────────────────────────────────
        //
        // Production expects uid 0. An unprivileged test cannot produce a
        // root-owned file, so it asks the same question the other way round:
        // expect an owner this process is *not*, and require the refusal.
        let wrong_owner = ManagedSettingsInstaller::new(&target, &work, FakeAuthority::granting())
            .expecting_owner_uid(current_uid(dir.path()).wrapping_add(1));
        let disclosure = wrong_owner.disclose(&document).expect("disclosure");
        let err = wrong_owner
            .install(&disclosure)
            .expect_err("a file owned by the wrong principal is not enforcement");
        assert!(
            matches!(&err, ManagedSettingsError::ReadBackMismatch { detail, .. } if detail.contains("owned by uid")),
            "the ownership check did not fire on this platform: {err}"
        );

        // ── not writable by group or other ─────────────────────────────────
        let installer = ManagedSettingsInstaller::new(&target, &work, FakeAuthority::granting())
            .expecting_owner_uid(current_uid(dir.path()));
        let disclosure = installer.disclose(&document).expect("disclosure");
        installer.install(&disclosure).expect("install");
        installer.verify_recorded().expect("a correct install attests");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = installer
            .verify_recorded()
            .expect_err("a world-writable file is not enforcement");
        assert!(
            matches!(&err, ManagedSettingsError::ReadBackMismatch { detail, .. } if detail.contains("other than the owner")),
            "the permission check did not fire on this platform: {err}"
        );

        evidence::record(
            SCENARIO,
            evidence::Measurement::Measured,
            &format!(
                "the managed-settings integrity model is present on {}: ownership and permission \
                 checks both refused; the third property ({}) is pinned by \
                 `managed_settings::managed_evidence_tests`",
                std::env::consts::OS,
                INTEGRITY_PROPERTIES[2],
            ),
        );
    }
}

/// On a platform with no integrity model, say so and fail — do not compile out.
///
/// This is the whole point of the file. `#[cfg(unix)]` on the model plus
/// `#[cfg(all(test, unix))]` on its tests means a Windows build has *neither*
/// the checks nor any test that notices; the suite goes green. Failing here is
/// the smallest change that turns "silently absent" into "reported absent", and
/// it fails with the list of what a Windows implementation would have to answer
/// rather than a bare `unimplemented!()`.
#[cfg(not(unix))]
#[test]
fn the_integrity_model_has_no_equivalent_on_this_platform() {
    let detail = format!(
        "the endpoint managed-settings integrity model ({}) is `#[cfg(unix)]` and is compiled out \
         on {}, with nothing standing in: `managed_installation_evidence_at` returns `NotInstalled` \
         unconditionally, so no managed file on this host can ever be treated as evidence — and \
         equally, no bad one is ever refused for a reason this build can name. A Windows \
         equivalent needs three decisions this ticket does not own: the canonical managed path \
         (the current constant is a macOS path), which SIDs count as authoritative in place of \
         uid 0, and a DACL check in place of the mode-bit check. Until those exist, this platform \
         produces NO integrity evidence.",
        INTEGRITY_PROPERTIES.join(", "),
        std::env::consts::OS,
    );
    evidence::record(SCENARIO, evidence::Measurement::UnsupportedPlatform, &detail);
    panic!("NO INTEGRITY MODEL [{SCENARIO}]: {detail}");
}
