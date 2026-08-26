//! Per-run unique synthetic credential generator (AAASM-5902).
//!
//! Every journey that claims "the raw secret never reaches destination X" needs
//! a secret that is (a) shaped exactly like something the real
//! [`aa_security::CredentialScanner`] detects, and (b) unique to this process
//! run, so a stale value left over in some fixture or log from a previous run
//! can never be mistaken for evidence about *this* run.
//!
//! # Why the self-test in `harness_primitives.rs` is not optional
//!
//! A [`Canary`] is only as good as its resemblance to what the scanner actually
//! matches. If the scanner's detector regex ever drifts from the shapes
//! generated here, every downstream journey that asserts "the canary is absent
//! from the forwarded payload" would still pass — not because redaction worked,
//! but because the "secret" was never a secret the scanner recognised in the
//! first place. That failure mode is silent by construction, which is exactly
//! why `harness_primitives.rs` asserts the generated value against the real
//! scanner and the *expected* [`aa_security::CredentialKind`], not just "some
//! finding was produced".

use aa_security::{CredentialKind, CredentialScanner};

/// A single-use synthetic credential, shaped to match a real
/// [`CredentialKind`]'s detector pattern, with a run-scoped unique suffix.
pub struct Canary {
    kind: CredentialKind,
    value: String,
    run_id: String,
}

impl Canary {
    /// Generate a new canary of `kind`.
    ///
    /// # Panics
    ///
    /// Panics if `kind` has no generator wired up here. Only the credential
    /// kinds a journey actually needs are implemented — see the `match` below
    /// for the supported set.
    pub fn new(kind: CredentialKind) -> Self {
        let run_id = short_unique_id();
        let value = match kind {
            // AKIA + 16 uppercase-alphanumeric, matching the real long-term AWS
            // access key ID shape the scanner's `AKIA` literal pattern plus
            // `token_end` extends over (aa-security/src/scanner.rs).
            CredentialKind::AwsAccessKey => format!("AKIA{}", upper_alnum(16, &run_id)),
            // sk-ant-api03-<random>, matching aa-security's own test vectors
            // (`scanner.rs` line ~4312: `sk-ant-api03-000000000000000000000000`).
            CredentialKind::AnthropicKey => format!("sk-ant-api03-{}", lower_hex(24, &run_id)),
            // sk-<random>. Hex-only suffix so it can never accidentally spell
            // `ant-` and get misclassified as an Anthropic key (the scanner
            // checks `sk-ant-` first, but this keeps the generator unambiguous
            // on its own terms too).
            CredentialKind::OpenAiKey => format!("sk-{}", lower_hex(40, &run_id)),
            // ghp_ + 36 alphanumeric, matching the real classic GitHub PAT shape
            // (aa-security/src/scanner.rs line ~3696).
            CredentialKind::GitHubPat => format!("ghp_{}", lower_alnum(36, &run_id)),
            other => panic!(
                "Canary::new({other:?}): no synthetic-value generator wired up for this \
                 CredentialKind yet — add one rather than guessing a shape, so it stays \
                 provably detected by the real scanner"
            ),
        };
        Self { kind, value, run_id }
    }

    /// The synthetic secret value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Which [`CredentialKind`] this canary is shaped as.
    pub fn kind(&self) -> CredentialKind {
        self.kind.clone()
    }

    /// Short unique id for this canary's run, for scoping temp state and log
    /// greps without embedding the raw secret value itself in either.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// The redaction label the real scanner emits for this canary's kind, e.g.
    /// `"[REDACTED:AwsAccessKey]"`.
    pub fn expected_redaction_marker(&self) -> String {
        format!("[REDACTED:{}]", self.kind.as_str())
    }

    /// Panics naming `destination` if the raw canary value appears anywhere in
    /// `haystack`.
    pub fn assert_absent(&self, destination: &str, haystack: &str) {
        assert!(
            !haystack.contains(self.value()),
            "canary {run_id} ({kind:?}) leaked into {destination}: raw secret found in \
             haystack of {len} bytes",
            run_id = self.run_id,
            kind = self.kind,
            len = haystack.len(),
        );
    }

    /// As [`Self::assert_absent`], searching raw bytes rather than a `&str`.
    pub fn assert_absent_bytes(&self, destination: &str, haystack: &[u8]) {
        let needle = self.value().as_bytes();
        let found = haystack.windows(needle.len().max(1)).any(|w| w == needle);
        assert!(
            !found,
            "canary {run_id} ({kind:?}) leaked into {destination}: raw secret found in byte \
             haystack of {len} bytes",
            run_id = self.run_id,
            kind = self.kind,
            len = haystack.len(),
        );
    }
}

/// A cheap process-unique id, hex-encoded, with no dependency on a `rand`
/// crate this workspace does not otherwise pull in — `uuid` (already a
/// dev-dependency here) is a sufficient source of run-scoped uniqueness.
fn short_unique_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// `len` uppercase alphanumeric characters derived from `seed`'s hex digits
/// (already alphanumeric and uppercase-able), repeated/truncated to `len`.
fn upper_alnum(len: usize, seed: &str) -> String {
    let hex = format!("{seed}{seed}{seed}{seed}").to_uppercase();
    hex.chars().take(len).collect()
}

/// `len` lowercase hex characters derived from `seed`, repeated/truncated.
fn lower_hex(len: usize, seed: &str) -> String {
    let hex = format!("{seed}{seed}{seed}{seed}{seed}");
    hex.chars().take(len).collect()
}

/// `len` lowercase alphanumeric characters derived from `seed`.
fn lower_alnum(len: usize, seed: &str) -> String {
    lower_hex(len, seed)
}

/// Run the real scanner over `text` and return the finding whose `matched`
/// label is `[REDACTED:<kind>]` for the expected kind, if any. Exposed for the
/// harness self-test so it asserts against the genuine detector, not a
/// hand-rolled regex that could drift independently of it.
pub fn scan(text: &str) -> aa_security::ScanResult {
    CredentialScanner::new().scan(text)
}
