//! Interception layer detection, and what may truthfully be claimed about it.
//!
//! The runtime supports three interception components — eBPF, proxy, and SDK —
//! each probed at startup. [`LayerDetector::detect`] returns the historic
//! [`LayerSet`] bitflag of which are *present*.
//!
//! # Presence is not protection
//!
//! A bitflag has nowhere to record how a bit came to be set, so every consumer
//! of [`LayerSet`] is forced to read "present" as "protecting". ADR 0033 §7
//! records why that is wrong for all three bits: `AA_LAYERS` replaces the probe
//! result outright, the proxy probe is satisfied by a binary existing on
//! `$PATH` without establishing that anything routes through it, and the SDK
//! bit is asserted unconditionally.
//!
//! [`LayerDetector::attest`] (AAASM-5535) is the honest reading of the same
//! probes: it returns a
//! [`ProtectionAttestation`](aa_core::attestation::ProtectionAttestation) that
//! keeps the *basis* of each answer, so none of the three can publish itself as
//! coverage. Both entry points consume one shared readout — a second copy of
//! the predicate would be free to drift from the one that gates behaviour.

use std::fmt;

use aa_core::attestation::{AttestationBasis, LayerAttestation, ProtectionAttestation, SelectedMode};

/// The environment variable that replaces the probe result wholesale.
const AA_LAYERS_ENV: &str = "AA_LAYERS";

bitflags::bitflags! {
    /// Bitflag set of active interception layers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LayerSet: u8 {
        /// Kernel-level eBPF instrumentation (Linux ≥ 5.8 with BTF and CAP_BPF).
        const EBPF  = 0x1;
        /// Sidecar proxy (`aa-proxy` binary on Linux or macOS).
        const PROXY = 0x2;
        /// In-process SDK hooks (always available).
        const SDK   = 0x4;
    }
}

impl LayerSet {
    /// Return human-readable names for each active layer, in fixed order.
    pub fn names(self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(3);
        if self.contains(Self::EBPF) {
            out.push("ebpf");
        }
        if self.contains(Self::PROXY) {
            out.push("proxy");
        }
        if self.contains(Self::SDK) {
            out.push("sdk");
        }
        out
    }
}

impl fmt::Display for LayerSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = self.names();
        if names.is_empty() {
            return write!(f, "none");
        }
        write!(f, "{}", names.join("+"))
    }
}

// ── eBPF availability probes ──────────────────────────────────────────────────

/// Check whether the running kernel version is ≥ 5.8 (minimum for BPF ring buffer).
///
/// Returns `false` on non-Linux or if the version string cannot be parsed.
fn check_kernel_version() -> bool {
    #[cfg(target_os = "linux")]
    {
        let info = match uname_release() {
            Some(s) => s,
            None => return false,
        };
        parse_kernel_version_ge(&info, 5, 8)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Parse a kernel release string (e.g. `"5.15.0-91-generic"`) and return
/// `true` if major.minor ≥ the given threshold.
#[cfg(any(target_os = "linux", test))]
fn parse_kernel_version_ge(release: &str, req_major: u32, req_minor: u32) -> bool {
    let mut parts = release.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    (major, minor) >= (req_major, req_minor)
}

/// Read the kernel release string via libc `uname(2)`.
#[cfg(target_os = "linux")]
fn uname_release() -> Option<String> {
    use std::ffi::CStr;
    unsafe {
        let mut info: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut info) != 0 {
            return None;
        }
        CStr::from_ptr(info.release.as_ptr()).to_str().ok().map(String::from)
    }
}

/// Check whether BTF type information is available (required by modern eBPF programs).
fn check_btf_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Whether the privileged eBPF loader daemon (`aa-ebpf-loaderd`) is reachable.
///
/// AAASM-3605: the runtime no longer loads probes in-process and holds NO
/// `CAP_BPF`/`CAP_PERFMON` (see [`crate::privilege`]). The eBPF layer is
/// therefore available not when the runtime itself is privileged, but when the
/// privileged daemon's control socket exists — the runtime delegates all BPF
/// operations to it. This deliberately replaces the previous `geteuid()==0`
/// (runtime-must-be-root) check: requiring the runtime to be privileged was the
/// "detach/replace the probe from userspace" attack surface this Story closes.
fn loader_daemon_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&loaderd_socket_path()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// The loader daemon's control-socket path, as this process would look for it.
///
/// Reported in the attestation so an operator can see *which* path was checked
/// rather than being told a prerequisite is unmet with no way to verify it.
fn loaderd_socket_path() -> String {
    std::env::var("AA_EBPF_LOADERD_SOCK").unwrap_or_else(|_| "/run/aa-ebpf-loaderd.sock".to_string())
}

/// Returns `true` if all eBPF prerequisites are met.
///
/// Note the runtime's own capabilities are intentionally NOT a prerequisite —
/// the loader daemon owns BPF privilege (AAASM-3605). What the runtime needs is
/// a supported kernel, BTF, and a reachable loader daemon to delegate to.
fn probe_ebpf() -> bool {
    check_kernel_version() && check_btf_available() && loader_daemon_available()
}

// ── Proxy availability probe ─────────────────────────────────────────────────

/// Returns `true` if the `aa-proxy` binary is available on a supported platform.
///
/// Supported platforms: Linux and macOS. The binary must be discoverable via `$PATH`.
fn probe_proxy() -> bool {
    let supported_platform = cfg!(target_os = "linux") || cfg!(target_os = "macos");
    supported_platform && which::which("aa-proxy").is_ok()
}

// ── Layer detector ───────────────────────────────────────────────────────────

/// Wire identifiers for the three components, shared by [`LayerSet::names`] and
/// the attestation so a reader never has to reconcile two vocabularies.
const EBPF_COMPONENT: &str = "ebpf";
const PROXY_COMPONENT: &str = "proxy";
const SDK_COMPONENT: &str = "sdk";

/// What one probe found, before any interpretation.
///
/// Split out so [`LayerDetector::detect`] and [`LayerDetector::attest`] read the
/// *same* readout rather than each running its own copy of the probes. A second
/// implementation of the predicate would be free to drift from the one that
/// actually gates behaviour, and then the attestation would describe a system
/// that does not exist.
struct LayerReadout {
    /// Whether the component is claimed present — exactly the bit
    /// [`LayerSet`] has always carried.
    present: bool,
    /// Whether configuration asked for this component.
    selected_mode: SelectedMode,
    /// How `present` was arrived at.
    basis: AttestationBasis,
    /// What was actually checked, in words.
    detail: String,
}

/// The readout for all three components.
struct Readout {
    ebpf: LayerReadout,
    proxy: LayerReadout,
    sdk: LayerReadout,
}

impl Readout {
    /// The bitflag view. This is the sole producer of [`LayerSet`], so the
    /// legacy flag and the attestation can never disagree about presence.
    fn layer_set(&self) -> LayerSet {
        let mut set = LayerSet::empty();
        if self.ebpf.present {
            set |= LayerSet::EBPF;
        }
        if self.proxy.present {
            set |= LayerSet::PROXY;
        }
        if self.sdk.present {
            set |= LayerSet::SDK;
        }
        set
    }

    /// The attestation view: presence *plus* the basis that produced it.
    fn attestation(self, now_unix_secs: u64) -> ProtectionAttestation {
        let layers = [
            (EBPF_COMPONENT, self.ebpf),
            (PROXY_COMPONENT, self.proxy),
            (SDK_COMPONENT, self.sdk),
        ]
        .into_iter()
        .map(|(component, r)| LayerAttestation::new(component, r.selected_mode, r.basis, now_unix_secs, r.detail))
        .collect();

        ProtectionAttestation::new(
            env!("CARGO_PKG_VERSION"),
            format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            now_unix_secs,
            layers,
        )
    }
}

/// Probes system capabilities and reports what each interception component can
/// truthfully claim.
pub struct LayerDetector;

impl LayerDetector {
    /// Produce a [`ProtectionAttestation`] for the three interception
    /// components (AAASM-5535).
    ///
    /// This runs the same probes as [`detect`](Self::detect) — they share one
    /// readout — but keeps the *basis* of each answer instead of discarding it
    /// into a bit. None of the three probes can substantiate a coverage claim,
    /// and the attestation says so rather than publishing presence as
    /// protection (ADR 0033 §7).
    ///
    /// Components that cannot run on this platform or in this build are
    /// included, carrying the reason. Silently reducing to an SDK-only set is
    /// the defect this replaces.
    pub fn attest(now_unix_secs: u64) -> ProtectionAttestation {
        Self::readout().attestation(now_unix_secs)
    }

    /// One readout, consumed by both public entry points.
    fn readout() -> Readout {
        match Self::from_env_override() {
            Some(set) => Self::env_override_readout(set),
            None => Self::probed_readout(),
        }
    }

    /// The `AA_LAYERS` path: no probe ran, so nothing here is evidence about
    /// anything (ADR 0033 §7). Every component records the override as its
    /// basis, and the named ones additionally record that they were *asked
    /// for*, which is what makes an unsubstantiated one report `Degraded`.
    fn env_override_readout(set: LayerSet) -> Readout {
        let entry = |present: bool| LayerReadout {
            present,
            selected_mode: if present {
                SelectedMode::Enabled
            } else {
                SelectedMode::Disabled
            },
            basis: AttestationBasis::EnvironmentOverride {
                variable: AA_LAYERS_ENV.to_string(),
            },
            detail: format!("{AA_LAYERS_ENV} was set, so no probe was run for this component"),
        };
        Readout {
            ebpf: entry(set.contains(LayerSet::EBPF)),
            proxy: entry(set.contains(LayerSet::PROXY)),
            sdk: entry(set.contains(LayerSet::SDK)),
        }
    }

    /// The probed path. Each component records which check decided it.
    fn probed_readout() -> Readout {
        Readout {
            ebpf: Self::ebpf_readout(),
            proxy: Self::proxy_readout(),
            sdk: LayerReadout {
                // Unconditionally present, exactly as before — and
                // unconditionally *unevidenced*, which is the new part.
                present: true,
                selected_mode: SelectedMode::Unset,
                basis: AttestationBasis::AssumedPresent,
                detail: "the in-process SDK path is compiled in; no agent adoption was observed".to_string(),
            },
        }
    }

    /// `present` still comes from [`probe_ebpf`] itself, so the bit
    /// [`detect`](Self::detect) publishes cannot drift from the attestation;
    /// only the *reason* is newly recorded.
    fn ebpf_readout() -> LayerReadout {
        if probe_ebpf() {
            return LayerReadout {
                present: true,
                selected_mode: SelectedMode::Unset,
                basis: AttestationBasis::ArtifactPresent {
                    artifact: loaderd_socket_path(),
                },
                // The probe is a `path.exists()`, not a connect and not an
                // adjudication, and the programs the daemon loads are
                // observe-only (ADR 0033 §5.1). Neither fact is coverage.
                detail: "the loader daemon's control socket exists; no probe traffic was adjudicated".to_string(),
            };
        }
        if !cfg!(target_os = "linux") {
            return LayerReadout {
                present: false,
                selected_mode: SelectedMode::Unset,
                basis: AttestationBasis::PlatformUnsupported {
                    platform: std::env::consts::OS.to_string(),
                },
                detail: "eBPF is a Linux mechanism; this platform has no host-level adapter".to_string(),
            };
        }
        // Name the *first* unmet prerequisite rather than reporting a bare
        // false, so an operator can act on it. Order matches `probe_ebpf`.
        let requirement = if !check_kernel_version() {
            "a Linux kernel >= 5.8".to_string()
        } else if !check_btf_available() {
            "BTF at /sys/kernel/btf/vmlinux".to_string()
        } else {
            format!("an aa-ebpf-loaderd control socket at {}", loaderd_socket_path())
        };
        LayerReadout {
            present: false,
            selected_mode: SelectedMode::Unset,
            detail: format!("unmet prerequisite: {requirement}"),
            basis: AttestationBasis::PrerequisiteUnmet { requirement },
        }
    }

    /// `present` still comes from [`probe_proxy`] itself; see
    /// [`ebpf_readout`](Self::ebpf_readout).
    fn proxy_readout() -> LayerReadout {
        if probe_proxy() {
            return LayerReadout {
                present: true,
                selected_mode: SelectedMode::Unset,
                basis: AttestationBasis::ArtifactPresent {
                    artifact: "aa-proxy".to_string(),
                },
                // ADR 0033 §7: finding the binary does not establish that any
                // process routes traffic through it.
                detail: "the aa-proxy binary was found on $PATH; no traffic was observed routed through it".to_string(),
            };
        }
        if !(cfg!(target_os = "linux") || cfg!(target_os = "macos")) {
            return LayerReadout {
                present: false,
                selected_mode: SelectedMode::Unset,
                basis: AttestationBasis::PlatformUnsupported {
                    platform: std::env::consts::OS.to_string(),
                },
                detail: "aa-proxy has no build path on this platform".to_string(),
            };
        }
        LayerReadout {
            present: false,
            selected_mode: SelectedMode::Unset,
            basis: AttestationBasis::PrerequisiteUnmet {
                requirement: "the aa-proxy binary on $PATH".to_string(),
            },
            detail: "aa-proxy was not found on $PATH".to_string(),
        }
    }
    /// Detect available interception layers.
    ///
    /// If the `AA_LAYERS` environment variable is set to a non-empty,
    /// comma-separated list of layer names (e.g. `"ebpf,sdk"`), the detector
    /// returns exactly those layers without running any probes. This is
    /// intended for testing and CI environments.
    ///
    /// Otherwise, each layer is probed independently:
    /// - **eBPF**: kernel ≥ 5.8, BTF present, CAP_BPF (root)
    /// - **Proxy**: supported platform + `aa-proxy` in `$PATH`
    /// - **SDK**: always available
    pub fn detect() -> LayerSet {
        Self::readout().layer_set()
    }

    /// Parse the `AA_LAYERS` env var if set and non-empty.
    fn from_env_override() -> Option<LayerSet> {
        let val = std::env::var(AA_LAYERS_ENV).ok()?;
        if val.trim().is_empty() {
            return None;
        }
        let mut set = LayerSet::empty();
        for token in val.split(',') {
            match token.trim().to_lowercase().as_str() {
                "ebpf" => set |= LayerSet::EBPF,
                "proxy" => set |= LayerSet::PROXY,
                "sdk" => set |= LayerSet::SDK,
                _ => {} // unknown tokens silently ignored
            }
        }
        Some(set)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::attestation::ClaimTerm;

    #[test]
    fn individual_flags_have_correct_bits() {
        assert_eq!(LayerSet::EBPF.bits(), 0x1);
        assert_eq!(LayerSet::PROXY.bits(), 0x2);
        assert_eq!(LayerSet::SDK.bits(), 0x4);
    }

    #[test]
    fn flags_combine_with_bitor() {
        let set = LayerSet::EBPF | LayerSet::SDK;
        assert!(set.contains(LayerSet::EBPF));
        assert!(set.contains(LayerSet::SDK));
        assert!(!set.contains(LayerSet::PROXY));
    }

    #[test]
    fn names_returns_active_layers_in_order() {
        let all = LayerSet::EBPF | LayerSet::PROXY | LayerSet::SDK;
        assert_eq!(all.names(), vec!["ebpf", "proxy", "sdk"]);

        let sdk_only = LayerSet::SDK;
        assert_eq!(sdk_only.names(), vec!["sdk"]);

        let proxy_sdk = LayerSet::PROXY | LayerSet::SDK;
        assert_eq!(proxy_sdk.names(), vec!["proxy", "sdk"]);
    }

    #[test]
    fn names_empty_for_empty_set() {
        let empty = LayerSet::empty();
        assert!(empty.names().is_empty());
    }

    #[test]
    fn display_joins_with_plus() {
        let all = LayerSet::EBPF | LayerSet::PROXY | LayerSet::SDK;
        assert_eq!(format!("{all}"), "ebpf+proxy+sdk");
    }

    #[test]
    fn display_sdk_only() {
        assert_eq!(format!("{}", LayerSet::SDK), "sdk");
    }

    #[test]
    fn display_empty_shows_none() {
        assert_eq!(format!("{}", LayerSet::empty()), "none");
    }

    // ── parse_kernel_version_ge tests ────────────────────────────────────────

    #[test]
    fn kernel_version_ge_accepts_exact_match() {
        assert!(parse_kernel_version_ge("5.8.0-generic", 5, 8));
    }

    #[test]
    fn kernel_version_ge_accepts_higher() {
        assert!(parse_kernel_version_ge("6.1.0", 5, 8));
        assert!(parse_kernel_version_ge("5.15.0-91-generic", 5, 8));
    }

    #[test]
    fn kernel_version_ge_rejects_lower() {
        assert!(!parse_kernel_version_ge("5.7.19", 5, 8));
        assert!(!parse_kernel_version_ge("4.18.0", 5, 8));
    }

    #[test]
    fn kernel_version_ge_handles_garbage() {
        assert!(!parse_kernel_version_ge("not-a-version", 5, 8));
    }

    // ── LayerDetector tests (env-var-mutating, serialized) ───────────────────

    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn detect_always_includes_sdk() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("AA_LAYERS");

        let set = LayerDetector::detect();
        assert!(set.contains(LayerSet::SDK));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn detect_ebpf_false_on_macos() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("AA_LAYERS");

        let set = LayerDetector::detect();
        assert!(!set.contains(LayerSet::EBPF));
    }

    #[test]
    fn aa_layers_override_ebpf_sdk() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_LAYERS", "ebpf,sdk");

        let set = LayerDetector::detect();
        assert_eq!(set, LayerSet::EBPF | LayerSet::SDK);

        std::env::remove_var("AA_LAYERS");
    }

    #[test]
    fn aa_layers_override_all() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_LAYERS", "ebpf,proxy,sdk");

        let set = LayerDetector::detect();
        assert_eq!(set, LayerSet::EBPF | LayerSet::PROXY | LayerSet::SDK);

        std::env::remove_var("AA_LAYERS");
    }

    #[test]
    fn aa_layers_override_empty_falls_back_to_detection() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_LAYERS", "");

        let set = LayerDetector::detect();
        // Empty string means no override — SDK is always detected.
        assert!(set.contains(LayerSet::SDK));

        std::env::remove_var("AA_LAYERS");
    }

    #[test]
    fn aa_layers_unknown_tokens_ignored() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_LAYERS", "sdk,quantum,wasm");

        let set = LayerDetector::detect();
        assert_eq!(set, LayerSet::SDK);

        std::env::remove_var("AA_LAYERS");
    }

    #[test]
    fn aa_layers_case_insensitive() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("AA_LAYERS", "EBPF,Proxy,SDK");

        let set = LayerDetector::detect();
        assert_eq!(set, LayerSet::EBPF | LayerSet::PROXY | LayerSet::SDK);

        std::env::remove_var("AA_LAYERS");
    }

    // ── AAASM-5535: attestation ──────────────────────────────────────────────

    /// A fixed instant for attestation tests, so freshness never depends on the
    /// wall clock.
    const ATTEST_NOW: u64 = 1_700_000_000;

    fn state_of<'a>(att: &'a ProtectionAttestation, component: &str) -> (ClaimTerm, &'a LayerAttestation) {
        let layer = att
            .layers
            .iter()
            .find(|l| l.component == component)
            .unwrap_or_else(|| panic!("{component} must be present in the attestation"));
        (layer.verified_state_at(ATTEST_NOW, att.freshness_window_secs), layer)
    }

    /// The defect this Story exists to close. `AA_LAYERS=ebpf,proxy,sdk` makes
    /// `detect()` report all three layers as active on a host whose own probes
    /// say otherwise, and the bitflag gives no caller any way to tell.
    ///
    /// `detect()` keeps that behaviour — it is an existing contract — but the
    /// attestation of the *same* readout reports every component as `Degraded`:
    /// asked for, and substantiated by nothing.
    #[test]
    fn attest_reports_env_override_layers_as_degraded_not_active() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(AA_LAYERS_ENV, "ebpf,proxy,sdk");

        let claimed = LayerDetector::detect();
        let att = LayerDetector::attest(ATTEST_NOW);

        std::env::remove_var(AA_LAYERS_ENV);

        // The legacy view still says "all three active".
        assert_eq!(claimed, LayerSet::EBPF | LayerSet::PROXY | LayerSet::SDK);

        // The attestation of the same readout refuses to.
        for component in ["ebpf", "proxy", "sdk"] {
            let (term, layer) = state_of(&att, component);
            assert_eq!(term, ClaimTerm::Degraded, "{component}");
            assert_eq!(layer.selected_mode, SelectedMode::Enabled, "{component}");
            assert!(
                matches!(layer.basis, AttestationBasis::EnvironmentOverride { .. }),
                "{component} basis was {:?}",
                layer.basis
            );
        }
        assert!(!att.any_coverage_verified_at(ATTEST_NOW));
        assert_eq!(att.degraded_at(ATTEST_NOW).len(), 3);
    }

    /// None of the three probes can substantiate a coverage claim, on any
    /// platform and by either path. This is the property the public trust
    /// surface renders, so it is asserted over the whole attestation rather
    /// than component by component.
    #[test]
    fn attest_never_claims_coverage_from_a_probe() {
        let _guard = ENV_LOCK.lock().unwrap();

        std::env::remove_var(AA_LAYERS_ENV);
        let probed = LayerDetector::attest(ATTEST_NOW);

        std::env::set_var(AA_LAYERS_ENV, "ebpf,proxy,sdk");
        let overridden = LayerDetector::attest(ATTEST_NOW);
        std::env::remove_var(AA_LAYERS_ENV);

        for (label, att) in [("probed", &probed), ("overridden", &overridden)] {
            assert!(
                !att.any_coverage_verified_at(ATTEST_NOW),
                "{label} attestation claimed coverage: {:?}",
                att.verified_states_at(ATTEST_NOW)
            );
            for layer in &att.layers {
                assert!(
                    !layer.basis.is_evidence(),
                    "{label}/{} used {:?} as evidence",
                    layer.component,
                    layer.basis
                );
            }
        }
    }
}
