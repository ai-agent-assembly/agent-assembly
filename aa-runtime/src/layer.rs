//! Interception layer detection and graceful fallback.
//!
//! The runtime supports three interception layers — eBPF, proxy, and SDK —
//! each detected at startup. [`LayerDetector::detect`] probes system
//! capabilities and returns a [`LayerSet`] bitflag indicating which layers
//! are available.

use std::fmt;

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
        let path = std::env::var_os("AA_EBPF_LOADERD_SOCK")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/run/aa-ebpf-loaderd.sock"));
        path.exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
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

/// Probes system capabilities and returns the set of available interception layers.
pub struct LayerDetector;

impl LayerDetector {
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
        if let Some(layers) = Self::from_env_override() {
            return layers;
        }

        let mut set = LayerSet::SDK;

        if probe_ebpf() {
            set |= LayerSet::EBPF;
        }
        if probe_proxy() {
            set |= LayerSet::PROXY;
        }

        set
    }

    /// Parse the `AA_LAYERS` env var if set and non-empty.
    fn from_env_override() -> Option<LayerSet> {
        let val = std::env::var("AA_LAYERS").ok()?;
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
}
