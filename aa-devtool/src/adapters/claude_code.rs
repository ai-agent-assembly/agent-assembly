//! Re-export of the authoritative Claude Code adapter.
//!
//! This module used to carry a second, detection-only `ClaudeCodeAdapter` whose
//! `generate_managed_settings` / `apply_settings` / `build_launch_command` all
//! returned `Err`, and which declared `L3Native` while the real implementation
//! in [`aa_devtool_claude_code`] declares `L2Enforce`. Discovery consumed the
//! stub and `aasm run` consumed neither, so the two disagreed about the same
//! tool. The duplicate is gone; one crate now owns Claude Code (AAASM-5274).
//!
//! The canonical governance level is `L2Enforce`: the adapter writes native
//! managed settings, but exec/file/network enforcement still requires `aa-proxy`
//! or eBPF. Per-capability tiers live in the governance capability matrix.

pub use aa_devtool_claude_code::ClaudeCodeAdapter;
