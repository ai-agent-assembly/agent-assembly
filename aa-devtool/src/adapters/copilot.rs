//! Re-export of the authoritative GitHub Copilot adapter.
//!
//! This module used to carry a second, detection-only `CopilotAdapter` that
//! declared `L1Observe` and could not apply settings or MCP governance, while
//! the real implementation in [`aa_devtool_copilot`] declares `L2Enforce` and
//! had no consumer at all. `L2Enforce` is canonical — the adapter aligns VS Code
//! settings and governs the MCP registry. One crate now owns Copilot
//! (AAASM-5274).

pub use aa_devtool_copilot::CopilotAdapter;
