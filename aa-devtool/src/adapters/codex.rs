//! Re-export of the authoritative Codex adapter.
//!
//! This module used to carry a second, detection-only `CodexAdapter` whose
//! non-detection methods all returned `Err`. `aasm run codex` already used the
//! real [`aa_devtool_codex`] implementation while discovery used the stub, so
//! the two could drift apart at any time. One crate now owns Codex
//! (AAASM-5274).

pub use aa_devtool_codex::CodexAdapter;
