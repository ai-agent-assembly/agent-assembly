//! Re-export of the authoritative Windsurf Cascade adapter.
//!
//! This module used to carry a second, detection-only `WindsurfAdapter` that
//! declared `L1Observe`, while `aasm run windsurf` used
//! [`aa_devtool_windsurf::WindsurfCascadeAdapter`] declaring `L2Enforce` — the
//! same tool, two answers. `L2Enforce` is canonical (admin-settings sync, MCP
//! registry control, terminal allow/deny). One crate now owns Windsurf
//! (AAASM-5274).
//!
//! The alias keeps the historical `WindsurfAdapter` name importable from
//! `aa_devtool::adapters` so existing callers do not have to change.

pub use aa_devtool_windsurf::WindsurfCascadeAdapter as WindsurfAdapter;
