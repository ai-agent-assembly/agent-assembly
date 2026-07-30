//! Name-stable re-exports of the per-tool adapters.
//!
//! Each submodule used to hold its own detection-only `DevToolAdapter`
//! implementation, duplicating — and in three cases contradicting — the
//! dedicated `aa-devtool-*` crate for the same tool. Those duplicates are gone;
//! the submodules exist only so `aa_devtool::adapters::{…}` keeps resolving for
//! existing callers. New code should go through [`crate::registry`], which is
//! the single place a tool is mapped to its adapter (AAASM-5274).
pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod util;
pub mod windsurf;

pub use claude_code::ClaudeCodeAdapter;
pub use codex::CodexAdapter;
pub use copilot::CopilotAdapter;
pub use windsurf::WindsurfAdapter;
