//! Minimal detection-only adapters for each supported dev tool.
//! Full adapter implementations (settings, MCP governance) are tracked in AAASM-201–204.
pub mod claude_code;
pub mod codex;
pub mod copilot;
pub mod util;
pub mod windsurf;

pub use claude_code::ClaudeCodeAdapter;
pub use codex::CodexAdapter;
pub use copilot::CopilotAdapter;
pub use windsurf::WindsurfAdapter;
