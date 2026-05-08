//! Integration tests for the SaaS governance overlay types.
//!
//! These tests exercise the overlay logic end-to-end: MCP allowlist enforcement
//! for Claude.ai and system-prompt note serialisation for ChatGPT.

use aa_devtool_saas::overlay::{ChatGptOverlay, ClaudeAiOverlay};

#[test]
fn claude_ai_allowlisted_mcp_server_passes() {
    let overlay = ClaudeAiOverlay {
        mcp_allowlist: vec!["filesystem".into()],
    };
    assert!(overlay.check_mcp_server("filesystem").is_ok());
}

#[test]
fn claude_ai_unlisted_mcp_server_rejected() {
    let overlay = ClaudeAiOverlay {
        mcp_allowlist: vec!["filesystem".into()],
    };
    let err = overlay.check_mcp_server("github").unwrap_err();
    assert!(err.to_string().contains("github"));
    assert!(err.to_string().contains("not on the Claude.ai allowlist"));
}

#[test]
fn chatgpt_system_prompt_note_roundtrips() {
    let overlay = ChatGptOverlay {
        system_prompt_note: "This GPT is governed by Agent Assembly.".into(),
    };
    let json = serde_json::to_string(&overlay).expect("serialize");
    let decoded: ChatGptOverlay = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(decoded.system_prompt_note, overlay.system_prompt_note);
}
