//! ChatGPT governance overlay — system-prompt note.
//!
//! ChatGPT Custom GPT configurations expose a system-prompt field that can be
//! used to prepend a governance note. This is an advisory L1 control: the
//! operator applies the note manually to the Custom GPT configuration.
//!
//! ChatGPT does not expose MCP server configuration via its Enterprise API,
//! so MCP allowlisting is intentionally absent from this overlay type.
//! See docs/devtools/governance-limits.md for details.

/// Governance overlay for ChatGPT Custom GPT configurations.
///
/// The `system_prompt_note` field contains a governance note that the operator
/// should prepend to the Custom GPT system prompt. This is advisory only (L1).
///
/// # Design note
///
/// ChatGPT does not support MCP allowlisting via its Enterprise API, so no
/// `mcp_allowlist` field exists here. The absence is intentional — this
/// documents the capability boundary rather than silently ignoring it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChatGptOverlay {
    /// Governance note appended to system prompt in Custom GPT configs.
    ///
    /// Advisory (L1 only). The operator must apply this manually to the
    /// Custom GPT configuration via the OpenAI platform.
    pub system_prompt_note: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_note_roundtrips_serde() {
        let overlay = ChatGptOverlay {
            system_prompt_note: "This GPT is governed by Agent Assembly.".into(),
        };
        let json = serde_json::to_string(&overlay).expect("serialize");
        let decoded: ChatGptOverlay = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.system_prompt_note, overlay.system_prompt_note);
    }

    #[test]
    fn no_mcp_allowlist_key_in_serialized_json() {
        let overlay = ChatGptOverlay {
            system_prompt_note: "governed".into(),
        };
        let value = serde_json::to_value(&overlay).expect("serialize");
        assert!(
            value.get("mcp_allowlist").is_none(),
            "ChatGptOverlay must not expose an mcp_allowlist key — ChatGPT does not support MCP allowlisting"
        );
    }
}
