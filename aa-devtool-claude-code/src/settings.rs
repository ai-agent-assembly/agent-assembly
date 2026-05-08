use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ClaudePermissions {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ClaudeSettings {
    pub permissions: ClaudePermissions,
    pub permission_mode: String,
    pub enabled_mcpjson_servers: Vec<String>,
    pub disabled_mcpjson_servers: Vec<String>,
}
