//! SaaS coding-agent observability adapter (L0–L1 only) for Agent Assembly.
//!
//! This crate implements [`DevToolAdapter`] for SaaS-hosted coding agents
//! (Claude.ai, ChatGPT, Cursor cloud). Because these agents run in opaque
//! SaaS environments, the adapter is capped at [`GovernanceLevel::L1Observe`]:
//! it can receive signed audit webhooks and apply advisory MCP allowlists, but
//! cannot perform in-process enforcement (L2) or native SDK integration (L3).
//!
//! # Secrets policy
//!
//! All HMAC secrets are stored as Vault-style opaque reference strings (e.g.
//! `"vault:secret/saas/claude-ai/hmac"`). The adapter never holds or logs a
//! plaintext secret; the resolution step is the caller's responsibility.
//!
//! # Modules
//!
//! | Module | Purpose |
//! | --- | --- |
//! | [`adapter`] | [`SaasCodingAgentAdapter`] + [`DevToolAdapter`] impl |
//! | [`provider`] | [`SaasProvider`] enum and [`SaasProviderConfig`] |
//! | [`signature`] | Per-provider HMAC-SHA256 webhook signature verification |
//! | [`overlay`] | Per-provider governance overlay types |
//!
//! [`DevToolAdapter`]: aa_core::DevToolAdapter
//! [`GovernanceLevel::L1Observe`]: aa_core::GovernanceLevel::L1Observe
//! [`SaasCodingAgentAdapter`]: adapter::SaasCodingAgentAdapter

pub mod adapter;
pub mod overlay;
pub mod provider;
pub mod signature;
