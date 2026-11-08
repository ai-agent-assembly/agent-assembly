//! Conversion between the runtime `AgentRecord`
//! and the durable [`storage::AgentRecord`](crate::storage::AgentRecord).
//!
//! The two records are intentionally different shapes (see
//! `aa-gateway/src/storage/agent.rs` for the rationale): the registry layer
//! owns liveness, heartbeats, and credential tokens; the storage layer
//! persists only the durable identity / configuration fields. This module
//! is the only place that knows how to translate between the two.
//!
//! Conversion runtime → storage is lossy by design: runtime-only fields
//! (`recent_events`, `active_sessions`, `credential_token`, lineage links,
//! …) are dropped because they are either ephemeral, security-sensitive,
//! or reconstructible at the next agent connect. The organization and the
//! registered public key are kept (AAASM-6451) so a restarted gateway can tell
//! that a re-registering caller holds the key of the record it is about to
//! re-bind; the credential is deliberately not kept, so a leaked database is not
//! a leaked token — the re-bind mints a new one. On rehydrate the inverse
//! direction synthesises defaults for the missing runtime fields so the
//! agent reappears in the registry as a root-level entry with status
//! [`AgentStatus::Active`].
//!
//! Introduced by Epic 18 Story S-I.2 (AAASM-1864) — the registry
//! write-through wiring that makes agent registrations durable across
//! gateway restarts.

use std::collections::VecDeque;

use aa_core::identity::AgentId;
use aa_core::{EnforcementMode, GovernanceLevel};
use chrono::Utc;

use crate::registry::AgentStatus;
use crate::storage::AgentRecord as StorageAgentRecord;

use super::store::AgentRecord as RuntimeAgentRecord;

/// Wire string persisted in `storage::AgentRecord::enforcement_mode` when the
/// runtime record carries no explicit per-agent override (`None`). Matches the
/// server-wide default the resolver falls back to, so a rehydrated agent with
/// no override behaves identically to a freshly-registered one.
const DEFAULT_ENFORCEMENT_MODE: &str = "enforce";

/// Metadata key used to carry the agent's friendly name through storage so
/// the runtime field can be restored on rehydrate. The runtime record's
/// `name` field has no direct column in `agent_registry`; piggy-backing on
/// `metadata["name"]` keeps the storage schema flat.
const METADATA_KEY_NAME: &str = "name";

/// Reserved metadata key carrying the agent's registered public key through
/// storage (AAASM-6451). `storage::AgentRecord` has no column for it, and a
/// rehydrated record with no key can never prove a re-registering caller holds
/// the same one. Only the bridge writes it: [`runtime_to_storage`] drops any
/// client-supplied entry under this key before inserting the record's own
/// `public_key`, and [`storage_to_runtime`] always removes it from the metadata
/// it hands back, so it never reaches a runtime record's metadata.
pub(crate) const METADATA_KEY_PUBLIC_KEY: &str = "aa.identity_pubkey";

/// Convert a runtime `AgentRecord` into its durable storage equivalent.
///
/// Lossy — runtime-only fields are dropped. `name` is round-tripped through
/// `metadata["name"]` so rehydrate can restore it.
///
/// AAASM-5288: the per-agent `enforcement_mode` override and its optional
/// shadow-window expiry are written through to durable storage so a mode
/// change survives a gateway restart. A `None` override persists the default
/// `"enforce"` string, matching the resolver's server-wide default.
pub fn runtime_to_storage(record: &RuntimeAgentRecord) -> StorageAgentRecord {
    let mut metadata = record.metadata.clone();
    metadata.insert(METADATA_KEY_NAME.to_string(), record.name.clone());
    metadata.remove(METADATA_KEY_PUBLIC_KEY);
    if !record.public_key.is_empty() {
        metadata.insert(METADATA_KEY_PUBLIC_KEY.to_string(), record.public_key.clone());
    }
    let enforcement_mode = record
        .enforcement_mode
        .map(EnforcementMode::as_wire)
        .unwrap_or(DEFAULT_ENFORCEMENT_MODE)
        .to_string();
    StorageAgentRecord {
        agent_id: AgentId::from_bytes(record.agent_id),
        team_id: record.team_id.clone(),
        // Persisted so a re-registering caller's operator key can be matched to
        // the record's organization after a restart (AAASM-6451), and so a
        // tenant-scoped delete finds the row it is meant to remove.
        org_id: record.org_id.clone(),
        metadata,
        registered_at: record.registered_at,
        last_seen_at: record.last_heartbeat,
        enforcement_mode,
        enforcement_mode_expires_at: record.enforcement_mode_expires_at,
    }
}

/// Synthesise a runtime `AgentRecord` from its storage row.
///
/// Used at boot-time rehydrate (see
/// `AgentRegistry::rehydrate_from_storage`). Fills the runtime-only fields
/// with defaults — restored agents reappear as root-level entries with
/// [`AgentStatus::Active`]; their credential tokens, lineage links, and
/// recent-event buffers do not survive a restart and are reconstructed at
/// the next agent connect.
pub fn storage_to_runtime(stored: StorageAgentRecord) -> RuntimeAgentRecord {
    let StorageAgentRecord {
        agent_id,
        team_id,
        org_id,
        mut metadata,
        registered_at,
        last_seen_at,
        enforcement_mode,
        enforcement_mode_expires_at,
    } = stored;

    let name = metadata.remove(METADATA_KEY_NAME).unwrap_or_default();
    let public_key = metadata.remove(METADATA_KEY_PUBLIC_KEY).unwrap_or_default();

    // AAASM-5288 — mandatory-expiry semantics must survive a restart. If the
    // persisted mode carried a shadow-window deadline that has already passed,
    // the window is reverted to the base mode on load: the override resolves
    // to `None` (falls through to the policy default / `Enforce`) and the
    // stale deadline is dropped. An already-expired shadow window must never
    // be silently resurrected as active. An unparseable mode string also
    // falls back to `None` rather than coercing to an active weaker mode.
    let expired = enforcement_mode_expires_at.is_some_and(|deadline| deadline <= Utc::now());
    let (enforcement_mode, enforcement_mode_expires_at) = if expired {
        (None, None)
    } else {
        let parsed = EnforcementMode::from_wire(&enforcement_mode);
        // HORO-1375 §4.2 — a persisted ("observe", NULL expiry) row is
        // corrupt or legacy: `set_enforcement_mode_persisted` now refuses to
        // ever write that shape (`RegistryError::UncappedShadowWindow`), so a
        // row like this on disk predates that guard or was written by
        // another path. Rehydrating it as `Some(Observe)` would resurrect an
        // uncapped, un-revertible shadow window. Fail closed to
        // `Some(Enforce)` instead — NOT `None`: under a personal-observe
        // deployment profile `None` itself resolves to `Observe`
        // (HORO-1375), so falling through to `None` here would silently
        // re-create the exact uncapped-Observe outcome this guard exists to
        // prevent.
        if matches!(parsed, Some(EnforcementMode::Observe)) && enforcement_mode_expires_at.is_none() {
            tracing::warn!(
                agent_id = ?agent_id,
                "rehydrated agent_registry row has enforcement_mode = observe with no expiry \
                 (corrupt or legacy row); fail-closed to enforce rather than resurrect an \
                 uncapped shadow window"
            );
            (Some(EnforcementMode::Enforce), None)
        } else {
            (parsed, enforcement_mode_expires_at)
        }
    };

    RuntimeAgentRecord {
        agent_id: *agent_id.as_bytes(),
        name,
        // Framework / version are not persisted today — left empty so
        // rehydrated entries are flagged for the next connect to refresh. The
        // public key comes back from its reserved metadata entry; a row written
        // before AAASM-6451 has none and stays empty, which no presented key equals.
        framework: String::new(),
        version: String::new(),
        risk_tier: 0,
        tool_names: Vec::new(),
        public_key,
        credential_token: String::new(),
        metadata,
        registered_at,
        last_heartbeat: last_seen_at,
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        active_sessions: Vec::new(),
        recent_events: VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: GovernanceLevel::L0Discover,
        parent_agent_id: None,
        team_id,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        // Restored agents reappear as roots — lineage is not persisted in
        // this Sub-task's storage schema.
        root_agent_id: Some(*agent_id.as_bytes()),
        children: Vec::new(),
        parent_key: None,
        enforcement_mode,
        enforcement_mode_expires_at,
        org_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn sample_runtime(agent_id: [u8; 16]) -> RuntimeAgentRecord {
        let mut metadata = BTreeMap::new();
        metadata.insert("env".to_string(), "staging".to_string());
        RuntimeAgentRecord {
            agent_id,
            name: "demo-agent".to_string(),
            framework: "langgraph".to_string(),
            version: "0.1.0".to_string(),
            risk_tier: 2,
            tool_names: vec!["search".to_string()],
            public_key: "pk".to_string(),
            credential_token: "token".to_string(),
            metadata,
            registered_at: Utc::now(),
            last_heartbeat: Utc::now(),
            status: AgentStatus::Active,
            pid: Some(1234),
            session_count: 0,
            last_event: None,
            active_sessions: Vec::new(),
            recent_events: VecDeque::new(),
            recent_traces: Vec::new(),
            layer: Some("enforced".to_string()),
            governance_level: GovernanceLevel::L1Observe,
            parent_agent_id: None,
            team_id: Some("teamA".to_string()),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: Some(agent_id),
            children: Vec::new(),
            parent_key: None,
            enforcement_mode: None,
            enforcement_mode_expires_at: None,
            org_id: None,
        }
    }

    #[test]
    fn runtime_to_storage_preserves_durable_fields() {
        let id = [9u8; 16];
        let rec = sample_runtime(id);
        let stored = runtime_to_storage(&rec);
        assert_eq!(stored.agent_id, AgentId::from_bytes(id));
        assert_eq!(stored.team_id.as_deref(), Some("teamA"));
        assert_eq!(stored.metadata.get("env").map(String::as_str), Some("staging"));
        // `name` is round-tripped via metadata so rehydrate can restore it.
        assert_eq!(
            stored.metadata.get(METADATA_KEY_NAME).map(String::as_str),
            Some("demo-agent")
        );
        assert_eq!(stored.enforcement_mode, DEFAULT_ENFORCEMENT_MODE);
    }

    #[test]
    fn storage_to_runtime_restores_name_and_team() {
        let id = [7u8; 16];
        let rec = sample_runtime(id);
        let stored = runtime_to_storage(&rec);
        let restored = storage_to_runtime(stored);
        assert_eq!(restored.agent_id, id);
        assert_eq!(restored.name, "demo-agent");
        assert_eq!(restored.team_id.as_deref(), Some("teamA"));
        // Rehydrate strips the synthetic `name` key from metadata.
        assert!(!restored.metadata.contains_key(METADATA_KEY_NAME));
        // Restored entries are roots with status Active.
        assert!(matches!(restored.status, AgentStatus::Active));
        assert_eq!(restored.parent_key, None);
        assert_eq!(restored.root_agent_id, Some(id));
    }

    #[test]
    fn org_and_public_key_survive_a_restart() {
        // AAASM-6451 — without these a restarted gateway cannot match a
        // re-registering caller's operator key to the record's organization, nor
        // check that the caller holds the key the record was created with.
        let id = [8u8; 16];
        let mut rec = sample_runtime(id);
        rec.org_id = Some("acme".to_string());
        rec.public_key = "pk-acme".to_string();
        rec.metadata
            .insert("aa.identity_key".to_string(), "durable/1".to_string());

        let stored = runtime_to_storage(&rec);
        assert_eq!(stored.org_id.as_deref(), Some("acme"));
        let restored = storage_to_runtime(stored);
        assert_eq!(restored.org_id.as_deref(), Some("acme"));
        assert_eq!(restored.public_key, "pk-acme");
        assert_eq!(
            restored.metadata.get("aa.identity_key").map(String::as_str),
            Some("durable/1"),
            "the durable-key marker must survive so an org-less record can be re-bound"
        );
        assert!(
            !restored.metadata.contains_key(METADATA_KEY_PUBLIC_KEY),
            "the reserved key is a transport detail and must not appear in runtime metadata"
        );
        assert_eq!(restored.credential_token, "", "the credential is never persisted");
    }

    #[test]
    fn a_client_supplied_public_key_entry_cannot_become_the_stored_key() {
        // The reserved entry is the gateway's alone: a record with no public key
        // must not carry whatever a client put under that name, or a legacy-shaped
        // row would look like it holds a key.
        let id = [10u8; 16];
        let mut rec = sample_runtime(id);
        rec.public_key = String::new();
        rec.metadata
            .insert(METADATA_KEY_PUBLIC_KEY.to_string(), "planted".to_string());
        let stored = runtime_to_storage(&rec);
        assert!(!stored.metadata.contains_key(METADATA_KEY_PUBLIC_KEY));
        assert_eq!(storage_to_runtime(stored).public_key, "");

        let mut with_key = sample_runtime(id);
        with_key.public_key = "real".to_string();
        with_key
            .metadata
            .insert(METADATA_KEY_PUBLIC_KEY.to_string(), "planted".to_string());
        assert_eq!(storage_to_runtime(runtime_to_storage(&with_key)).public_key, "real");
    }

    #[test]
    fn enforcement_mode_survives_a_restart() {
        // AAASM-5288 — a non-default per-agent override must be durably written
        // and read back on rehydrate, not reset to the in-memory default.
        //
        // HORO-1375: uses `Disabled`, not `Observe`, as the non-default
        // example. An `Observe` override with no expiry is now a corrupt/
        // legacy shape `storage_to_runtime` fail-closes to `Enforce` (see
        // `n7_uncapped_observe_row_rehydrates_fail_closed_to_enforce` below);
        // this test's purpose — an ordinary non-default override round-trips
        // unchanged — is unaffected by that guard when the mode is `Disabled`.
        let id = [3u8; 16];
        let mut rec = sample_runtime(id);
        rec.enforcement_mode = Some(EnforcementMode::Disabled);

        // Simulate the restart: runtime → storage (write-through) → runtime
        // (rehydrate on boot).
        let stored = runtime_to_storage(&rec);
        assert_eq!(
            stored.enforcement_mode, "disabled",
            "override must reach the durable column"
        );
        let restored = storage_to_runtime(stored);
        assert_eq!(
            restored.enforcement_mode,
            Some(EnforcementMode::Disabled),
            "override must survive the restart round-trip"
        );
    }

    #[test]
    fn expired_shadow_window_is_not_silently_resurrected() {
        // AAASM-5288 — a shadow (Observe) window whose deadline has already
        // passed must read back as reverted to the base mode on rehydrate,
        // never as an active Observe. Mandatory-expiry semantics survive the
        // restart.
        let id = [4u8; 16];
        let mut rec = sample_runtime(id);
        rec.enforcement_mode = Some(EnforcementMode::Observe);
        rec.enforcement_mode_expires_at = Some(Utc::now() - chrono::Duration::hours(1));

        let stored = runtime_to_storage(&rec);
        // The window is still stored as-was; the revert happens on load.
        assert_eq!(stored.enforcement_mode, "observe");
        assert!(stored.enforcement_mode_expires_at.is_some());

        let restored = storage_to_runtime(stored);
        assert_eq!(
            restored.enforcement_mode, None,
            "expired shadow window must resolve to the base mode, not stay Observe"
        );
        assert_eq!(
            restored.enforcement_mode_expires_at, None,
            "the stale deadline must be dropped on revert"
        );
    }

    #[test]
    fn unexpired_shadow_window_is_preserved() {
        // A shadow window whose deadline is still in the future must survive
        // the restart intact — the revert only fires once the deadline passes.
        let id = [5u8; 16];
        let deadline = Utc::now() + chrono::Duration::hours(1);
        let mut rec = sample_runtime(id);
        rec.enforcement_mode = Some(EnforcementMode::Observe);
        rec.enforcement_mode_expires_at = Some(deadline);

        let restored = storage_to_runtime(runtime_to_storage(&rec));
        assert_eq!(restored.enforcement_mode, Some(EnforcementMode::Observe));
        assert_eq!(restored.enforcement_mode_expires_at, Some(deadline));
    }

    /// HORO-1375 AC-3 N7 — a persisted `("observe", NULL expiry)` row (corrupt
    /// or legacy — `set_enforcement_mode_persisted` now refuses to ever write
    /// this shape) rehydrates FAIL-CLOSED to `Some(Enforce)`, never `None`
    /// (which would itself resolve to `Observe` under the personal-observe
    /// profile — the exact outcome this guard exists to prevent) and never
    /// left as the uncapped `Some(Observe)` it was stored as.
    #[test]
    fn n7_uncapped_observe_row_rehydrates_fail_closed_to_enforce() {
        let id = [6u8; 16];
        let mut rec = sample_runtime(id);
        rec.enforcement_mode = Some(EnforcementMode::Observe);
        rec.enforcement_mode_expires_at = None;

        let stored = runtime_to_storage(&rec);
        assert_eq!(stored.enforcement_mode, "observe");
        assert!(stored.enforcement_mode_expires_at.is_none());

        let restored = storage_to_runtime(stored);
        assert_eq!(
            restored.enforcement_mode,
            Some(EnforcementMode::Enforce),
            "an uncapped Observe row must fail closed to Enforce, not None and not Observe"
        );
        assert_eq!(restored.enforcement_mode_expires_at, None);
    }
}
