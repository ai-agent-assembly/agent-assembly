//! Immutable, hash-chained audit entry for Agent Assembly governance events.
//!
//! Each [`AuditEntry`] commits to all tamper-meaningful fields via a SHA-256 hash
//! that includes the hash of the preceding entry, forming a tamper-evident chain.
//!
//! Gated on the `alloc` feature because [`AuditEntry::payload`] is an
//! [`alloc::string::String`].

use alloc::string::String;
use sha2::{Digest, Sha256};

use crate::{AgentId, SessionId};

// ---------------------------------------------------------------------------
// AuditEventType
// ---------------------------------------------------------------------------

/// Category of a governance event recorded in an [`AuditEntry`].
///
/// The `#[repr(u32)]` attribute makes `event_type as u32` the canonical
/// 4-byte discriminant used in the SHA-256 hash input.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuditEventType {
    /// A tool call was intercepted by the governance layer before execution.
    ToolCallIntercepted = 0,
    /// An evaluated action violated an active policy rule.
    PolicyViolation = 1,
    /// A credential or secret present in tool arguments was blocked.
    CredentialLeakBlocked = 2,
    /// Human approval was requested before the action could proceed.
    ApprovalRequested = 3,
    /// A pending human approval request was granted.
    ApprovalGranted = 4,
    /// A pending human approval request was denied.
    ApprovalDenied = 5,
    /// The session budget is approaching its configured limit.
    BudgetLimitApproached = 6,
    /// The session budget has been exhausted; further actions are blocked.
    BudgetLimitExceeded = 7,
    /// A pending human approval request expired before a decision was made.
    ApprovalTimedOut = 8,
    /// An approval request was routed to a team-specific approver queue.
    ApprovalRouted = 9,
    /// An approval request was escalated after the initial approver did not respond.
    ApprovalEscalated = 10,
    /// An agent was force-deregistered by the gateway because it exceeded its configured maximum age.
    AgentForceDeregistered = 11,
}

impl AuditEventType {
    /// Returns the string label used in [`Display`] output and log messages.
    ///
    /// [`Display`]: core::fmt::Display
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToolCallIntercepted => "ToolCallIntercepted",
            Self::PolicyViolation => "PolicyViolation",
            Self::CredentialLeakBlocked => "CredentialLeakBlocked",
            Self::ApprovalRequested => "ApprovalRequested",
            Self::ApprovalGranted => "ApprovalGranted",
            Self::ApprovalDenied => "ApprovalDenied",
            Self::BudgetLimitApproached => "BudgetLimitApproached",
            Self::BudgetLimitExceeded => "BudgetLimitExceeded",
            Self::ApprovalTimedOut => "ApprovalTimedOut",
            Self::ApprovalRouted => "ApprovalRouted",
            Self::ApprovalEscalated => "ApprovalEscalated",
            Self::AgentForceDeregistered => "AgentForceDeregistered",
        }
    }
}

// ---------------------------------------------------------------------------
// Lineage
// ---------------------------------------------------------------------------

/// Optional agent-topology fields attached to an [`AuditEntry`].
///
/// All fields are `None` for entries emitted without an `AgentContext`
/// (legacy path). `Lineage::default()` passed to
/// [`AuditEntry::new_with_lineage`] produces a hash identical to
/// [`AuditEntry::new`] with the same base fields.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lineage {
    /// Root agent identifier at the top of the delegation chain.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub root_agent_id: Option<AgentId>,
    /// Identifier of the agent that directly spawned this agent.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub parent_agent_id: Option<AgentId>,
    /// Team identifier associated with the agent that produced the entry.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub team_id: Option<String>,
    /// Human-readable reason the action was delegated to this agent.
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub delegation_reason: Option<String>,
    /// Name of the tool or framework that spawned this agent (e.g. `"langgraph"`).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub spawned_by_tool: Option<String>,
    /// Delegation depth from the root agent (`0` = root, `1` = first delegate, …).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    pub depth: Option<u32>,
}

// ---------------------------------------------------------------------------
// AuditEntry
// ---------------------------------------------------------------------------

/// An immutable, hash-chained record of a single governance event.
///
/// ## Immutability
///
/// All fields are private. The only way to create an [`AuditEntry`] is via
/// [`AuditEntry::new`]. There are no mutation methods.
///
/// ## Hash chain
///
/// `entry_hash` is a SHA-256 digest computed over all tamper-meaningful fields
/// in a canonical byte order (see [`AuditEntry::new`] for the full sequence).
/// Each entry commits to `previous_hash`, linking entries into a tamper-evident
/// chain. The genesis entry uses `[0u8; 32]` as `previous_hash`.
///
/// ## Tamper detection
///
/// [`AuditEntry::verify_integrity`] re-computes the hash from the stored fields
/// and compares it to the stored `entry_hash`. Any field alteration — including
/// via `unsafe` code — will cause the re-computed hash to diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuditEntry {
    seq: u64,
    timestamp_ns: u64,
    event_type: AuditEventType,
    agent_id: AgentId,
    session_id: SessionId,
    payload: String,
    previous_hash: [u8; 32],
    entry_hash: [u8; 32],
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    root_agent_id: Option<AgentId>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    parent_agent_id: Option<AgentId>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    team_id: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    delegation_reason: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    spawned_by_tool: Option<String>,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none", default))]
    depth: Option<u32>,
}

impl AuditEntry {
    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// Create a new [`AuditEntry`], computing `entry_hash` over all fields.
    ///
    /// ## Parameters
    ///
    /// - `seq` — monotonic counter within the session; genesis entry is `0`.
    /// - `timestamp_ns` — nanoseconds since the Unix epoch (caller-supplied;
    ///   use `Timestamp::from(SystemTime::now()).as_nanos()` in `std` environments).
    /// - `event_type` — category of the governance event.
    /// - `agent_id` — identifier of the agent that produced the event.
    /// - `session_id` — identifier of the specific agent run.
    /// - `payload` — pre-serialized UTF-8 string (JSON in practice).
    /// - `previous_hash` — `entry_hash` of the preceding entry;
    ///   `[0u8; 32]` for the genesis entry.
    ///
    /// ## Canonical hash input (84 fixed bytes + variable payload)
    ///
    /// ```text
    /// SHA-256(
    ///     seq.to_be_bytes()                  //  8 bytes
    ///     || timestamp_ns.to_be_bytes()      //  8 bytes
    ///     || (event_type as u32).to_be_bytes() // 4 bytes
    ///     || agent_id.as_bytes()             // 16 bytes
    ///     || session_id.as_bytes()           // 16 bytes
    ///     || previous_hash                   // 32 bytes
    ///     || payload.as_bytes()              // variable
    /// )
    /// ```
    pub fn new(
        seq: u64,
        timestamp_ns: u64,
        event_type: AuditEventType,
        agent_id: AgentId,
        session_id: SessionId,
        payload: String,
        previous_hash: [u8; 32],
    ) -> Self {
        let entry_hash = Self::compute_hash(
            seq,
            timestamp_ns,
            &event_type,
            &agent_id,
            &session_id,
            &previous_hash,
            &payload,
            &Lineage::default(),
        );
        Self {
            seq,
            timestamp_ns,
            event_type,
            agent_id,
            session_id,
            payload,
            previous_hash,
            entry_hash,
            root_agent_id: None,
            parent_agent_id: None,
            team_id: None,
            delegation_reason: None,
            spawned_by_tool: None,
            depth: None,
        }
    }

    /// Create a new [`AuditEntry`] with optional lineage fields, computing `entry_hash`
    /// over all fields including the lineage data.
    ///
    /// When `lineage` is `Lineage::default()` (all fields `None`), the resulting
    /// `entry_hash` is identical to that produced by [`AuditEntry::new`] with the
    /// same base fields, preserving backward compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_lineage(
        seq: u64,
        timestamp_ns: u64,
        event_type: AuditEventType,
        agent_id: AgentId,
        session_id: SessionId,
        payload: String,
        previous_hash: [u8; 32],
        lineage: Lineage,
    ) -> Self {
        let entry_hash = Self::compute_hash(
            seq,
            timestamp_ns,
            &event_type,
            &agent_id,
            &session_id,
            &previous_hash,
            &payload,
            &lineage,
        );
        Self {
            seq,
            timestamp_ns,
            event_type,
            agent_id,
            session_id,
            payload,
            previous_hash,
            entry_hash,
            root_agent_id: lineage.root_agent_id,
            parent_agent_id: lineage.parent_agent_id,
            team_id: lineage.team_id,
            delegation_reason: lineage.delegation_reason,
            spawned_by_tool: lineage.spawned_by_tool,
            depth: lineage.depth,
        }
    }

    // -----------------------------------------------------------------------
    // Getters
    // -----------------------------------------------------------------------

    /// Monotonic sequence counter within the session.
    #[inline]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Nanoseconds since the Unix epoch at the time the entry was created.
    #[inline]
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Category of the governance event.
    #[inline]
    pub fn event_type(&self) -> AuditEventType {
        self.event_type
    }

    /// Identifier of the agent that produced this entry.
    #[inline]
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Identifier of the specific agent run (session) that produced this entry.
    #[inline]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Pre-serialized UTF-8 payload (JSON in practice).
    #[inline]
    pub fn payload(&self) -> &str {
        &self.payload
    }

    /// SHA-256 hash of the preceding entry; `[0u8; 32]` for the genesis entry.
    #[inline]
    pub fn previous_hash(&self) -> &[u8; 32] {
        &self.previous_hash
    }

    /// SHA-256 hash computed over all tamper-meaningful fields at construction.
    #[inline]
    pub fn entry_hash(&self) -> &[u8; 32] {
        &self.entry_hash
    }

    /// Root agent identifier in the delegation chain, if present.
    #[inline]
    pub fn root_agent_id(&self) -> Option<AgentId> {
        self.root_agent_id
    }

    /// Parent agent identifier that directly spawned this agent, if present.
    #[inline]
    pub fn parent_agent_id(&self) -> Option<AgentId> {
        self.parent_agent_id
    }

    /// Team identifier associated with the agent, if present.
    #[inline]
    pub fn team_id(&self) -> Option<&str> {
        self.team_id.as_deref()
    }

    /// Reason this agent was delegated the action, if present.
    #[inline]
    pub fn delegation_reason(&self) -> Option<&str> {
        self.delegation_reason.as_deref()
    }

    /// Name of the tool that spawned this agent, if present.
    #[inline]
    pub fn spawned_by_tool(&self) -> Option<&str> {
        self.spawned_by_tool.as_deref()
    }

    /// Delegation depth from the root agent, if present.
    #[inline]
    pub fn depth(&self) -> Option<u32> {
        self.depth
    }

    // -----------------------------------------------------------------------
    // Integrity
    // -----------------------------------------------------------------------

    /// Returns `true` if the stored `entry_hash` matches a fresh re-computation
    /// over the stored fields.
    ///
    /// Returns `false` if any field has been altered after construction — including
    /// via `unsafe` code.
    pub fn verify_integrity(&self) -> bool {
        let lineage = Lineage {
            root_agent_id: self.root_agent_id,
            parent_agent_id: self.parent_agent_id,
            team_id: self.team_id.clone(),
            delegation_reason: self.delegation_reason.clone(),
            spawned_by_tool: self.spawned_by_tool.clone(),
            depth: self.depth,
        };
        let expected = Self::compute_hash(
            self.seq,
            self.timestamp_ns,
            &self.event_type,
            &self.agent_id,
            &self.session_id,
            &self.previous_hash,
            &self.payload,
            &lineage,
        );
        expected == self.entry_hash
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Canonical SHA-256 computation over all tamper-meaningful fields.
    ///
    /// Field order and encoding are fixed — see [`AuditEntry::new`] for the
    /// documented byte sequence. Lineage fields append only when `Some`;
    /// when all lineage fields are `None`, output equals the pre-AAASM-934 hash exactly.
    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        seq: u64,
        timestamp_ns: u64,
        event_type: &AuditEventType,
        agent_id: &AgentId,
        session_id: &SessionId,
        previous_hash: &[u8; 32],
        payload: &str,
        lineage: &Lineage,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(seq.to_be_bytes());
        hasher.update(timestamp_ns.to_be_bytes());
        hasher.update((*event_type as u32).to_be_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(previous_hash);
        hasher.update(payload.as_bytes());
        // Lineage — append only when present; None contributes 0 bytes.
        // When all fields are None, hash equals pre-AAASM-934 output exactly.
        if let Some(id) = &lineage.root_agent_id {
            hasher.update(id.as_bytes());
        }
        if let Some(id) = &lineage.parent_agent_id {
            hasher.update(id.as_bytes());
        }
        if let Some(s) = &lineage.team_id {
            hasher.update((s.len() as u32).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        if let Some(s) = &lineage.delegation_reason {
            hasher.update((s.len() as u32).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        if let Some(s) = &lineage.spawned_by_tool {
            hasher.update((s.len() as u32).to_be_bytes());
            hasher.update(s.as_bytes());
        }
        if let Some(d) = lineage.depth {
            hasher.update(d.to_be_bytes());
        }
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

impl core::fmt::Display for AuditEntry {
    /// Human-readable one-line representation suitable for log output.
    ///
    /// Format: `[seq=N ts=T agent=HEX session=HEX event=TypeName]`
    ///
    /// `payload` is omitted from `Display` — it may be arbitrarily large.
    /// Use [`AuditEntry::payload`] to access the full payload string.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[seq={} ts={} agent=", self.seq, self.timestamp_ns)?;
        for b in self.agent_id.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, " session=")?;
        for b in self.session_id.as_bytes() {
            write!(f, "{:02x}", b)?;
        }
        write!(f, " event={}]", self.event_type.as_str())
    }
}

// ---------------------------------------------------------------------------
// AuditLogError
// ---------------------------------------------------------------------------

/// Error returned by [`AuditLog::push`] when an appended entry violates
/// the log's monotonicity or hash-chain invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditLogError {
    /// The entry's `seq` did not equal the log's expected next sequence number.
    SequenceGap {
        /// The sequence number the log expected.
        expected: u64,
        /// The sequence number the entry carried.
        got: u64,
    },
    /// The entry's `previous_hash` did not match the `entry_hash` of the
    /// last entry in the log (or the genesis zero-hash for the first entry).
    HashChainBroken {
        /// The `seq` of the entry that broke the chain.
        at_seq: u64,
    },
}

impl core::fmt::Display for AuditLogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SequenceGap { expected, got } => {
                write!(f, "audit log sequence gap: expected seq={expected}, got seq={got}")
            }
            Self::HashChainBroken { at_seq } => {
                write!(f, "audit log hash chain broken at seq={at_seq}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

/// A session-scoped, append-only sequence of [`AuditEntry`] records that
/// enforces monotonic sequence numbers and hash-chain continuity on every append.
///
/// ## Invariants
///
/// - Every entry's `seq` equals the previous entry's `seq + 1` (genesis: `seq = 0`).
/// - Every entry's `previous_hash` equals the preceding entry's `entry_hash`
///   (genesis entry uses `[0u8; 32]`).
///
/// Both invariants are checked by [`AuditLog::push`] at append time.
/// [`AuditLog::verify_chain`] re-validates them across the entire stored log.
pub struct AuditLog {
    agent_id: AgentId,
    session_id: SessionId,
    entries: alloc::vec::Vec<AuditEntry>,
    /// The `seq` value the next appended entry must carry.
    next_seq: u64,
    /// The `entry_hash` of the last appended entry; `[0u8; 32]` before any entry.
    last_hash: [u8; 32],
}

impl AuditLog {
    /// Create a new, empty [`AuditLog`] for the given agent and session.
    ///
    /// The log starts with `next_seq = 0` and `last_hash = [0u8; 32]` (the
    /// genesis previous-hash sentinel).
    pub fn new(agent_id: AgentId, session_id: SessionId) -> Self {
        Self {
            agent_id,
            session_id,
            entries: alloc::vec::Vec::new(),
            next_seq: 0,
            last_hash: [0u8; 32],
        }
    }

    /// Read-only view of all entries in append order.
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Number of entries currently stored in the log.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the log contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The agent identifier associated with this log.
    pub fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// The session identifier associated with this log.
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Append a pre-built [`AuditEntry`] to the log, validating both invariants.
    ///
    /// ## Errors
    ///
    /// - [`AuditLogError::SequenceGap`] if `entry.seq() != self.next_seq`.
    /// - [`AuditLogError::HashChainBroken`] if `entry.previous_hash() != &self.last_hash`.
    ///
    /// On error the log is not modified.
    pub fn push(&mut self, entry: AuditEntry) -> Result<(), AuditLogError> {
        if entry.seq() != self.next_seq {
            return Err(AuditLogError::SequenceGap {
                expected: self.next_seq,
                got: entry.seq(),
            });
        }
        if entry.previous_hash() != &self.last_hash {
            return Err(AuditLogError::HashChainBroken { at_seq: entry.seq() });
        }
        self.last_hash = *entry.entry_hash();
        self.next_seq += 1;
        self.entries.push(entry);
        Ok(())
    }

    /// Build and append the next [`AuditEntry`] in one atomic step.
    ///
    /// `seq` and `previous_hash` are derived automatically from the log's
    /// current state, eliminating the risk of caller-side sequencing errors.
    ///
    /// ## Parameters
    ///
    /// - `event_type` — category of the governance event.
    /// - `timestamp_ns` — nanoseconds since Unix epoch (caller-supplied for
    ///   `no_std` compatibility).
    /// - `payload` — pre-serialized UTF-8 string (JSON in practice).
    ///
    /// Returns a reference to the newly appended entry.
    pub fn next_entry(&mut self, event_type: AuditEventType, timestamp_ns: u64, payload: String) -> &AuditEntry {
        let entry = AuditEntry::new(
            self.next_seq,
            timestamp_ns,
            event_type,
            self.agent_id,
            self.session_id,
            payload,
            self.last_hash,
        );
        // next_entry constructs the entry with the correct seq and previous_hash,
        // so push() cannot fail here.
        self.push(entry).expect("next_entry invariant: push cannot fail");
        self.entries.last().expect("entry was just pushed")
    }

    /// Build and append the next [`AuditEntry`] with lineage fields in one atomic step.
    ///
    /// Equivalent to [`AuditLog::next_entry`] but attaches agent-topology metadata.
    /// `seq` and `previous_hash` are derived automatically from the log's current state.
    ///
    /// ## Parameters
    ///
    /// - `event_type` — category of the governance event.
    /// - `timestamp_ns` — nanoseconds since Unix epoch (caller-supplied for `no_std` compatibility).
    /// - `payload` — pre-serialized UTF-8 string (JSON in practice).
    /// - `lineage` — optional agent-topology fields; `Lineage::default()` produces the same hash
    ///   as [`AuditLog::next_entry`] with the same base fields.
    ///
    /// Returns a reference to the newly appended entry.
    pub fn next_entry_with_lineage(
        &mut self,
        event_type: AuditEventType,
        timestamp_ns: u64,
        payload: String,
        lineage: Lineage,
    ) -> &AuditEntry {
        let entry = AuditEntry::new_with_lineage(
            self.next_seq,
            timestamp_ns,
            event_type,
            self.agent_id,
            self.session_id,
            payload,
            self.last_hash,
            lineage,
        );
        self.push(entry)
            .expect("next_entry_with_lineage invariant: push cannot fail");
        self.entries.last().expect("entry was just pushed")
    }

    /// Re-validate the entire log in O(n), checking both invariants for every entry.
    ///
    /// Returns `true` if:
    /// - Every entry passes [`AuditEntry::verify_integrity`] (SHA-256 matches stored hash).
    /// - Every entry's `seq` is exactly one greater than the previous entry's `seq`
    ///   (first entry must have `seq = 0`).
    /// - Every entry's `previous_hash` matches the preceding entry's `entry_hash`
    ///   (first entry must have `previous_hash = [0u8; 32]`).
    ///
    /// Returns `true` for an empty log (vacuously valid).
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev_hash: [u8; 32] = [0u8; 32];

        for (expected_seq, entry) in self.entries.iter().enumerate() {
            if !entry.verify_integrity() {
                return false;
            }
            if entry.seq() != expected_seq as u64 {
                return false;
            }
            if entry.previous_hash() != &expected_prev_hash {
                return false;
            }
            expected_prev_hash = *entry.entry_hash();
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Shared test fixtures
    const AGENT_BYTES: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    const SESSION_BYTES: [u8; 16] = [17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    const GENESIS_HASH: [u8; 32] = [0u8; 32];

    fn make_entry(seq: u64) -> AuditEntry {
        AuditEntry::new(
            seq,
            1_714_222_134_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            alloc::string::String::from("{\"tool\":\"bash\",\"args\":{\"cmd\":\"ls\"}}"),
            GENESIS_HASH,
        )
    }

    // --- AuditEventType ---

    #[test]
    fn event_type_as_str_all_variants() {
        assert_eq!(AuditEventType::ToolCallIntercepted.as_str(), "ToolCallIntercepted");
        assert_eq!(AuditEventType::PolicyViolation.as_str(), "PolicyViolation");
        assert_eq!(AuditEventType::CredentialLeakBlocked.as_str(), "CredentialLeakBlocked");
        assert_eq!(AuditEventType::ApprovalRequested.as_str(), "ApprovalRequested");
        assert_eq!(AuditEventType::ApprovalGranted.as_str(), "ApprovalGranted");
        assert_eq!(AuditEventType::ApprovalDenied.as_str(), "ApprovalDenied");
        assert_eq!(AuditEventType::BudgetLimitApproached.as_str(), "BudgetLimitApproached");
        assert_eq!(AuditEventType::BudgetLimitExceeded.as_str(), "BudgetLimitExceeded");
        assert_eq!(AuditEventType::ApprovalTimedOut.as_str(), "ApprovalTimedOut");
        assert_eq!(AuditEventType::ApprovalRouted.as_str(), "ApprovalRouted");
        assert_eq!(AuditEventType::ApprovalEscalated.as_str(), "ApprovalEscalated");
    }

    #[test]
    fn event_type_discriminants_are_0_through_10() {
        assert_eq!(AuditEventType::ToolCallIntercepted as u32, 0);
        assert_eq!(AuditEventType::PolicyViolation as u32, 1);
        assert_eq!(AuditEventType::CredentialLeakBlocked as u32, 2);
        assert_eq!(AuditEventType::ApprovalRequested as u32, 3);
        assert_eq!(AuditEventType::ApprovalGranted as u32, 4);
        assert_eq!(AuditEventType::ApprovalDenied as u32, 5);
        assert_eq!(AuditEventType::BudgetLimitApproached as u32, 6);
        assert_eq!(AuditEventType::BudgetLimitExceeded as u32, 7);
        assert_eq!(AuditEventType::ApprovalTimedOut as u32, 8);
        assert_eq!(AuditEventType::ApprovalRouted as u32, 9);
        assert_eq!(AuditEventType::ApprovalEscalated as u32, 10);
    }

    #[test]
    fn event_type_variants_are_all_distinct() {
        let variants = [
            AuditEventType::ToolCallIntercepted,
            AuditEventType::PolicyViolation,
            AuditEventType::CredentialLeakBlocked,
            AuditEventType::ApprovalRequested,
            AuditEventType::ApprovalGranted,
            AuditEventType::ApprovalDenied,
            AuditEventType::BudgetLimitApproached,
            AuditEventType::BudgetLimitExceeded,
            AuditEventType::ApprovalTimedOut,
            AuditEventType::ApprovalRouted,
            AuditEventType::ApprovalEscalated,
        ];
        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(variants[i], variants[j]);
            }
        }
    }

    // --- AuditEntry::new() and getters ---

    #[test]
    fn new_produces_nonzero_entry_hash() {
        let entry = make_entry(0);
        assert_ne!(entry.entry_hash(), &[0u8; 32]);
    }

    #[test]
    fn getters_return_correct_values() {
        let payload = alloc::string::String::from("{\"k\":\"v\"}");
        let entry = AuditEntry::new(
            42,
            999_000_000,
            AuditEventType::PolicyViolation,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            payload.clone(),
            GENESIS_HASH,
        );
        assert_eq!(entry.seq(), 42);
        assert_eq!(entry.timestamp_ns(), 999_000_000);
        assert_eq!(entry.event_type(), AuditEventType::PolicyViolation);
        assert_eq!(entry.agent_id(), AgentId::from_bytes(AGENT_BYTES));
        assert_eq!(entry.session_id(), SessionId::from_bytes(SESSION_BYTES));
        assert_eq!(entry.payload(), "{\"k\":\"v\"}");
        assert_eq!(entry.previous_hash(), &GENESIS_HASH);
    }

    #[test]
    fn genesis_entry_uses_zero_previous_hash() {
        let entry = make_entry(0);
        assert_eq!(entry.previous_hash(), &[0u8; 32]);
    }

    // --- verify_integrity() ---

    #[test]
    fn verify_integrity_true_for_untampered_entry() {
        assert!(make_entry(0).verify_integrity());
    }

    #[test]
    fn verify_integrity_false_after_seq_tamper() {
        let mut entry = make_entry(0);
        // SAFETY: deliberate tampering to test integrity detection.
        unsafe {
            let ptr = &mut entry.seq as *mut u64;
            *ptr = 999;
        }
        assert!(!entry.verify_integrity());
    }

    #[test]
    fn verify_integrity_false_after_payload_tamper() {
        let mut entry = make_entry(0);
        // SAFETY: deliberate tampering to test integrity detection.
        unsafe {
            let ptr = entry.payload.as_mut_vec();
            if let Some(b) = ptr.first_mut() {
                *b = b'X';
            }
        }
        assert!(!entry.verify_integrity());
    }

    #[test]
    fn verify_integrity_false_after_event_type_tamper() {
        let mut entry = make_entry(0);
        // SAFETY: deliberate tampering to test integrity detection.
        unsafe {
            let ptr = &mut entry.event_type as *mut AuditEventType;
            *ptr = AuditEventType::BudgetLimitExceeded;
        }
        assert!(!entry.verify_integrity());
    }

    #[test]
    fn verify_integrity_false_after_previous_hash_tamper() {
        let mut entry = make_entry(0);
        // SAFETY: deliberate tampering to test integrity detection.
        unsafe {
            let ptr = &mut entry.previous_hash as *mut [u8; 32];
            (*ptr)[0] = 0xFF;
        }
        assert!(!entry.verify_integrity());
    }

    // --- Hash chain linkage ---

    #[test]
    fn chained_entries_have_distinct_hashes() {
        let first = make_entry(0);
        let second = AuditEntry::new(
            1,
            1_714_222_134_000_000_001,
            AuditEventType::PolicyViolation,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            alloc::string::String::from("{\"rule\":\"deny\"}"),
            *first.entry_hash(),
        );
        assert_ne!(first.entry_hash(), second.entry_hash());
        assert_eq!(second.previous_hash(), first.entry_hash());
        assert!(second.verify_integrity());
    }

    #[test]
    fn different_seq_produces_different_hash() {
        let a = make_entry(0);
        let b = make_entry(1);
        assert_ne!(a.entry_hash(), b.entry_hash());
    }

    #[test]
    fn different_previous_hash_produces_different_entry_hash() {
        let prev_a = [0u8; 32];
        let mut prev_b = [0u8; 32];
        prev_b[0] = 1;

        let a = AuditEntry::new(
            0,
            0,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            alloc::string::String::from("{}"),
            prev_a,
        );
        let b = AuditEntry::new(
            0,
            0,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            alloc::string::String::from("{}"),
            prev_b,
        );
        assert_ne!(a.entry_hash(), b.entry_hash());
    }

    // --- Display ---

    #[test]
    fn display_contains_seq_ts_and_event_name() {
        let entry = make_entry(7);
        let s = alloc::format!("{}", entry);
        assert!(s.starts_with('['));
        assert!(s.ends_with(']'));
        assert!(s.contains("seq=7"));
        assert!(s.contains("ts=1714222134000000000"));
        assert!(s.contains("event=ToolCallIntercepted"));
    }

    #[test]
    fn display_contains_agent_and_session_hex() {
        let entry = make_entry(0);
        let s = alloc::format!("{}", entry);
        // AGENT_BYTES starts with 01 02 03 04
        assert!(s.contains("agent=01020304"));
        // SESSION_BYTES starts with 11 12 13 14
        assert!(s.contains("session=11121314"));
    }

    #[test]
    fn display_does_not_contain_payload() {
        let entry = make_entry(0);
        let s = alloc::format!("{}", entry);
        assert!(!s.contains("bash"));
    }

    // --- AuditLog helpers ---

    fn make_log() -> AuditLog {
        AuditLog::new(AgentId::from_bytes(AGENT_BYTES), SessionId::from_bytes(SESSION_BYTES))
    }

    fn make_valid_entry(seq: u64, previous_hash: [u8; 32]) -> AuditEntry {
        AuditEntry::new(
            seq,
            1_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AgentId::from_bytes(AGENT_BYTES),
            SessionId::from_bytes(SESSION_BYTES),
            alloc::string::String::from("{}"),
            previous_hash,
        )
    }

    // --- AuditLog::push() ---

    #[test]
    fn push_genesis_entry_succeeds() {
        let mut log = make_log();
        let entry = make_valid_entry(0, GENESIS_HASH);
        assert!(log.push(entry).is_ok());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn push_rejects_seq_gap_skipping_forward() {
        let mut log = make_log();
        let entry = make_valid_entry(2, GENESIS_HASH); // expected seq=0
        let err = log.push(entry).unwrap_err();
        assert_eq!(err, AuditLogError::SequenceGap { expected: 0, got: 2 });
        assert!(log.is_empty(), "log must be unmodified on error");
    }

    #[test]
    fn push_rejects_seq_going_backward() {
        let mut log = make_log();
        let e0 = make_valid_entry(0, GENESIS_HASH);
        let hash0 = *e0.entry_hash();
        log.push(e0).unwrap();

        let e_back = make_valid_entry(0, hash0); // duplicate seq=0
        let err = log.push(e_back).unwrap_err();
        assert_eq!(err, AuditLogError::SequenceGap { expected: 1, got: 0 });
        assert_eq!(log.len(), 1, "log must be unmodified on error");
    }

    #[test]
    fn push_rejects_broken_hash_chain() {
        let mut log = make_log();
        let e0 = make_valid_entry(0, GENESIS_HASH);
        log.push(e0).unwrap();

        let wrong_prev = [0xAB; 32]; // not equal to e0.entry_hash()
        let e1 = make_valid_entry(1, wrong_prev);
        let err = log.push(e1).unwrap_err();
        assert_eq!(err, AuditLogError::HashChainBroken { at_seq: 1 });
        assert_eq!(log.len(), 1, "log must be unmodified on error");
    }

    #[test]
    fn push_two_valid_entries_succeeds() {
        let mut log = make_log();
        let e0 = make_valid_entry(0, GENESIS_HASH);
        let hash0 = *e0.entry_hash();
        log.push(e0).unwrap();

        let e1 = make_valid_entry(1, hash0);
        log.push(e1).unwrap();

        assert_eq!(log.len(), 2);
        assert_eq!(log.entries()[0].seq(), 0);
        assert_eq!(log.entries()[1].seq(), 1);
    }

    #[test]
    fn audit_log_error_display_sequence_gap() {
        let err = AuditLogError::SequenceGap { expected: 3, got: 7 };
        let s = alloc::format!("{}", err);
        assert!(s.contains("expected seq=3"));
        assert!(s.contains("got seq=7"));
    }

    #[test]
    fn audit_log_error_display_hash_chain_broken() {
        let err = AuditLogError::HashChainBroken { at_seq: 5 };
        let s = alloc::format!("{}", err);
        assert!(s.contains("at_seq=5") || s.contains("at seq=5"));
    }

    // --- AuditLog::next_entry() ---

    #[test]
    fn next_entry_genesis_has_seq_zero_and_zero_prev_hash() {
        let mut log = make_log();
        let e = log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        assert_eq!(e.seq(), 0);
        assert_eq!(e.previous_hash(), &GENESIS_HASH);
        assert!(e.verify_integrity());
    }

    #[test]
    fn next_entry_auto_increments_seq() {
        let mut log = make_log();
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::PolicyViolation,
            2_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::ApprovalGranted,
            3_000,
            alloc::string::String::from("{}"),
        );

        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[0].seq(), 0);
        assert_eq!(log.entries()[1].seq(), 1);
        assert_eq!(log.entries()[2].seq(), 2);
    }

    #[test]
    fn next_entry_links_previous_hash_correctly() {
        let mut log = make_log();
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::PolicyViolation,
            2_000,
            alloc::string::String::from("{}"),
        );

        let e0_hash = *log.entries()[0].entry_hash();
        assert_eq!(log.entries()[1].previous_hash(), &e0_hash);
    }

    #[test]
    fn next_entry_mixed_with_push_works_correctly() {
        let mut log = make_log();
        // First entry via next_entry
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        let hash0 = *log.entries()[0].entry_hash();

        // Second entry via manual push with correct seq and previous_hash
        let e1 = make_valid_entry(1, hash0);
        log.push(e1).unwrap();

        // Third entry via next_entry — should pick up seq=2 and hash1
        log.next_entry(
            AuditEventType::ApprovalGranted,
            3_000,
            alloc::string::String::from("{}"),
        );

        assert_eq!(log.len(), 3);
        assert_eq!(log.entries()[2].seq(), 2);
        assert_eq!(log.entries()[2].previous_hash(), log.entries()[1].entry_hash());
    }

    #[test]
    fn next_entry_all_entries_pass_verify_integrity() {
        let mut log = make_log();
        for i in 0..5 {
            log.next_entry(
                AuditEventType::ToolCallIntercepted,
                i * 1_000,
                alloc::string::String::from("{}"),
            );
        }
        for entry in log.entries() {
            assert!(entry.verify_integrity());
        }
    }

    // --- AuditLog::verify_chain() ---

    #[test]
    fn verify_chain_empty_log_returns_true() {
        assert!(make_log().verify_chain());
    }

    #[test]
    fn verify_chain_valid_log_returns_true() {
        let mut log = make_log();
        for i in 0..4 {
            log.next_entry(
                AuditEventType::ToolCallIntercepted,
                i * 1_000,
                alloc::string::String::from("{}"),
            );
        }
        assert!(log.verify_chain());
    }

    #[test]
    fn verify_chain_false_after_unsafe_seq_tamper() {
        let mut log = make_log();
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::PolicyViolation,
            2_000,
            alloc::string::String::from("{}"),
        );

        // Tamper the seq of the first entry.
        // SAFETY: deliberate tampering to test verify_chain detection.
        unsafe {
            let entry = &mut *(log.entries.as_mut_ptr());
            let ptr = &mut entry.seq as *mut u64;
            *ptr = 99;
        }
        assert!(!log.verify_chain());
    }

    #[test]
    fn verify_chain_false_after_unsafe_payload_tamper() {
        let mut log = make_log();
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::PolicyViolation,
            2_000,
            alloc::string::String::from("{}"),
        );

        // Tamper the payload of the second entry — breaks its verify_integrity().
        // SAFETY: deliberate tampering to test verify_chain detection.
        unsafe {
            let entry = &mut *(log.entries.as_mut_ptr().add(1));
            if let Some(b) = entry.payload.as_mut_vec().first_mut() {
                *b = b'X';
            }
        }
        assert!(!log.verify_chain());
    }

    #[test]
    fn verify_chain_false_after_unsafe_previous_hash_tamper() {
        let mut log = make_log();
        log.next_entry(
            AuditEventType::ToolCallIntercepted,
            1_000,
            alloc::string::String::from("{}"),
        );
        log.next_entry(
            AuditEventType::PolicyViolation,
            2_000,
            alloc::string::String::from("{}"),
        );

        // Tamper previous_hash of the second entry — breaks chain linkage check.
        // SAFETY: deliberate tampering to test verify_chain detection.
        unsafe {
            let entry = &mut *(log.entries.as_mut_ptr().add(1));
            let ptr = &mut entry.previous_hash as *mut [u8; 32];
            (*ptr)[0] = 0xFF;
        }
        assert!(!log.verify_chain());
    }
}

#[cfg(all(test, feature = "alloc", feature = "serde"))]
mod lineage_tests {
    use super::*;

    const AGENT: AgentId = AgentId::from_bytes([1u8; 16]);
    const SESSION: SessionId = SessionId::from_bytes([2u8; 16]);
    const ROOT: AgentId = AgentId::from_bytes([7u8; 16]);
    const PARENT: AgentId = AgentId::from_bytes([9u8; 16]);

    fn base_entry() -> AuditEntry {
        AuditEntry::new(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            r#"{"tool":"bash"}"#.into(),
            [0u8; 32],
        )
    }

    #[test]
    fn lineage_default_is_all_none() {
        let l = Lineage::default();
        assert!(l.root_agent_id.is_none());
        assert!(l.parent_agent_id.is_none());
        assert!(l.team_id.is_none());
        assert!(l.delegation_reason.is_none());
        assert!(l.spawned_by_tool.is_none());
        assert!(l.depth.is_none());
    }

    #[test]
    fn new_with_empty_lineage_produces_same_hash_as_new() {
        let legacy = base_entry();
        let with_lineage = AuditEntry::new_with_lineage(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            r#"{"tool":"bash"}"#.into(),
            [0u8; 32],
            Lineage::default(),
        );
        assert_eq!(
            legacy.entry_hash(),
            with_lineage.entry_hash(),
            "Lineage::default() must not change the hash"
        );
    }

    #[test]
    fn new_with_lineage_getters_return_correct_values() {
        let lineage = Lineage {
            root_agent_id: Some(ROOT),
            parent_agent_id: Some(PARENT),
            team_id: Some("team-alpha".into()),
            delegation_reason: Some("summarise".into()),
            spawned_by_tool: Some("langgraph".into()),
            depth: Some(2),
        };
        let entry = AuditEntry::new_with_lineage(
            0,
            1_000,
            AuditEventType::PolicyViolation,
            AGENT,
            SESSION,
            "{}".into(),
            [0u8; 32],
            lineage,
        );
        assert_eq!(entry.root_agent_id(), Some(ROOT));
        assert_eq!(entry.parent_agent_id(), Some(PARENT));
        assert_eq!(entry.team_id(), Some("team-alpha"));
        assert_eq!(entry.delegation_reason(), Some("summarise"));
        assert_eq!(entry.spawned_by_tool(), Some("langgraph"));
        assert_eq!(entry.depth(), Some(2));
    }

    #[test]
    fn verify_integrity_true_with_lineage() {
        let lineage = Lineage {
            root_agent_id: Some(ROOT),
            team_id: Some("ops".into()),
            depth: Some(1),
            ..Lineage::default()
        };
        let entry = AuditEntry::new_with_lineage(
            0,
            1_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            "{}".into(),
            [0u8; 32],
            lineage,
        );
        assert!(entry.verify_integrity());
    }

    #[test]
    fn lineage_fields_change_hash() {
        let no_lineage = base_entry();
        let lineage = Lineage {
            depth: Some(1),
            ..Lineage::default()
        };
        let with_depth = AuditEntry::new_with_lineage(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            r#"{"tool":"bash"}"#.into(),
            [0u8; 32],
            lineage,
        );
        assert_ne!(
            no_lineage.entry_hash(),
            with_depth.entry_hash(),
            "A present lineage field must change the hash"
        );
    }

    #[test]
    fn serde_round_trip_with_lineage() {
        let lineage = Lineage {
            root_agent_id: Some(ROOT),
            parent_agent_id: Some(PARENT),
            team_id: Some("t1".into()),
            delegation_reason: Some("r".into()),
            spawned_by_tool: Some("s".into()),
            depth: Some(3),
        };
        let entry = AuditEntry::new_with_lineage(
            0,
            1_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            "{}".into(),
            [0u8; 32],
            lineage,
        );
        let json = serde_json::to_string(&entry).unwrap();
        let restored: AuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry.entry_hash(), restored.entry_hash());
        assert_eq!(restored.root_agent_id(), Some(ROOT));
        assert_eq!(restored.depth(), Some(3));
    }

    #[test]
    fn legacy_jsonl_without_lineage_fields_deserialises_and_verifies() {
        let pre_change_entry = AuditEntry::new(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolCallIntercepted,
            AGENT,
            SESSION,
            r#"{"tool":"bash"}"#.into(),
            [0u8; 32],
        );
        let json = serde_json::to_string(&pre_change_entry).unwrap();
        assert!(!json.contains("root_agent_id"), "None fields must not appear in JSON");
        let restored: AuditEntry = serde_json::from_str(&json).unwrap();
        assert!(restored.root_agent_id().is_none());
        assert!(
            restored.verify_integrity(),
            "Legacy entries must still verify after adding lineage fields"
        );
    }

    #[test]
    fn next_entry_with_lineage_links_chain() {
        let mut log = AuditLog::new(AGENT, SESSION);
        let lineage = Lineage {
            depth: Some(1),
            team_id: Some("t".into()),
            ..Lineage::default()
        };
        log.next_entry_with_lineage(AuditEventType::ToolCallIntercepted, 1_000, "{}".into(), lineage.clone());
        log.next_entry_with_lineage(AuditEventType::PolicyViolation, 2_000, "{}".into(), lineage);
        assert!(log.verify_chain());
        assert_eq!(log.len(), 2);
    }
}
