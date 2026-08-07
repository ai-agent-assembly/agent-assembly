//! Proxy-side audit record for the MitM data path.
//!
//! [`ProxyAuditEntry`] is the small, self-contained record the proxy emits
//! after handling one intercepted request. It carries the decision the proxy
//! made (forward / forward-redacted / block) plus any `credential_findings`
//! produced by the in-path scanner, but never the raw secret bytes.
//!
//! Layer naming note: unlike `aa-gateway::audit::AuditWriter` (which persists
//! a hash-chained `AuditEntry`), this module is the proxy's purpose-built
//! sink. The two records have different shapes because the proxy and the
//! gateway observe different things; see [`JsonlWriter`] for how this struct
//! reaches disk.
//!
//! # What this sink does not promise
//!
//! It is not the tamper-evident tier (ADR 0032 §9), which is why
//! [`PersistedFinding`] drops byte offsets. It is also **not complete**: the
//! data path drops rather than stalls when the channel is full, and
//! [`RotationPolicy`] discards the oldest segment to hold the file inside a
//! size bound. Both losses are counted and republished as
//! [`SinkCompleteness`], so a count taken from this file is a lower bound that
//! says so rather than a number that looks exact.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use aa_core::types::sensitive_data::ExecutionEvidence;
use aa_security::{CredentialFinding, CredentialKind};

/// Decision recorded for a single intercepted request.
///
/// Every variant states what the proxy **did**, never what it would have done.
/// That distinction is why [`Self::AnsweredLocally`] exists (AAASM-5449).
///
/// # Why this is `#[non_exhaustive]`
///
/// `aa-proxy` is in the crates.io publish set and this enum is publicly
/// reachable as `aa_proxy::audit_jsonl::ProxyAuditDecision`, so every variant
/// added here is a source-breaking change for any downstream `match` that
/// enumerates the variants. The set is *expected* to grow: each variant records
/// one way the proxy can dispose of a request, and new dispositions arrive with
/// new interception paths — `AnsweredLocally` is the second such addition.
///
/// `#[non_exhaustive]` moves that break to a single point in time. Downstream
/// matches must carry a wildcard arm from now on, and in exchange no later
/// variant breaks them again. Adopted with the variant rather than after it, so
/// the cost is paid once (AAASM-5449).
///
/// Readers deserializing this type should expect values they do not know:
/// `serde` will reject an unrecognised discriminant, so a consumer pinned to an
/// older `aa-proxy` must tolerate a decode failure rather than assume the sink
/// is corrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProxyAuditDecision {
    /// Request forwarded unmodified (no findings, or policy `alert_only`).
    Forwarded,
    /// Request forwarded with secrets replaced by `[REDACTED:<Kind>]`
    /// markers in the body (policy `redact_only`).
    ForwardedRedacted,
    /// Request blocked at the proxy; upstream never dialled — either by the
    /// credential verdict (policy `block`) or by a rule, in which case
    /// [`ProxyAuditEntry::refusal_rule`] names it.
    Blocked,
    /// The proxy answered the request itself and never relayed it, for a reason
    /// that is **not** a policy refusal — today only the protection-probe
    /// protocol ([`crate::probe_adjudication`]).
    ///
    /// The probe branch used to record [`Self::Forwarded`] /
    /// [`Self::ForwardedRedacted`] here for a request that was never dialled.
    /// Both were counterfactual: the *verdict* would have forwarded, the
    /// request did not. Keeping a knowingly-false field beside a true one
    /// ([`ProxyAuditEntry::execution`]) only works for as long as every reader
    /// knows which is which, and AAASM-5359/5360 are readers that do not exist
    /// yet — so the false one was removed rather than annotated.
    ///
    /// A genuine `Block` during a probe is still [`Self::Blocked`]: there the
    /// verdict and the outcome agree, and that refusal is real (it is marked
    /// synthetic by [`ProxyAuditEntry::probe_correlation`], not weakened).
    ///
    /// It carries no claim about protection in either direction. The paired
    /// evidence is
    /// [`TransmissionEvidence::NotRecorded`](aa_core::types::sensitive_data::TransmissionEvidence::NotRecorded),
    /// which is defined so that it can never satisfy ADR 0032 §8 — a probe
    /// under `redact_only` would otherwise manufacture a prevented
    /// transmission for traffic the policy would have forwarded.
    AnsweredLocally,
}

/// Which **rule** refused a request, on a record whose decision is
/// [`ProxyAuditDecision::Blocked`] (AAASM-5449).
///
/// These are the proxy's most provable preventions: each is applied before any
/// dial exists on the code path, so the 403 (or JSON-RPC error envelope) is
/// written *instead of* the bytes going. Until this field existed they were
/// logged and discarded, so ADR 0032 §8 could count redaction-with-forwarding
/// but not the refusals a reader would find hardest to argue with.
///
/// Why the rule belongs on the record rather than only in the log: a
/// fail-closed credential block and a denylist refusal are both `Blocked` with
/// an empty finding list, and a consumer that cannot tell them apart cannot
/// attribute a prevention to the control that made it.
///
/// `None` on a credential verdict's own refusal. What refused it is already
/// spelled by [`ProxyAuditEntry::credential_findings`] and the decision, and
/// relabelling those records would change what an existing line means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalRule {
    /// Operator denylist (`AA_PROXY_DENIED_HOSTS`) matched the host.
    EgressDenylist,
    /// A non-empty network allowlist did not match the host.
    EgressAllowlist,
    /// The host was an IP literal in a blocked range (loopback, RFC-1918,
    /// link-local, cloud metadata) — the SSRF guard.
    SsrfBlockedAddress,
    /// A cleartext `http://` request addressed a known LLM provider, which
    /// would bypass the HTTPS-only DLP path entirely.
    PlaintextLlmDowngrade,
    /// The gateway denied an MCP `tools/call`, or the call could not be
    /// evaluated and was refused fail-closed.
    McpToolCall,
}

/// A single audit record emitted by the proxy's data path.
///
/// `redacted_body` carries the *post-scan* body bytes (the form that was or
/// would have been forwarded). The original raw body is never stored — only
/// its redacted projection. `credential_findings` is the per-match metadata
/// produced by `CredentialScanner`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuditEntry {
    /// Wall-clock timestamp in milliseconds since the Unix epoch.
    pub ts_ms: i64,
    /// Agent identifier that owned the connection, when known.
    pub agent_id: Option<String>,
    /// Target host (no port) from the CONNECT line.
    pub host: String,
    /// HTTP method of the intercepted request inside the tunnel.
    pub method: String,
    /// Request path of the intercepted request inside the tunnel.
    pub path: String,
    /// What the proxy did with the request.
    pub decision: ProxyAuditDecision,
    /// Which rule refused it, when a rule did (AAASM-5449).
    ///
    /// `None` for anything that is not a rule refusal, including the credential
    /// verdict's own `Blocked`. See [`RefusalRule`].
    pub refusal_rule: Option<RefusalRule>,
    /// What was **observed** about whether the payload left this process.
    ///
    /// [`Self::decision`] is what the proxy resolved to do; this is what
    /// happened to the bytes, and the two are not the same claim. A
    /// [`ProxyAuditDecision::ForwardedRedacted`] is a *transformed
    /// transmission* — the scrubbed bytes went — and only evidence recorded
    /// here can distinguish that from a payload that never left, which is the
    /// distinction ADR 0032 §8's prevention rule turns on (AAASM-5358).
    ///
    /// Built by [`crate::transmission_evidence`]; there is no default, because
    /// a record that omitted it would be an event with no execution evidence,
    /// and the whole point is that such an event exists and says so out loud
    /// rather than being absent.
    pub execution: ExecutionEvidence,
    /// Correlation id when this record describes a protection probe's own
    /// request, `None` for ordinary traffic.
    ///
    /// Probe traffic is synthetic. Under `credential_action=block` a probe's
    /// request is genuinely refused before any dial, so its record satisfies
    /// every condition of ADR 0032 §8 and would be counted as a prevented
    /// transmission — one per probe run, indistinguishable from a real leak
    /// that was stopped. A consumer computing a prevention rate has to be able
    /// to exclude synthetic traffic, and can only do that if the record says
    /// which it is (AAASM-5359/5360).
    ///
    /// The value is an opaque caller-minted id whose grammar is enforced by
    /// [`ProbeCorrelation`](crate::probe_adjudication::ProbeCorrelation) — 32
    /// lowercase hex characters, which is deliberately too short to be a
    /// content digest.
    pub probe_correlation: Option<String>,
    /// Per-match scanner output, projected for this tier. Empty when no secrets
    /// were detected.
    ///
    /// Capped at [`MAX_PERSISTED_FINDINGS`]; the overflow is counted in
    /// [`Self::findings_omitted`] rather than dropped silently.
    pub credential_findings: Vec<PersistedFinding>,
    /// How many findings the cap dropped from
    /// [`Self::credential_findings`].
    ///
    /// A truncated list that said nothing about being truncated would make the
    /// finding count on this record quietly wrong, and finding counts are a
    /// measure ADR 0032 §8 keeps deliberately separate from event counts.
    pub findings_omitted: u32,
    /// Post-scan body content.
    ///
    /// `None` when the proxy bypassed the scanner, when the caller had no body
    /// to persist, **and** when re-inspection reported the post-scan bytes as
    /// still carrying a sensitive value — see
    /// [`crate::proxy::ProxyServer::observe_forwarding`]. Persisting bytes the
    /// proxy has itself just declared unscrubbed would make the "no raw value
    /// on disk" guarantee exactly as strong as the scrubber, in the one case
    /// where the proxy knows the scrubber did not hold.
    pub redacted_body: Option<String>,
}

/// A scanner finding as it may be persisted **outside** the tamper-evident
/// audit tier.
///
/// `aa_security::CredentialFinding` carries a `pub offset` — the byte position
/// of the match in the original body — and ADR 0032 §9 permits offsets and
/// lengths **only** in the tamper-evident tier. This module's own header states
/// it is not that tier, and AAASM-5358 is what first constructs the writer in
/// production, so this PR is what would first put those offsets on disk.
///
/// `aa-security` already drew this line and drew it half-way: `end` is private
/// and `#[serde(skip)]` citing §9, while `offset` stays public and serializes.
/// Projecting here rather than widening that skip keeps the decision local to
/// the tier that has the constraint — the tamper-evident writer still needs the
/// offset.
///
/// File permissions are not a substitute. `0600` is access control; §9 is about
/// what may exist in the record at all, and an offset paired with a category
/// can identify a value in a small domain regardless of who can read the file.
///
/// `matched` is the redaction **label** (`[REDACTED:AwsAccessKey]`), derived
/// from `kind` and never the secret. It is kept because it is what a consumer
/// already reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedFinding {
    /// Category of the detected credential.
    pub kind: CredentialKind,
    /// Redaction label, e.g. `[REDACTED:AwsAccessKey]`.
    pub matched: String,
}

impl PersistedFinding {
    /// Project a scanner finding, discarding the byte offset.
    pub fn project(finding: &CredentialFinding) -> Self {
        Self {
            kind: finding.kind.clone(),
            matched: finding.matched.clone(),
        }
    }
}

/// Most findings persisted on a single record.
///
/// `redacted_body` alone does not bound a line: a 64 MiB body densely packed
/// with detectable patterns yields on the order of a million findings at ~50-80
/// serialized bytes each, so an uncapped vector turns one request into a line of
/// hundreds of megabytes. [`RotationPolicy`] bounds the *file*; this bounds the
/// line, and a single line larger than a segment would defeat both.
pub const MAX_PERSISTED_FINDINGS: usize = 256;

/// Project and cap a finding list, returning the retained rows and how many
/// were dropped.
pub fn bound_persisted_findings(findings: &[CredentialFinding]) -> (Vec<PersistedFinding>, u32) {
    let kept: Vec<PersistedFinding> = findings
        .iter()
        .take(MAX_PERSISTED_FINDINGS)
        .map(PersistedFinding::project)
        .collect();
    let omitted = findings.len().saturating_sub(kept.len()) as u32;
    (kept, omitted)
}

/// Longest post-scan body persisted on a single record.
///
/// The MitM path accepts bodies up to `MAX_BODY_LEN` (64 MiB), so an unbounded
/// body turns one oversized request into a line larger than a whole rotation
/// segment — which would make the file bound meaningless by forcing a rotation
/// per request. Truncation is on a character boundary and marked, so a reader
/// can tell a short body from a cut one.
pub const MAX_PERSISTED_BODY_BYTES: usize = 8 * 1024;

/// Marker appended to a body that was cut at [`MAX_PERSISTED_BODY_BYTES`].
pub const BODY_TRUNCATION_MARKER: &str = "…[truncated]";

/// Bound a post-scan body to [`MAX_PERSISTED_BODY_BYTES`], on a character
/// boundary.
pub fn bound_persisted_body(body: String) -> String {
    if body.len() <= MAX_PERSISTED_BODY_BYTES {
        return body;
    }
    let cut = body
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX_PERSISTED_BODY_BYTES)
        .last()
        .unwrap_or(0);
    let mut out = body[..cut].to_owned();
    out.push_str(BODY_TRUNCATION_MARKER);
    out
}

/// Count of audit entries dropped because the channel was full or closed.
///
/// A prevention metric derived from a silently lossy record is not
/// authoritative. `try_send` is the right call on the data path — a slow writer
/// must not stall an intercepted request — so the loss is *counted* rather than
/// prevented.
///
/// AAASM-5358 left this in-process only, which meant a consumer reading the
/// JSONL had no way to gate a published rate on it. It is now republished into
/// [`SinkCompleteness`] beside the sink, so an out-of-process reader — which is
/// what AAASM-5359/5360 are — sees the loss without linking this crate.
static DROPPED_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// Record one dropped entry, returning the new running total.
pub fn record_dropped_entry() -> u64 {
    DROPPED_ENTRIES.fetch_add(1, Ordering::Relaxed) + 1
}

/// Entries dropped since process start.
pub fn dropped_entries() -> u64 {
    DROPPED_ENTRIES.load(Ordering::Relaxed)
}

/// Count of rotated segments discarded because they fell past
/// [`RotationPolicy::retained_segments`].
///
/// Rotation is what keeps the sink from filling the disk, and it does that by
/// throwing records away. A prevention rate computed over a window that was
/// rotated out from under the reader is an under-count, so the discard is
/// counted and published exactly like a channel drop.
///
/// Counts the **size** bound only. Deletions made by the age bound are
/// [`EXPIRED_SEGMENTS`], because the two answer different operator questions:
/// "did I lose evidence I wanted?" and "did the deletion I asked for happen?".
static DISCARDED_SEGMENTS: AtomicU64 = AtomicU64::new(0);

/// Segments discarded since process start.
pub fn discarded_segments() -> u64 {
    DISCARDED_SEGMENTS.load(Ordering::Relaxed)
}

/// Count of segments deleted because they aged past
/// [`RotationPolicy::max_age`] (AAASM-5660).
///
/// Separate from [`DISCARDED_SEGMENTS`] on purpose. An expiry is the operator's
/// configured deletion happening as asked; a size discard is evidence being lost
/// to a ceiling they may not have intended. Merging them into one number would
/// make a healthy retention policy indistinguishable from an undersized ring.
static EXPIRED_SEGMENTS: AtomicU64 = AtomicU64::new(0);

/// Segments deleted by the age bound since process start.
pub fn expired_segments() -> u64 {
    EXPIRED_SEGMENTS.load(Ordering::Relaxed)
}

/// Count of segments the **size** bound deleted while the **age** bound would
/// still have kept them (AAASM-5660).
///
/// This is the disagreement between the two bounds, made countable. See
/// [`RotationPolicy`] for the rule: size always wins, so a shortfall is the
/// proxy telling an operator who configured 90 days that they are getting
/// rather less, at the moment it happens rather than at the moment they need
/// the answer.
static RETENTION_SHORTFALLS: AtomicU64 = AtomicU64::new(0);

/// Segments lost to the size bound while still inside the age bound.
pub fn retention_shortfalls() -> u64 {
    RETENTION_SHORTFALLS.load(Ordering::Relaxed)
}

/// Count of sink I/O operations that failed — an append, a flush, or the
/// rotation that follows them (AAASM-5660).
///
/// A full disk is the case this exists for: every one of those calls fails with
/// `ENOSPC`, and the previous behaviour — log it and carry on — left the file
/// silently short of what the proxy recorded, with nothing beside it to say so.
/// A silent drop is the one option a governance sink does not get.
///
/// Non-zero means the file on disk is **not** what the proxy intended: either a
/// record never landed (a failed append or flush) or the sink is outside the
/// bound it was configured with (a failed rotation). Which of the two is in the
/// log; that it happened at all is what a consumer needs, and that is what is
/// published.
///
/// The proxy deliberately does **not** stall the data path or exit. An
/// intercepted request must not fail because the audit disk filled, and a proxy
/// that quits on a full disk turns a recording problem into an outage. It
/// counts the failure, publishes it, and keeps enforcing — so the window
/// reports as lossy rather than as complete.
static WRITE_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Sink writes, flushes or rotations that failed since process start.
pub fn write_failures() -> u64 {
    WRITE_FAILURES.load(Ordering::Relaxed)
}

/// Count of export attempts that failed (AAASM-5660).
///
/// The point of counting rather than retrying silently: an exporter that fails
/// without saying so is **worse than no exporter**, because it converts a
/// known-lossy local ring into an assumed-complete remote record. A non-zero
/// figure here means at least one segment was not handed off and the ring is
/// still the only copy.
static EXPORT_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Export attempts that failed since process start.
pub fn export_failures() -> u64 {
    EXPORT_FAILURES.load(Ordering::Relaxed)
}

/// Record one failed write, returning the new running total.
fn record_write_failure() -> u64 {
    WRITE_FAILURES.fetch_add(1, Ordering::Relaxed) + 1
}

/// Default bytes a live segment may reach before rotating (32 MiB).
///
/// Unchanged from AAASM-5449 so that making the bound configurable does not
/// change what an existing deployment does.
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 32 * 1024 * 1024;

/// Default rotated segments kept beside the live file.
pub const DEFAULT_RETAINED_SEGMENTS: usize = 3;

/// How often the writer re-examines the segments for age-based expiry.
///
/// The size bound is enforced by the append path, so it needs no timer. The age
/// bound does: a proxy that stops receiving traffic still owes the operator the
/// deletion they configured, and a purely append-driven sweep would leave a
/// quiet host holding evidence for ever.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How large the sink is allowed to get, how much history survives, and how
/// long any of it may live.
///
/// # Why the proxy rotates rather than leaving it to the operator
///
/// The obvious alternative — "operators own retention, point `logrotate` at
/// it" — does not work with this writer and would have been a claim rather
/// than a design. [`JsonlWriter`] holds the file descriptor for the lifetime
/// of the process and never reopens, so an external rotation that renames or
/// unlinks the file leaves the proxy appending to an unlinked inode: records
/// keep being written and nothing can read them again. An operator who
/// configured rotation would end up with *less* audit trail than one who
/// configured none, and would have no way to notice.
///
/// # The rule when the two bounds disagree
///
/// They are both **ceilings, never floors**, and a segment is retained only if
/// it satisfies *both*. Deletion is therefore the union of the two triggers and
/// retention is their intersection:
///
/// * past [`Self::retained_segments`] → deleted, counted in
///   [`discarded_segments`];
/// * older than [`Self::max_age`] → deleted, counted in [`expired_segments`];
/// * both → deleted once, counted as a size discard, because that is the bound
///   that reached it first.
///
/// **Size wins.** [`Self::max_age`] is a maximum age, never a minimum
/// guarantee: setting 90 days does not reserve 90 days of disk, and under
/// enough traffic the ring will discard a segment the age bound would have
/// kept. That case is not left to be inferred — it increments
/// [`retention_shortfalls`], so an operator who configured 90 days and is
/// actually getting six hours learns it from the sidecar rather than from the
/// quarter-end question they cannot answer.
///
/// The converse never happens: the age bound cannot make the sink exceed the
/// size bound, because it only ever deletes.
///
/// # Granularity of the age bound
///
/// Segments are deleted whole, so the age bound is not exact to the record. A
/// rotated segment expires when its **newest** record is older than
/// [`Self::max_age`] — so no record is ever deleted *before* its age is up —
/// and the live segment is rotated once its **oldest** record reaches that age,
/// so a quiet proxy cannot hold a segment open indefinitely. A single record
/// therefore survives at least `max_age` and at most about `2 * max_age`.
///
/// # Growth rate
///
/// One record is roughly 250 bytes with no body and no findings; the two
/// unbounded parts are already capped at [`MAX_PERSISTED_BODY_BYTES`] (8 KiB)
/// and [`MAX_PERSISTED_FINDINGS`] (256 rows, ~60 bytes each), so ~24 KiB is
/// the worst case for a single line. The defaults below therefore hold on the
/// order of 500k typical records, and bound the sink at
/// `(retained_segments + 1) * max_segment_bytes` = 128 MiB whatever the
/// traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Bytes a live segment may reach before it is rotated. Checked *after*
    /// each append, so a segment may exceed this by at most one line.
    pub max_segment_bytes: u64,
    /// Rotated segments kept beside the live file (`<path>.1` … `<path>.N`).
    pub retained_segments: usize,
    /// Longest a segment may live before it is deleted, or `None` for no age
    /// bound.
    ///
    /// `None` is the default because it reproduces AAASM-5449's behaviour
    /// exactly; an existing deployment that upgrades gets the same ring it had.
    /// See the type docs for what happens when this disagrees with the size
    /// bound.
    pub max_age: Option<Duration>,
    /// How often [`JsonlWriter::run`] re-checks the age bound.
    ///
    /// Not operator-configurable: it trades promptness of a deletion against
    /// idle wakeups and has no effect on what is retained, only on how late the
    /// deletion is. It is a field rather than a constant so a test can drive the
    /// timer path in milliseconds instead of minutes.
    pub sweep_interval: Duration,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            retained_segments: DEFAULT_RETAINED_SEGMENTS,
            max_age: None,
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
        }
    }
}

impl RotationPolicy {
    /// Whether `age` has passed this policy's age bound.
    ///
    /// `false` when no age bound is configured — the absence of a bound must
    /// never expire anything.
    pub fn is_expired(&self, age: Duration) -> bool {
        self.max_age.is_some_and(|max| age >= max)
    }
}

/// Where sealed segments are handed off so the evidence can outlive the local
/// ring (AAASM-5660).
///
/// # What this is, and what it deliberately is not
///
/// This is a **spool-and-forward seam**, not a remote client. The proxy seals a
/// rotated segment into a directory the operator chose, atomically, at `0600`;
/// what happens beyond that directory belongs to whatever the operator points
/// at it — a mounted volume, a collector that tails the directory, or the SaaS
/// control plane. Durable replication that outlives the host is a SaaS
/// capability; the open-source proxy owns getting the evidence out of the ring
/// and saying whether that succeeded.
///
/// # Why not the alternatives
///
/// * **An object-store client (S3/GCS) in the proxy.** A new heavyweight
///   dependency, and it would put long-lived cloud credentials inside the
///   process that [`crate::hardening`] deliberately makes non-dumpable
///   *because* it already holds more than it should. Widening that blast radius
///   to gain a copy the operator can obtain by pointing a collector at a
///   directory is a bad trade.
/// * **The `StorageBackend` tier.** It would make a sidecar depend on a
///   database. The proxy runs beside the agent, frequently on a laptop, and
///   frequently with nothing reachable; a sink that only works when a database
///   is up is a sink that is missing when it matters. (Redis is separately
///   barred from backing audit at all.)
/// * **syslog or OTLP.** UDP syslog cannot acknowledge, so "at-least-once with
///   observable failure" is unachievable on it — the failure is precisely what
///   is invisible, which is the exact defect this seam exists to avoid. TCP
///   syslog and OTLP both mean a new dependency and an in-band network client
///   on the enforcement host.
/// * **Streaming each entry as it is written.** It couples the sink to network
///   latency and needs its own unbounded buffer. Segment granularity bounds the
///   work and leaves the data path untouched.
/// * **`logrotate` and friends.** Already rejected in [`RotationPolicy`]: this
///   writer never reopens its descriptor, so external rotation leaves the proxy
///   appending to an unlinked inode.
///
/// # Delivery semantics
///
/// At-least-once, by construction rather than by claim. Export is idempotent —
/// the target name is derived from the segment's own content (first record
/// timestamp, last-write time, length), so re-exporting a segment the previous
/// process already handed off is a no-op rather than a duplicate. Every segment
/// still in the ring is re-offered on every sweep and at every rotation,
/// including after a restart, so a failure retries by itself.
///
/// What is **not** promised: that every segment is exported before the ring
/// discards it. Guaranteeing that would mean blocking rotation on the exporter,
/// and rotation is what keeps the disk from filling. A segment discarded while
/// still un-exported leaves [`export_failures`] non-zero and the window lossy,
/// which is the honest reading and the one a consumer can act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ExportTarget {
    /// No handoff: the bounded local ring is the only copy of this evidence,
    /// and it does not survive loss of this host.
    ///
    /// This is the open-source default, and it is a **stated position** rather
    /// than an absent setting — see [`ExportStatus::LocalRingOnly`], which is
    /// published in the sidecar so a consumer reads "the evidence lives only in
    /// the ring" instead of inferring "probably fine".
    #[default]
    LocalRingOnly,
    /// Seal rotated segments into this directory. Created at `0700` if absent.
    Directory(PathBuf),
}

impl ExportTarget {
    /// How this target renders in [`SinkCompleteness::export`].
    pub fn status(&self) -> ExportStatus {
        match self {
            Self::LocalRingOnly => ExportStatus::LocalRingOnly,
            Self::Directory(_) => ExportStatus::Directory,
        }
    }
}

/// What a consumer is told about where this evidence lives, beside the counts
/// of what was lost.
///
/// It is a named state on every snapshot, never an omitted field. "No exporter
/// configured" and "retention is fine" are not the same fact, and an operator
/// who reads an absence as reassurance is exactly the failure this sink exists
/// to stop.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportStatus {
    /// The bounded ring on this host is the only copy. Rotation deletes
    /// evidence permanently and nothing replicates it; durable retention that
    /// outlives the host is a SaaS capability and is not present here.
    #[default]
    LocalRingOnly,
    /// Sealed segments are being handed to an operator-configured directory.
    /// Whether they then reach durable storage is that collector's contract,
    /// not this sink's.
    Directory,
}

/// Path of rotated segment `n` (1 = most recent).
fn segment_path(path: &Path, n: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    PathBuf::from(name)
}

/// Path of the completeness file published beside `path`.
fn completeness_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".completeness.json");
    PathBuf::from(name)
}

/// Milliseconds since the Unix epoch, saturating rather than panicking on a
/// clock before 1970.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Bytes read when looking for a segment's first record.
///
/// One line is bounded by [`MAX_PERSISTED_BODY_BYTES`] plus
/// [`MAX_PERSISTED_FINDINGS`] rows, so 32 KiB comfortably contains the first
/// newline of any line this writer produces. Reading a bounded prefix rather
/// than the file keeps the age check O(1) in segment size.
const FIRST_RECORD_PROBE_BYTES: usize = 32 * 1024;

/// Timestamp of the first record in `path`, if it has one.
///
/// Used for the age bound instead of the filesystem's creation time, which is
/// not reported on every platform and filesystem, and which would in any case
/// describe the file rather than the evidence. The record's own `ts_ms` is what
/// an operator means by "older than 90 days".
///
/// `None` for an empty, unreadable or unparseable segment. A caller must treat
/// that as "age unknown" and not as "expired": deleting evidence because its
/// first line could not be parsed would turn a read failure into data loss.
async fn first_record_ms(path: &Path) -> Option<i64> {
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let mut buf = vec![0u8; FIRST_RECORD_PROBE_BYTES];
    let read = file.read(&mut buf).await.ok()?;
    let head = &buf[..read];
    let line_end = head.iter().position(|b| *b == b'\n')?;
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    serde_json::from_str::<ProxyAuditEntry>(line).ok().map(|e| e.ts_ms)
}

/// Name a segment is exported under.
///
/// Derived entirely from the segment's own content and metadata so that the
/// same segment always maps to the same name. That is what makes export
/// idempotent, and idempotence is what turns "offer every segment on every
/// sweep" into at-least-once delivery instead of an ever-growing pile of
/// duplicates.
///
/// `first_ms` is the timestamp of the segment's first record (`0` when it could
/// not be read), `mtime_ms` dates its last, and `len` disambiguates the rest.
fn export_name(sink: &Path, first_ms: i64, mtime_ms: i64, len: u64) -> String {
    let stem = sink
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "proxy-audit".to_owned());
    format!("{stem}.{first_ms}-{mtime_ms}-{len}")
}

/// Copy `segment` to `target`, atomically and at `0600`.
///
/// Staged through a dotted `.part` sibling and renamed, for the same reason the
/// completeness snapshot is: a collector watching the directory must never read
/// a half-copied segment and treat a truncated window as the whole one.
async fn publish_segment(segment: &Path, target: &Path) -> io::Result<()> {
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(target.file_name().unwrap_or_default());
    tmp_name.push(".part");
    let tmp = target.with_file_name(tmp_name);
    tokio::fs::copy(segment, &tmp).await?;
    // `copy` carries the source's mode on Unix, but the guarantee is asserted
    // rather than inherited — an exported segment holds the same per-agent
    // behavioural trail as the sink and must not become readable to every local
    // account because of a platform detail.
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).await?;
    tokio::fs::rename(&tmp, target).await
}

/// Last-write time of `path` in milliseconds since the Unix epoch.
async fn mtime_ms(path: &Path) -> Option<i64> {
    let modified = tokio::fs::metadata(path).await.ok()?.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64)
}

/// Age of the newest record in `path`, derived from its modification time.
///
/// The last write to a segment is the moment its newest record was appended, so
/// mtime dates the *youngest* evidence it holds. Expiring on that is what makes
/// the age bound safe in the direction that matters: a segment is deleted only
/// once everything in it is past the bound, so no record is ever deleted early.
///
/// `None` when the file is absent or its mtime is unreadable, or when the clock
/// has moved backwards since the write — all of which mean "cannot say", and a
/// caller must not expire on that.
async fn newest_record_age(path: &Path) -> Option<Duration> {
    let modified = tokio::fs::metadata(path).await.ok()?.modified().ok()?;
    SystemTime::now().duration_since(modified).ok()
}

/// What a consumer has to know before turning a count from this sink into a
/// rate (AAASM-5449).
///
/// The counters were in-process only, so an out-of-process reader — which is
/// what AAASM-5359/5360 are — could not tell a complete window from a lossy
/// one. They are published beside the file the consumer already opens.
///
/// Both figures describe **this file**, not this process: the baseline is read
/// back at open, so a restart does not erase an earlier window's loss. They are
/// reset only when the sink is deleted.
///
/// A non-zero figure does not say *which* records went — that is not
/// recoverable — so the honest use is as a gate: a rate computed over a window
/// with loss is a lower bound, and a consumer that cannot accept a lower bound
/// should refuse to publish rather than round it away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SinkCompleteness {
    /// When this snapshot was written, ms since the Unix epoch.
    pub updated_ms: i64,
    /// Records the data path produced that never reached the file, because the
    /// channel was full and the proxy chose to drop rather than stall a
    /// request.
    pub dropped_entries: u64,
    /// Rotated segments discarded to hold the sink inside its size bound.
    pub discarded_segments: u64,
    /// Segments deleted because they aged past the configured retention.
    ///
    /// Reported separately from [`Self::discarded_segments`]: an expiry is the
    /// deletion the operator asked for, a discard is evidence the ceiling took.
    ///
    /// `#[serde(default)]` so a sidecar written by an older proxy still
    /// deserializes — the restart baseline depends on being able to read the
    /// previous process's snapshot, and a field-count mismatch that made it
    /// unreadable would silently reset an earlier window's loss to zero.
    #[serde(default)]
    pub expired_segments: u64,
    /// Segments the size bound deleted while the age bound would still have
    /// kept them.
    ///
    /// The configured retention was not met for those segments. See
    /// [`RotationPolicy`] for why size wins and why this is counted rather than
    /// left to be inferred.
    #[serde(default)]
    pub retention_shortfalls: u64,
    /// Sink I/O the writer could not complete — a failed append or flush (the
    /// record is not on disk) or a failed rotation (the sink is outside its
    /// bound).
    ///
    /// Distinct from [`Self::dropped_entries`], which is loss on the way *to*
    /// the writer. This is the writer's own failure, and it is the number that
    /// stops a full disk from being a silent drop.
    #[serde(default)]
    pub write_failures: u64,
    /// Where this evidence lives beyond the local ring, as a named state.
    ///
    /// [`ExportStatus::LocalRingOnly`] is a statement, not a gap: it says the
    /// bounded ring on this host is the only copy. A consumer that finds no
    /// exporter must read that rather than infer that retention is fine.
    #[serde(default)]
    pub export: ExportStatus,
    /// Export attempts that failed.
    ///
    /// Non-zero means at least one segment was not handed off, so the ring is
    /// still the only copy of it — the case in which an assumed-complete remote
    /// record would be wrong.
    #[serde(default)]
    pub export_failures: u64,
    /// Segments currently in the ring that the exporter has not yet accepted.
    ///
    /// A gauge, not a running total: it is what is outstanding right now, and
    /// it falls back to zero when the backlog clears. Zero with
    /// [`Self::export`] set to [`ExportStatus::LocalRingOnly`] means nothing is
    /// outstanding because nothing is being exported at all.
    #[serde(default)]
    pub pending_exports: u64,
}

/// Read the completeness published beside `path`, if any.
///
/// `None` when the sink has never been opened or the file is unreadable — a
/// consumer must treat that as "unknown", not as "complete".
pub async fn read_completeness(path: &Path) -> Option<SinkCompleteness> {
    let raw = tokio::fs::read_to_string(completeness_path(path)).await.ok()?;
    serde_json::from_str(&raw).ok()
}

/// Append-only JSONL writer.
///
/// Construct with [`JsonlWriter::new`], drive with `tokio::spawn(writer.run())`.
/// The task terminates when all senders drop and the channel closes.
///
/// "Append-only" is bounded by [`RotationPolicy`]: the live file is rotated at
/// a size threshold and the oldest segment is discarded, because the proxy
/// holds this descriptor open for its whole life and no external tool can
/// manage the file underneath it.
pub struct JsonlWriter {
    receiver: mpsc::Receiver<ProxyAuditEntry>,
    file: tokio::io::BufWriter<tokio::fs::File>,
    path: PathBuf,
    rotation: RotationPolicy,
    /// Bytes in the live segment, seeded from its length at open so an
    /// appended-to file is not treated as empty.
    segment_bytes: u64,
    /// `ts_ms` of the oldest record in the live segment, or `None` while it is
    /// empty.
    ///
    /// The age bound rotates the live segment once its *oldest* record reaches
    /// [`RotationPolicy::max_age`]. Without that, a proxy quiet enough never to
    /// fill a segment would hold its first record for ever and the configured
    /// deletion would simply not happen.
    live_started_ms: Option<i64>,
    /// Loss recorded against this file before this process opened it.
    baseline: SinkCompleteness,
    /// Process-wide counter readings at open, so only this process's own
    /// increments are added to the baseline.
    dropped_at_open: u64,
    discarded_at_open: u64,
    expired_at_open: u64,
    shortfalls_at_open: u64,
    write_failures_at_open: u64,
    export_failures_at_open: u64,
    /// Where sealed segments are handed off, if anywhere.
    export: ExportTarget,
    /// Segments in the ring the exporter has not accepted, as of the last
    /// attempt.
    pending_exports: u64,
    /// Last snapshot written, so an unchanged sidecar is not rewritten on
    /// every line.
    published: SinkCompleteness,
}

impl JsonlWriter {
    /// Open `path` in append mode (creating it if missing) and bind the
    /// supplied receiver. Parent directories must already exist.
    ///
    /// The file is `0600`, and an existing file's mode is re-asserted on every
    /// open — the same discipline `CaStore` applies to the CA private key. The
    /// default `0644` would have been world-readable.
    ///
    /// What justifies that is what the record *does* carry: the destination
    /// host, the redacted request path, the redacted body, and which credential
    /// categories an agent was caught sending. That is a per-agent behavioural
    /// trail, and it does not belong to every local account on the machine.
    ///
    /// It is **not** justified by byte offsets: [`PersistedFinding`] discards
    /// `CredentialFinding.offset`, because ADR 0032 §9 permits offsets only in
    /// the tamper-evident tier and this module is explicitly not that tier.
    /// Permissions are access control; §9 is about what may exist in the record
    /// at all, and the two are not substitutes for one another.
    pub async fn new(path: &Path, receiver: mpsc::Receiver<ProxyAuditEntry>) -> io::Result<Self> {
        Self::with_rotation(path, receiver, RotationPolicy::default()).await
    }

    /// [`Self::new`] with an explicit [`RotationPolicy`] and no export.
    pub async fn with_rotation(
        path: &Path,
        receiver: mpsc::Receiver<ProxyAuditEntry>,
        rotation: RotationPolicy,
    ) -> io::Result<Self> {
        Self::with_retention(path, receiver, rotation, ExportTarget::LocalRingOnly).await
    }

    /// [`Self::new`] with an explicit retention policy and export target.
    ///
    /// A configured export directory is created at `0700` if absent, and a
    /// failure to create it is propagated rather than degraded to "no export".
    /// An operator who configured a handoff and silently got none would believe
    /// the evidence outlives the host when it does not, which is the single
    /// misconception this whole surface exists to prevent.
    pub async fn with_retention(
        path: &Path,
        receiver: mpsc::Receiver<ProxyAuditEntry>,
        rotation: RotationPolicy,
        export: ExportTarget,
    ) -> io::Result<Self> {
        if let ExportTarget::Directory(dir) = &export {
            tokio::fs::create_dir_all(dir).await?;
            tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await?;
        }
        let file = Self::open_segment(path).await?;
        let segment_bytes = file.metadata().await?.len();
        // Loss recorded against this file by an earlier run. Without carrying
        // it forward a restart would publish a clean window over a file whose
        // earlier half is missing lines.
        let baseline = read_completeness(path).await.unwrap_or(SinkCompleteness {
            updated_ms: 0,
            dropped_entries: 0,
            discarded_segments: 0,
            expired_segments: 0,
            retention_shortfalls: 0,
            write_failures: 0,
            export: export.status(),
            export_failures: 0,
            pending_exports: 0,
        });
        // The live segment may already hold records from an earlier process, so
        // its age is read back rather than assumed to start now — a proxy
        // restarted every hour would otherwise reset the age bound every hour
        // and never expire anything.
        let live_started_ms = first_record_ms(path).await;
        Ok(Self {
            receiver,
            file: tokio::io::BufWriter::new(file),
            path: path.to_path_buf(),
            rotation,
            segment_bytes,
            live_started_ms,
            baseline,
            dropped_at_open: dropped_entries(),
            discarded_at_open: discarded_segments(),
            expired_at_open: expired_segments(),
            shortfalls_at_open: retention_shortfalls(),
            write_failures_at_open: write_failures(),
            export_failures_at_open: export_failures(),
            export,
            pending_exports: 0,
            published: baseline,
        })
    }

    /// Open a segment in append mode at `0600`.
    ///
    /// The mode is re-asserted rather than trusted: `mode()` applies only at
    /// creation, so a file left over from an earlier, looser build would keep
    /// whatever it had.
    async fn open_segment(path: &Path) -> io::Result<tokio::fs::File> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .await?;
        let mut perms = file.metadata().await?.permissions();
        if perms.mode() & 0o777 != 0o600 {
            perms.set_mode(0o600);
            file.set_permissions(perms).await?;
        }
        Ok(file)
    }

    /// Path the writer is appending to (useful for tests).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Background consumption loop.
    ///
    /// One entry per JSON line, flushed per write so external observers see
    /// the line as soon as the proxy returns to the client. Per-entry write
    /// failures are logged but do not stop the loop — losing one audit line
    /// is preferable to silently halting subsequent requests.
    /// The age bound needs a clock, not just traffic: a proxy that stops
    /// receiving requests still owes the operator the deletion they configured,
    /// so the loop waits on the channel *and* a sweep timer.
    pub async fn run(mut self) {
        tracing::info!(path = %self.path.display(), "proxy audit jsonl writer started");
        // Before the first tick, so a proxy restarted after a long outage
        // expires what aged out while it was down rather than after another
        // sweep interval.
        self.sweep_retention().await;
        self.publish_completeness(true).await;

        let mut sweep = tokio::time::interval(self.rotation.sweep_interval);
        // `interval` fires immediately; the startup sweep above already covered
        // that instant.
        sweep.tick().await;

        loop {
            tokio::select! {
                received = self.receiver.recv() => {
                    let Some(entry) = received else { break };
                    if let Err(e) = self.append(&entry).await {
                        let total = record_write_failure();
                        tracing::error!(
                            error = %e,
                            write_failures = total,
                            "proxy audit jsonl write failed — the file on disk is not what \
                             the proxy recorded; the published window is now lossy",
                        );
                    }
                    // After the append, not before: a drop recorded by the data
                    // path while this line was in flight belongs to the window a
                    // reader is about to see.
                    self.publish_completeness(false).await;
                }
                _ = sweep.tick() => {
                    self.sweep_retention().await;
                    self.publish_completeness(false).await;
                }
            }
        }

        if let Err(e) = self.file.flush().await {
            let total = record_write_failure();
            tracing::error!(
                error = %e,
                write_failures = total,
                "proxy audit jsonl final flush failed — buffered records were not written",
            );
        }
        self.publish_completeness(true).await;
        tracing::info!(path = %self.path.display(), "proxy audit jsonl writer stopped");
    }

    async fn append(&mut self, entry: &ProxyAuditEntry) -> io::Result<()> {
        let json = serde_json::to_string(entry).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.file.write_all(json.as_bytes()).await?;
        self.file.write_all(b"\n").await?;
        self.file.flush().await?;
        self.segment_bytes += json.len() as u64 + 1;
        self.live_started_ms.get_or_insert(entry.ts_ms);
        // Rotate *after* the write so a line is never split across segments —
        // a consumer parses this file line by line and half a record is worse
        // than a segment that overshoots by one line.
        if self.segment_bytes >= self.rotation.max_segment_bytes {
            self.rotate().await?;
        }
        Ok(())
    }

    /// Apply the age bound: rotate the live segment if its oldest record has
    /// aged out, then delete every rotated segment whose newest record has.
    ///
    /// A no-op when [`RotationPolicy::max_age`] is `None`, which is the default
    /// — an operator who configured no age bound must get exactly the ring
    /// AAASM-5449 gave them.
    ///
    /// Failures are logged rather than propagated: a sweep that cannot delete a
    /// segment must not stop the writer from recording the next refusal.
    async fn sweep_retention(&mut self) {
        // Export first and unconditionally: the handoff is not gated on an age
        // bound being configured, and a segment must never be deleted that
        // could still have been exported.
        self.export_segments().await;
        if self.rotation.max_age.is_none() {
            return;
        }
        if self.live_segment_has_aged_out() {
            if let Err(e) = self.rotate().await {
                let total = record_write_failure();
                tracing::error!(
                    error = %e,
                    write_failures = total,
                    "proxy audit jsonl age-based rotation failed",
                );
            }
        }
        self.expire_aged_segments().await;
    }

    /// Offer every rotated segment to the exporter.
    ///
    /// Runs in the writer task, never on the enforcement path: the data path's
    /// only interaction with this sink is a `try_send` on a bounded channel, so
    /// a slow or wedged exporter costs audit latency and nothing else. That is
    /// the same constraint `emit_rule_refusal` already lives under.
    ///
    /// Every segment is re-offered every time. Export is idempotent by name
    /// (see [`export_name`]), so an already-delivered segment costs one
    /// `try_exists` and a failed one retries by itself — which is what makes
    /// delivery at-least-once across a restart without any persisted cursor.
    async fn export_segments(&mut self) {
        let ExportTarget::Directory(dir) = self.export.clone() else {
            self.pending_exports = 0;
            return;
        };
        let mut pending = 0u64;
        for n in 1..=self.rotation.retained_segments {
            let segment = segment_path(&self.path, n);
            let Ok(meta) = tokio::fs::metadata(&segment).await else {
                continue;
            };
            if meta.len() == 0 {
                continue;
            }
            let first = first_record_ms(&segment).await.unwrap_or(0);
            let mtime = mtime_ms(&segment).await.unwrap_or(0);
            let target = dir.join(export_name(&self.path, first, mtime, meta.len()));
            if tokio::fs::try_exists(&target).await.unwrap_or(false) {
                continue;
            }
            match publish_segment(&segment, &target).await {
                Ok(()) => tracing::info!(
                    segment = %segment.display(),
                    target = %target.display(),
                    "proxy audit jsonl segment exported",
                ),
                Err(e) => {
                    pending += 1;
                    let total = EXPORT_FAILURES.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::error!(
                        error = %e,
                        segment = %segment.display(),
                        target = %target.display(),
                        export_failures = total,
                        "proxy audit jsonl segment export failed — the local ring is still the \
                         only copy of this evidence",
                    );
                }
            }
        }
        self.pending_exports = pending;
    }

    /// Whether the oldest record in the live segment has reached the age bound.
    fn live_segment_has_aged_out(&self) -> bool {
        let Some(started) = self.live_started_ms else {
            return false;
        };
        let elapsed_ms = now_ms().saturating_sub(started).max(0) as u64;
        self.rotation.is_expired(Duration::from_millis(elapsed_ms))
    }

    /// Delete rotated segments whose newest record is past the age bound.
    ///
    /// Iterates the whole chain rather than stopping at the first survivor: a
    /// clock adjustment or a hand-copied file can leave the chain out of age
    /// order, and a bound that gave up at the first young segment would then
    /// keep evidence the operator asked to have deleted.
    async fn expire_aged_segments(&mut self) {
        for n in 1..=self.rotation.retained_segments {
            let segment = segment_path(&self.path, n);
            let Some(age) = newest_record_age(&segment).await else {
                continue;
            };
            if !self.rotation.is_expired(age) {
                continue;
            }
            match tokio::fs::remove_file(&segment).await {
                Ok(()) => {
                    let total = EXPIRED_SEGMENTS.fetch_add(1, Ordering::Relaxed) + 1;
                    tracing::info!(
                        path = %segment.display(),
                        age_secs = age.as_secs(),
                        expired_total = total,
                        "proxy audit jsonl segment deleted by the configured retention period",
                    );
                }
                Err(e) => tracing::error!(
                    error = %e,
                    path = %segment.display(),
                    "proxy audit jsonl segment expiry failed",
                ),
            }
        }
    }

    /// Shift the segment chain along by one and start a fresh live file.
    ///
    /// The oldest segment is removed, which is the whole point — and is why
    /// [`DISCARDED_SEGMENTS`] exists: a bound that quietly discards audit
    /// records would turn every long-running proxy into a silent under-count.
    async fn rotate(&mut self) -> io::Result<()> {
        self.file.flush().await?;
        // Before the discard below, which is the last moment the oldest segment
        // exists. Waiting for the next timed sweep would lose it.
        self.export_segments().await;
        let oldest = segment_path(&self.path, self.rotation.retained_segments);
        if tokio::fs::metadata(&oldest).await.is_ok() {
            // Read the age *before* the unlink: this is the one moment the two
            // bounds can be compared on the same segment, and a segment the
            // size bound is about to take while the age bound would have kept
            // it is the disagreement made concrete.
            let still_within_age = newest_record_age(&oldest)
                .await
                .is_some_and(|age| !self.rotation.is_expired(age));
            tokio::fs::remove_file(&oldest).await?;
            let total = DISCARDED_SEGMENTS.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                path = %oldest.display(),
                discarded_total = total,
                "proxy audit jsonl segment discarded to stay inside the size bound",
            );
            if self.rotation.max_age.is_some() && still_within_age {
                let shortfall = RETENTION_SHORTFALLS.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    path = %oldest.display(),
                    shortfall_total = shortfall,
                    "configured retention period NOT met: the size bound discarded a segment the \
                     age bound would have kept — reduce traffic, raise the size bound, or export",
                );
            }
        }
        for n in (1..self.rotation.retained_segments).rev() {
            let from = segment_path(&self.path, n);
            if tokio::fs::metadata(&from).await.is_ok() {
                tokio::fs::rename(&from, segment_path(&self.path, n + 1)).await?;
            }
        }
        // `retained_segments == 0` means "keep nothing": the live file is
        // simply discarded rather than renamed onto itself.
        if self.rotation.retained_segments == 0 {
            tokio::fs::remove_file(&self.path).await?;
            let total = DISCARDED_SEGMENTS.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(discarded_total = total, "proxy audit jsonl segment discarded");
        } else {
            tokio::fs::rename(&self.path, segment_path(&self.path, 1)).await?;
        }
        self.file = tokio::io::BufWriter::new(Self::open_segment(&self.path).await?);
        self.segment_bytes = 0;
        self.live_started_ms = None;
        Ok(())
    }

    /// Current completeness of this file: the baseline it was opened with plus
    /// what this process has lost since.
    fn completeness(&self) -> SinkCompleteness {
        SinkCompleteness {
            updated_ms: now_ms(),
            dropped_entries: self.baseline.dropped_entries + dropped_entries().saturating_sub(self.dropped_at_open),
            discarded_segments: self.baseline.discarded_segments
                + discarded_segments().saturating_sub(self.discarded_at_open),
            expired_segments: self.baseline.expired_segments + expired_segments().saturating_sub(self.expired_at_open),
            retention_shortfalls: self.baseline.retention_shortfalls
                + retention_shortfalls().saturating_sub(self.shortfalls_at_open),
            write_failures: self.baseline.write_failures + write_failures().saturating_sub(self.write_failures_at_open),
            // The status is what this process is doing, not what an earlier one
            // did: an operator who removed the export directory must see the
            // sink say so now rather than inherit yesterday's reassurance.
            export: self.export.status(),
            export_failures: self.baseline.export_failures
                + export_failures().saturating_sub(self.export_failures_at_open),
            pending_exports: self.pending_exports,
        }
    }

    /// Write the completeness snapshot beside the sink.
    ///
    /// Skipped when the figures have not moved, unless `force` — the sidecar
    /// must exist from the moment the sink does, so a consumer that finds no
    /// file knows the sink was never opened rather than guessing.
    async fn publish_completeness(&mut self, force: bool) {
        let current = self.completeness();
        if !force
            && current.dropped_entries == self.published.dropped_entries
            && current.discarded_segments == self.published.discarded_segments
            && current.expired_segments == self.published.expired_segments
            && current.retention_shortfalls == self.published.retention_shortfalls
            && current.write_failures == self.published.write_failures
            && current.export_failures == self.published.export_failures
            && current.pending_exports == self.published.pending_exports
        {
            return;
        }
        if let Err(e) = write_completeness(&self.path, current).await {
            tracing::error!(error = %e, "proxy audit jsonl completeness write failed");
            return;
        }
        self.published = current;
    }
}

/// Write `completeness` beside `path`, replacing any previous snapshot.
///
/// Written to a temporary and renamed so a consumer never reads a half-written
/// snapshot and concludes the window was clean.
async fn write_completeness(path: &Path, completeness: SinkCompleteness) -> io::Result<()> {
    let target = completeness_path(path);
    let mut tmp = target.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let json = serde_json::to_vec(&completeness).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)
            .await?;
        file.write_all(&json).await?;
        file.flush().await?;
        // Same reasoning as the sink itself: a leftover file keeps its old
        // mode, and this one names the hosts an agent was refused for.
        let mut perms = file.metadata().await?.permissions();
        if perms.mode() & 0o777 != 0o600 {
            perms.set_mode(0o600);
            file.set_permissions(perms).await?;
        }
    }
    tokio::fs::rename(&tmp, &target).await
}

/// Bounded capacity of the audit channel.
///
/// The data path uses `try_send` and drops on overflow rather than
/// back-pressuring an intercepted request, so this bound is the amount of
/// writer lag the proxy will absorb before audit lines start being lost.
const AUDIT_CHANNEL_CAPACITY: usize = 1024;

/// Open the audit sink an operator asked for, and spawn the writer that drains
/// it.
///
/// `None` in, `None` out: no path configured means no persistence, which is
/// the historical default and leaves the data path byte-identical.
///
/// # Errors
///
/// Propagates the open failure rather than degrading to `None`. An operator who
/// configured an audit trail and silently got none would be in exactly the state
/// this whole work stream exists to prevent — believing a record exists when it
/// does not — so the proxy refuses to start instead.
pub async fn build_audit_sink(path: Option<&Path>) -> io::Result<Option<mpsc::Sender<ProxyAuditEntry>>> {
    let Some(path) = path else { return Ok(None) };
    let (tx, rx) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);
    let writer = JsonlWriter::new(path, rx).await?;
    tokio::spawn(writer.run());
    Ok(Some(tx))
}

#[cfg(test)]
mod tests {
    use super::*;

    use aa_core::policy::EnforcementMode;
    use aa_core::types::sensitive_data::{EnforcementPoint, TransmissionEvidence};

    /// Synthetic AWS access key from AWS public documentation. Not a real credential.
    const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    /// Security invariant: the raw secret value must never appear in the
    /// JSONL file on disk, even when the body that produced the finding
    /// embedded the secret verbatim. Drives the AAASM-1566 acceptance
    /// criterion "grep for the raw key against the JSONL file returns 0
    /// matches".
    #[tokio::test]
    async fn audit_writer_never_writes_raw_secret() {
        use aa_security::CredentialScanner;

        let body = format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#);
        let scan = CredentialScanner::new().scan(&body);
        assert!(
            !scan.findings.is_empty(),
            "scanner fixture invariant — AWS key must be detected"
        );
        let redacted = scan.redact(&body);

        let entry = ProxyAuditEntry {
            ts_ms: 1_700_000_000_000,
            agent_id: Some("agent-1".into()),
            host: "api.openai.com".into(),
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            decision: ProxyAuditDecision::ForwardedRedacted,
            refusal_rule: None,
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
            probe_correlation: None,
            credential_findings: scan.findings.iter().map(PersistedFinding::project).collect(),
            findings_omitted: 0,
            redacted_body: Some(redacted),
        };

        let tmp = tempfile::tempdir().expect("create tempdir");
        let path = tmp.path().join("proxy-audit.jsonl");
        let (tx, rx) = mpsc::channel(4);
        let writer = JsonlWriter::new(&path, rx).await.expect("open jsonl writer");
        let handle = tokio::spawn(writer.run());

        tx.send(entry).await.expect("send entry");
        drop(tx);
        handle.await.expect("writer task joins cleanly");

        let on_disk = tokio::fs::read_to_string(&path).await.expect("read JSONL");
        assert!(
            !on_disk.contains(FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT VIOLATED: raw secret present in proxy audit JSONL: {on_disk}",
        );
        assert!(
            on_disk.contains("[REDACTED:AwsAccessKey]"),
            "JSONL must carry the [REDACTED:AwsAccessKey] marker, got: {on_disk}",
        );
        assert_eq!(
            on_disk.matches('\n').count(),
            1,
            "single entry must produce exactly one trailing newline: {on_disk}",
        );
    }

    /// Build a minimal clean entry (no findings, no redaction) for tests that
    /// care about framing rather than redaction.
    fn clean_entry(host: &str, decision: ProxyAuditDecision) -> ProxyAuditEntry {
        ProxyAuditEntry {
            ts_ms: 1_700_000_000_000,
            agent_id: None,
            host: host.into(),
            method: "GET".into(),
            path: "/".into(),
            decision,
            refusal_rule: None,
            execution: ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
            probe_correlation: None,
            credential_findings: vec![],
            findings_omitted: 0,
            redacted_body: None,
        }
    }

    #[tokio::test]
    async fn writer_appends_one_jsonl_line_per_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());

        for host in ["a.example", "b.example", "c.example"] {
            tx.send(clean_entry(host, ProxyAuditDecision::Forwarded)).await.unwrap();
        }
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = on_disk.lines().collect();
        assert_eq!(lines.len(), 3, "three entries → three lines");
        // Every line is independently valid JSON.
        for line in &lines {
            serde_json::from_str::<ProxyAuditEntry>(line).expect("each line is a valid entry");
        }
        assert!(on_disk.contains("a.example") && on_disk.contains("c.example"));
    }

    #[tokio::test]
    async fn writer_appends_to_existing_file_across_two_runs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // First run writes one line, then the writer is dropped (file closed).
        {
            let (tx, rx) = mpsc::channel(4);
            let writer = JsonlWriter::new(&path, rx).await.unwrap();
            let handle = tokio::spawn(writer.run());
            tx.send(clean_entry("first.example", ProxyAuditDecision::Blocked))
                .await
                .unwrap();
            drop(tx);
            handle.await.unwrap();
        }

        // Second run opens the same path in append mode; the first line survives.
        {
            let (tx, rx) = mpsc::channel(4);
            let writer = JsonlWriter::new(&path, rx).await.unwrap();
            let handle = tokio::spawn(writer.run());
            tx.send(clean_entry("second.example", ProxyAuditDecision::Forwarded))
                .await
                .unwrap();
            drop(tx);
            handle.await.unwrap();
        }

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(on_disk.lines().count(), 2, "append mode preserves prior content");
        assert!(on_disk.contains("first.example"));
        assert!(on_disk.contains("second.example"));
    }

    #[tokio::test]
    async fn writer_with_no_entries_produces_empty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(1);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());
        // Drop the sender immediately: the loop exits without writing anything.
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(on_disk.is_empty(), "no entries → empty file");
    }

    #[tokio::test]
    async fn writer_exposes_its_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        assert_eq!(writer.path(), path.as_path());
    }

    #[tokio::test]
    async fn writer_new_errors_when_parent_dir_missing() {
        // `new` documents that parent dirs must already exist; opening under a
        // non-existent directory therefore surfaces an I/O error.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does/not/exist/audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        // `JsonlWriter` is not `Debug`, so match the Result rather than using
        // `expect_err`, which requires `T: Debug`.
        match JsonlWriter::new(&path, rx).await {
            Ok(_) => panic!("opening under a missing parent dir must fail"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    #[test]
    fn decision_serializes_to_snake_case() {
        let cases = [
            (ProxyAuditDecision::Forwarded, "\"forwarded\""),
            (ProxyAuditDecision::ForwardedRedacted, "\"forwarded_redacted\""),
            (ProxyAuditDecision::Blocked, "\"blocked\""),
            (ProxyAuditDecision::AnsweredLocally, "\"answered_locally\""),
        ];
        for (decision, expected) in cases {
            assert_eq!(serde_json::to_string(&decision).unwrap(), expected);
            // Round-trips back to the same variant.
            let back: ProxyAuditDecision = serde_json::from_str(expected).unwrap();
            assert_eq!(back, decision);
        }
    }

    #[test]
    fn entry_round_trips_through_json_preserving_fields() {
        let entry = ProxyAuditEntry {
            ts_ms: 42,
            agent_id: Some("agent-x".into()),
            host: "api.example".into(),
            method: "POST".into(),
            path: "/v1/do".into(),
            decision: ProxyAuditDecision::ForwardedRedacted,
            refusal_rule: None,
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::ForwardedClean,
                EnforcementMode::Enforce,
            ),
            probe_correlation: None,
            credential_findings: vec![],
            findings_omitted: 0,
            redacted_body: Some("clean body".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ts_ms, 42);
        assert_eq!(back.agent_id.as_deref(), Some("agent-x"));
        assert_eq!(back.host, "api.example");
        assert_eq!(back.decision, ProxyAuditDecision::ForwardedRedacted);
        assert_eq!(back.redacted_body.as_deref(), Some("clean body"));
        assert_eq!(back.execution, entry.execution);
    }

    /// ADR 0032 §9 permits byte offsets only in the tamper-evident tier, and
    /// this sink is not it. AAASM-5358 is what first constructs the writer in
    /// production, so without the projection this would be the change that put
    /// them on disk.
    #[tokio::test]
    async fn a_persisted_finding_carries_no_byte_offset() {
        use aa_security::CredentialScanner;

        let body = format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#);
        let scan = CredentialScanner::new().scan(&body);
        assert!(!scan.findings.is_empty(), "scanner fixture invariant");
        // Non-vacuity: the source finding really does carry an offset, and the
        // body is long enough that the offset is not coincidentally 0.
        let source_offset = scan.findings[0].offset;
        assert!(source_offset > 0, "fixture must produce a non-zero offset");

        let (projected, omitted) = bound_persisted_findings(&scan.findings);
        assert_eq!(omitted, 0);
        assert!(!projected.is_empty(), "otherwise the assertions below are vacuous");
        assert_eq!(projected[0].kind, scan.findings[0].kind);
        assert_eq!(projected[0].matched, scan.findings[0].matched);

        let entry = ProxyAuditEntry {
            credential_findings: projected,
            ..clean_entry("api.example", ProxyAuditDecision::ForwardedRedacted)
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            !json.contains("\"offset\""),
            "ADR 0032 §9: a byte offset must not reach this tier: {json}"
        );
        // The category — which §9 does permit — survives, so the record is
        // still useful.
        assert!(json.contains("AwsAccessKey"), "the category must survive: {json}");
    }

    /// `redacted_body` alone does not bound a line: the findings vector does
    /// too, and a densely-matching 64 MiB body produces on the order of a
    /// million of them.
    #[test]
    fn an_oversized_finding_list_is_capped_and_the_remainder_counted() {
        use aa_security::CredentialScanner;

        let one = CredentialScanner::new().scan(&format!(r#"{{"k":"{FAKE_AWS_ACCESS_KEY}"}}"#));
        assert!(!one.findings.is_empty(), "scanner fixture invariant");
        let many: Vec<_> = std::iter::repeat_with(|| one.findings[0].clone())
            .take(MAX_PERSISTED_FINDINGS + 37)
            .collect();

        let (kept, omitted) = bound_persisted_findings(&many);
        assert_eq!(kept.len(), MAX_PERSISTED_FINDINGS);
        assert_eq!(omitted, 37, "the remainder must be counted, not silently dropped");

        // Under the cap nothing is omitted, so the counter is not simply
        // always-positive.
        let (kept, omitted) = bound_persisted_findings(&many[..3]);
        assert_eq!(kept.len(), 3);
        assert_eq!(omitted, 0);
    }

    /// The sink is a new durable file holding a per-agent behavioural trail —
    /// destination hosts, redacted paths and bodies, and which credential
    /// categories an agent was caught sending. The default `0644` would have
    /// published all of it to every local account.
    ///
    /// Byte offsets are handled separately and are not on disk at all; see
    /// [`PersistedFinding`] and `a_persisted_finding_carries_no_byte_offset`.
    #[tokio::test]
    async fn the_audit_file_is_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (_tx, rx) = mpsc::channel(1);
        let _writer = JsonlWriter::new(&path, rx).await.unwrap();
        let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file mode was {mode:o}");
    }

    /// A file left over from an earlier, looser build must be tightened rather
    /// than inherited — `mode()` applies only at creation.
    #[tokio::test]
    async fn an_existing_loose_audit_file_is_tightened_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        tokio::fs::write(&path, b"").await.unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .await
            .unwrap();
        // Non-vacuity: the file really is loose before the writer opens it.
        let before = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(before, 0o644);

        let (_tx, rx) = mpsc::channel(1);
        let _writer = JsonlWriter::new(&path, rx).await.unwrap();
        let after = tokio::fs::metadata(&path).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(after, 0o600, "an existing audit file kept mode {after:o}");
    }

    /// The MitM path accepts bodies up to 64 MiB and this sink has no rotation,
    /// so one oversized request must not become an unbounded line.
    #[test]
    fn an_oversized_body_is_truncated_on_a_character_boundary_and_marked() {
        let short = "already small".to_owned();
        assert_eq!(bound_persisted_body(short.clone()), short);

        // Multi-byte characters, so a naive byte slice would panic.
        let big = "é".repeat(MAX_PERSISTED_BODY_BYTES);
        assert!(big.len() > MAX_PERSISTED_BODY_BYTES);
        let bounded = bound_persisted_body(big);
        assert!(bounded.ends_with(BODY_TRUNCATION_MARKER), "truncation must be visible");
        assert!(
            bounded.len() <= MAX_PERSISTED_BODY_BYTES + BODY_TRUNCATION_MARKER.len(),
            "bounded body was {} bytes",
            bounded.len()
        );
    }

    /// A prevention metric computed over a silently lossy record is not
    /// authoritative. The data path is right to drop rather than block, so the
    /// loss has to be countable.
    #[test]
    fn dropped_entries_are_counted() {
        let before = dropped_entries();
        let first = record_dropped_entry();
        let second = record_dropped_entry();
        assert_eq!(first, before + 1);
        assert_eq!(second, before + 2);
        assert_eq!(dropped_entries(), before + 2);
    }

    /// A rule refusal and a fail-closed credential block are both `Blocked`
    /// with an empty finding list, so without this field a consumer cannot
    /// attribute a prevention to the control that made it (AAASM-5449).
    #[test]
    fn a_refusal_rule_round_trips_and_stays_absent_on_a_verdict_record() {
        let entry = ProxyAuditEntry {
            refusal_rule: Some(RefusalRule::EgressDenylist),
            ..clean_entry("evil.example", ProxyAuditDecision::Blocked)
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(
            json.contains("\"egress_denylist\""),
            "the rule must be spelled on the line: {json}"
        );
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.refusal_rule, Some(RefusalRule::EgressDenylist));

        // Non-vacuity: the field really does distinguish, rather than being
        // present on every record.
        let verdict_block = clean_entry("api.example", ProxyAuditDecision::Blocked);
        assert!(
            verdict_block.refusal_rule.is_none(),
            "a credential verdict's refusal names no rule"
        );
    }

    /// Every rule is a distinct on-the-wire token: two rules that serialised to
    /// the same string would silently merge two controls into one count.
    #[test]
    fn every_refusal_rule_serializes_distinctly() {
        let rules = [
            RefusalRule::EgressDenylist,
            RefusalRule::EgressAllowlist,
            RefusalRule::SsrfBlockedAddress,
            RefusalRule::PlaintextLlmDowngrade,
            RefusalRule::McpToolCall,
        ];
        let mut seen = Vec::new();
        for rule in rules {
            let json = serde_json::to_string(&rule).unwrap();
            assert!(!seen.contains(&json), "{rule:?} collides with an earlier rule: {json}");
            let back: RefusalRule = serde_json::from_str(&json).unwrap();
            assert_eq!(back, rule);
            seen.push(json);
        }
        assert_eq!(seen.len(), rules.len());
    }

    /// A probe's own traffic must be identifiable in the record, so a consumer
    /// can exclude synthetic preventions from a rate.
    #[test]
    fn a_probe_record_round_trips_its_correlation_id() {
        let entry = ProxyAuditEntry {
            probe_correlation: Some("0123456789abcdef0123456789abcdef".into()),
            ..clean_entry("api.example", ProxyAuditDecision::Blocked)
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ProxyAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.probe_correlation.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        // Ordinary traffic stays distinguishable from synthetic traffic.
        let ordinary = clean_entry("api.example", ProxyAuditDecision::Blocked);
        assert!(ordinary.probe_correlation.is_none());
    }

    /// `build_audit_sink(None)` is the historical default: no path, no writer,
    /// nothing on disk.
    #[tokio::test]
    async fn no_configured_path_builds_no_sink() {
        let sink = build_audit_sink(None).await.expect("no path is not an error");
        assert!(sink.is_none(), "an unconfigured proxy must not construct a writer");
    }

    /// The wiring `run()` depends on: a configured path really does produce a
    /// live sender whose entries reach the file. Without this the sink would be
    /// constructed-in-name-only, which is the exact defect this ticket found in
    /// production.
    #[tokio::test]
    async fn a_configured_path_builds_a_sink_that_reaches_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let sink = build_audit_sink(Some(&path))
            .await
            .expect("open succeeds")
            .expect("a configured path yields a sender");

        sink.send(clean_entry("wired.example", ProxyAuditDecision::Blocked))
            .await
            .expect("the writer task is alive and draining");
        drop(sink);

        // The writer task owns the file; poll briefly for the flushed line
        // rather than assuming the spawn has been scheduled.
        let mut on_disk = String::new();
        for _ in 0..200 {
            on_disk = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            if !on_disk.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            on_disk.contains("wired.example"),
            "the sink returned by build_audit_sink never reached disk: {on_disk:?}"
        );
    }

    /// An operator who asked for an audit trail and cannot have one must be
    /// told, not silently given a proxy that records nothing.
    #[tokio::test]
    async fn an_unopenable_path_is_an_error_not_a_silent_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("does/not/exist/audit.jsonl");
        match build_audit_sink(Some(&path)).await {
            Ok(_) => panic!("a configured-but-unopenable audit path must not degrade to no sink"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
        }
    }

    /// The evidence has to survive serialisation to reach a reader at all, and
    /// it has to survive it *as the thing that was recorded* — a round trip that
    /// silently normalised `not_forwarded` into anything else would leave the
    /// prevention rule reading a value the proxy never observed.
    #[tokio::test]
    async fn non_transmission_evidence_survives_the_trip_to_disk() {
        let entry = ProxyAuditEntry {
            execution: ExecutionEvidence::new(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
            ..clean_entry("api.example", ProxyAuditDecision::Blocked)
        };

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let (tx, rx) = mpsc::channel(4);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();
        let handle = tokio::spawn(writer.run());
        tx.send(entry).await.unwrap();
        drop(tx);
        handle.await.unwrap();

        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(
            on_disk.contains("\"not_forwarded\""),
            "the on-disk line must spell the evidence: {on_disk}"
        );
        let back: ProxyAuditEntry = serde_json::from_str(on_disk.trim()).expect("the line parses");
        assert!(
            back.execution.establishes_non_transmission(),
            "the persisted record lost the only observation that can support a prevention claim"
        );
    }
}

/// Retention, rotation and completeness of the sink.
///
/// # Falsification record (AAASM-5660)
///
/// Assertions here were confirmed non-vacuous by mutating the implementation
/// and watching named tests fail. Re-run these mutations if you change the
/// retention path; a test that no longer dies to its mutation is no longer
/// proving anything.
///
/// | Mutation | Test that dies |
/// |---|---|
/// | `expire_aged_segments` returns immediately | `a_segment_past_the_age_bound_is_deleted_and_counted` |
/// | `RotationPolicy::is_expired` always `false` | `a_segment_past_the_age_bound_is_deleted_and_counted`, `the_size_bound_wins_when_the_two_bounds_disagree` |
/// | shortfall counting removed from `rotate` | `the_size_bound_wins_when_the_two_bounds_disagree` |
/// | `sweep_retention` dropped from `run`'s timer arm | `a_quiet_proxy_still_honours_the_age_bound` |
#[cfg(test)]
mod retention_tests {
    use super::*;

    use crate::transmission_evidence::DecisionRecord;
    use aa_core::policy::EnforcementMode;

    /// `ts_ms` is *now* rather than a frozen literal: the age bound reads the
    /// first record's own timestamp to decide when the live segment has aged
    /// out, so a 2023 literal would make every fixture's live segment
    /// instantly expired and mask whatever the test meant to show.
    fn entry(host: &str) -> ProxyAuditEntry {
        ProxyAuditEntry {
            ts_ms: now_ms(),
            agent_id: None,
            host: host.into(),
            method: "POST".into(),
            path: "/v1/do".into(),
            decision: ProxyAuditDecision::Blocked,
            refusal_rule: Some(RefusalRule::EgressDenylist),
            execution: ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
            probe_correlation: None,
            credential_findings: vec![],
            findings_omitted: 0,
            redacted_body: None,
        }
    }

    /// A tiny policy so the test rotates in milliseconds rather than gigabytes.
    fn tiny() -> RotationPolicy {
        RotationPolicy {
            max_segment_bytes: 1024,
            retained_segments: 2,
            ..RotationPolicy::default()
        }
    }

    /// Move a file's modification time into the past.
    ///
    /// The age bound reads mtime to date a rotated segment's newest record, so
    /// this is how a test produces a segment that is genuinely old without
    /// waiting. It writes the real filesystem timestamp — the code under test
    /// reads the same `metadata().modified()` a production sweep does, with no
    /// injected clock standing in for it.
    fn backdate(path: &Path, age: Duration) {
        let when = SystemTime::now()
            .checked_sub(age)
            .expect("test ages are far smaller than the epoch");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap_or_else(|e| panic!("open {} to backdate: {e}", path.display()));
        file.set_times(std::fs::FileTimes::new().set_modified(when))
            .unwrap_or_else(|e| panic!("backdate {}: {e}", path.display()));
    }

    async fn drain(path: &Path, policy: RotationPolicy, count: usize) {
        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::with_rotation(path, rx, policy).await.unwrap();
        let handle = tokio::spawn(writer.run());
        for i in 0..count {
            tx.send(entry(&format!("h{i}.example"))).await.unwrap();
        }
        drop(tx);
        handle.await.unwrap();
    }

    /// The sink is a file the proxy creates and never stops appending to.
    /// External `logrotate` cannot manage it — the writer holds the descriptor
    /// for the process lifetime and would keep writing to an unlinked inode —
    /// so the bound has to live here.
    #[tokio::test]
    async fn an_oversized_sink_rotates_and_keeps_a_bounded_number_of_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = tiny();

        drain(&path, policy, 200).await;

        // Non-vacuity: the run really did produce far more than the ceiling, so
        // "bounded" is not trivially true of a run that never filled a segment.
        let line = serde_json::to_string(&entry("h0.example")).unwrap().len() as u64 + 1;
        let produced = line * 200;
        let ceiling = (policy.retained_segments as u64 + 1) * (policy.max_segment_bytes + line);
        assert!(
            produced > ceiling * 2,
            "the fixture wrote {produced} bytes against a {ceiling}-byte ceiling; it cannot show a bound"
        );

        let mut total = tokio::fs::metadata(&path).await.unwrap().len();
        for n in 1..=policy.retained_segments {
            let seg = segment_path(&path, n);
            total += tokio::fs::metadata(&seg)
                .await
                .unwrap_or_else(|e| panic!("segment {} missing: {e}", seg.display()))
                .len();
        }
        assert!(
            tokio::fs::metadata(segment_path(&path, policy.retained_segments + 1))
                .await
                .is_err(),
            "a segment beyond the retention limit was kept"
        );
        assert!(
            total <= ceiling,
            "the sink held {total} bytes against a {ceiling} ceiling"
        );
    }

    /// Rotation discards data. A consumer computing a rate over a window that
    /// was rotated away must be able to see that it happened, or the rate is a
    /// silent under-count.
    #[tokio::test]
    async fn a_discarded_segment_is_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let before = discarded_segments();

        // Enough to rotate at least once but not to push a segment past the
        // retention limit, so the counter must still be where it was.
        drain(&path, tiny(), 5).await;
        assert!(
            tokio::fs::metadata(segment_path(&path, 1)).await.is_ok(),
            "the fixture must actually have rotated, or the assertion below is vacuous"
        );
        assert_eq!(
            discarded_segments(),
            before,
            "a rotation that discarded nothing must not be counted as loss"
        );

        // Enough to push a segment past the retention limit.
        drain(&path, tiny(), 200).await;
        assert!(
            discarded_segments() > before,
            "a segment fell off the end and nothing counted it"
        );
    }

    /// A rotated segment holds the same per-agent behavioural trail as the live
    /// file, so it must not become world-readable by being renamed.
    #[tokio::test]
    async fn a_rotated_segment_keeps_its_restricted_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        drain(&path, tiny(), 60).await;

        let seg = segment_path(&path, 1);
        let mode = tokio::fs::metadata(&seg).await.unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "rotated segment mode was {mode:o}");
    }

    // ── time-based retention (AAASM-5660) ──────────────────────────────────

    /// Making the bound configurable must not move it. An existing deployment
    /// that upgrades gets the same 32 MiB × 3 ring AAASM-5449 gave it, and no
    /// age bound at all.
    #[test]
    fn the_defaults_reproduce_the_previous_hard_coded_bound() {
        let policy = RotationPolicy::default();
        assert_eq!(policy.max_segment_bytes, 32 * 1024 * 1024);
        assert_eq!(policy.retained_segments, 3);
        assert_eq!(
            policy.max_age, None,
            "a default age bound would delete evidence a 5449-era deployment expected to keep"
        );
        assert!(
            !policy.is_expired(Duration::from_secs(60 * 60 * 24 * 3650)),
            "with no age bound configured, nothing may ever expire on age"
        );
    }

    /// The age bound is a threshold, not a mood: it must fire at and past the
    /// configured age and never before it.
    #[test]
    fn the_age_bound_fires_only_at_or_past_the_configured_age() {
        let policy = RotationPolicy {
            max_age: Some(Duration::from_secs(100)),
            ..RotationPolicy::default()
        };
        assert!(!policy.is_expired(Duration::from_secs(99)));
        assert!(policy.is_expired(Duration::from_secs(100)));
        assert!(policy.is_expired(Duration::from_secs(101)));
    }

    /// Compliance questions are phrased in days, so a segment past the
    /// configured period has to actually be deleted — and the deletion has to
    /// be counted, because a deletion nobody can see is indistinguishable from
    /// a window in which nothing was ever prevented.
    #[tokio::test]
    async fn a_segment_past_the_age_bound_is_deleted_and_counted() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        drain(&path, tiny(), 60).await;

        let old = segment_path(&path, 1);
        let kept = segment_path(&path, 2);
        // Non-vacuity: both segments exist and hold real lines before the sweep,
        // so "deleted" is a change rather than a description of the start state.
        for seg in [&old, &kept] {
            let body = tokio::fs::read_to_string(seg).await.unwrap();
            assert!(!body.is_empty(), "{} must hold lines before the sweep", seg.display());
        }
        backdate(&old, Duration::from_secs(48 * 60 * 60));

        let before = expired_segments();
        let policy = RotationPolicy {
            max_age: Some(Duration::from_secs(24 * 60 * 60)),
            ..tiny()
        };
        let (_tx, rx) = mpsc::channel(1);
        let mut writer = JsonlWriter::with_rotation(&path, rx, policy).await.unwrap();
        writer.sweep_retention().await;

        assert!(
            tokio::fs::metadata(&old).await.is_err(),
            "a segment two days past a one-day retention period was kept"
        );
        assert_eq!(
            expired_segments(),
            before + 1,
            "the expiry happened but nothing counted it"
        );
        // The control: a segment inside the period is untouched, so the sweep
        // is deleting by age rather than deleting whatever it finds.
        assert!(
            tokio::fs::metadata(&kept).await.is_ok(),
            "a segment inside the retention period was deleted"
        );
    }

    /// The pinned rule when the two bounds disagree: **size wins**, and the
    /// shortfall against the configured period is counted rather than left to
    /// emerge. See [`RotationPolicy`].
    ///
    /// An operator who configures 90 days and gets six hours has to learn it
    /// from the sink, not from the quarter-end question they cannot answer.
    #[tokio::test]
    async fn the_size_bound_wins_when_the_two_bounds_disagree() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // A generous age bound that would keep everything, against a ring far
        // too small to hold what the fixture writes.
        let policy = RotationPolicy {
            max_segment_bytes: 512,
            retained_segments: 1,
            max_age: Some(Duration::from_secs(90 * 24 * 60 * 60)),
            ..RotationPolicy::default()
        };

        let discarded_before = discarded_segments();
        let shortfall_before = retention_shortfalls();
        let expired_before = expired_segments();
        drain(&path, policy, 200).await;

        let discarded = discarded_segments() - discarded_before;
        assert!(
            discarded > 0,
            "the fixture never overflowed the ring, so it cannot show which bound wins"
        );
        assert_eq!(
            retention_shortfalls() - shortfall_before,
            discarded,
            "every segment the size bound took inside the 90-day period is a shortfall against it"
        );
        assert_eq!(
            expired_segments() - expired_before,
            0,
            "nothing was old enough to expire; these deletions are the size bound's"
        );
    }

    /// The other half of the rule, and the control that stops
    /// `retention_shortfalls` from being "the discard counter under a second
    /// name": a discard of an *already expired* segment is not a shortfall,
    /// because the age bound would have deleted it anyway.
    #[tokio::test]
    async fn a_discard_of_already_expired_evidence_is_not_a_shortfall() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = RotationPolicy {
            max_segment_bytes: 512,
            retained_segments: 1,
            // Everything is instantly past a zero-length retention period.
            max_age: Some(Duration::ZERO),
            ..RotationPolicy::default()
        };

        let discarded_before = discarded_segments();
        let shortfall_before = retention_shortfalls();
        drain(&path, policy, 200).await;

        assert!(
            discarded_segments() - discarded_before > 0,
            "the fixture never overflowed the ring, so the assertion below is vacuous"
        );
        assert_eq!(
            retention_shortfalls() - shortfall_before,
            0,
            "a segment the age bound had already condemned was reported as a retention shortfall"
        );
    }

    /// A configured deletion is a promise about the calendar, not about
    /// traffic. A proxy that goes quiet still has to honour it, which is why
    /// the writer waits on a timer as well as on the channel — an
    /// append-driven sweep alone would leave an idle host holding evidence for
    /// ever.
    #[tokio::test]
    async fn a_quiet_proxy_still_honours_the_age_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = RotationPolicy {
            // Far too large to ever rotate on size: only the age bound can
            // move anything here.
            max_segment_bytes: 64 * 1024 * 1024,
            retained_segments: 2,
            max_age: Some(Duration::from_millis(50)),
            sweep_interval: Duration::from_millis(20),
        };

        let before = expired_segments();
        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::with_rotation(&path, rx, policy).await.unwrap();
        let handle = tokio::spawn(writer.run());

        // One record, then silence. Nothing else will ever wake the writer.
        tx.send(entry("quiet.example")).await.unwrap();

        // The live segment must first age out and rotate, then the rotated
        // segment must itself age out — two sweeps at minimum.
        let mut expired = false;
        for _ in 0..500 {
            if expired_segments() > before {
                expired = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(tx);
        handle.await.unwrap();

        assert!(
            expired,
            "no traffic arrived after the first record and nothing was ever deleted, \
             so the configured retention period was not honoured on an idle proxy"
        );
        assert!(
            tokio::fs::metadata(segment_path(&path, 1)).await.is_err(),
            "the aged segment survived the sweep"
        );
    }

    /// Both new counters reach a consumer, and a restart does not erase them —
    /// the same baseline discipline AAASM-5449 established for the two it
    /// already published.
    #[tokio::test]
    async fn expiry_and_shortfall_counts_are_published_and_survive_a_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = RotationPolicy {
            max_segment_bytes: 512,
            retained_segments: 1,
            max_age: Some(Duration::from_secs(90 * 24 * 60 * 60)),
            ..RotationPolicy::default()
        };
        drain(&path, policy, 200).await;

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert!(
            published.retention_shortfalls > 0,
            "the shortfall never reached the file a consumer reads: {published:?}"
        );
        let shortfalls = published.retention_shortfalls;

        // A clean second run must carry the first run's shortfall forward.
        drain(&path, RotationPolicy::default(), 2).await;
        let after = read_completeness(&path).await.unwrap();
        assert_eq!(
            after.retention_shortfalls, shortfalls,
            "a restart erased the earlier window's retention shortfall"
        );
    }

    /// A sidecar written before these fields existed must still deserialize:
    /// the restart baseline is read from it, and a decode failure would
    /// silently reset an earlier window's recorded loss to zero — exactly the
    /// regression requirement 4 forbids.
    #[tokio::test]
    async fn an_older_sidecar_without_the_new_fields_still_seeds_the_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        tokio::fs::write(
            completeness_path(&path),
            br#"{"updated_ms":1,"dropped_entries":7,"discarded_segments":2}"#,
        )
        .await
        .unwrap();

        let recovered = read_completeness(&path)
            .await
            .expect("an AAASM-5449 sidecar must parse");
        assert_eq!(recovered.dropped_entries, 7);
        assert_eq!(recovered.discarded_segments, 2);
        assert_eq!(recovered.expired_segments, 0);

        // And the writer carries it forward rather than starting from zero.
        drain(&path, RotationPolicy::default(), 1).await;
        let published = read_completeness(&path).await.unwrap();
        assert_eq!(published.dropped_entries, 7, "the earlier window's loss was erased");
        assert_eq!(published.discarded_segments, 2);
    }

    // ── failed sink I/O: the disk-full class (AAASM-5660) ──────────────────

    /// Disk-full is defined as **count and keep enforcing**, never as a silent
    /// drop and never as killing the proxy.
    ///
    /// `ENOSPC` surfaces at exactly one place — the `io::Result` of an append,
    /// a flush or the rotation that follows them — so the fixture produces a
    /// real failure at that same boundary rather than mocking the filesystem: a
    /// directory sitting where the rotation's `remove_file` expects a segment
    /// makes `rotate` fail with a genuine OS error, on a parent directory that
    /// is still writable so the sidecar can still be published.
    ///
    /// (A literal full filesystem is not portably constructible in a unit test
    /// on this platform; what is under test is the handling of the failure, and
    /// that handling is shared by every `io::Error` the sink can take.)
    #[tokio::test]
    async fn a_sink_write_that_fails_is_counted_and_published() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = RotationPolicy {
            max_segment_bytes: 256,
            retained_segments: 1,
            ..RotationPolicy::default()
        };

        // A directory where rotation expects to unlink the oldest segment.
        // `remove_file` on a directory is an error on every Unix.
        let blocked = segment_path(&path, 1);
        std::fs::create_dir(&blocked).unwrap();

        let before = write_failures();
        drain(&path, policy, 20).await;

        let failures = write_failures() - before;
        assert!(
            failures > 0,
            "the sink could not complete its rotation and reported nothing"
        );
        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(
            published.write_failures, failures,
            "the failure never reached the file a consumer reads: {published:?}"
        );
    }

    /// The control: the identical fixture without the obstruction completes
    /// every write and reports zero, so `write_failures` is not simply
    /// always-positive.
    #[tokio::test]
    async fn a_sink_that_writes_cleanly_reports_no_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let policy = RotationPolicy {
            max_segment_bytes: 256,
            retained_segments: 1,
            ..RotationPolicy::default()
        };

        let before = write_failures();
        drain(&path, policy, 20).await;

        assert_eq!(write_failures(), before, "a clean run reported a write failure");
        let published = read_completeness(&path).await.unwrap();
        assert_eq!(published.write_failures, 0);
        // Non-vacuity: the fixture really did rotate, so it exercised the same
        // code path the obstructed run failed in.
        assert!(
            tokio::fs::metadata(segment_path(&path, 1)).await.is_ok(),
            "the fixture never rotated, so it does not control for the failing case"
        );
    }

    // ── durable export seam (AAASM-5660) ───────────────────────────────────

    async fn drain_with_export(path: &Path, policy: RotationPolicy, export: ExportTarget, count: usize) {
        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::with_retention(path, rx, policy, export).await.unwrap();
        let handle = tokio::spawn(writer.run());
        for i in 0..count {
            tx.send(entry(&format!("h{i}.example"))).await.unwrap();
        }
        drop(tx);
        handle.await.unwrap();
    }

    fn exported_files(dir: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                // `.part` stages are not published segments.
                !p.file_name()
                    .map(|n| n.to_string_lossy().starts_with('.'))
                    .unwrap_or(false)
            })
            .collect();
        out.sort();
        out
    }

    /// The seam itself: a rotated segment leaves the ring, whole, before the
    /// ring can discard it. What happens beyond the directory is the
    /// collector's contract; getting it out and saying so is this sink's.
    #[tokio::test]
    async fn a_rotated_segment_is_exported_out_of_the_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let out = tmp.path().join("spool");

        let before = export_failures();
        drain_with_export(&path, tiny(), ExportTarget::Directory(out.clone()), 200).await;

        let exported = exported_files(&out);
        assert!(
            !exported.is_empty(),
            "nothing left the ring, so the export seam does not exist"
        );
        assert_eq!(export_failures(), before, "a clean export reported a failure");

        // Every exported byte is a parseable record: the handoff copies whole
        // lines, not a truncated tail.
        let mut lines = 0usize;
        for file in &exported {
            let body = tokio::fs::read_to_string(file).await.unwrap();
            assert!(!body.is_empty(), "{} is empty", file.display());
            for line in body.lines() {
                serde_json::from_str::<ProxyAuditEntry>(line)
                    .unwrap_or_else(|e| panic!("exported line does not parse: {e}: {line}"));
                lines += 1;
            }
        }
        assert!(lines > 0);

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(published.export, ExportStatus::Directory);
        assert_eq!(published.export_failures, 0);
        assert_eq!(published.pending_exports, 0);
    }

    /// An exported segment carries the same per-agent behavioural trail as the
    /// sink, so it gets the same mode — and the directory holding it is not
    /// world-traversable either.
    #[tokio::test]
    async fn an_exported_segment_is_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let out = tmp.path().join("spool");
        drain_with_export(&path, tiny(), ExportTarget::Directory(out.clone()), 200).await;

        let dir_mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "export directory mode was {dir_mode:o}");
        for file in exported_files(&out) {
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "exported segment {} mode was {mode:o}", file.display());
        }
    }

    /// A silently-failing exporter is worse than none: it converts a
    /// known-lossy local ring into an assumed-complete remote record. The
    /// failure is therefore counted, published, and left outstanding as
    /// `pending_exports` rather than reported as delivered.
    #[tokio::test]
    async fn an_export_that_cannot_be_written_is_counted_never_assumed_delivered() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let out = tmp.path().join("spool");

        let (tx, rx) = mpsc::channel(8);
        let writer = JsonlWriter::with_retention(&path, rx, tiny(), ExportTarget::Directory(out.clone()))
            .await
            .unwrap();
        // The directory exists and is writable at open, then becomes
        // unwritable — a real `EACCES` from the real filesystem at the same
        // call an exhausted or read-only volume would fail at.
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o500)).unwrap();

        let before = export_failures();
        let handle = tokio::spawn(writer.run());
        for i in 0..200 {
            tx.send(entry(&format!("h{i}.example"))).await.unwrap();
        }
        drop(tx);
        handle.await.unwrap();

        let failures = export_failures() - before;
        assert!(failures > 0, "an export that could not be written reported success");
        assert!(
            exported_files(&out).is_empty(),
            "the fixture did not actually block the export, so it proves nothing"
        );

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(
            published.export_failures, failures,
            "the export failure never reached the file a consumer reads: {published:?}"
        );
        assert!(
            published.pending_exports > 0,
            "a segment nobody accepted must stay outstanding: {published:?}"
        );

        // Leave the directory writable so the tempdir can be cleaned up.
        std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// At-least-once without a persisted cursor: every segment still in the
    /// ring is re-offered on every rotation and every sweep, and the target
    /// name is derived from the segment's own content, so a second process
    /// re-exporting what the first already delivered is a no-op rather than a
    /// duplicate.
    #[tokio::test]
    async fn export_is_idempotent_and_retried_after_a_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let out = tmp.path().join("spool");

        // Run 1 exports nothing: no target is configured at all.
        drain(&path, tiny(), 200).await;
        assert!(
            tokio::fs::metadata(segment_path(&path, 1)).await.is_ok(),
            "the fixture must leave segments in the ring for run 2 to retry"
        );

        // Run 2 configures the directory and must pick up what run 1 left.
        drain_with_export(&path, tiny(), ExportTarget::Directory(out.clone()), 1).await;
        let after_second = exported_files(&out);
        assert!(
            !after_second.is_empty(),
            "a restart did not retry the segments already sitting in the ring"
        );

        // Run 3 re-offers the very same segments and must not duplicate them.
        drain_with_export(&path, tiny(), ExportTarget::Directory(out.clone()), 1).await;
        let after_third = exported_files(&out);
        let carried_over: Vec<_> = after_third
            .iter()
            .filter(|p| after_second.contains(p))
            .cloned()
            .collect();
        assert_eq!(
            carried_over.len(),
            after_second.len(),
            "an already-exported segment was renamed or re-copied under a new name"
        );
    }

    /// The open-source default is a **stated position**, not an absent
    /// setting. "No exporter configured" and "retention is fine" are different
    /// facts, and the sidecar has to say which one this is.
    #[tokio::test]
    async fn the_default_states_that_the_ring_is_the_only_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        drain(&path, RotationPolicy::default(), 3).await;

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(
            published.export,
            ExportStatus::LocalRingOnly,
            "the default must name itself rather than leave the field out"
        );
        // And it is spelled on the wire, so a non-Rust consumer sees it too.
        let raw = tokio::fs::read_to_string(completeness_path(&path)).await.unwrap();
        assert!(
            raw.contains("\"local_ring_only\""),
            "the on-disk snapshot never says where the evidence lives: {raw}"
        );
        // Non-vacuity: the two states really are distinguishable on the wire.
        assert!(!raw.contains("\"directory\""));
    }

    /// An operator who configured a handoff and silently got none would believe
    /// the evidence outlives the host when it does not.
    #[tokio::test]
    async fn an_unusable_export_directory_is_an_error_not_a_silent_downgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        // A regular file where the export directory should be.
        let blocked = tmp.path().join("spool");
        std::fs::write(&blocked, b"not a directory").unwrap();

        let (_tx, rx) = mpsc::channel(1);
        match JsonlWriter::with_retention(&path, rx, tiny(), ExportTarget::Directory(blocked)).await {
            Ok(_) => panic!("a configured-but-unusable export directory must not degrade to no export"),
            Err(e) => assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory | io::ErrorKind::Other
                ),
                "unexpected error kind {:?}",
                e.kind()
            ),
        }
    }

    // ── completeness ───────────────────────────────────────────────────────

    fn dropped_record(host: &str) -> DecisionRecord {
        DecisionRecord {
            host: host.into(),
            method: "POST".into(),
            path: "/v1/do".into(),
            decision: ProxyAuditDecision::Blocked,
            refusal_rule: Some(RefusalRule::EgressDenylist),
            findings: Vec::new(),
            redacted_body: None,
            probe_correlation: None,
        }
    }

    /// AC4: the counter existed but nothing outside this crate could read it,
    /// so a consumer reading the JSONL had no way to tell a complete window
    /// from a lossy one. It is published beside the file the consumer already
    /// opens.
    #[tokio::test]
    async fn a_lossy_window_is_published_beside_the_sink() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        let (tx, rx) = mpsc::channel(1);
        let writer = JsonlWriter::new(&path, rx).await.unwrap();

        // The writer is not draining yet, so the channel fills and the
        // production path's own `try_send` drops — a real drop, not a call to
        // the counter.
        let before = dropped_entries();
        for host in ["a.example", "b.example", "c.example"] {
            dropped_record(host).send(Some(&tx), ExecutionEvidence::unrecorded(EnforcementMode::Enforce));
        }
        let dropped_now = dropped_entries() - before;
        assert_eq!(dropped_now, 2, "capacity 1 must swallow one and drop two");

        let handle = tokio::spawn(writer.run());
        drop(tx);
        handle.await.unwrap();

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(
            published.dropped_entries, dropped_now,
            "the published loss must match what actually happened: {published:?}"
        );
        assert!(published.updated_ms > 0);
    }

    /// The positive control: a run that lost nothing must publish zero, or
    /// "loss was reported" would be true of every window.
    #[tokio::test]
    async fn a_complete_window_publishes_no_loss() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        drain(&path, RotationPolicy::default(), 3).await;

        let published = read_completeness(&path).await.expect("the sidecar must exist");
        assert_eq!(published.dropped_entries, 0);
        assert_eq!(published.discarded_segments, 0);
        // Non-vacuity: the run really did write the lines it was given.
        let on_disk = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(on_disk.lines().count(), 3);
    }

    /// The JSONL survives a restart, so the completeness that describes it has
    /// to as well: a per-process counter would report a clean window over a
    /// file whose earlier half is missing lines.
    #[tokio::test]
    async fn published_loss_carries_across_a_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");

        // Run 1: force one drop.
        {
            let (tx, rx) = mpsc::channel(1);
            let writer = JsonlWriter::new(&path, rx).await.unwrap();
            let before = dropped_entries();
            dropped_record("a.example").send(Some(&tx), ExecutionEvidence::unrecorded(EnforcementMode::Enforce));
            dropped_record("b.example").send(Some(&tx), ExecutionEvidence::unrecorded(EnforcementMode::Enforce));
            assert_eq!(dropped_entries() - before, 1, "fixture must produce exactly one drop");
            let handle = tokio::spawn(writer.run());
            drop(tx);
            handle.await.unwrap();
        }
        assert_eq!(read_completeness(&path).await.unwrap().dropped_entries, 1);

        // Run 2: loses nothing, and must not erase run 1's loss.
        drain(&path, RotationPolicy::default(), 2).await;
        assert_eq!(
            read_completeness(&path).await.unwrap().dropped_entries,
            1,
            "a clean restart erased the earlier window's loss"
        );
    }

    /// The sidecar describes the same behavioural trail as the sink, and is
    /// written by the same writer, so it gets the same mode.
    #[tokio::test]
    async fn the_completeness_file_is_not_world_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        drain(&path, RotationPolicy::default(), 1).await;

        let mode = tokio::fs::metadata(completeness_path(&path))
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "completeness file mode was {mode:o}");
    }
}
