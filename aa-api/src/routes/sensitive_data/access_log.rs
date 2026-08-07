//! The access log the compliance export writes before it returns anything.
//!
//! # Why the export is gated on the log succeeding
//!
//! ADR 0032 §9 confines raw values to the tamper-evident tier and makes reads of
//! the sensitive-data tier an audited act. The compliance export is the widest
//! read on that tier — a whole window of one tenant's governance record, in a
//! form intended to leave the system — so "who exported what, when" has to
//! exist *before* the bytes do. The handler therefore records first and
//! serialises second, and a record that cannot be written is a 503 rather than
//! an unlogged export: an export nobody can attribute is the failure this log
//! exists to prevent.
//!
//! # What is deliberately not in a record
//!
//! No finding values, no field paths, no event ids — only the caller, the scope
//! and the shape of what was taken. The log is read by people investigating an
//! export; making it a second copy of the exported data would widen the
//! exposure it is meant to make accountable.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// One recorded compliance-export access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ExportAccessRecord {
    /// When the export was authorised, RFC 3339.
    pub at: String,
    /// The authenticated caller's key id or JWT subject. Never a credential.
    pub principal: String,
    /// The organisation whose records were exported.
    pub org_id: String,
    /// The tenant within it.
    pub tenant_id: String,
    /// Inclusive lower bound of the exported window, epoch nanoseconds.
    pub from_ns: u64,
    /// Exclusive upper bound, epoch nanoseconds.
    pub to_ns: u64,
    /// How many event rows were released.
    pub event_count: u64,
    /// How many finding rows were released.
    pub finding_count: u64,
}

/// Somewhere a compliance export can be recorded.
///
/// A trait so a deployment can point it at a durable sink without the handler
/// changing; the in-memory implementation is what the local single-process
/// wiring gets, and it is enough to make the obligation testable and to make an
/// unrecorded export impossible in that wiring.
pub trait ExportAccessLog: Send + Sync {
    /// Record one export. `Err` means nothing was recorded, and the caller must
    /// not release the data.
    ///
    /// # Errors
    ///
    /// Implementation-defined; the handler treats any error as "do not export".
    fn record(&self, record: ExportAccessRecord) -> Result<(), String>;

    /// Every record so far, oldest first.
    fn records(&self) -> Vec<ExportAccessRecord>;
}

/// Process-local export access log.
#[derive(Debug, Default)]
pub struct InMemoryExportAccessLog {
    records: RwLock<Vec<ExportAccessRecord>>,
}

impl InMemoryExportAccessLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ExportAccessLog for InMemoryExportAccessLog {
    fn record(&self, record: ExportAccessRecord) -> Result<(), String> {
        // A poisoned lock is reported rather than recovered: the log's contents
        // are no longer trustworthy, and the handler's contract is that an
        // unrecordable export does not happen.
        let mut guard = self
            .records
            .write()
            .map_err(|_| "export access log is poisoned".to_string())?;
        guard.push(record);
        Ok(())
    }

    fn records(&self) -> Vec<ExportAccessRecord> {
        self.records.read().map(|g| g.clone()).unwrap_or_default()
    }
}
