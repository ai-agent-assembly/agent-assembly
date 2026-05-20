//! Storage backend for [`AlertRule`] records (AAASM-1386).
//!
//! Today the only implementation is the in-memory
//! [`InMemoryAlertRuleStore`] — a persisted store (e.g. SQLite) is
//! deferred per the Story's acceptance criteria.
