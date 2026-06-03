//! Storage trait abstraction for the Agent Assembly persistence layer.
//!
//! This crate is a **pure interface**: it defines the narrow storage traits that
//! every persistence backend implements, and it carries no concrete backend
//! dependency (no `sqlx`, no `redis`, no `tonic`). Its only dependencies are
//! `async-trait`, `thiserror`, and the shared domain types re-exported from
//! `aa-core`.
//!
//! The OSS Postgres/Redis/memory drivers and the Enterprise gateway driver all
//! implement the same contract, so swapping the persistence backend never
//! changes any caller code.

#![warn(missing_docs)]
