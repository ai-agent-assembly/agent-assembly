//! Dev tool registry, discovery and orchestration for Agent Assembly.
//!
//! This crate is the layer *above* the per-tool `aa-devtool-*` adapter crates:
//! it decides which adapter backs each supported tool ([`registry`]) and runs
//! them ([`discovery`]). It deliberately contains no adapter implementations of
//! its own — see [`registry`] for why (AAASM-5274).
pub mod adapters;
pub mod capability_bridge;
pub mod discovery;
pub mod registry;

pub use discovery::DiscoveryService;
