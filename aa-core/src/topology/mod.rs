//! Agent-graph mesh topology types and repository trait (AAASM-985).

pub mod edge;

pub use edge::EdgeType;

#[cfg(feature = "alloc")]
pub use edge::UnknownEdgeType;
