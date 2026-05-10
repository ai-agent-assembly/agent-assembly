//! Agent-graph mesh topology types and repository trait (AAASM-985).

pub mod cycle;
pub mod edge;

pub use edge::EdgeType;

#[cfg(feature = "alloc")]
pub use edge::UnknownEdgeType;

#[cfg(feature = "std")]
pub use edge::{Edge, EdgeRepo, EdgeRepoError, NewEdge};

#[cfg(feature = "std")]
pub use cycle::cycle_detect;

#[cfg(all(feature = "std", feature = "test-utils"))]
pub use edge::MockEdgeRepo;
