//! Domain types and trait for the agent-graph mesh edge model (AAASM-985).

/// The six relationship kinds that can exist between agents in the topology graph.
///
/// Serialises to / deserialises from the snake_case wire string
/// (e.g. `"delegates_to"`, `"calls"`) when the `serde` feature is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EdgeType {
    /// Agent A has granted authority to Agent B to act on its behalf.
    DelegatesTo,
    /// Agent A invokes Agent B as a sub-agent or tool.
    Calls,
    /// Agent A reads data owned or produced by Agent B.
    Reads,
    /// Agent A writes data that Agent B owns or consumes.
    Writes,
    /// Agent A approves an action or output of Agent B.
    Approves,
    /// Agent A sends a message to Agent B.
    Messages,
}

impl EdgeType {
    /// Returns the canonical snake_case wire string for this edge type.
    pub fn as_str(&self) -> &'static str {
        match self {
            EdgeType::DelegatesTo => "delegates_to",
            EdgeType::Calls => "calls",
            EdgeType::Reads => "reads",
            EdgeType::Writes => "writes",
            EdgeType::Approves => "approves",
            EdgeType::Messages => "messages",
        }
    }

    /// All six valid edge type variants in declaration order.
    pub const ALL: &'static [EdgeType] = &[
        EdgeType::DelegatesTo,
        EdgeType::Calls,
        EdgeType::Reads,
        EdgeType::Writes,
        EdgeType::Approves,
        EdgeType::Messages,
    ];
}

impl core::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a string cannot be parsed into an [`EdgeType`].
#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct UnknownEdgeType(pub alloc::string::String);

#[cfg(feature = "alloc")]
impl core::fmt::Display for UnknownEdgeType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown edge type: {:?}", self.0)
    }
}

#[cfg(feature = "alloc")]
impl core::convert::TryFrom<&str> for EdgeType {
    type Error = UnknownEdgeType;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "delegates_to" => Ok(EdgeType::DelegatesTo),
            "calls" => Ok(EdgeType::Calls),
            "reads" => Ok(EdgeType::Reads),
            "writes" => Ok(EdgeType::Writes),
            "approves" => Ok(EdgeType::Approves),
            "messages" => Ok(EdgeType::Messages),
            other => Err(UnknownEdgeType(alloc::string::String::from(other))),
        }
    }
}
