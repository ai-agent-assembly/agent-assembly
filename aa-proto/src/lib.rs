//! Generated protobuf and gRPC types for Agent Assembly.
//!
//! This crate is the single code-generation entrypoint for all proto definitions
//! in `proto/`. Other crates (`aa-runtime`, `aa-gateway`, …) declare this crate
//! as a dependency — they never run their own prost/tonic codegen.
//!
//! # Module layout
//!
//! The generated modules mirror the proto package hierarchy:
//!
//! ```text
//! assembly::common::v1   — shared types (AgentId, Decision, RiskTier, …)
//! assembly::agent::v1    — lifecycle + ControlStream (paths ① ④)
//! assembly::policy::v1   — policy check hot path (path ②)
//! assembly::audit::v1    — async audit trail (path ③)
//! assembly::event::v1    — internal event bus envelope (paths ⑤ ⑥)
//! assembly::approval::v1 — human-in-the-loop approval queue
//! assembly::topology::v1 — agent tree, lineage, and team-member queries
//! assembly::gateway::v1  — L1 cache push-invalidation channel
//! assembly::ipc::v1      — local SDK ↔ runtime UDS handshake (AAASM-3569)
//! assembly::devint::v1   — local Developer Integration API (AAASM-5279)
//! ```

pub mod assembly {
    pub mod common {
        pub mod v1 {
            tonic::include_proto!("assembly.common.v1");
        }
    }

    pub mod agent {
        pub mod v1 {
            tonic::include_proto!("assembly.agent.v1");
        }
    }

    pub mod policy {
        pub mod v1 {
            tonic::include_proto!("assembly.policy.v1");
        }
    }

    pub mod audit {
        pub mod v1 {
            tonic::include_proto!("assembly.audit.v1");
        }
    }

    pub mod event {
        pub mod v1 {
            // AuditEvent grew with AAASM-934 lineage fields; the Payload oneof
            // variant size disparity is expected in generated code.
            #![allow(clippy::large_enum_variant)]
            tonic::include_proto!("assembly.event.v1");
        }
    }

    pub mod approval {
        pub mod v1 {
            tonic::include_proto!("assembly.approval.v1");
        }
    }

    pub mod topology {
        pub mod v1 {
            tonic::include_proto!("assembly.topology.v1");
        }
    }

    pub mod secrets {
        pub mod v1 {
            tonic::include_proto!("assembly.secrets.v1");
        }
    }

    pub mod gateway {
        pub mod v1 {
            tonic::include_proto!("assembly.gateway.v1");
        }
    }

    pub mod ipc {
        // Local SDK ↔ runtime UDS handshake messages (AAASM-3569). Carried as
        // prost payloads behind the hand-rolled IPC codec's wire tags, not gRPC.
        pub mod v1 {
            tonic::include_proto!("assembly.ipc.v1");
        }
    }

    pub mod devint {
        // Developer Integration API wire schema (ADR 0030 Decision 5,
        // AAASM-5279). Served on its own UDS (`~/.aa/run/devint.sock`) behind
        // the same length-delimited IPC codec — deliberately not a gRPC service
        // and deliberately not the SDK fast-path socket, so agent-action and
        // policy-decision traffic is unreachable from a DI client by
        // construction.
        pub mod v1 {
            tonic::include_proto!("assembly.devint.v1");
        }
    }
}
