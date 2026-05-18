#![allow(unused_imports)]
//! AAASM-1497 / F122 ST-P — live-gateway integration tests for `GET /api/v1/ws/events`.
//!
//! ## Endpoint under test
//!
//! `GET /api/v1/ws/events` — WebSocket upgrade endpoint that streams `GovernanceEvent`
//! JSON text frames from the gateway's `EventBroadcast` channel. Supports replay
//! via `?since=<id>` and type filtering via `?types=<csv>`.
//!
//! ## Divergences from the ticket AC
//!
//! | Ticket expectation | Actual behaviour |
//! |---|---|
//! | Filter param `event_types=` | Actual param is `types=` (from `WsQueryParams`) |
//! | `?types=garbage` → 400 | 101 upgrade + silent empty stream; `EventType::parse_filter` drops unknowns |
//! | `AuthMode::ApiKey` variant | Auth mode is `AuthMode::On`; `start_with_auth` already exists |
//! | Replay buffer capacity unspecified | Confirmed 1000 events (circular, oldest dropped) |

mod common;

use std::time::Duration;

use aa_api::models::{EventType, GovernanceEvent};
use aa_core::{AgentId, PolicyResult};
use aa_gateway::budget::types::BudgetAlert;
use aa_runtime::approval::ApprovalRequest;
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource, PipelineEvent};
use chrono::Utc;
use common::TopologyTestEnv;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;
