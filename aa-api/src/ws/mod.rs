//! WebSocket event streaming endpoint.

pub mod alerts_handler;
pub mod alerts_params;
pub mod auth;
pub mod handler;
pub mod params;
pub mod tenant;
pub mod ticket;

pub use alerts_handler::ws_alerts_handler;
pub use alerts_params::{AlertEventKind, AlertsFilter, AlertsWsQueryParams, FilterError, WireSeverity};
pub use auth::{resolve_ws_caller, WsHeaderCaller};
pub use handler::ws_events_handler;
pub use params::WsQueryParams;
pub use ticket::{WsTicket, WsTicketPurpose, WsTicketStore};
