//! Policy YAML parser and validator for aa-gateway.
//!
//! Entry point: [`validator::PolicyValidator::from_yaml`].

pub mod document;
pub mod error;
pub(crate) mod expr;
pub mod history;
pub mod raw;
pub mod rbac;
pub mod scope;
pub mod validator;

pub use document::{ActiveHours, BudgetPolicy, DataPolicy, NetworkPolicy, PolicyDocument, SchedulePolicy, ToolPolicy};
pub use error::{PolicyParseError, ValidationError, ValidationWarning};
pub use rbac::{CallerRole, MutationKind, PolicyScopeKind, required_role_for};
pub use scope::{OrgId, PolicyScope, TeamId};
pub use validator::{PolicyValidator, PolicyValidatorOutput};
