//! Budget tracking engine for `aa-gateway`.
//!
//! Entry point: [`tracker::BudgetTracker::record_usage`].

pub mod types;
pub use types::{BudgetAlert, BudgetState, BudgetStatus, Model, Provider};

pub mod pricing;
pub use pricing::{PricingEntry, PricingLoadError, PricingTable};

pub mod persistence;
pub use persistence::{
    default_budget_path, load_from_disk, save_to_disk_atomic, start_background_writer, PersistedAgentEntry,
    PersistedBudget, PersistenceError,
};

pub mod tracker;
pub use tracker::BudgetTracker;

pub mod rollup;
pub use rollup::{compute_budget_rollup, BudgetRollup, BudgetRow};
