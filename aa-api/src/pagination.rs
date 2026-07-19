//! Reusable pagination types for list endpoints.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Default page number when not specified.
const DEFAULT_PAGE: u32 = 1;

/// Default items per page when not specified.
const DEFAULT_PER_PAGE: u32 = 50;

/// Maximum allowed items per page.
const MAX_PER_PAGE: u32 = 100;

/// Query parameters for paginated list endpoints.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct PaginationParams {
    /// Page number (1-indexed). Defaults to 1.
    #[param(minimum = 1)]
    pub page: Option<u32>,
    /// Items per page (max 100). Defaults to 50.
    #[param(minimum = 1, maximum = 100)]
    pub per_page: Option<u32>,
}

impl PaginationParams {
    /// Resolved page number (clamped to >= 1).
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(DEFAULT_PAGE).max(1)
    }

    /// Resolved items per page (clamped to 1..=100).
    pub fn per_page(&self) -> u32 {
        self.per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE)
    }

    /// Compute the zero-based offset for slicing.
    pub fn offset(&self) -> usize {
        ((self.page() - 1) * self.per_page()) as usize
    }
}

/// Wrapper for paginated list responses.
///
/// The generated OpenAPI schema must match this `{ items, page, per_page, total }`
/// shape — deriving `ToSchema` here (rather than annotating handlers `body =
/// Vec<T>`) is what keeps the spec honest for consumers that would otherwise
/// `.map` over a non-array body (AAASM-4892).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedResponse<T: Serialize + ToSchema> {
    /// Items in the current page.
    pub items: Vec<T>,
    /// Current page number.
    pub page: u32,
    /// Items per page.
    pub per_page: u32,
    /// Total number of items across all pages.
    pub total: u64,
}
