//! `GET /api/v1/admin/status` — gateway admin status with storage health.
//!
//! Sibling of [`super::healthz`] that returns the deeper readiness signal:
//! backend type, database connection health and latency, hot-tier row
//! counts, and an optional TimescaleDB chunk + compression rollup. The
//! `aasm status` CLI consumes this endpoint to render the operator-facing
//! storage section delivered by AAASM-1591 / Epic 18 S-J.
//!
//! Unlike `/healthz`, this handler performs a backend round-trip per call
//! and is **not** intended for high-frequency load-balancer probes; mount
//! it behind admin-only access (Epic 17 S-G IAM gating, to land).
