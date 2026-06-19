# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for `agent-assembly`. Each ADR documents a significant architectural choice — the context that drove the decision, the alternatives considered, and the consequences accepted.

The format follows a lightweight variant of [Michael Nygard's template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions). New ADRs are numbered sequentially and never rewritten; superseded decisions are recorded by adding a new ADR that links back.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-storage-architecture.md) | Storage Architecture — SQLite (local) / PostgreSQL + TimescaleDB (production) | Accepted |
| [0002](0002-sdk-security-boundary.md) | SDK Security Boundary, Shared-Crate Layout & Distribution | Accepted |
| [0003](0003-cross-repo-dependency-pinning.md) | Cross-Repo Dependency Pinning on the Core Crates | Accepted |
| [0004](0004-governance-enforcement-flow.md) | Governance Enforcement Flow — SDK → `aa-sdk-client` → core (gRPC / UDS) | Accepted |
| [0005](0005-sdk-only-gateway-access.md) | SDK-Client-Only Gateway Access — Two-Plane Mutual Auth + Dashboard Control-Plane | Accepted |
