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
| [0006](0006-limited-self-host-k8s-terraform.md) | Limited-Function Self-Host — Kubernetes (Helm) / Terraform Support | Accepted |
| [0007](0007-public-domain-and-url-contract.md) | Public Domain & URL Contract | Proposed |
| [0008](0008-saas-host-routing-auth-cookie-boundaries.md) | SaaS Host Routing, Auth & Cookie Boundaries | Proposed |
| [0009](0009-versioned-base-image-tags-and-sdk-pinning.md) | Versioned Base-Image Tags & Reproducible SDK Pinning | Proposed |
| [0010](0010-gateway-distribution-self-host-examples.md) | Gateway Distribution for Self-Host & Examples | Proposed |
