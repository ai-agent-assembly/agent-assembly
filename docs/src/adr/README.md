# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for `agent-assembly`. Each ADR documents a significant architectural choice — the context that drove the decision, the alternatives considered, and the consequences accepted.

The format follows a lightweight variant of [Michael Nygard's template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions). New ADRs are numbered sequentially and never rewritten; superseded decisions are recorded by adding a new ADR that links back.

An ADR records **only** durable product or system decisions — product and business semantics, user-visible behaviour, security and enforcement semantics, public API and data contracts, OSS-vs-SaaS boundaries, durable architecture and component boundaries, and long-term direction that constrains future implementations. Development-process instructions are **not** ADR material: CI, review, release and test-execution procedure, merge and branch policy, and contributor workflow conventions belong in [`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CONTRIBUTING.md), `.claude/`, a runbook, a PR template, or a CI workflow. Being technical is not the test — the test is whether the primary subject is a *decision* or a *procedure*.

**Numbers are permanent identifiers.** A number, once used, is never reassigned — so the gaps below are deliberate and must stay empty: **0005** never existed, and **0028** is retired (its CI trigger-scoping rule moved to `CONTRIBUTING.md` as development process). There are **27** active ADRs.

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
| [0011](0011-cross-process-op-control-nats-subject.md) | Cross-Process Op-Control Delivery via a NATS Subject (durable JetStream) | Accepted |
| [0012](0012-websocket-and-browser-credential-handling.md) | WebSocket & Browser Credential Handling (OSS vs SaaS) | Accepted |
| [0013](0013-version-metadata-source-of-truth-and-drift-gate.md) | Version Metadata Source-of-Truth & Drift Gate | Proposed |
| [0014](0014-canonical-metadata-registry-and-drift-gate.md) | Canonical Metadata Registry & Drift Gate | Proposed |
| [0015](0015-dlp-trust-boundary-and-redaction-semantics.md) | DLP Trust Boundary, Redaction Fail-Safety & Heuristic Detection Limits | Accepted |
| [0016](0016-default-branch-master-to-main-migration.md) | Organization-wide Default Branch — `master` → `main` | Accepted |
| [0017](0017-dashboard-design-parity-ratified-evolutions.md) | Dashboard Design-Parity — Ratified Evolutions | Accepted |
| [0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) | Canonical Runtime Verdict & Enriched Decision Record | Accepted |
| [0019](0019-agent-trust-score-derivation.md) | Agent Trust-Score Derivation | Accepted |
| [0020](0020-rolling-monthly-budget-window.md) | Rolling vs Calendar Monthly Budget Windows — and the Missing Team Tier | Proposed |
| [0021](0021-topology-enforcement-mode-mutation-safety.md) | Topology Enforcement-Mode Mutation — Authorization, Blast Radius & Reversibility | Proposed |
| [0022](0022-agent-config-projection-and-quantified-recommendations.md) | Agent-Detail Config Projection & Quantified Posture Recommendations | Proposed |
| [0023](0023-aa-api-policy-cascade-wiring.md) | Is `aa-api` Meant to Carry a Policy Cascade? | Accepted |
| [0024](0024-empty-cascade-semantics.md) | Semantics of an Empty or Unavailable Policy Cascade | Accepted |
| [0025](0025-design-v2-authoritative-visual-spec.md) | `design/v2/` Is the Authoritative Visual Specification | Proposed |
| [0026](0026-open-dashboard-product-semantics.md) | Seven Open Dashboard Product-Semantics Decisions | Proposed (Decision 2 Accepted) |
| [0027](0027-accessibility-floor-overrides-visual-spec.md) | The Accessibility Floor Overrides the Visual Specification | Accepted |
| [0029](0029-capability-over-permission-derivation.md) | Capability Over-Permission Derivation | Proposed |
| [0030](0030-developer-integration-boundaries-and-trust-model.md) | Developer Integration Boundaries, Capability Model & Local Trust Model | Proposed |
| [0031](0031-oss-native-account-authentication.md) | OSS Native Account Authentication | Accepted |
