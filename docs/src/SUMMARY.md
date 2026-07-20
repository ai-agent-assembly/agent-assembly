# Summary

[agent-assembly](README.md)

# Introduction

- [Introduction](introduction/README.md)
  - [What it is & the problem](introduction/overview.md)
  - [Core concepts](introduction/concepts.md)
  - [The three-layer model](introduction/three-layer-model.md)

# Quick Start

- [Requirements](quick-start/requirements.md)
- [Installation](quick-start/installation.md)
- [Configuration](quick-start/configuration.md)
- [First run](quick-start/first-run.md)

# CLI Reference

- [Overview](cli/overview.md)
- [aasm status](cli/status.md)
- [aasm agent](cli/agent.md)
- [aasm policy](cli/policy.md)
- [aasm topology](cli/topology.md)
- [aasm alerts](cli/alerts.md)
- [aasm approvals](cli/approvals.md)
- [aasm audit](cli/audit.md)
- [aasm logs](cli/logs.md)
- [aasm trace](cli/trace.md)
- [aasm cost](cli/cost.md)
- [aasm dashboard](cli/dashboard.md)
- [aasm gateway](cli/gateway.md)
- [aasm proxy](cli/proxy.md)
- [aasm start / stop](cli/start-stop.md)
- [aasm sandbox](cli/sandbox.md)
- [aasm config](cli/config.md)
- [aasm context](cli/context.md)
- [aasm admin](cli/admin.md)
- [aasm uninstall](cli/uninstall.md)
- [aasm version](cli/version.md)
- [aasm completion](cli/completion.md)

# Usage Guide

- [Usage Guide](usage-guide/overview.md)
  - [Govern an agent end-to-end](usage-guide/govern-an-agent.md)
  - [Enforce an egress policy](usage-guide/enforce-egress-policy.md)
  - [Team budgets and cost](usage-guide/team-budgets.md)
  - [Observe in the dashboard](usage-guide/observe-in-dashboard.md)
  - [Choosing interception layers](usage-guide/interception-layers.md)
  - [Self-hosting (open source)](usage-guide/self-hosting.md)
  - [Container base images](usage-guide/container-base-images.md)
  - [Runnable examples](usage-guide/examples.md)
  - [Troubleshooting](usage-guide/troubleshooting.md)

# Security Model

- [Overview](security/overview.md)
- [Threat model](security/threat-model.md)
- [Release threat model](security/release-threat-model.md)
- [Three-layer defense in depth](security/three-layer-defense.md)
- [Protection and enforcement](security/protection-model.md)
- [Trust boundaries](security/trust-boundaries.md)
- [Trust-boundary review checklist](security/trust-boundary-review-checklist.md)
- [Audit and assurance](security/audit-assurance.md)

# Architecture

- [Architecture](architecture/README.md)
  - [Infrastructure overview](architecture/infra-overview.md)
  - [System architecture](architecture/system-architecture.md)
  - [Component deep-dives](architecture/components.md)
  - [Key workflows](architecture/workflows.md)
  - [Data flows](architecture/data-flows.md)
  - [Building & contributing](architecture/building.md)

---

# Reference

- [API Reference](api-reference.md)
- [Framework Compatibility](reference/framework-compatibility.md)

# Project Status

- [Compatibility Matrix](compatibility.md)
- [Versioning Policy](versioning.md)

# Governance

- [Policy YAML Reference](policy-reference.md)
- [L0-L3 Capability Matrix](governance/capability-matrix.md)
- [Policy RBAC Role Matrix](policy-rbac.md)

# Protocol

- [Changelog](protocol/CHANGELOG.md)

# Migration

- [Migration Template](migration/template.md)

# Events

- [Cross-Team Edge](events/cross_team_edge.md)

# Operations

- [In-Flight Ops Registry](operations/ops-registry-architecture.md)
- [Sandbox / Dry-Run Mode](operations/sandbox-dry-run.md)
- [Compliance Export](operations/compliance-export.md)
- [Agent-to-Agent Identity](operations/a2a-identity.md)
- [Tool Sandbox: Network Egress](operations/tool-sandbox-network.md)
- [Org-Tier Isolation](operations/org-isolation.md)
- [Multi-Document Policy Cascade](operations/policy-cascade-loader.md)

# Releases

- [Releases](releases.md)

# Benchmarks

- [Baseline](benchmarks/BASELINE.md)
- [Build-Time Baseline](benchmarks/build-time-baseline.md)
- [Policy Check p99](benchmarks/policy-check-p99.md)
- [CI/CD Pipeline Performance](benchmarks/ci-cd-pipeline-performance.md)

# Development

- [Local Development](development/local-development.md)
- [Consuming the Shared Crates](development/consuming-shared-crates.md)
- [Shared Docs Metadata](development/shared-docs-metadata.md)

# Architecture Decision Records

- [Index](adr/README.md)
  - [0001 - Storage Architecture](adr/0001-storage-architecture.md)
  - [0002 - SDK Security Boundary](adr/0002-sdk-security-boundary.md)
  - [0003 - Cross-Repo Dependency Pinning](adr/0003-cross-repo-dependency-pinning.md)
  - [0004 - Governance Enforcement Flow](adr/0004-governance-enforcement-flow.md)
  - [0006 - Limited-Function Self-Host K8s/Terraform](adr/0006-limited-self-host-k8s-terraform.md)
  - [0007 - Public Domain & URL Contract](adr/0007-public-domain-and-url-contract.md)
  - [0008 - SaaS Host Routing, Auth & Cookie Boundaries](adr/0008-saas-host-routing-auth-cookie-boundaries.md)
  - [0009 - Versioned Base-Image Tags & SDK Pinning](adr/0009-versioned-base-image-tags-and-sdk-pinning.md)
  - [0010 - Gateway Distribution for Self-Host & Examples](adr/0010-gateway-distribution-self-host-examples.md)
  - [0011 - Cross-Process Op-Control via NATS Subject (durable JetStream)](adr/0011-cross-process-op-control-nats-subject.md)
  - [0012 - WebSocket & Browser Credential Handling](adr/0012-websocket-and-browser-credential-handling.md)
  - [0013 - Version Metadata Source-of-Truth & Drift Gate](adr/0013-version-metadata-source-of-truth-and-drift-gate.md)
