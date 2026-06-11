# Summary

[agent-assembly](README.md)

# Introduction

- [Introduction](introduction/README.md)
  - [What it is & the problem](introduction/overview.md)
  - [Core concepts](introduction/concepts.md)
  - [The three-layer model](introduction/three-layer-model.md)

# Quick Start

- [Quick Start](quickstart/README.md)
  - [Requirements](quickstart/requirements.md)
  - [Installation](quickstart/installation.md)
  - [Configuration](quickstart/configuration.md)
  - [First run](quickstart/first-run.md)

# CLI Reference

- [Overview](cli-reference/README.md)
  - [aasm status](cli-reference/status.md)
  - [aasm topology](cli-reference/topology.md)
  - [aasm agent](cli-reference/agent.md)
  - [aasm policy](cli-reference/policy.md)
  - [aasm alerts](cli-reference/alerts.md)
  - [aasm approvals](cli-reference/approvals.md)
  - [aasm audit](cli-reference/audit.md)
  - [aasm logs](cli-reference/logs.md)
  - [aasm trace](cli-reference/trace.md)
  - [aasm cost](cli-reference/cost.md)
  - [aasm dashboard](cli-reference/dashboard.md)
  - [aasm gateway](cli-reference/gateway.md)
  - [aasm start / stop](cli-reference/start-stop.md)
  - [aasm sandbox](cli-reference/sandbox.md)
  - [aasm config](cli-reference/config.md)
  - [aasm context](cli-reference/context.md)
  - [aasm admin](cli-reference/admin.md)
  - [aasm completion](cli-reference/completion.md)
  - [aasm version](cli-reference/version.md)

# Usage Guide

- [Usage Guide](usage/README.md)
  - [Govern an agent end-to-end](usage/govern-an-agent.md)
  - [Author and apply a policy](usage/author-policy.md)
  - [Set budgets and monitor cost](usage/budgets-and-cost.md)
  - [Audit and compliance export](usage/audit-and-compliance.md)

# Security Model

- [Security Model](security/README.md)
  - [Threat model](security/threat-model.md)
  - [Three-layer defense in depth](security/three-layer-defense.md)
  - [Protection and enforcement](security/protection-enforcement.md)
  - [Trust boundaries](security/trust-boundaries.md)
  - [Audit and assurance](security/audit-assurance.md)

# Architecture

- [Architecture](architecture/README.md)
  - [System architecture](architecture/system-architecture.md)
  - [Component deep-dives](architecture/components.md)
  - [Key workflows](architecture/workflows.md)
  - [Data flows](architecture/data-flows.md)

---

# Reference

- [Architecture overview](architecture.md)
- [API Reference](api-reference.md)
- [Command-Line Interface](cli.md)
- [Dashboard](dashboard.md)

# Project Status

- [Compatibility Matrix](compatibility.md)
- [Versioning Policy](versioning.md)

# Governance

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

# Architecture Decision Records

- [Index](adr/README.md)
  - [0001 - Storage Architecture](adr/0001-storage-architecture.md)
  - [0002 - SDK Security Boundary](adr/0002-sdk-security-boundary.md)
