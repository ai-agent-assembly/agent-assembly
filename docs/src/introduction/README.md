# Introduction

**agent-assembly** is a governance and security runtime for AI agents. It sits
between an agent and the tools, models, and networks it reaches for, evaluates
every action against policy and budget, and records the outcome in an immutable
audit trail. It is the open-source core of the AI Agent Assembly platform.

This section is the place to start. It explains *what* the runtime is and the
problem it solves, defines the handful of [core concepts](concepts.md) the rest
of the book assumes, and gives a teaser of the [three-layer interception
model](three-layer-model.md) that lets the runtime see what an agent does no
matter how the agent is built.

Read the pages in order:

| Page | What it covers |
|---|---|
| [What it is & the problem](overview.md) | What Agent Assembly governs, why ungoverned agent tool-use is risky, and the value proposition. |
| [Core concepts](concepts.md) | Agents, policies, budgets, audit — the vocabulary used throughout the book. |
| [The three-layer model](three-layer-model.md) | How the SDK, sidecar proxy, and eBPF layers compose so nothing slips through. |

When you are ready to run something, jump to the [Quick Start](../quickstart/README.md).
For the security rationale behind the design, read the [Security
Model](../security/README.md); for the crate-level implementation, read
[Architecture](../architecture/README.md).
