# What Agent Assembly is & the problem

## What it is

`agent-assembly` is a **governance-native runtime for AI agents**. An AI agent —
an LLM wired up to tools, APIs, shells, and network access — is given a goal and
then decides, on its own, which actions to take to reach it. Agent Assembly
governs those actions. Every time an agent tries to call a tool, reach the
network, or spend money on a model call, the runtime evaluates that action
against a **policy** and a **budget**, returns *allow* or *deny* before the
action runs, and writes an immutable **audit** record of the decision.

A governing gateway, pointed at a reference policy, is one command away:

```bash
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml
```

That daemon listens on `127.0.0.1:50051` and is ready for any interception layer
to connect. The rest of this book explains how to put it to work.

## The problem: ungoverned agent tool-use is risky

A traditional program does exactly what its code says. An AI agent does not. It
plans its own steps at runtime, so the set of actions it might take is open-ended
and not knowable in advance. The moment you give an agent real capabilities —
the ability to run shell commands, hit internal APIs, call third-party services,
read files, or pay for tokens — that open-endedness becomes a concrete risk:

- **Unbounded tool-use.** An agent can invoke any tool it has been handed, in any
  order, with any arguments it constructs. A prompt-injected or simply confused
  agent may call a destructive tool it was never meant to use.
- **Data exfiltration.** An agent that can both read sensitive data and reach the
  network can leak that data — intentionally coerced by an attacker, or by
  accident — over an outbound request. Secrets and credentials are the
  highest-value target.
- **Runaway spend.** Agents loop. A planning loop that retries, fans out, or gets
  stuck can burn through an LLM budget in minutes with no natural stopping point.
- **No accountability.** When an agent does something it should not have, teams
  need to answer *what did it do, when, and was it allowed?* Without a tamper-
  evident record of every decision, that question has no answer.
- **Bypass.** Controls that live only inside the agent's own code are only as
  trustworthy as the agent. An agent that skips the SDK, or is compromised, slips
  past anything that depended on its cooperation.

These risks are not hypothetical edge cases — they are the default behavior of a
capable agent with no guardrails. Restricting the model's prompt is not enough,
because the model is exactly the component you cannot fully trust.

## The value proposition

Agent Assembly turns "trust the agent to behave" into "the runtime enforces what
the agent may do." It provides:

- **Policy enforcement at the action boundary.** Allow/deny decisions are made by
  a central [gateway](../architecture/README.md) *before* an action executes,
  driven by declarative policy rather than agent cooperation.
- **Budget control.** Per-team spend is tracked and enforced; a request that
  would breach the budget is denied, so a runaway loop is stopped, not just
  reported after the fact.
- **An immutable audit trail.** Every decision — allow and deny alike — is
  recorded, giving teams a complete, tamper-evident account of agent behavior for
  debugging, incident response, and compliance.
- **Defense that does not depend on the agent.** Enforcement is layered across
  three independent interception points (see [the three-layer
  model](three-layer-model.md)), so governance holds even when an agent skips its
  SDK or actively tries to evade it.

Crucially, the agent does not have to cooperate. The whole point is that
governance is enforced *around* the agent, by infrastructure the agent does not
control. The [Security Model](../security/overview.md) section makes the trust
boundaries explicit.

## Who this book is for

This book is the reference for **contributors and operators of the
`agent-assembly` core** — people running the gateway, writing policy, and
deploying the interception layers. If you are instead building an application
*with* a language SDK, start from the per-SDK guides: [Python
SDK](https://ai-agent-assembly.github.io/python-sdk/), [Node
SDK](https://ai-agent-assembly.github.io/node-sdk/), [Go
SDK](https://ai-agent-assembly.github.io/go-sdk/).
