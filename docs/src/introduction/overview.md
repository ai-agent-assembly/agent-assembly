# What Agent Assembly is & the problem

> **In plain terms.** AI agents act on their own — they run tools, call
> services, and spend money to get a job done. Agent Assembly is the set of
> guardrails around them: for each action that reaches it, it checks the action
> against rules you define, allows or blocks it *before* it happens, and keeps a
> tamper-*evident* record of what was decided — one you can check for alteration,
> though nothing in the product deletes it on a schedule, so retention is yours
> to run. Think of it as a security checkpoint on
> the paths you route through it — which means the paths you leave unrouted
> still need their own controls. Which actions reach the checkpoint depends on
> how the agent is wired up; [Enforcement mechanisms at a
> glance](enforcement-mechanisms.md) explains what each mechanism does and does
> not see, and [Limitations and known bypasses](../devtools/limitations.md)
> states the gaps that remain today.
>
> It is for the people responsible for those agents — **developers** wiring them
> up, **security and operations** teams keeping them safe, and the **planners**
> who need to know the controls exist. With it you can decide which tools an
> agent may use, stop it from leaking data or overspending, and review exactly
> what was observed and decided.

## What it is

`agent-assembly` is a **governance-native runtime for AI agents**. An AI agent —
an LLM wired up to tools, APIs, shells, and network access — is given a goal and
then decides, on its own, which actions to take to reach it. Agent Assembly
governs those actions. Each time a governed action reaches the runtime — a tool
call the SDK wraps, an outbound request routed through the proxy, a model call
on an inspected host — the runtime evaluates that action against a **policy** and
a **budget**, returns *allow* or *deny* before the action runs, and writes a
hash-chained **audit** record of the decision. Actions that reach none of those
interception points are neither evaluated nor recorded.

A governing gateway, pointed at a reference policy, is one command away:

```bash
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml
```

That daemon listens on `127.0.0.1:50051` and is ready for any enforcement mechanism
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
- **A hash-chained audit trail.** Every decision the runtime makes — allow and
  deny alike — is recorded, giving teams a tamper-*evident* account of the agent
  behavior that was observed, for debugging, incident response, and compliance.
  Tamper-evident is not immutable: the SHA-256 chain is unkeyed and covers the
  JSONL sink only. Retention pruning does not reach that sink — it deletes rows
  from the SQL copy, which carries no chain — so the chained record itself is
  bounded by nothing the product ships. See [Audit](concepts.md#audit) and
  [what is retained](../security/audit-assurance.md#what-is-retained-and-what-is-deleted).
- **Defense that does not depend on the agent's cooperation.** Governance can
  observe through three independently-deployable mechanisms (see [Enforcement
  mechanisms at a glance](enforcement-mechanisms.md)), so it can still hold
  when an agent skips its SDK. Each mechanism has its own precondition, so
  deploying more of them narrows the gap rather than eliminating it.

Crucially, the agent does not have to cooperate on the paths that are wired up:
governance is enforced *around* the agent, by infrastructure the agent does not
control. What that does **not** mean is universal mediation — an action on a path
no deployed layer observes is not governed, and a tool launched outside the
managed path is a demonstrated example. The [Security
Model](../security/overview.md) section makes the trust boundaries explicit, and
[Limitations and known bypasses](../devtools/limitations.md) states what is
unmeasured or unsupported today.

## Who this book is for

This book is the reference for **contributors and operators of the
`agent-assembly` core** — people running the gateway, writing policy, and
deploying the enforcement mechanisms. If you are instead building an application
*with* a language SDK, start from the per-SDK guides: [Python
SDK](https://docs.agent-assembly.com/python-sdk/stable/), [Node
SDK](https://docs.agent-assembly.com/node-sdk/stable/), [Go
SDK](https://docs.agent-assembly.com/go-sdk/stable/).
