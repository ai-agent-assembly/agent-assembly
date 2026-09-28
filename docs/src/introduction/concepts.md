# Core concepts

Four concepts recur throughout this book. Understanding them here makes every
later chapter easier to read.

## Agent

An **agent** is the workload being governed: an LLM-driven program that decides,
at runtime, which actions to take to accomplish a goal. From the runtime's point
of view an agent is an identity that performs *actions* — calling a tool, making
an LLM request, or reaching out over the network. Agents register with the
[gateway](../architecture/) and are organized under a **team** and an
**org**, which is the scope at which policy and budget are applied.

Each governed action is described by an **action type** (for example, a tool call
or an LLM call), a **target** (what it is acting on), and surrounding context —
the agent's team and org, its governance level, and its place in any delegation
chain. That bundle is the unit the runtime makes a decision about, and it is what
the policy sections and any `requires_approval_if` guard are evaluated against.

## Policy

A **policy** is a declarative document — written in YAML — that states what agents
are and are not allowed to do. It is **not** a list of match/effect rules: a
document is a set of independent *sections* (`network`, `schedule`, `budget`,
`data`, `tools`, `capabilities`, `filesystem`, `syscalls`), and a top-level
`rules:` key is refused outright rather than loaded as an allow-all. Decisions
resolve to *allow*, *deny*, or *requires approval*. See
[Policy](../concepts/policy.md) for the full schema.

Policies are **scoped and they cascade.** A document is attached at the `global`,
`org`, `team`, `agent`, or `tool` level; when an action is evaluated, the gateway
walks those scopes and merges them with a **most-restrictive-wins** rule, so a
broad organizational deny cannot be loosened by a narrower scope. Policy is
evaluated **server-side, in the gateway** — never by the agent or a dashboard —
so the decision cannot be tampered with by the workload it governs. The reference
policies under `policy-examples/` are a good starting point. The detailed
evaluation path is documented in [Architecture](../architecture/).

## Budget

A **budget** caps how much a team may spend on agent activity, primarily the cost
of LLM calls. The gateway tracks consumption per team against a cost model and
treats the budget as part of the policy decision. For an **LLM call** the check is
pre-emptive: the call is priced and its spend reserved before it runs, and a request
that *would* breach the cap is downgraded from allow to deny with nothing charged.
For every **other** governed action the cap is reactive — once a limit is already
exceeded, whatever comes next is denied. Either way budget is a hard guardrail that
stops runaway spend in the moment, rather than a billing report that arrives after
the money is gone. See [Policy](../concepts/policy.md) for the two paths in detail.

## Audit

The **audit trail** is the hash-chained record of the decisions the gateway
makes — both allows and denies — together with the action that prompted it. Each
entry in the per-session JSONL log carries an unkeyed SHA-256 digest over its own
fields plus the preceding entry's digest, and `aasm audit verify-chain` re-walks
it, so careless alteration is detectable. Read the guarantee precisely: the chain
is **tamper-evident, not tamper-proof and not immutable** — it is unkeyed, so it
is not a signature; it covers the JSONL sink only, and the database mirror stores
no chain metadata; the log is append-only by convention rather than by
constraint, since retention pruning deletes rows; and emission is best-effort —
`verify-chain` reports a lost entry as `INCOMPLETE`, distinct from `FAIL` for an
altered or removed one, but a *tail* or *prefix* loss is still indistinguishable
from a tail/prefix deletion, since there is no following entry to anchor against.
Within those bounds it
answers the accountability question for a governed agent: *what did it do, when,
and was it permitted?* Audit
records use a single wire format regardless of which enforcement mechanism observed
the action, so the gateway presents one unified history. Audit data underpins
debugging, incident response, and [compliance
export](../operations/compliance-export.md).

---

With these four in hand — **agents** perform actions, **policy** decides
allow/deny, **budget** caps spend, and **audit** records each evaluated action —
[Enforcement mechanisms at a glance](enforcement-mechanisms.md) explains *how*
the runtime actually sees an agent's actions in order to govern them.

This page is the primer. The **Concepts** chapter is the reference: one page per
concept, each stating the exact shapes, defaults, and failure modes —
[Agent](../concepts/agent.md), [Policy](../concepts/policy.md),
[Approval](../concepts/approval.md), [Audit](../concepts/audit.md),
[Trace](../concepts/trace.md), [DID](../concepts/did.md), and
[Connector](../concepts/connector.md). Where the two differ in detail, the
Concepts page is normative.
