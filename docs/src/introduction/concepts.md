# Core concepts

Four concepts recur throughout this book. Understanding them here makes every
later chapter easier to read.

## Agent

An **agent** is the workload being governed: an LLM-driven program that decides,
at runtime, which actions to take to accomplish a goal. From the runtime's point
of view an agent is an identity that performs *actions* — calling a tool, making
an LLM request, or reaching out over the network. Agents register with the
[gateway](../architecture/index.md) and are organized under a **team** and an
**org**, which is the scope at which policy and budget are applied.

Each governed action is described by an **action type** (for example, a tool call
or an LLM call), a **target** (what it is acting on), and a set of **labels**
(metadata used by policy rules). This is the unit the runtime makes a decision
about.

## Policy

A **policy** is a declarative document — written in YAML or TOML — that states
what agents are and are not allowed to do. Rules match on the action type,
target, and labels of a request and resolve to *allow* or *deny*.

Policies are **scoped and they cascade.** Rules can be attached at the `org`,
`team`, `agent`, and `tool` levels; when an action is evaluated, the gateway
walks those scopes and merges them with a **most-restrictive-wins** rule, so a
broad organizational deny cannot be loosened by a narrower scope. Policy is
evaluated **server-side, in the gateway** — never by the agent or a dashboard —
so the decision cannot be tampered with by the workload it governs. The reference
policies under `policy-examples/` are a good starting point. The detailed
evaluation path is documented in [Architecture](../architecture/index.md).

## Budget

A **budget** caps how much a team may spend on agent activity, primarily the cost
of LLM calls. The gateway tracks consumption per team against a cost model and
treats the budget as part of the policy decision: a request that *would* breach
the budget is downgraded from allow to deny. This makes budget a hard guardrail
that stops runaway spend in the moment, rather than a billing report that
arrives after the money is gone.

## Audit

The **audit trail** is the immutable, append-only record of every decision the
gateway makes — both allows and denies — together with the action that prompted
it. Because it is tamper-evident and complete, it answers the accountability
question for any agent: *what did it do, when, and was it permitted?* Audit
records use a single wire format regardless of which interception layer observed
the action, so the gateway presents one unified history. Audit data underpins
debugging, incident response, and [compliance
export](../operations/compliance-export.md).

---

With these four in hand — **agents** perform actions, **policy** decides
allow/deny, **budget** caps spend, and **audit** records everything — the [three-
layer interception model](three-layer-model.md) explains *how* the runtime
actually sees an agent's actions in order to govern them.
