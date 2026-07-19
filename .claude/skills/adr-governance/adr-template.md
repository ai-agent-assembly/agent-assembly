# ADR NNNN: <Short decision title>

**Status**: Proposed | Accepted | Superseded by NNNN
**Date**: YYYY-MM
**Ticket**: [AAASM-XXXX](https://lightning-dust-mite.atlassian.net/browse/AAASM-XXXX)

<One paragraph: what this ADR records and why it exists. Name the other ADRs it
complements or supersedes.>

---

## Context

<The forces at play. If the decision is security- or tenancy-relevant, state the
**threat model(s)** explicitly — different editions / deployment modes often have
different adversaries and therefore different correct answers. Include the
constraint that forced the design (an API limitation, a platform boundary, a
compatibility requirement).>

## Decision

<What we are doing, stated so a future implementer can comply without guessing.
Number the sub-decisions if there is more than one. Be concrete about the
mechanism (endpoint, storage, flag, protocol), not just the intent.>

## Accepted risks

<What residual risk we are knowingly taking, and the assumptions that make it
acceptable. Omit the section only if there genuinely are none.>

## Explicitly forbidden designs

<The alternatives that must NOT be used, so a later change doesn't reintroduce
them. This is often the most valuable section — it stops silent regressions.>

## Consequences

<What changes for each affected audience (operators, SaaS, SDK/CLI, future
contributors). Both the good and the costs.>

## Operational guidance

<What an operator / deployer must do or avoid as a result. Omit if not applicable.>

## Validation requirements

<The tests or checks that must exist to prove the decision holds — so a reviewer
can confirm the ADR is actually enforced, not just written down.>

## Reconsideration triggers

<The specific future changes that should re-open this ADR (a new deployment
topology, a shipped backend surface, a discovered vulnerability, a new edition).
An accepted-risk record MUST list these.>

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-XXXX](https://lightning-dust-mite.atlassian.net/browse/AAASM-XXXX) | <what it is> |
| [ADR NNNN](NNNN-....md) | <complements / superseded-by / related> |
| Implementation PRs | <#NNN ...> |
