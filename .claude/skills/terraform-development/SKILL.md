<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/terraform-development/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — terraform-development

## Purpose

Plan-first iteration on Terraform (or compatible IaC) changes: format,
validate, lint/static-analyze, and produce a safe human-readable plan
summary — without ever exposing a sensitive value or treating a plan as
proof of a safe apply. This is the company-common capability referenced by
`governance/engineering/agent-skill-architecture.md` (HORO-969) §1; it
composes with `engineering-loop`, which supplies the Explore → Narrow →
Validate → Escalate → Full Gate loop and diagnostic discipline this skill
runs inside of.

## Type

Auto-used. Invoke whenever iterating on a `.tf`/`.tf.json` change, in any
repo where `manifest.yaml`'s `stacks: [terraform]` applicability matches
(HORO-969 §3 — `*.tf` evidence).

## Security posture — read before anything else

Terraform plans routinely surface values that must never land in agent
context, a commit, a PR body, or CI output verbatim — resource attribute
values, some outputs, and provider-specific fields a schema marks
sensitive (and some it doesn't, see below). This skill's central
obligation is `references/sensitive-value-safety.md`. Read it before
running `terraform plan` on any repo that provisions real infrastructure.

This skill does not restate the company's non-waivable secret-handling
invariant — never inspect, print, log, or otherwise cause a credential's
plaintext to appear in output, files, commits, or conversation context —
that rule lives in `governance/engineering/security.md`'s "Secrets —
opaque-capability model" section and applies here unmodified. A Terraform
plan/state that carries a raw credential (a generated DB password, an API
key output) is covered by that rule exactly like any other secret; this
skill's `references/sensitive-value-safety.md` is the *operational
procedure* for the broader class of plan-carried sensitive values
(including ones no schema flags as sensitive), not a replacement for it.

## When to use

- Any iterative loop that edits Terraform config: adding/changing a
  resource, module, variable, or output.
- Reviewing what a proposed change would actually do before it is
  authorized to apply.

## When NOT to use

- To perform `terraform apply`, `destroy`, `import`, or any direct state
  mutation (`state mv`/`rm`/`push`) automatically. These stay **outside
  this skill's automatic scope** — see "Apply and state mutation" below.
- As proof that a change is safe to deploy — `terraform validate` checks
  syntax and internal consistency only; it is never deployment/apply
  proof. Only a reviewed `plan` (and, once authorized, a real `apply`)
  demonstrates what will actually happen.

## Routing decision — the plan-first progression

Run, in order, stopping to fix at the first failure: `fmt -check` →
`validate` → lint/static analysis → `plan`. Full detail on each stage,
module/workspace/backend/provider discovery, init/lockfile behavior, and
identity verification before any production-sensitive action:
`references/plan-first-workflow.md`.

Never skip straight to `plan` on unformatted or unvalidated config — a
`plan` run against config that doesn't even parse cleanly wastes a cycle
and, worse, can produce a misleading diff against stale provider state.

## `-target` is exceptional, not routine

`-target` restricts `plan`/`apply` to a subgraph. It is a surgical
recovery tool for a specific, understood problem (e.g. unblocking one
broken resource while a dependency is fixed out of band) — never a
routine way to make `plan` faster or to avoid understanding a change's
full blast radius. A `-target` plan is not a substitute for eventually
running a full, untargeted plan before anything is authorized to apply.

## Apply, destroy, import, and state mutation

This skill's automatic scope ends at a reviewed `plan` and its safe
summary. `apply`, `destroy`, `import`, and any `terraform state`
mutation always require **explicit task authorization** — a human or an
explicitly-scoped task instruction naming the action — never inferred
from "the plan looked fine" or "tests passed." This mirrors
`engineering-loop`'s Full Gate discipline (a passing narrow check is
evidence, never blanket authorization) and the credential-adjacent
boundary in `governance/engineering/agent-skill-architecture.md` §5.

## Worked example

`examples/fmt-validate-plan-review.md` — a concrete `fmt -check` →
`validate` → safe plan-summary walkthrough for adding a cloud resource.
