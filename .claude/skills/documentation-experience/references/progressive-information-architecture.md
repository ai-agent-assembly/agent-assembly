# Reference — progressive information architecture (Layer 0–3)

## Why layers, not one page

Forcing every fact onto one page produces either a shallow page that can't
answer a real question, or a deep page that buries the answer a first-time
reader actually needs. The layered model exists so a reader who needs
orientation gets orientation, and a reader who needs a precise fact gets a
precise fact — without either reader wading through the other's content.

Each layer is a *kind of content*, not a literal single page or URL depth.
A small product might fit Layer 0–1 on one page with anchors; a large
product needs many pages per layer. What matters is that a reader can tell,
from where they are, which kind of answer they're getting.

## Layer 0 — Immediate orientation

The homepage/landing/README/docs-entry surface. Answer with minimal
cognitive load, in this order of priority:

- What is this?
- What problem/job does it solve?
- Why does it exist / why is it needed?
- Who is it for?
- What can I do now?
- What is the one primary next action?

**Do not** lead with internal architecture, jargon, feature inventory, or
company history unless that is itself the reader's job at this surface
(e.g. an internal contributor-docs entry point may legitimately lead with
architecture — see `surface-communication-jobs.md`).

## Layer 1 — Common workflows / learning

The next click from orientation. Make the most useful next knowledge easy
to discover:

- start here / when to use
- quick path / first successful outcome
- usage scenarios
- persona/role guides
- common workflows/tasks
- operating/use guidelines
- examples
- troubleshooting entry points
- current limitations/maturity

## Layer 2 — Deep guidance / concepts

For a reader who needs to understand *behavior*, not just copy a command:

- concepts / mental model
- detailed workflow guidance
- lifecycle/state behavior
- security/privacy model
- failure/recovery semantics
- deployment/operations
- advanced usage
- architecture where relevant to the audience
- trade-offs and design constraints

## Layer 3 — Reference

Precise, lookup-oriented material — a reader here already knows what they
want and needs the exact fact fast:

- CLI/API/SDK/reference
- configuration/environment variables
- compatibility/support matrices
- schemas/contracts
- error/reference tables
- generated API docs where appropriate
- release/version details

**Two non-negotiables**: never force a reader to read Layer 3 to *learn*
the product (that's what Layers 0–2 are for), and never bury an exact
reference fact inside marketing prose where a Layer 3 reader can't find it
by scanning.

## Worked example — a hypothetical CLI-based secrets-rotation tool

Assume a plausible product: `keyturn`, a CLI that rotates and audits cloud
credentials on a schedule.

| Content | Layer | Why |
|---|---|---|
| "keyturn rotates cloud credentials before they expire, so on-call engineers stop getting paged for stale keys." | 0 | Problem + outcome, no jargon, answers "why does this exist." |
| "Who it's for: platform engineers running production cloud accounts." | 0 | Answers "who is it for" directly. |
| `keyturn init && keyturn rotate --dry-run` as the one primary next action | 0 | The single next step, not a menu of options. |
| "Quick Start: rotate your first key in under five minutes" | 1 | First successful outcome — Layer 1's job. |
| Persona guide for "Operators" vs "Security admins" (only if their workflows actually diverge — see `surface-communication-jobs.md`) | 1 | Common-workflow routing. |
| "How keyturn decides a key is near-expiry (the rotation state machine)" | 2 | Behavior/mental-model detail, not needed to run the quick path. |
| "What happens if rotation fails mid-flight — recovery semantics" | 2 | Failure/recovery semantics, a Layer 2 concern. |
| "Security model: what `keyturn` can read, what it never stores" | 2 | Security/privacy model. |
| `keyturn rotate --help` full flag reference | 3 | Precise lookup, not learning material. |
| Supported cloud-provider compatibility matrix | 3 | Reference table. |
| Error code `E-4102: KMS_ACCESS_DENIED` reference entry | 3 | Exact fact a reader searches for by error code, not prose. |

Notice what does **not** belong on Layer 0: the rotation state machine
(Layer 2) and the full flag reference (Layer 3) would both drown the
five-second answer a first-time visitor needs. Notice what does **not**
belong on Layer 3 alone: the security model needs prose explanation
(Layer 2) even though a reference table of exact permissions (Layer 3) may
also exist — the two serve different readers asking different questions.
