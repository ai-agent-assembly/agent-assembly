<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/credential-operations/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — credential-operations

## Purpose

Safe credential discovery and consumption: how an agent finds an
available credential capability, and how it falls back from a native
tool/MCP to an official CLI to a documented API without ever letting the
credential's plaintext reach agent context, output, or files. This is the
company-common capability referenced by
`governance/engineering/agent-skill-architecture.md` (HORO-969) §1/§5.

## Type

Auto-used, no `manifest.yaml` — deliberately, matching
`shell-development`. `agents/common/project_skills.py`'s
`resolve_applicable_skills()` treats a skill with no manifest as always
applicable, which is correct here: any repo, on any stack, may need a
credential at any time — there is no single stack-evidence file that
could gate this the way `Cargo.toml` gates `rust-development`.

## Canonical rule source — read this first

The non-waivable rule text lives in
`governance/engineering/security.md`'s "Credential Discovery & Safe
Consumption Protocol" section (HORO-980) — the discovery order, the
tool/API fallback sequence, the "credentials are capabilities, not
context" principle, and the explicit prohibition list. That section is
governance, not this Skill: per HORO-969 §5, the credential-plaintext
prohibition itself is a non-waivable invariant that must render the same
way in every session, while the *procedure* for applying it is
operational knowledge an agent reaches for when the situation calls for
it — that procedure is what this Skill provides.

This `SKILL.md` does not restate that protocol. It points to it and adds
the concrete operational layer on top: worked patterns, provider-specific
fallback sequences (one dogfooded in this workspace, others pattern-only
where no real usage exists yet — each section says which), and two safe
helper scripts. If this file and `security.md` ever appear to disagree,
`security.md` is authoritative — treat the disagreement as a bug in this
Skill, not a loophole.

## When to use

- Any task that needs a credential (API token, CLI auth session, service
  account) to complete an authorized operation — before reaching for any
  discovery mechanism, not after one already came up empty.
- Deciding how to call a provider when the preferred tool (MCP, official
  CLI) doesn't cover the specific operation needed.
- Writing or reviewing a script/skill/CI step that touches credentials,
  `.env*` files, or authenticated CLIs.

## When NOT to use

- As authorization for an action a held credential happens to make
  technically possible but the task didn't ask for — see "credentials are
  capabilities, not context" in `security.md`. This Skill never expands
  what a task is authorized to do; it only governs how to safely use what
  it's already authorized to do.
- As a replacement for a provider-specific integration's own
  documentation — this Skill's provider examples ground the *pattern*,
  they are not a substitute for reading that provider's actual API/CLI
  docs for the operation at hand.
- For secret *values* that must be provisioned by a human (category B in
  the standing secret-handling policy — payment credentials, real
  customer secrets, an owner-gated production credential) — this Skill
  covers discovery/consumption of an already-authorized credential, not
  who is allowed to hold one.

## Routing decision

1. Apply the discovery order from `security.md` (MCP/integration → CLI →
   env presence → provider config names-only → repo `.env*` names-only →
   unavailable). Operational detail and a worked Jira-token walkthrough:
   `references/discovery-order.md`.
2. Once a credential/authenticated mechanism is available, apply the
   tool/API fallback sequence (native tool/MCP → CLI → documented API via
   a safe client → escalate). Worked provider sequences — Jira/Atlassian
   dogfooded from HORO-968, GitHub/Cloudflare/GCP marked pattern-only
   where not yet dogfooded in this workspace:
   `references/provider-fallback-examples.md`.
3. For the concrete case of an MCP tool that doesn't cover the needed
   operation at all — attempt the fallback honestly, and report the
   genuine limitation rather than fabricating success:
   `examples/jira-api-fallback-safe.md` (the real HORO-968 case).
4. For presence/name-only checks, use the two helper scripts rather than
   hand-rolling an `env`/`grep`-based check:
   - `scripts/probe_env_presence.py VAR_NAME` — prints only `PRESENT` or
     `ABSENT`, never the value.
   - `scripts/parse_dotenv_keys.py path/to/.env` — prints only the
     declared key names, never a value or value fragment, handling
     quoting/`export`/comments/multiline values/malformed lines safely.

## Composes with

- `engineering-loop` for the iteration discipline while building or
  debugging a script that touches credentials.
- `shell-development`'s non-negotiables
  (`references/process-and-filesystem-safety.md`) for the shell-specific
  instances of the same prohibitions (no `env`/`set`/`export -p`, no
  `set -x` around a credentialed call, no secret in argv).
- `terraform-development`'s `references/sensitive-value-safety.md` for
  the adjacent but distinct problem of a plan/state that carries a
  credential-shaped value the provider schema didn't mark sensitive.

## Worked examples

- `examples/jira-api-fallback-safe.md` — the real HORO-968 case: Jira MCP
  lacks Team Central/Atlas Goal creation, the REST API requires OAuth 2.0
  3LO that wasn't available, and the honest outcome was a reported
  limitation, not a fabricated success.
