<!-- horonom:generated -->
<!-- Source: horonomy/.github agents/skills/rust-development/SKILL.md. Do not hand-edit — rerun `python3 agents/common/project_skills.py`. -->

# SKILL.md — rust-development

## Purpose

Give any Horonom repo with a Rust workspace the company-common Cargo/
nextest/clippy execution knowledge — repository discovery, the
`cargo check` vs. build/link/native boundary, targeted test iteration,
and lint/format/doc validation. It reuses the durable Rust-development
evidence from `ai-agent-assembly/agent-assembly`'s AAASM-5991/5992
benchmark campaign rather than re-deriving it, while keeping that repo's
own machine/benchmark specifics out of company-wide fact — see
`references/aa-evidence-classification.md` for exactly which claims
transfer and which don't.

## Type

Auto-used, stack-gated. Applies whenever the touched repo/surface carries
Rust evidence (`Cargo.toml`, per `manifest.yaml`'s `applicability.stacks:
[rust]`). Composes with `engineering-loop`
(`agents/skills/engineering-loop/SKILL.md`) — that skill owns the
Explore→Narrow→Validate→Escalate→Full Gate execution model and the L0–L3
diagnostic contract; this skill does not restate either. It supplies the
concrete Cargo/nextest/clippy commands `engineering-loop`'s Narrow and
Full Gate stages call.

## When to use

- Iterating on a change inside a Rust crate or workspace: editing,
  compiling, testing, linting.
- Choosing the right-sized Cargo/nextest invocation for the current
  execution stage (fast edit vs. targeted test vs. full verification).
- Interpreting a Cargo/rustc/clippy/nextest failure before escalating
  through `engineering-loop`'s diagnostic ladder.

## When NOT to use

- Non-Rust repos or surfaces — no Rust evidence means this skill does not
  apply; don't project or follow it merely because the org has it.
- As a substitute for `engineering-loop`'s execution model or diagnostic
  contract — this skill never redefines Explore/Narrow/Validate/Escalate/
  Full Gate, it only fills in the Rust-specific commands for each stage.
- As a source of release/dist-profile guidance — release/dist profile
  tuning is a correctness/size boundary, not a dev-speed lever, and is out
  of this skill's scope (see `references/cargo-workflow.md`).

## Routing

1. **Discover the workspace** before running anything —
   `references/cargo-workflow.md` § Repository/workspace discovery.
2. **Narrow stage (engineering-loop)**: `cargo check` gives the fastest
   syntax/type feedback but is never build/link/native/release proof — it
   skips codegen and linking, so it cannot surface link errors, native/FFI
   symbol-resolution failures, build-script problems, `#[cfg]`-gated
   codegen failures, or release-profile-only breakage (LTO,
   `codegen-units`, `panic=abort`). Scope every `cargo nextest run`
   invocation (`--lib`, `--test <stem>`, or `-p <crate>` at minimum) — see
   `references/cargo-workflow.md` § Targeted test loops.
3. **Escalate (engineering-loop)**: read the actual rustc/clippy
   diagnostic before assuming a fix — `references/cargo-workflow.md` §
   High-signal diagnostics.
4. **Full Gate (engineering-loop, always)**: before declaring a Rust
   change done, run the repo's own authoritative full build/test/clippy
   gate. A passing `cargo check` or scoped `nextest` run is evidence the
   fix works, never proof the workspace is releasable.
5. **Optional accelerators** (RTK/CodeGraph) follow the shared
   preferred→fallback contract in
   `agents/skills/engineering-loop/references/optional-tool-fallback.md` —
   this skill does not define its own variant of that contract.

## References

- `references/cargo-workflow.md` — discovery, the check/build/link/native
  boundary, targeted test/lint/doc commands, high-signal diagnostics.
- `references/aa-evidence-classification.md` — what from
  `ai-agent-assembly/agent-assembly`'s bench-5992 evidence is a reusable
  company-level Rust pattern vs. AA-specific fact vs. machine-specific vs.
  needing revalidation, and the deference rule to that repo's own policy.

## Examples

- `examples/targeted-nextest-then-full-gate.md` — a failing test, targeted
  `cargo nextest run --lib` iteration, then the full workspace gate before
  declaring the change done.
