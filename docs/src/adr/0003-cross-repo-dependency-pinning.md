# ADR 0003: Cross-Repo Dependency Pinning on the Core Crates

**Status**: Accepted
**Date**: 2026-06
**Task**: [AAASM-3173](https://lightning-dust-mite.atlassian.net/browse/AAASM-3173)
**Relates to**: [ADR 0002](0002-sdk-security-boundary.md) (which first chose the git-SHA pin), [AAASM-2552](https://lightning-dust-mite.atlassian.net/browse/AAASM-2552)

---

## Context

This monorepo is the source of truth for the protocol and the shared `aa-*`
crates. Several sibling repos consume those crates, and a 2026-06-18 audit of how
they declare that dependency found a deliberate two-tier model:

**Tier 1 — internal build-time consumers pin by exact git commit SHA (`rev`):**

| Consumer | Crates pinned | Pin (2026-06-18) |
|---|---|---|
| `python-sdk` (`native/aa-ffi-python`) | `aa-core`, `aa-proto`, `aa-sdk-client` | `rev = 4f9eea19…` |
| `node-sdk` (`native/aa-ffi-node`) | `aa-sdk-client`, `aa-proto` | `rev = 4f9eea19…` (same SHA) |
| `go-sdk` (`native/aa-ffi-go`) | `aa-sdk-client`, `aa-proto` | `rev = 4f9eea19…` (same SHA) |
| `agent-assembly-enterprise` (workspace) | `aa-core`, `aa-gateway`, `aa-storage`, `aa-proto`, `aa-proxy`, `aa-runtime`, `aa-cache`, … | `rev = 6ba36f3d…` (all one SHA) |

Each manifest enforces one invariant in its comments: **all crates from this
monorepo share a single SHA**, so cargo resolves one checkout and the
`aa-core` ↔ `aa-proto` wire-codec can never skew. The three SDK repos are kept on
the same release SHA by the coordinated release fan-out (`repository_dispatch`,
AAASM-2959 keeps each `aa-sdk-client` rev + `Cargo.lock` in sync per release);
`agent-assembly-enterprise` moves on its own cadence.

**Tier 2 — end-user / example consumers pin by published release:**

- `agent-assembly-examples` depends on `@agent-assembly/sdk` (npm), `agent-assembly`
  (PyPI), and `github.com/ai-agent-assembly/go-sdk` (Go module tag) — the artifacts
  a real user installs, not the core directly.
- `agent-assembly-cloud` has **no** build-time dependency on the core; it talks to
  the gateway over the wire (gRPC/`aa-proto`). Wire-decoupled by design.

## Decision

1. **Keep the git-SHA pin for Tier 1, for now.** `rev = <SHA>` is the most
   reproducible git-dep form — immutable (unlike `branch =`, which moves, or
   `tag =`, which can be re-pointed/force-pushed), so the dependency graph cannot
   shift under a consumer. Combined with the single-SHA-across-crates invariant it
   removes protocol/wire skew, and it ships SDK fixes without waiting on a registry
   publish while the protocol is still evolving (the crates are `0.x`, marked
   "internal use only"). This holistically restates the distribution choice ADR
   0002 made for the SDK boundary and extends it to `agent-assembly-enterprise`.
2. **Keep Tier 2 on published releases.** Examples must consume the shipped
   packages so they validate the real user surface; cloud stays wire-only.
3. **Define an explicit stabilization trigger to revisit.** When the protocol
   (`aa-proto`) and the public Rust API reach **1.0 stability** *and*
   `aa-core` / `aa-proto` / `aa-sdk-client` publish reliably to crates.io,
   re-open ADR 0002's "publish to crates.io (rejected)" alternative and **migrate
   Tier 1 to crates.io semver version deps** (or, as an interim, git `tag =` at
   release commits). Tracked by **AAASM-3173**, deferred until the trigger is met.

## Alternatives Considered

- **Migrate to crates.io version deps now** — *rejected (timing).* The crates are
  pre-1.0 with no API-stability commitment and the alpha/beta publish series is
  still a dry-run; a registry version would force a publish on the critical path of
  every SDK fix and impose semver discipline the protocol isn't ready for. This is
  the revisit target, not a now-decision (see ADR 0002's same rejection).
- **Pin by git `tag =` at release commits now** — *rejected (interim only).* More
  readable than a SHA and points at release points, but a tag is mutable
  (re-pointable), losing the immutability that makes the current pin safe. Retained
  as a possible interim step under the trigger.
- **Pin by `branch =` (e.g. `master`)** — *rejected.* A moving target; defeats
  reproducibility and lockstep. (Cargo also won't resolve a bare branch `rev` once
  a crate consumes it — see the `feedback_cargo_rev_needs_sha` lesson.)

## Consequences

### Positive

- **Reproducible & tamper-evident.** A consumer's core dependency is an immutable
  commit; no silent drift.
- **No protocol/wire skew.** The single-SHA invariant guarantees `aa-core` and
  `aa-proto` are always the same revision across a consumer.
- **Ships fixes fast.** No registry publish on the SDK-fix critical path.
- **Right artifact per audience.** Examples exercise the published packages; cloud
  stays wire-decoupled.

### Negative (accepted, with a planned exit)

- **Opacity.** A SHA conveys nothing at a glance; readers must resolve it to a
  release. Mitigated by pinning at release SHAs + the per-release sync tooling.
- **Lockstep toil.** Bumping the shared SHA across three SDK repos + enterprise is
  manual discipline, mitigated by the `repository_dispatch` release fan-out.
- These costs are the reason for the stabilization trigger (AAASM-3173): the design
  is correct for the pre-1.0 phase and is expected to be revised, not kept forever.
