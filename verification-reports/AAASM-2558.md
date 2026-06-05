# AAASM-2558 — Verification: ADR for SDK trust boundary, crate layout & distribution

Verifies Story **AAASM-2558** (ADR — SDK trust boundary + shared-crate layout +
distribution mechanism). The ADR is authored in subtask **AAASM-2577** as
`docs/src/adr/0002-sdk-security-boundary.md`; this subtask (**AAASM-2578**)
checks it against every acceptance criterion of the Story.

## How verified

| # | Method |
|---|--------|
| 1 | Reviewed `docs/src/adr/0002-sdk-security-boundary.md` against each Story AC and each item the Epic (AAASM-2552) requires the ADR to record. |
| 2 | Confirmed the two "open items" were resolved against the actual code, not asserted: canonical-copy claim and distribution mechanism. |
| 3 | Confirmed the ADR is registered in `docs/src/adr/README.md` (index) and `docs/src/SUMMARY.md` (mdBook nav). |

## Acceptance criteria

| AC (Story AAASM-2558) | Result | Evidence |
|----|--------|----------|
| ADR records the **trust boundary** | ✅ Pass | ADR §Decision + §Trust model: SDK untrusted (not a security boundary); `aa-runtime` authoritative; gateway/control-plane SoT; SDK detection advisory-preflight-only; explicit invariant "no `clean`/`already_scanned` marker on the wire". |
| ADR records **crate layout + dependency direction** | ✅ Pass | ADR §Crate topology table + "Dependency direction: `aa-runtime, aa-gateway, aa-proxy, aa-sdk-client → aa-security`" (security logic out of `aa-core`). |
| **Canonical copy** of each duplicated binding identified | ✅ Pass | ADR §Canonical bindings (resolved): Python — `python-sdk/rust/aa-ffi-python` canonical (git-pinned consumer), monorepo `aa-ffi-python` is the duplicate to retire; Node — single binding, re-pointed onto `aa-sdk-client`; Go — already correct. Verified against code (line counts 719 vs 1,357; Node imports no `aa_*`). |
| **Distribution mechanism** chosen with rationale | ✅ Pass | ADR §Distribution mechanism: **git SHA pin**, shown already in production in `python-sdk/rust/aa-ffi-python/Cargo.toml` (`aa-core`/`aa-proto` at `rev = ed4aa11a…`); crates.io rejected (dropped in AAASM-2338) in §Alternatives. |
| **Migration order** recorded | ✅ Pass | ADR §Migration order: boundary-first 9-step sequence; steps 6–9 explicitly gated on step 3 (the runtime-enforcement gate, AAASM-2568). |
| ADR registered in index + nav | ✅ Pass | `docs/src/adr/README.md` index row for 0002; `docs/src/SUMMARY.md` nav entry under "Architecture Decision Records". |

## Open-item resolution (verified, not asserted)

- **Canonical copy** — `python-sdk/rust/aa-ffi-python` is a 719-line `lib.rs` that imports `aa_core`/`aa_proto` via a git-SHA pin; the monorepo `agent-assembly/aa-ffi-python` is 1,357 lines over `path` deps. The ADR records the SDK copy as canonical and the monorepo copy as the duplicate to retire, and flags that the shared logic must be reconciled into `aa-sdk-client` by diffing both (not lifting either wholesale).
- **Distribution mechanism** — git SHA pin is not a new choice; it is the existing production pattern in `python-sdk`. The ADR's decision is to extend it to `aa-security`/`aa-sdk-client`.

## Outcome

- All Story AAASM-2558 acceptance criteria: **pass**.
- No gaps found; nothing filed back to AAASM-2577.

The ADR is complete and merge-ready. "ADR merged" (the literal Story wording) is
the process step completed when PR for AAASM-2577 lands on `master`.
