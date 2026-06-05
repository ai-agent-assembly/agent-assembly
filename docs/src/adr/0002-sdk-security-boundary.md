# ADR 0002: SDK Security Boundary, Shared-Crate Layout & Distribution

**Status**: Accepted
**Date**: 2026-06
**Epic**: [AAASM-2552](https://lightning-dust-mite.atlassian.net/browse/AAASM-2552)

---

## Context

Two problems in the SDK / FFI layer were audited on 2026-06-05 and must be resolved together, because the fix for one constrains the other.

### 1. Security enforcement is in the wrong place

`CredentialScanner` (in `aa-core/src/scanner.rs`) is the credential-detection/redaction primitive. Today it runs:

| Location | Trusted? | Authoritative? |
| --- | --- | --- |
| `aa-gateway` (`audit.rs`, `engine/mod.rs`) | yes (server) | yes |
| `aa-proxy` (`intercept/`, `audit_jsonl.rs`) | yes (sidecar) | yes |
| `aa-ffi-python` (`src/handle.rs`) | **no — in the SDK binding** | it is the *only* scan on the SDK fast-path |
| `aa-runtime` | yes (trusted) | **no — it does not scan or redact at all** |

The SDK event fast-path is `SDK → UDS → aa-runtime → gRPC → gateway`. `aa-runtime` is the mandatory chokepoint, but its pipeline is only `enrich → is_policy_violation (blocked_actions) → forward/batch` — it forwards the SDK's payload without independently scanning or redacting it. Therefore a removed or bypassed SDK scanner lets raw secrets flow `SDK → runtime → gateway`, where the only remaining guard is the gateway's narrower banned-key sanitizer. The SDK is being trusted as a security boundary, and it must not be.

### 2. The FFI bindings are duplicated and diverged

The bindings are reimplemented per language rather than sharing one implementation:

| Binding | Form | Shared-crate use |
| --- | --- | --- |
| `agent-assembly/aa-ffi-python` | 1,357 lines (`codec/config/detect/handle/hooks/ipc/lib`), `path` deps | in-workspace |
| `python-sdk/rust/aa-ffi-python` | 719-line `lib.rs`, imports `aa_core` + `aa_proto` | **git-SHA-pinned** (`rev = ed4aa11a…`) |
| `node-sdk/native/aa-ffi-node` | 178 lines, imports **no** `aa_*` crate | none — reimplemented |
| `go-sdk/internal/ffi` | Go cgo consumer of the `aa-ffi-go` staticlib | consumes a built artifact |

The Node binding diverged precisely because it shares no code with the Python one — nothing forces it to track the same logic. Go already follows the correct model (one Rust artifact in the monorepo, consumed by the language).

---

## Decision

| Concern | Choice |
| --- | --- |
| Is the SDK a security boundary? | **No.** The SDK is untrusted. |
| Authoritative enforcement point | **`aa-runtime`** — scans, redacts, and normalizes every event before forward/audit, unconditionally. |
| Source of truth | **gateway / control-plane** (policy SoT; audit-write sanitizer kept as final backstop). |
| SDK-side detection | **Best-effort advisory preflight only.** No `clean` / `already_scanned` marker exists on the wire, and none is honored. |
| Security primitives home | A new **`aa-security`** crate (scanner, redaction, audit-normalization) — moved out of `aa-core`. |
| Shared runtime-client home | A new **`aa-sdk-client`** crate (UDS transport, proto codec, `AssemblyHandle` lifecycle, event shipping, advisory preflight). |
| Per-language bindings | **Thin pyo3 / napi / cgo shims** over `aa-sdk-client`: ergonomic API, hooks, type translation, event capture — no security authority. |
| Dependency direction | `aa-runtime, aa-gateway, aa-proxy, aa-sdk-client → aa-security` (security logic is **not** in `aa-core`). |
| Shared-crate distribution | **git SHA pin** (see below). |

### Trust model

```
UNTRUSTED                    TRUSTED ENFORCEMENT                 SOURCE OF TRUTH
Python/Node/Go SDK   ──UDS──▶ aa-runtime (mandatory chokepoint) ──gRPC──▶ gateway / control-plane
 • ergonomic API              • scan   (authoritative)                   • policy SoT
 • hooks, event capture       • redact (before forward + audit)          • audit-write sanitizer
 • type translation           • policy / approval (already server-side)    (final backstop)
 • BEST-EFFORT preflight      • normalize; re-scans EVERYTHING, always
   (advisory only)
```

**Invariant:** nothing the SDK asserts can shorten the runtime's work. The runtime scans unconditionally; `aa-security` running inside the SDK is *advisory*, the same crate running inside `aa-runtime` is *authoritative*. Position — not code — confers authority.

### Crate topology

| Crate | Role | Authority |
| --- | --- | --- |
| `aa-security` *(new)* | scanner / redactor / normalization primitives | none (library) |
| `aa-core` | wire types, traits | none |
| `aa-sdk-client` *(new)* | UDS transport, proto codec, `AssemblyHandle`, event shipping, advisory preflight | none |
| `aa-runtime` | **authoritative scan / redact / normalize + policy / approval** | ✅ the boundary |
| `aa-gateway` | policy SoT + audit-write sanitizer (final backstop) | ✅ SoT |
| `aa-ffi-{python,node,go}` | thin pyo3 / napi / cgo shims | none |

### Canonical bindings (resolved)

- **Python**: `python-sdk/rust/aa-ffi-python` (the git-pinned SDK consumer) is canonical; the monorepo `agent-assembly/aa-ffi-python` is the duplicate to retire. The two differ in size (719 vs 1,357 lines), so the shared logic must be reconciled into `aa-sdk-client` by diffing both — not by lifting either copy wholesale.
- **Node**: `node-sdk/native/aa-ffi-node` is the only Node binding, but it shares no code with the core (imports no `aa_*` crate). It is re-pointed onto `aa-sdk-client`, which makes the drift structurally impossible.
- **Go**: already correct; `aa-ffi-go` stays the staticlib artifact that `go-sdk` consumes.

### Distribution mechanism: git SHA pin

The shared crates (`aa-core`, `aa-proto`, and the new `aa-security`, `aa-sdk-client`) are consumed by the SDK repos via **git dependency pinned to an exact commit SHA**. This is already the established, in-production pattern — `python-sdk/rust/aa-ffi-python/Cargo.toml` already declares:

```toml
aa-core  = { git = "https://github.com/AI-agent-assembly/agent-assembly.git", rev = "ed4aa11a…", package = "aa-core", features = ["serde"] }
aa-proto = { git = "https://github.com/AI-agent-assembly/agent-assembly.git", rev = "ed4aa11a…", package = "aa-proto" }
```

The decision is to **extend this same mechanism** to `aa-security` and `aa-sdk-client`, not to introduce a new one.

### Migration order (boundary-first, gated)

The Epic executes in this order so SDK-side scanning is **never** removed before the runtime is authoritative:

1. This ADR.
2. Extract `aa-security` (move scanner/redaction/normalization out of `aa-core`; temporary re-export for compat).
3. **[GATE]** `aa-runtime` authoritative scan/redact/normalize stage + guardrails.
4. SDK-bypass resistance test suite (proves the gate).
5. Make the shared crates pinnable.
6. Extract `aa-sdk-client`.
7. Node SDK → thin shim. **8.** Python SDK → thin shim. **9.** Remove fat `aa-ffi-*` from the workspace.

Steps 6–9 (anything that removes SDK-side scanning) are blocked on step 3.

---

## Alternatives Considered

### Trust SDK-side scanning (rejected)

Treating the SDK as the scan boundary is the current accidental state. Rejected: the SDK is attacker-controllable (a bypassed, modified, or simply outdated SDK), so any guarantee anchored there is not a guarantee. Security must hold even when the SDK does nothing.

### Keep security primitives in `aa-core` (rejected)

`aa-core` is depended on by everything, including the thin shims and storage drivers. Hosting the scanner there enlarges the security-review blast radius to the whole base crate and forces unrelated consumers to pull it in. A small, dedicated `aa-security` crate gives a reviewable surface and a clean dependency direction.

### Per-language reimplementation / pure-language transport (rejected)

Letting each SDK speak UDS + protobuf natively (no shared Rust) is internally coherent, but it reproduces the transport logic N times. The current divergence (Python rich, Node reinvented, no shared types) is exactly this failure mode realized halfway — paying the native-build cost *and* duplicating. One shared `aa-sdk-client` removes the duplication while keeping the shims idiomatic.

### Publish shared crates to crates.io / a private registry (rejected)

A registry would enable prebuilt-artifact reuse, but crates.io publishing was already attempted and **dropped** (AAASM-2338), and it adds a publish pipeline plus version-bump discipline. git-SHA pinning is already working in `python-sdk`, requires no new infrastructure, and pins to an exact, reproducible commit. (`cargo`'s `rev` must be a SHA, not a bare branch name, or resolution fails once a crate consumes the dependency.)

### Keep the bindings in the monorepo workspace (rejected for ownership)

Keeping `aa-ffi-*` in the workspace preserves atomic cross-crate changes, but couples each SDK's release to the monorepo and keeps the FFI dep trees (pyo3/napi/prost/tokio) in the core build. Moving the thin shims into their SDK repos — consuming pinned shared crates — gives the SDKs independent release cadence and shrinks the core workspace, while the shared `aa-sdk-client` keeps a single source of truth. Go already demonstrates the artifact-consumption variant of this model.

---

## Consequences

### Positive

- **The SDK can no longer weaken enforcement.** Scan/redact/normalize run authoritatively at `aa-runtime` regardless of SDK behavior; this is proven by the bypass-resistance suite.
- **Drift becomes structurally impossible.** One `aa-sdk-client` implementation, consumed by thin shims, replaces N reimplementations.
- **Reviewable security surface.** `aa-security` is a small, leaf crate that the trusted enforcers depend on directly.
- **Smaller core build.** Removing the fat bindings drops pyo3/napi/prost/tokio FFI dep trees from `cargo build --workspace`.
- **No new release infrastructure.** Distribution reuses the git-SHA pin already in production.

### Negative / accepted trade-offs

- **Authoritative scanning adds hot-path cost.** Payload inspection at the runtime is more work than the current `blocked_actions` check; the gate Story carries explicit guardrails (precompiled scanner, secret-bearing-fields only, size caps, metrics) and must stay within the policy-latency budget.
- **The SDK repos rebuild the shared crates** (no shared `target/`); org-wide CPU may rise unless `sccache` or prebuilt artifacts are added later.
- **Pinned SHAs require deliberate bumps.** SDK repos pick up core changes only when their pin is advanced — an explicit, visible step rather than implicit coupling.
- **A temporary `aa-core` re-export** of the moved primitives is needed during migration and must be removed once consumers are repointed.

---

## Related

- Epic: [AAASM-2552](https://lightning-dust-mite.atlassian.net/browse/AAASM-2552) — SDK security boundary + FFI consolidation
- Story: [AAASM-2558](https://lightning-dust-mite.atlassian.net/browse/AAASM-2558) — this ADR
- Gate: [AAASM-2568](https://lightning-dust-mite.atlassian.net/browse/AAASM-2568) — `aa-runtime` authoritative enforcement (blocks Stories 6–9)
- Follow-on stories: AAASM-2567 (`aa-security`), AAASM-2570 (`aa-sdk-client`), AAASM-2559 (pinnable crates), AAASM-2560 / AAASM-2561 (Node / Python shims), AAASM-2562 (remove fat bindings), AAASM-2569 (bypass tests)
