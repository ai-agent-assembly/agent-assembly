# Trust-boundary review checklist

> **Fill this in once per release**, as part of the `/security-review` gate. It
> maps a concrete release diff onto the trust boundaries documented in
> [Trust boundaries](trust-boundaries.md) and
> [ADR 0002](../adr/0002-sdk-security-boundary.md).

[Trust boundaries](trust-boundaries.md) is the *authority on **where** trust
sits*. This page is the *operational form*: it forces the reviewer to enumerate,
for **this** release, which boundaries the diff actually touched. Its purpose is
to convert the Story's attacker note — *"because no one wrote down which layer is
supposed to stop me, each team assumes an adjacent layer does; I operate in the
gap that everyone thinks someone else owns"* — into an explicit, named, signed-off
line item per boundary, instead of an unexamined assumption.

## How to use

1. Run `git log <prev-tag>..HEAD` for the release window (the `/security-review`
   SKILL does this for you).
2. For each row, mark **Changed? (Y/N)**, cite the **commit/PR**, and add a
   **reviewer note**.
3. Any **Y** row must be justified in the release's
   [sign-off artifact](../../release/security-signoff/) and re-checked against the
   [release threat model](release-threat-model.md) layer map.
4. The **guarded NO** row (no wire trust marker) must stay **N**. A **Y** there
   is an automatic BLOCK — it means a release reintroduced an SDK trust marker,
   which violates the core invariant of ADR 0002.

## Checklist

Copy this table into the per-release sign-off artifact and fill it in.

| # | Trust boundary | Authority / where it lives | Changed? (Y/N) | Commit / PR | Reviewer note |
|---|---|---|---|---|---|
| 1 | **Did this release add or move an authoritative enforcement point?** (scan/redact/normalize must stay in `aa-runtime`, never relocated up into the SDK) | `aa-runtime/src/pipeline/enforcement.rs` ([ADR 0002](../adr/0002-sdk-security-boundary.md)) | | | |
| 2 | **Did any field gain a wire-level trust marker?** — *must stay NO* (no `clean` / `already_scanned` marker is emitted or honored) | `aa-runtime` pipeline; the exhaustive wildcard-free `Detail` match | | | A **Y** here is an automatic **BLOCK**. |
| 3 | **New network egress path added?** | `aa-gateway/src/policy/network.rs` + `aa-proxy` | | | |
| 4 | **New endpoint or RPC method added?** (new authn/authz surface) | gateway gRPC / `aa-api` HTTP surface | | | |
| 5 | **New IPC / UDS surface** between SDK ↔ runtime ↔ gateway? | `aa-sdk-client` ↔ `aa-runtime` UDS path | | | |
| 6 | **Loosened policy default?** (a default that now permits what it used to deny; the empty cascade must stay fail-closed `Deny`) | `aa-gateway/src/engine/decision.rs`, `aa-gateway/src/policy/` | | | |
| 7 | **Changed sanitizer / redaction scope?** (a field newly carried, banned-key list changed, or a field newly exempted from scanning) | `aa-gateway/src/sanitizer/`, `aa-security` redaction | | | |
| 8 | **Changed audit subject / publish path?** (tamper-evidence of the trail) | `aa-runtime/src/audit_publisher/` | | | |
| 9 | **Budget / spend-enforcement default changed?** | `aa-gateway/src/budget/` | | | |
| 10 | **eBPF probe coverage changed or removed?** (the bypass floor) | `aa-ebpf-probes/src/` | | | |

## Decision

- **All rows N** (and row 2 N) → no trust-boundary delta this release; record in
  the sign-off artifact and proceed.
- **Any row Y** → justify each in the sign-off, re-check the
  [release threat model](release-threat-model.md), and confirm the *next* layer
  in the "assume previous breached" chain still holds.
- **Row 2 Y** → **BLOCK.** A wire trust marker violates ADR 0002.

## See also

- [Trust boundaries](trust-boundaries.md) — the authority on where trust sits.
- [Release threat model](release-threat-model.md) — the versioned layer map.
- [ADR 0002 — SDK Security Boundary](../adr/0002-sdk-security-boundary.md).
