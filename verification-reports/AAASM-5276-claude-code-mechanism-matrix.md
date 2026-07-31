# AAASM-5276 — Claude Code integration mechanism matrix (measured)

Raw measured evidence from the Spike harness
(`aa-integration-tests/tests/spike_claude_code_lifecycle.rs` +
`tests/spike_support/`). **This document records measurements and their
classification only.** The Go / Conditional Go / No-Go decision and the
lifecycle-contract recommendations are written separately from this evidence.

## Environment measured

| Fact | Value | How established |
|---|---|---|
| Host | macOS (Darwin 25.4.0), arm64 | test host |
| Claude Code | `/opt/homebrew/bin/claude`, `2.1.220 (Claude Code)` | `claude --version` via the harness |
| Binary format | native Mach-O arm64 with an embedded Node runtime (`X-Stainless-Runtime: node`, `v26.3.0`) | request headers captured by the mock provider |
| Adapter | `aa-devtool-claude-code`, `MIN_VERSION = 1.0.0` | `aa-devtool-claude-code/src/lib.rs:34` |
| Scanner | `aa_security::CredentialScanner`, `sk-ant-` → `CredentialKind::AnthropicKey` | `aa-security/src/scanner.rs:15,58` |
| Suite result | 15 tests, 15 passed, 0 skipped, 10.9 s | `cargo nextest run -p aa-integration-tests --test spike_claude_code_lifecycle` |

Synthetic secret: `sk-ant-api03-AAASM5276SYNTHETICDONOTUSE…AA` — fabricated, matches
the scanner's `sk-ant-` literal pattern, never a credential.

## Mechanism classification

| Mechanism | Class | Evidence |
|---|---|---|
| **`HTTPS_PROXY` + `aa-proxy` MitM** | **Required** — the only model-path interception that exists | Real binary, 4/4 requests intercepted; 2 bodies carried `[REDACTED:AnthropicKey]`, none carried the raw value. Emulated client: 1/1 request redacted, forwarded body still valid Messages JSON. `scenario_11_3_*` |
| **`NODE_EXTRA_CA_CERTS`** | **Required** — MitM does not work without it | `claude --debug`: `CA certs: Appended extra certificates from NODE_EXTRA_CA_CERTS (…)`. Default store is `bundled,system`; the repo plumbs **zero** CA-trust env vars today (`aa-cli/src/commands/run.rs:326-330` injects only `HTTP_PROXY`/`HTTPS_PROXY`). |
| **Managed launch (`aasm run claude`)** | **Required** — it is the only place the proxy + CA env can be injected | `build_launch_command` sets `HTTPS_PROXY` but **not** `NODE_EXTRA_CA_CERTS` (`aa-devtool-claude-code/src/lib.rs:272-290`). An unmanaged launch is unprotected — asserted in `scenario_11_11`. |
| **Managed user settings (`~/.claude/settings.json`)** | **Optional** (tool-governance, not data-path) | Install is idempotent (SHA-256 identical across two applies) and preserves every unmanaged key; footprint is exactly the four keys in `apply.rs:47`. `scenario_11_1`, `scenario_11_2` |
| **Project settings (`<cwd>/.claude/settings.json`)** | **Optional**, and a **hazard** | The adapter's resolver silently prefers it whenever a `.claude/` dir exists in cwd (`apply.rs:24-29`). Not selectable by the caller; the harness had to inject `home_dir` to avoid it. |
| **`ANTHROPIC_BASE_URL` redirection** | **Unsuitable for protection** | Real binary + emulated client both delivered the **raw** secret to the mock with no AASM component in the path. Asserted positively in `scenario_11_3_base_url_redirection_removes_aasm_from_the_path`. Also documented to suppress server-managed settings fetch. |
| **`--settings <file-or-json>` flag** | **Defence-in-depth** (unmeasured) | Present in the binary; merges rather than replaces. Not exercised — the adapter does not emit it. |
| **Managed-settings file (`/Library/Application Support/ClaudeCode`)** | **Unproven** | Directory does not exist on the test host and creating it requires root. Deliberately not attempted (no system-level writes). The managed-only keys (`allowManagedPermissionRulesOnly`, `disableBypassPermissionsMode`, …) are the strongest available bypass counters and remain **unmeasured**. |
| **Hooks** | **Unsuitable for sensitive-data protection**; optional for tool governance | Hooks govern tool/action execution and cannot see or modify model-bound prompt content. No hook can carry a sensitive-data claim. |
| **MCP configuration** | **Optional** | `apply_mcp_governance` writes `enabledMcpjsonServers`/`disabledMcpjsonServers` idempotently (`apply.rs:104`). Not required for protection. |
| **`NODE_TLS_REJECT_UNAUTHORIZED`** | **Forbidden** | Never set by the harness. Setting it would make MitM "work" by disabling verification — a TLS failure is a finding, not something to suppress. |
| **macOS host enforcement** | **Unavailable** | Out of scope and unimplemented. Reported as `Host Enforced: unavailable on this platform` in every status render rather than omitted (`scenario_11_8`). |

## Measured side effects worth carrying forward

* **The proxy scans the binary's side channels, not just `/v1/messages`.** One
  headless `claude -p` run produced four upstream requests: two `/v1/messages`
  POSTs, one MCP-registry GET, and a **130 KB `POST /api/event_logging/v2/batch`
  telemetry payload**. All four passed through the scanner. Any protection claim
  scoped to "the model endpoint" understates what is actually covered — and any
  `llm_only`-scoped deployment would leave the telemetry channel unscanned.
* **Redaction is non-destructive.** The forwarded body remained parseable
  Messages JSON with `anthropic-version` intact and the surrounding prompt text
  unchanged; the client received a 200.
* **Install/remove is semantics-exact but not byte-exact.**
  `apply_settings_at` reserialises the whole document
  (`aa-devtool-claude-code/src/apply.rs:85`), so a user file in non-canonical
  formatting cannot survive a cycle byte-for-byte regardless of receipt quality.
  Asserted as a known limitation in
  `scenario_11_7_byte_exact_restore_fails_for_non_canonical_formatting`.

## Latency and startup

| Measurement | Value |
|---|---|
| `aa-proxy` start → first accepted connection | ~0.13 ms (in-process) |
| Proxied request round-trip, emulated client | ~1.2 ms |
| Direct request round-trip, no proxy | ~0.47 ms |
| Real `claude -p`, base-URL redirection, to clean exit | ~0.85 s |
| Real `claude -p` through the proxy, to full 4-request egress | ~10.3 s |
| Core-stop → connections refused | ~0.07 ms |

Added per-request cost of MitM interception is sub-millisecond at this body size
and is not the constraint on MVP design.

## Demonstrated vs inferred bypasses

**Demonstrated by this harness:**

1. `ANTHROPIC_BASE_URL` pointed at any endpoint removes AASM from the path; the
   raw secret arrives. Shown with both the real binary and an emulated client.
2. Launching `claude` outside the managed path (no `HTTPS_PROXY`) is unprotected.
3. `Observe`/`AlertOnly` forwards the secret unchanged — correct behaviour, and
   the reason observe-only must never render as protection.

**Inferred, not demonstrated** (documented, not measured here): `--dangerously-skip-permissions`,
`defaultMode: bypassPermissions`, `--bare`, unsetting the proxy env in the shell,
repointing `CLAUDE_CONFIG_DIR`, symlinking `.claude`, replacing the binary,
calling the API directly with the user's own key, switching provider
(`CLAUDE_CODE_USE_BEDROCK`/`_VERTEX`), running a pre-managed-settings release,
and a hook exiting 1 instead of 2.

## Spike scaffolding that must not be promoted

`tests/spike_support/receipt.rs` and `tests/spike_support/status.rs` exist only
to make the measurements possible. They deliberately omit transactional
multi-mechanism apply, receipt schema versioning, tamper-evidence, concurrent
install locking, partial-install detection, and receipt storage outside the
tool's own config tree. AAASM-5278 owns the production model.

---

# Spike decision

## Verdict: **Conditional Go**

The Spike's central uncertainty was whether Agent Assembly can actually see, and
act on, Claude Code's model-bound traffic on macOS. **It can.** The real
`claude 2.1.220` binary accepted the `aa-proxy` MitM CA via `NODE_EXTRA_CA_CERTS`,
every upstream request it made traversed the proxy, the deterministic scanner
matched the synthetic secret, and the forwarded body carried
`[REDACTED:AnthropicKey]` while remaining valid Messages JSON — with sub-millisecond
added latency. That is a stronger result than the design assumed, because the
proxy also captured the binary's MCP-registry call and a 130 KB telemetry batch,
not just `/v1/messages`.

It is **Conditional**, not an unqualified Go, because the mechanism that makes
this work is **not wired up in the product today**. `aasm run claude` injects
`HTTPS_PROXY` and no CA-trust variable, so on `main` the MitM handshake would fail
and `Gateway Protected` would be unachievable — silently. The conditions below are
what turn a proven mechanism into a shipped one. All of them fit inside existing
Epic children; none requires new architecture, and none contradicts ADR 0030.

## Conditions

| # | Condition | Why it blocks the claim | Owner |
|---|---|---|---|
| **C1** | Materialise the proxy CA as a PEM and inject **`NODE_EXTRA_CA_CERTS`** on the managed launch path. | Without it the MitM handshake fails and the entire `Gateway Protected` level is unreachable. `aa-devtool-claude-code/src/lib.rs:272-290` and `aa-cli/src/commands/run.rs:326-330` both inject proxy vars only. **Highest priority in the Epic.** | AAASM-5281 |
| **C2** | Make the settings scope an **explicit, caller-selected** parameter. | `apply.rs:24-29` silently prefers `<cwd>/.claude/settings.json` whenever a `.claude/` directory exists in cwd. A lifecycle tool that writes to a different file depending on the caller's working directory cannot produce a trustworthy receipt, cannot detect drift reliably, and can surprise a user by mutating a checked-in project file. | AAASM-5277 (contract), AAASM-5281 (adapter) |
| **C3** | Accept and document **semantics-exact, not byte-exact**, restore — or preserve the original document. | `apply.rs:85` reserialises the whole JSON document, so a user file in non-canonical formatting cannot survive an install→remove cycle byte-for-byte no matter how good the receipt is. This must be an accepted, stated constraint rather than an implied guarantee. | AAASM-5278 |
| **C4** | Classify `ANTHROPIC_BASE_URL` redirection as **Unsuitable for protection**, in the capability model and in user-facing docs. | Measured: with base-URL redirection the raw secret reached the provider with no AASM component in the path. It is a *routing* feature, not a protection mechanism, and shipping it as one would be a direct over-claim. It additionally suppresses Claude Code's server-managed-settings fetch when set in the shell. | AAASM-5277, AAASM-5284 |
| **C5** | Ensure the Claude Code integration plan intercepts the binary's **side channels**, not only the model endpoint. | One headless run produced a 130 KB `POST /api/event_logging/v2/batch`. `aa-proxy`'s `llm_only` default (`aa-proxy/src/config.rs`) is `true`, which would leave that channel unscanned. Scope this per-integration rather than by flipping a global default — changing `llm_only` wholesale would MitM every host on the machine. | AAASM-5281 |
| **C6** | Treat the endpoint **managed-settings file as unproven** until measured on a managed device. | `/Library/Application Support/ClaudeCode/managed-settings.json` is root-owned and was deliberately not attempted (no privileged writes were made during this Spike). Its managed-only keys are the strongest bypass counters available, and they remain unmeasured — so no non-overridable-enforcement claim may be made. | AAASM-5284 + AAASM-5298 |

> **C6 update (AAASM-5298, 2026-07-31) — half closed.** The *install* half is delivered: an opt-in,
> explicitly authorized, read-back-verified privileged write installs the managed-settings file, and
> `HostEnforced` is reachable from nothing else. The *enforcement* half is still open: no real
> override attempt has been measured against a managed device, so `HostEnforced` claims "the policy
> is installed where the developer cannot rewrite it", **not** "this bypass was demonstrated to
> fail", and no non-overridable-enforcement claim is made anywhere.

## Recommended lifecycle-contract changes (input to AAASM-5277)

1. **An integration step kind for trust material and environment**, not just settings writes. The plan must be able to express "materialise CA PEM at path P" and "inject env var E at launch" as first-class, receipted, reversible steps. C1 is otherwise unrepresentable.
2. **Separate the capabilities `ModelPathInterception` and `ModelGatewayBaseUrl`.** They look alike and are opposites: the first is a protection capability, the second is routing that *removes* protection. Collapsing them invites exactly the over-claim C4 forbids.
3. **`SettingsScope` must be explicit** (`User` / `Project` / `Managed`) and carried in both the plan and the receipt — see C2.
4. **`VerificationResult` must distinguish *exercised* from *read-back* evidence.** Scenario 11.8 shows this is load-bearing: a configuration can be fully applied and verified by read-back while no traffic has ever been protected. Only exercised evidence may raise the level to `GatewayProtected`.
5. **Protection state must be re-derived on read, never cached.** Scenario 11.9 measured ~66 µs from core stop to connections refused; a cached level would keep displaying protection that no longer exists.
6. **The receipt must record the achieved level *and* the evidence that justified it**, so a later `status` can tell "verified once, long ago" from "verified now".

## Backlog amendments

* **AAASM-5281** takes on C1 (CA-trust plumbing) and C5 (side-channel coverage). C1 is the single highest-value item in the remaining Epic — without it the product's headline protection claim is a no-op.
* **AAASM-5277** takes on the six contract changes above; the capability enum gains the `ModelPathInterception` / `ModelGatewayBaseUrl` split and an explicit `SettingsScope`.
* **AAASM-5278** must state the byte-exactness limitation (C3) as an accepted constraint with its reconsideration trigger, and owns replacing `tests/spike_support/{receipt,status}.rs`.
* **AAASM-5283** should promote scenarios 11.1–11.11 from this harness rather than rewriting them, keeping the two negative assertions (11.10 observe-mode forwards, 11.11 unmanaged launch bypasses) — they are what stop "monitoring" being displayed as "protected".
* **AAASM-5284** must publish the demonstrated-versus-inferred bypass split verbatim, and must not claim non-overridable enforcement (C6).
* **New follow-up required:** measure the endpoint managed-settings path on a managed/MDM macOS device. It is independently deliverable, needs hardware and privilege this Spike deliberately did not use, and introduces a **privileged install step** — so it is a product decision, not an engineering default.

## What the Spike does *not* license

* No claim of host-level bypass prevention. Ten bypasses remain inferred-but-undemonstrated and three are demonstrated.
* No claim that protection survives an unmanaged launch — measured, and it does not.
* No claim that the deterministic scanner recognises secret shapes outside its pattern set.
