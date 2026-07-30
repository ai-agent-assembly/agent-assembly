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
