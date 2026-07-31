# Authoring a dev-tool adapter

This guide explains how to write an adapter that plugs an AI dev tool into
Agent Assembly's governance framework. The in-repo sample at
[`examples/aa-devtool-sample-myeditor/`][sample-crate] is a working, minimal
crate to copy from.

[sample-crate]: https://github.com/ai-agent-assembly/agent-assembly/tree/HEAD/examples/aa-devtool-sample-myeditor

> **Read [ADR 0030][adr0030] first.** It fixes the trust model this guide
> operates inside: which side owns which decision, what an adapter is allowed to
> see, and why the packaging rules below are what they are.

[adr0030]: ../adr/0030-developer-integration-boundaries-and-trust-model.md

---

## Two traits, and which one you want

There are two adapter contracts in the tree. New adapters implement the first.

| Trait | Where | Status |
|---|---|---|
| **`DevToolIntegration`** | `aa-core/src/integration/contract.rs` | **The contract.** Lifecycle-aware: plan, status, verify, removal, capability declaration. Implement this. |
| `DevToolAdapter` | `aa-core/src/dev_tool.rs` | Legacy, retained unchanged for the migration (ADR 0030 §7). Bridged by `LegacyAdapterShim`. |

`LegacyAdapterShim<A: DevToolAdapter>` is generic over *any* `DevToolAdapter`,
so an existing adapter — including one out of tree that this repo has never
seen — keeps compiling and gains a working lifecycle without being rewritten.
The sample crate is still a `DevToolAdapter` and is carried by the shim.

What the shim costs you is worth knowing before you decide to stay on the old
trait: a legacy adapter can substantiate only detection and managed-settings
writing. Everything else the old trait exposes is either unverifiable or a
documented no-op (`apply_mcp_governance` returns `Ok(())` for tools with no MCP;
`build_launch_command` fails at run time for tools that cannot be launched), so
the shim cannot tell a working mechanism from a stub and **declares neither**.
A shimmed adapter is therefore capped at `Integrated` and can never plan
`GatewayProtected`, and its plan carries a warning saying so.

### `DevToolIntegration` — the surface you implement

| Method | Async | Purpose |
|---|---|---|
| `fn capabilities(&self) -> DevToolCapabilities` | sync | Declare which integration mechanisms exist for this tool. |
| `fn detect(&self) -> Option<DevToolInfo>` | sync | Is the tool installed and readable? No network I/O. |
| `fn version_support(&self) -> VersionSupport` | sync | Which tool versions this adapter understands, plus its own version and lifecycle schema. |
| `async fn plan_integration(&self, &IntegrationRequest) -> Result<IntegrationPlan, AdapterError>` | async | **Author** the steps. Reading the host to decide them is expected; writing to it is not. |
| `async fn integration_status(&self, Option<&IntegrationReceipt>) -> Result<IntegrationStatus, AdapterError>` | async | What is true now, with the evidence. Derived on every call, never cached. |
| `async fn verify_integration(&self, &IntegrationReceipt) -> Result<VerificationResult, AdapterError>` | async | Check the receipt's claims still hold. No mechanism ⇒ `Unverifiable`, not `Passed`, and not an error. |
| `async fn plan_removal(&self, &IntegrationReceipt) -> Result<RemovalPlan, AdapterError>` | async | Undo what was *done*, derived from the receipt — not re-derived from current host state. |

Plus three optional mechanism surfaces, each behind an accessor whose default
body returns `None`:

| Accessor | Trait | For |
|---|---|---|
| `as_mcp_governed()` | `McpGovernedTool` | Tools that expose their MCP configuration. |
| `as_launchable()` | `LaunchableTool` | Tools that can be started through a governed launcher. |
| `as_hookable()` | `HookableTool` | Tools that expose installable hooks. |

**A tool that cannot do a thing implements nothing rather than a misleading
no-op.** That is the point of the split: the old trait forced `aa-devtool-codex`
to implement `apply_mcp_governance` as `Ok(())` with a comment saying Codex has
no MCP governance — a tool made to claim a capability and then lie quietly.

### There is deliberately no `apply_integration`

The adapter **authors** a plan; the service **executes** it (ADR 0030 matrix
rows 2 and 3). Putting apply on the adapter trait would re-create the
shared-ownership problem the matrix exists to prevent, and would put rollback
correctness and crash recovery in N places instead of one.

### `build_launch_command` takes a `LaunchSpec`

The launch surface moved onto `LaunchableTool` and takes one struct rather than
five positional arguments:

```rust
fn build_launch_command(&self, spec: &LaunchSpec) -> Result<std::process::Command, AdapterError>;
```

`LaunchSpec` carries `tool_args`, `agent_id`, `team_id`, `proxy_addr` **and an
`env` map**. The env map is not tidiness: a proxy address alone will not make an
Electron/Node tool trust the intercepting proxy — `NODE_EXTRA_CA_CERTS` has to
point at the CA an earlier plan step materialised, and a launch surface with no
way to carry that variable cannot express the highest-value fix the AAASM-5276
spike identified.

The legacy five-argument `DevToolAdapter::build_launch_command` still exists on
the old trait. In either form, return `AdapterError::LaunchFailed` only for
genuine run-time failures (the binary has moved, an argument cannot be encoded)
— *"this tool has no launch command"* is a capability declaration, not an error.

---

## Depend on `aa-devtool-contract`, never on `aa-core`

```toml
[dependencies]
aa-devtool-contract = { path = "../../aa-devtool-contract" }
async-trait  = "0.1"
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
```

`aa-devtool-contract` is a **capability-restricted facade** (AAASM-3565): it
depends on the full `aa-core` internally and re-exports only the audited symbol
set an adapter needs. A smuggled call into an unrelated `aa-core` subsystem —
`aa_core::storage::…`, identity, gateway credential types — is a **compile
error** in an adapter crate rather than a silent capability.

This is enforced, not merely recommended. A CI job rejects any
`aa-devtool-*/Cargo.toml` that declares a direct `aa-core` dependency
(`.github/workflows/ci.yml`, "Enforce devtool contract boundary"). The sample
crate under `examples/` follows the same rule.

Adding a symbol to the facade widens what every adapter can reach and requires a
security reviewer (see `.github/CODEOWNERS`).

---

## Declare your capabilities honestly — it is checked

`capabilities()` returns a `DevToolCapabilities` mapping each
`IntegrationCapability` to a `CapabilitySupport`:

| `CapabilitySupport` | Meaning |
|---|---|
| `Supported` | The adapter can do this for this tool. |
| `Unsupported { reason }` | It cannot, and `reason` says why in words a user reads in the plan's dry-run output. |
| `RequiresVersion { min, detected }` | The mechanism exists from `min` onwards; `detected` is what was found on this host. |

Two rules govern how declarations are read, and both fail **downward**:

1. **Fail-absent.** A capability that is not declared is *absent* — not
   `Unsupported`, and never supported. An adapter that has not been updated for
   a new capability has not answered the question, and a missing answer is never
   read as a yes. `RequiresVersion` with `detected: None` is absent for the same
   reason: a missing version is a missing comparison.
2. **Declared must match implemented.** Declaring a capability `Supported` while
   its accessor returns `None` is a contract violation, not a style issue —
   everything downstream reads the declaration.

`aa_devtool_contract::capability_conformance(&integration)` is the check for
rule 2, and it is meant to be called **from your own test suite**. It returns
every violation rather than short-circuiting on the first.

### Two capabilities that look alike and are opposites

* `ModelPathInterception` — an AASM component sits *in* the model-bound path and
  inspects what crosses it. This is the **only** mechanism whose exercised
  evidence can justify `GatewayProtected`.
* `ModelGatewayBaseUrl` — the tool honours a configurable model base URL. This
  is **routing, not protection**. The AAASM-5276 spike measured base-URL
  redirection delivering a raw synthetic secret to the provider with no AASM
  component anywhere in the path.

`HttpProxy` is likewise a transport lever: it is often *how* interception is
achieved, but on its own it says nothing about what is on the other end.

---

## Protection state is derived, not declared

Adapters do **not** set a protection level. `integration_status` reports
observations; the state is derived from that evidence on every read
(`aa-core/src/integration/state.rs`, `StateDerivation::derive`). The rule order
is itself part of the contract:

1. An unreadable schema or an incompatible tool version is terminal.
2. The ladder is climbed only as far as the evidence reaches; an unknown version
   caps it at `PartiallyIntegrated`.
3. Drift overrides the rung it replaces, carrying the rung last held.
4. A rung below the planned level, at or above `Integrated`, is reported as
   `Degraded` so the gap is visible rather than silently smaller.

The ladder is `NotInstalled` → `DetectedNotIntegrated` → `PartiallyIntegrated`
→ `Integrated` → `GatewayProtected` → `HostEnforced`. Missing evidence lowers
the reported state; it never raises it. See
[Protection levels](protection-levels.md).

> **`GovernanceLevel` (`L0Discover`–`L3Native`) is a different thing.** It is
> the legacy `DevToolAdapter`'s *static, self-declared* cap. It still exists on
> `DevToolInfo` and in the
> [L0–L3 capability matrix](../governance/capability-matrix.md), but it is not
> the protection state, it is not evidence, and nothing derives from it. Do not
> use it to describe what a tool is currently protected by.

---

## Error handling — use `AdapterError`

Return `aa_devtool_contract::AdapterError` from every fallible method:

| Variant | When |
|---|---|
| `ToolNotFound` | The tool is genuinely not installed (don't conflate with errors). |
| `DetectionFailed(String)` | Permission denied, version probe failed, but the tool may exist. |
| `SettingsGenerationFailed(String)` | Policy contains constructs the tool's native config can't express. |
| `SettingsApplyFailed(io::Error)` | File write failed. |
| `LaunchFailed(String)` | Can't construct a runnable `Command`. |
| `McpConfigFailed(String)` | MCP config malformed or schema mismatch. |
| `Io(#[from] std::io::Error)` | Catch-all for unexpected I/O — use `?`. |
| `Serde(String)` | Stringify your `serde_json::Error` first; the contract deliberately does not depend on `serde_json` at run time. |

The enum is `#[non_exhaustive]`, so future variants will not break your matches
**as long as you include a `_ =>` arm**.

Prefer a capability declaration over an error for anything knowable at plan
time. `aa-devtool-copilot` used to return
`LaunchFailed("GitHub Copilot is a VS Code extension and cannot be launched…")`
— a run-time error for a fact that was knowable before anything ran.

---

## Crate layout — copy from the sample

```
your-adapter/
├── Cargo.toml
├── src/
│   └── lib.rs           # impl DevToolIntegration for YourAdapter
├── tests/
│   └── contract.rs      # capability_conformance + one test per method
└── fixtures/            # hand-rolled inputs for tests; no real binary needed
    └── mcp_servers.json
```

Every adapter's test suite should call `capability_conformance` and assert it
returns no violations. Beyond that, mirror the sample's
[`tests/contract.rs`][sample-tests]: detection present and absent, settings
render and apply, MCP parse / missing / malformed, and — for a launchable tool —
that `LaunchSpec`'s identity, proxy and `env` entries reach `cmd.get_envs()`.

[sample-tests]: https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/examples/aa-devtool-sample-myeditor/tests/contract.rs

If your tests touch process-wide state (env vars, current directory), serialize
them with a `Mutex<()>` exactly as the sample's `EnvVarGuard` does. `cargo test`
runs tests in parallel threads of one process; unscoped mutation races.

---

## How adapters get loaded — build-time linking, by decision

Agent Assembly links adapters **at build time**. An adapter is loaded by linking
its crate into a binary that constructs it explicitly and registers it in an
in-memory registry at startup.

There is **no** `inventory::submit!`-style runtime registration and **no**
dynamic shared-library loading. That is no longer a gap awaiting work: ADR 0030
Decision 6 makes build-time linking the *chosen* model and dynamic loading
**forbidden rather than merely absent** — it would introduce a code-loading
trust boundary for no benefit. The only thing that must vary at run time is
which integrations a given developer installs, and that is *data*: a plan, a
receipt, a capability set, a protection state.

---

## Packaging an out-of-tree adapter

**You cannot publish an adapter to crates.io, and neither can we.** Every
`aa-devtool-*` crate, `aa-devtool-contract` itself, and the sample are all
`publish = false`. There is nothing on crates.io to depend on or to pin.

ADR 0030 §6.3 is the operative statement: a third-party `DevToolIntegration`
impl is supported **as a source crate consumed by a build of AASM**, with
exactly the `aa-devtool-contract` privilege an in-tree adapter has — no
additional capability is available to it, and none is granted by being
third-party. Getting into an official binary requires a PR and a CODEOWNERS
review.

So the two supported routes are:

1. **Consume it in your own build of AASM.** Depend on your adapter crate by
   path or git from the binary you build, and register it at startup.
2. **Upstream it.** Open a PR adding your crate to `[workspace.members]` in the
   root `Cargo.toml`. It goes through CODEOWNERS review like any in-tree
   adapter.

### Versioning

An adapter is coupled to the `aa-devtool-contract` / `aa-core` version it was
built against, and the core distributes as **one versioned unit** (runtime +
gateway + the linked adapters), so a git or path dependency pinned to a tag is
the practical form of that coupling. When a breaking change lands on
`DevToolIntegration`, every adapter is rebuilt against it.

`AdapterError` and `IntegrationCapability` are `#[non_exhaustive]` — adding
variants is not a breaking change, so do not match exhaustively on either.

---

## What is and is not in scope

| Extension point | Status |
|---|---|
| Per-tool adapters for Claude Code / Codex / Copilot / Windsurf / SaaS | **Shipped** (`aa-devtool-*`). Claude Code is the first fully migrated to the lifecycle contract. |
| Governed launcher CLI | **Shipped** as `aasm run`, and the lifecycle as [`aasm integrations`](../cli/integrations.md) — both present on every install channel except crates.io, where `.ci/strip-for-publish.sh` removes them. |
| L0–L3 capability matrix with per-tool boundaries | **Shipped**: [L0–L3 Governance Capability Matrix](../governance/capability-matrix.md). |
| A shared conformance check every adapter imports | **Shipped in part**: `capability_conformance` covers declaration-vs-implementation. A full shared harness is not offered; the sample's `tests/contract.rs` remains the reference for the rest. |
| Automated / dynamic registration (`inventory`, `dlopen`) | **Forbidden**, not pending — ADR 0030 Decision 6. Do not design around it arriving. |
| Publishing adapters to crates.io | **Not available.** Every adapter crate is `publish = false`; see Packaging above. |

If you need something not listed here, file a ticket rather than inventing a
workaround.

---

## See also

* [Onboarding a Developer Integration](onboarding.md) — the lifecycle from the
  operator's side.
* [Protection levels](protection-levels.md) — what each rung claims.
* [Limitations and known bypasses](limitations.md).
* [ADR 0030][adr0030] — the trust model and the packaging decisions.
