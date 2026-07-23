# Authoring a custom `DevToolAdapter` plugin

This guide explains how to write a custom AI-dev-tool adapter that plugs
into Agent Assembly's governance framework. The reference
implementation is the in-repo sample at
[`examples/aa-devtool-sample-myeditor/`][sample-crate] — copy and
adapt.

[sample-crate]: https://github.com/ai-agent-assembly/agent-assembly/tree/HEAD/examples/aa-devtool-sample-myeditor

---

## Trait surface — what you implement

The contract lives in [`aa_core::DevToolAdapter`][trait]:

| Method | Async | Purpose |
|---|---|---|
| `fn detect(&self) -> Option<DevToolInfo>` | sync | Probe the host: is the tool installed and readable? |
| `async fn generate_managed_settings(&self, policy: &PolicyDocument) -> Result<String, AdapterError>` | async | Translate the Agent Assembly policy into the tool's native config format. |
| `async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError>` | async | Write the rendered settings into the tool's configuration surface. |
| `fn build_launch_command(&self, tool_args, agent_id, team_id, proxy_addr) -> Result<Command, AdapterError>` | sync | Build a `std::process::Command` with governance wiring (identity, proxy). |
| `async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError>` | async | Read the tool's currently-configured MCP servers. |
| `async fn apply_mcp_governance(&self, allowed, denied) -> Result<(), AdapterError>` | async | Apply an allow/deny list to the tool's MCP config. |
| `fn governance_level(&self) -> GovernanceLevel` | sync | Static cap (`L0Discover`–`L3Native`) for what this adapter can achieve. |

[trait]: https://docs.rs/aa-core/latest/aa_core/trait.DevToolAdapter.html

The trait is **object-safe** — it can be used as `&dyn DevToolAdapter`
or `Box<dyn DevToolAdapter>`. This is enforced by a compile-time test
in `aa-core/src/dev_tool.rs::tests::trait_is_object_safe` (added by
AAASM-925). Object-safety is required because the gateway and the
forthcoming `aa run` launcher dispatch through trait objects, not
generics.

The async methods are implemented via the [`async_trait`][async-trait]
macro, which desugars `async fn` into `Pin<Box<dyn Future + Send + '_>>`
return types. Your adapter crate must `use async_trait::async_trait`
and annotate the impl block with `#[async_trait]` exactly as the sample
does.

[async-trait]: https://docs.rs/async-trait

---

## Crate layout — copy from the sample

```
your-adapter/
├── Cargo.toml
├── src/
│   └── lib.rs           # impl DevToolAdapter for YourAdapter
├── tests/
│   └── contract.rs      # one test per trait method (mirror the sample)
└── fixtures/            # hand-rolled inputs for tests; no real binary needed
    └── mcp_servers.json
```

Required `Cargo.toml` dependencies (see the sample's `Cargo.toml` for the exact lines):

| Dep | Purpose |
|---|---|
| `aa-core` (path or version) with `features = ["std", "serde"]` | trait + types + error |
| `async-trait = "0.1"` | for the `#[async_trait]` impl |
| `serde` + `serde_json` | rendering managed settings, parsing tool config |

For dev-dependencies the sample uses `tempfile` (filesystem tests) and
`tokio` (async test driver). Pick what your tests need.

---

## How adapters get loaded — current pattern

Right now Agent Assembly uses **build-time linking**: an adapter is
loaded by linking its crate into a binary that constructs the adapter
explicitly and either calls it directly or registers it in an
in-memory map keyed by the tool's discriminator (e.g. by
`DevToolKind::Custom("myeditor".into())`).

There is **no** `inventory::submit!`-style runtime registration in
`aa-core` today, and there is no dynamic shared-library loading. Both
were proposed in early designs but neither has been implemented; do
not write code that assumes either exists. When the `aa run` launcher
(AAASM-200) lands, it will publish the contract for how it expects to
discover adapters; until then, the integration shape is "construct an
instance and pass it in."

If you are publishing an out-of-tree adapter today, the pattern is:

1. Publish your adapter as a normal crate (`cargo publish` or path /
   git dependency in the consuming binary).
2. Have the consuming binary depend on your crate and call
   `YourAdapter::new(...)` to construct it.
3. Pass the `Box<dyn DevToolAdapter>` to whatever code consumes
   adapters.

This is the same pattern the sample's contract tests use.

---

## Versioning expectations

Adapters are tightly coupled to the `aa-core` major version they were
built against. Pin `aa-core` exactly in your `Cargo.toml`:

```toml
[dependencies]
aa-core = { version = "=0.0.1", features = ["std", "serde"] }
```

When `aa-core` makes a breaking change to `DevToolAdapter`, every
adapter crate has to be rebuilt against the new major. `AdapterError`
is `#[non_exhaustive]` — adding new error variants is **not** a
breaking change, so do not match exhaustively on it.

---

## Contract tests — required for every adapter

The sample's [`tests/contract.rs`][sample-tests] is the **reference
test suite** every adapter should mirror. Adapt each test to your
tool's specifics:

[sample-tests]: https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/examples/aa-devtool-sample-myeditor/tests/contract.rs

| Sample test | What it verifies | What you change |
|---|---|---|
| `myeditor_adapter_is_object_safe_and_send_sync` | `&dyn YourAdapter` and `Box<dyn YourAdapter>: Send + Sync` compile. | Replace the type. The test body is mechanical. |
| `detect_returns_none_when_env_var_unset` / `..._when_env_var_set` | `detect` returns `None` when the tool is absent and a populated `DevToolInfo` when it's present. | Replace the env-var probe with whatever your detection mechanism is (`which`, install-marker file, etc.). |
| `generate_managed_settings_returns_valid_json` | Output is parseable as the tool's native format. | Replace the parse target with your tool's actual schema. |
| `apply_settings_writes_managed_json_next_to_fixture` | Side effect is observable on disk. | Use `tempfile::tempdir()` so tests don't leak. |
| `build_launch_command_injects_identity_and_proxy` / `..._errors_when_binary_unset` | `AA_AGENT_ID` / `AA_TEAM_ID` / `HTTPS_PROXY` end up in `cmd.get_envs()`; missing binary returns `LaunchFailed`. | Adjust the env-var names if your tool uses different conventions. |
| `list_mcp_servers_*` (×3) | Parses the fixture; returns `Io` on missing file; returns `McpConfigFailed` on malformed JSON. | Use a fixture matching your tool's actual MCP config layout. |
| `apply_mcp_governance_is_a_noop_in_sample` | The method completes successfully. | Replace with assertions about the actual side effect your adapter performs. |
| `governance_level_is_l1_observe` | Static cap value. | Pick the right level for your tool category (see below). |

If your tests touch process-wide state (env vars, current working
directory, etc.), use a `Mutex<()>` to serialize them, exactly as the
sample's `EnvVarGuard` does. `cargo test` runs tests in parallel
threads of the same process; unscoped mutation races otherwise.

---

## Picking the right `GovernanceLevel`

Each adapter publishes the **highest** governance level it can
practically achieve. Use this rough mapping (from the spec, Epic 14
section 4486–4558):

| Tool category | Typical level | Why |
|---|---|---|
| CLI / local agent (e.g. Claude Code, Codex CLI) | **L3Native** when SDK-integrated; **L2Enforce** otherwise | Full process control + filesystem access |
| IDE agent (Copilot, Windsurf, MyEditor) | **L1Observe** | IDE host limits hooks; usually no enforcement surface |
| SaaS / cloud agent | **L0Discover** to **L1Observe** | Mostly black-box; eBPF/proxy may surface external traffic |
| Custom / unknown | **L0Discover** | Default until measured |

`detect()`'s `DevToolInfo::governance_level` and the trait's
`governance_level()` method **must agree** — the gateway uses one to
sanity-check the other.

---

## Error handling — use `AdapterError`

Return [`aa_core::AdapterError`][adapter-error] from every fallible
method. The variants and when to use them:

[adapter-error]: https://docs.rs/aa-core/latest/aa_core/enum.AdapterError.html

| Variant | When |
|---|---|
| `ToolNotFound` | Tool is genuinely not installed (don't conflate with errors). |
| `DetectionFailed(String)` | Permission denied, version probe failed, but the tool may exist. |
| `SettingsGenerationFailed(String)` | Policy contains constructs the tool's native config can't express. |
| `SettingsApplyFailed(io::Error)` | File write failed. |
| `LaunchFailed(String)` | Can't construct a runnable `Command`. |
| `McpConfigFailed(String)` | MCP config malformed or schema mismatch. |
| `Io(#[from] std::io::Error)` | Catch-all for unexpected I/O errors — use `?`. |
| `Serde(String)` | Stringify your `serde_json::Error` (`.to_string()`) before constructing this; `aa-core` deliberately does not depend on `serde_json` at runtime. |

The enum is `#[non_exhaustive]`, so future variants will not break
your matches **as long as you include a `_ =>` arm**.

---

## What's not yet in scope (out-of-scope today)

The following extension points are reasonable and may be added later,
but are **not** in `aa-core` or `aa-cli` as of this writing. If you
need any of these, file a ticket; do not invent a workaround.

| Future extension point | Status | Tracking |
|---|---|---|
| Automated registration mechanism (`inventory::submit!`, dynamic shared-library loading, etc.) | Not implemented. Adapters are constructed explicitly today. | (no ticket yet — open one if needed) |
| Shared `aa-devtool-contract-tests` crate that every adapter imports | Not implemented. The sample's `tests/contract.rs` is the reference; copy and adapt for now. | (no ticket yet — open one if needed) |
| Per-tool adapter examples for Claude Code / Codex / Copilot / Windsurf / SaaS | In flight. | AAASM-201..205, AAASM-918 |
| `aa run` launcher CLI (the binary that consumes `Box<dyn DevToolAdapter>` registrations) | In flight. | AAASM-200 |
| L0–L3 governance capability matrix doc with per-tool boundaries | In flight. | AAASM-1064 |

---

## Submitting your adapter

1. Implement `DevToolAdapter` in your crate; mirror `tests/contract.rs`.
2. Run `cargo test -p your-adapter` locally.
3. If you want your adapter merged into the workspace alongside the
   sample, open a PR adding it to `[workspace.members]` in the root
   `Cargo.toml`.
4. If you want it as a third-party crate, publish it to `crates.io`
   with `aa-core` pinned to the exact version you tested against.

The sample at
[`examples/aa-devtool-sample-myeditor/`][sample-crate] is intentionally
small and complete — when in doubt, follow it.
