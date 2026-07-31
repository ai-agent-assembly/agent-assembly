# Verification Report — AAASM-1112

**Subtask:** AAASM-1112 — Verify F74: Claude Code adapter acceptance criteria
**Parent Story:** AAASM-201 — F74: Claude Code adapter — managed settings, MCP governance, wrapper integration
**Branch:** `v0.0.1/AAASM-1112/test/verification_evidence`
**Date:** 2026-07-31

This report walks every acceptance-criterion bullet of the parent Story, records
the exact commands run and their full result summaries, names every skipped or
not-measured scenario with its reason, and gives a per-AC verdict.

> **Verdict up front: AAASM-1112 CANNOT be signed off, and AAASM-201 must not be
> closed.** AC4 fails verification. See [Findings](#findings) and
> [Sign-off](#sign-off).

---

## 1. Environment record

| Fact | Value |
|---|---|
| Commit under test | `2e5438847cdcdcb2b047c3aeea0516fd5128ed44` (branch cut from `main`) |
| Worktree | `agent-assembly-ws3-conformance` |
| OS | macOS 26.4.1, build 25E253 (`sw_vers`) |
| Architecture | arm64 (Apple silicon) |
| `rustc --version` | `rustc 1.97.0 (2d8144b78 2026-07-07)` |
| `cargo --version` | `cargo 1.97.0 (c980f4866 2026-06-30)` |
| `which claude` | `/opt/homebrew/bin/claude` |
| `claude --version` | `2.1.220 (Claude Code)` |
| `~/.claude` exists | **yes** |

### Source build vs published crate

`aasm run` and `aasm tools` are stripped from the **crates.io-published** crate
(AAASM-5309). Every command below was executed against a **source build** of this
worktree (`cargo build --workspace --tests`, binary at `target/debug/aasm`, 0
errors). AC4 is a behavioural criterion about the launcher, so a source build is
the correct context in which to verify it.

Be precise about which artifact, because the strip is narrower than it reads.
`.ci/strip-for-publish.sh` runs in exactly one job — `publish-crates` in
`release.yml`. The `build` job compiles the **unstripped** tree, and its artifacts
are what the GitHub Release and the Homebrew tap ship. So `cargo install aasm` has
no `aasm run`; a Homebrew or GitHub-Release `aasm` **does**. The defect recorded
below therefore reaches real users on the primary install path — it is not
confined to source builds.

### Real-home safety

`ClaudeCodeAdapter::new()` resolves its binary with `which claude` and its settings
file from `$HOME`, so verification could have rewritten the developer's real
`~/.claude/settings.json`. It did not. Every suite redirects its roots by explicit
injection (`ClaudeCodePaths` / `ClaudeCodeAdapter::with_overrides`) or, for the new
CLI-level test, by setting `HOME` / `PATH` / `CLAUDE_CONFIG_DIR` / `AASM_STATE_DIR` /
`AA_CA_DIR` / `AASM_CLAUDE_MANAGED_ROOT` and the working directory **on the child
`aasm` process only**. Both the conformance suite and the new CLI-level test use
`RealHomeGuard`, which fingerprints the live settings file on **length and mtime
and never reads its contents** — deliberately, because that file is in daily use
and may hold credentials, and a byte comparison would print them into any failure
message and therefore into the CI log. Both passed.

Two honest limits on that guard, since it is cited as a safety claim: it covers
`~/.claude/settings.json` only, so a write to `settings.local.json`, `.mcp.json`,
`~/.claude/projects/` or `~/.aasm/` would not be caught; and where the real file
does not exist — every CI runner — a `None` fingerprint compares equal to `None`,
so the guard is inert there. It is load-bearing on a developer machine, which is
where the risk actually lives.

---

## 2. Commands run and results

All commands executed from the worktree root.

| # | Command | Result |
|---|---|---|
| 1 | `cargo build --workspace --tests` | **PASS** — 0 errors, 6 pre-existing manifest warnings (`default-features` ignored for workspace deps in `aa-core` / `aa-integration-tests` / `aa-storage-postgres`) |
| 2 | `cargo nextest run -p aa-devtool-claude-code` | **PASS** — `134 tests run: 134 passed, 0 skipped` |
| 3 | `cargo nextest run -p aa-core -p aa-runtime` | **PASS** — `932 tests run: 932 passed, 2 skipped` |
| 4 | `AASM_BIN_PATH=$(pwd)/target/debug/aasm cargo nextest run -p aa-cli` | **PASS** — `874 tests run: 874 passed, 0 skipped` |
| 5 | `cargo nextest run -p aa-integration-tests --test conformance_claude_code --no-capture` | **PASS** — `26 tests run: 26 passed, 0 skipped` |
| 6 | `cargo nextest run -p aa-integration-tests --test claude_code_integration_lifecycle` | **PASS** — `12 tests run: 12 passed, 0 skipped` |
| 7 | `AASM_BIN_PATH=… cargo nextest run -p aa-integration-tests --test cli_run` | **PASS** — `9 tests run: 9 passed, 0 skipped` |
| 8 | `cargo nextest run -p aa-devtool` (added: AC3 capability-bridge evidence) | **PASS** — `25 tests run: 25 passed, 0 skipped` |
| 9 | `AASM_BIN_PATH=… cargo nextest run -p aa-integration-tests --test cli_run_claude_governed_launch` (new, this ticket) | **PASS** — `2 tests run: 2 passed, 0 skipped` |
| 10 | `cargo fmt --all -- --check` | **PASS** — clean |
| 11 | `cargo clippy -p aa-integration-tests --all-targets --all-features -- -D warnings` | **PASS** — clean |

**Total: 2 014 tests executed, 2 014 passed, 2 skipped.**

---

## 3. Every skipped / not-measured scenario, with its reason

A skipped scenario proves nothing. The complete list for this run:

| Scope | Item | Mechanism | Reason | Bearing on AAASM-201 |
|---|---|---|---|---|
| `aa-runtime` | `ipc::server::tests::round_trip_latency_under_1ms` | `#[ignore]` | Latency benchmark, not run by default | None — no AC concerns IPC latency |
| `aa-runtime` | `pipeline::tests::pipeline_load_benchmark` | `#[ignore]` | Load benchmark, not run by default | None |
| conformance | — | `require_claude()` / `require_macos()` | **Not triggered.** Both guards passed: this host is macOS and `which claude` found `/opt/homebrew/bin/claude` | — |
| conformance | — | `NOT MEASURED` empty-capture guard | **Not triggered.** The real binary produced traffic (see below) | — |

**No `SKIP [...]` line and no `NOT MEASURED` line appeared anywhere in the
`--no-capture` conformance output.** All 26 conformance scenarios, including the
optional real-tool lane, **actually executed**.

The real-tool lane's measurements, verbatim from the run:

```
MEASURED real binary: exit=None stopped_by_harness=true elapsed=410.647459ms
MEASURED real-binary requests reaching the provider: 3
MEASURED real-binary request lines: [("POST", "/v1/messages?beta=true"),
  ("GET", "/mcp-registry/v0/servers?version=latest&limit=100&visibility=commercial%2Cgsuite%2Centerprise%2Chealth"),
  ("POST", "/v1/messages?beta=true")]
MEASURED real-binary bodies carrying the placeholder: 2 of 3
```

That is a genuine execution of `claude 2.1.220` through the installed launch
environment, with a positive assertion that traffic was recorded and that the
synthetic secret was redacted before reaching the provider — not a vacuous pass.

### The same measurement, reproduced in CI

The run above is a **local** run on the author's machine. A local run is a
credible report; it is not something a reviewer can re-derive. The lane that
takes this measurement in CI (`real-tool` in
`.github/workflows/claude-code-conformance.yml`) is `workflow_dispatch`-only and
had **never been dispatched** — `gh run list --workflow=claude-code-conformance.yml`
showed zero `workflow_dispatch` events across its entire history, and the
`hermetic` and `macos` lanes never install `claude`.

It has now been dispatched against `main`, so this evidence is reproducible:

| | |
|---|---|
| Run | <https://github.com/ai-agent-assembly/agent-assembly/actions/runs/30626265894> |
| Commit | `608c6db3` on `main` |
| Tool | `@anthropic-ai/claude-code@2.1.220` (`claude --version` → `2.1.220 (Claude Code)`) |
| Result | 26 tests run, **26 passed, 0 skipped** |

```
MEASURED real binary: exit=None stopped_by_harness=true elapsed=1.631710875s
MEASURED real-binary requests reaching the provider: 3
MEASURED real-binary bodies carrying the placeholder: 2 of 3
```

Two limits on what that buys, recorded so nobody reads more into it than it
carries. The lane is `continue-on-error: true` and does not run on `main`, so
this is a **snapshot, not a standing gate** — it cannot fail a build and it will
not re-run. And the `NOT MEASURED` empty-capture guard that was not triggered
here returns `Ok(())` when it *is* triggered, so a run that measured nothing
would have been green too. **AAASM-5326** tracks that defect; it is not fixed by
this ticket.

---

## 4. Per-AC evidence map

### AC1 — Detect Claude Code binary on the system (`which claude`, `~/.claude/`)

**Implementation:** `aa-devtool-claude-code/src/lib.rs:293` (`detect`), which calls
`resolve_binary` → `probe_which(CLAUDE_BIN)` at `lib.rs:225` (literally
`Command::new("which").arg("claude")`), and `dot_claude_marker` at `lib.rs:203`.

| Evidence | Executed? |
|---|---|
| `aa-devtool-claude-code/src/lib.rs:506` `detect_returns_none_for_nonexistent_binary_override` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:525` `detect_returns_none_for_version_below_minimum` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:535` `detect_returns_some_for_valid_version` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:550` `detect_normalizes_version_with_prefix` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:561` `detect_returns_none_when_probe_returns_none` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:572` `dot_claude_marker_found_when_dir_exists` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:582` `dot_claude_marker_absent_when_dir_missing` | ✅ executed |
| `aa-integration-tests/tests/cli_run_claude_governed_launch.rs` (**new**) — the CLI resolves the adapter through `aa_devtool::registry` with **no** binary override, so `probe_which` runs for real; the run's own stderr records `tool=claude version=2.1.999 path=…/bin/claude governance_level=L2Enforce`. The stub deliberately reports a version no real release uses, so this line cannot be mistaken for a detection of the developer's own `claude 2.1.220` | ✅ executed |

**Gap found and closed.** Before this ticket, every `detect` test injected
`binary_path_override`, so the `which claude` branch at `lib.rs:190`/`:225` — the
exact mechanism the AC names — was **never exercised by any test**. The new
integration test resolves the adapter the way production does and therefore drives
`probe_which` end to end.

**Residual observation (not a defect):** `detect()` computes `dot_claude_marker()`
into `let _marker` at `lib.rs:203`/`:299` and discards it — the `~/.claude/`
signal influences no output. The code documents this as intentional ("secondary
signal; does not gate detection on its own", because CI hosts may have `claude` on
`PATH` before a first interactive run). The AC says "detect … (`which claude`,
`~/.claude/`)", and both probes exist and are covered.

> **AC1 verdict: SATISFIED** (evidence from executing tests).

---

### AC2 — Generate managed `settings.json` from Agent Assembly policy

**Implementation:** `aa-devtool-claude-code/src/settings.rs:19`
(`map_policy_to_settings`) → `lib.rs:327` (`generate_managed_settings`) →
`lib.rs:332` (`apply_settings`) → `apply.rs` atomic managed-key merge.

| Evidence | Executed? |
|---|---|
| `aa-devtool-claude-code/src/settings.rs:90` `policy_with_bash_allow_emits_allow_bash` | ✅ executed |
| `aa-devtool-claude-code/src/settings.rs:98` `enforce_policy_maps_to_default_mode` | ✅ executed |
| `aa-devtool-claude-code/src/settings.rs:109` `permissive_policy_maps_to_accept_edits` | ✅ executed |
| `aa-devtool-claude-code/src/settings.rs:130` `require_approval_maps_to_plan_mode` | ✅ executed |
| `aa-devtool-claude-code/src/settings.rs:141` `snapshot_full_policy_fixture` | ✅ executed |
| `aa-devtool-claude-code/src/apply.rs:151/168/187` create / preserve-unmanaged / atomic-on-failure | ✅ executed |
| `aa-devtool-claude-code/tests/settings_merge.rs:40/56/74/105` scope resolution + user-key preservation | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:101` `install_is_idempotent_and_records_a_receipt` | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:195` `unrelated_user_configuration_survives_install_repair_and_remove` | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:614` `the_profile_selects_the_tool_action_governance_the_install_writes` | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:1196` `repair_restores_every_managed_key_and_touches_no_user_key` | ✅ executed |

Idempotence is asserted on the **bytes** of the settings file, and the generated
document is written through a real install/repair/remove cycle, not merely
serialised in memory.

**Observation for the record (does not change the verdict):** `aa-cli`'s
`load_policy()` at `aa-cli/src/commands/run.rs:310` returns a hard-coded
`PolicyDocument` with an **empty rule list**. The generator is correct and proven;
the `run` path simply never feeds it a real policy. The AC is about generation,
which the integrations/lifecycle path does drive from a real profile — so this is
recorded, not counted against AC2. It is, however, an additional reason AC4's
"end-to-end" claim does not hold (see Findings).

> **AC2 verdict: SATISFIED** (evidence from executing tests).

---

### AC3 — Apply MCP allow/deny lists to Claude Code's MCP configuration

**Implementation:** two mechanisms.
1. Policy `mcp:<server>` rules → `enabledMcpjsonServers` / `disabledMcpjsonServers`
   (`settings.rs:29-33`), written by `apply_settings`.
2. Direct governance: `lib.rs:406` `apply_mcp_governance` → `apply.rs:104`
   `apply_mcp_governance_at`; planned and receipted in the lifecycle as
   `StepAction::ConfigureMcpServers` over `MCP_KEYS` (`lifecycle.rs:122`, `:678`,
   `:752`, `:1390`).

| Evidence | Executed? |
|---|---|
| `aa-devtool-claude-code/src/settings.rs:119` `mcp_allow_list_emits_enabled_servers` — `mcp:filesystem` Allow / `mcp:search` Deny → `enabled=["filesystem"]`, `disabled=["search"]` | ✅ executed |
| `aa-devtool-claude-code/src/apply.rs:205` `apply_mcp_governance_replaces_lists` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:611` `apply_mcp_governance_writes_to_resolved_path` | ✅ executed |
| `aa-devtool-claude-code/src/lib.rs:671/680` `list_mcp_servers_*` (discovery, global config + `.claude/.mcp.json`) | ✅ executed |
| `aa-devtool-claude-code/tests/settings_merge.rs:143` `mcp_governance_only_touches_active_scope` | ✅ executed |
| `aa-devtool/src/capability_bridge.rs:100–157` five `apply_*` tests (CapabilitySet → allow/deny translation) | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:641` — install writes **both** MCP keys as arrays | ✅ executed |
| `aa-integration-tests/tests/conformance_claude_code.rs:1213` — both MCP keys drifted and restored by `repair` | ✅ executed |

**Observations for the record (do not change the verdict):**
* No conformance scenario populates a **non-empty** MCP allow/deny list from a
  policy through the installed lifecycle — the lifecycle's default document
  (`lifecycle.rs:745-746`) writes empty arrays, and the scenarios assert the keys
  are present and repairable rather than that a specific server was denied. The
  non-empty case is covered at unit/adapter level only.
* `aa-devtool/src/capability_bridge.rs:33` `apply_capability_set` — the translator
  from a policy `CapabilitySet` to `apply_mcp_governance` — has **no caller outside
  its own tests** anywhere in `aa-cli`, `aa-api`, `aa-runtime` or `aa-devtool`.
  The translation is correct and tested; nothing in a shipped command invokes it.

Both observations sit under the AC as written ("apply MCP allow/deny lists to
Claude Code's MCP configuration"), which the adapter demonstrably does.

> **AC3 verdict: SATISFIED** (evidence from executing tests), with the two
> integration-reach observations above recorded.

---

### AC4 — `aa run claude` launches Claude Code with identity, proxy, and monitoring — end-to-end

This AC concerns the **launcher** (`aasm run claude`), not `aasm integrations`. The
AAASM-5283 conformance suite exercises the integrations lifecycle and therefore does
**not** evidence AC4; that distinction is what this section turns on.

#### What the pre-existing tests establish — and what they do not

| Pre-existing evidence | Executed? | What it actually proves |
|---|---|---|
| `aa-integration-tests/tests/cli_run.rs:97–200` — 9 tests | ✅ executed | Only `--dry-run`, which short-circuits at `run.rs:503` **before** `detect()`, before registration and before any spawn. A printed plan is configuration, not behaviour. |
| `aa-cli/tests/run_command.rs:133` `run_command_exits_zero_and_deregisters` | ✅ executed | A child is spawned and register/deregister fire — but through a hand-written `EchoAdapter`, with `proxy_addr: null`. Nothing about the Claude Code adapter; nothing at all about the proxy. |
| `aa-cli/tests/run_command.rs:186` `run_command_propagates_nonzero_exit_and_deregisters` | ✅ executed | Exit-code propagation and deregistration on failure. Same fake-adapter caveat. |
| `aa-cli/src/commands/run.rs:883` `build_child_env_sets_proxy` | ✅ executed | The env **map** is built correctly — one function call short of asserting a launched process received it. It also feeds in `"http://proxy:8080"`, a value that already carries a scheme, which is why it misses Finding (2). |
| `aa-cli/src/commands/run.rs:968` `register_with_gateway_posts_correct_body` | ✅ executed | The registration body is well-formed — against a mock that answers. |
| `aa-cli/src/commands/run.rs:1249` `detected_tool_succeeds` | ✅ executed | `execute_with_adapters` returns `Ok` with a stub adapter and `proxy_addr: null`. |

No pre-existing test launches the real `ClaudeCodeAdapter` through `aasm run claude`
against a gateway and asserts what the launched process observed.

#### New evidence added by this ticket

`aa-integration-tests/tests/cli_run_claude_governed_launch.rs` (see §6).

1. `run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session`
   — real `aasm` binary, real `ClaudeCodeAdapter` via `aa_devtool::registry` (no
   override constructor), a real HTTP gateway that returns identity **and** a
   `proxy_addr`, a real child process, and assertions on what the child read out of
   its **own** environment. **PASS.** Identity (`AA_AGENT_ID`, `AA_TRACE_ID`,
   `AA_SESSION_ID`, `AA_REGISTRATION_ID`, `AA_TEAM_ID`) and the proxy variables all
   reached the launched tool; the gateway recorded exactly one registration
   (`kind=claude_code`, `version=2.1.999`) and exactly one deregistration.

2. `against_the_real_gateway_the_launcher_cannot_register_and_never_starts_the_tool`
   — the same run against the **real** in-process Agent Assembly gateway
   (`aa_api::server::build_app`). **PASS**, and what it measures is the failure:

```
MEASURED `aasm run claude` against the real gateway at http://127.0.0.1:20643: exit=Some(1)
stderr:
tool=claude version=2.1.999 path=/…/bin/claude governance_level=L2Enforce
error: gateway registration failed: HTTP 405 Method Not Allowed
```

`aasm run` registers by `POST /api/v1/agents` (`aa-cli/src/commands/run.rs:209`).
The API serves only `GET` there —
`aa-api/src/routes/mod.rs:124` mounts `.route("/agents", get(agents::list_agents))`,
and `openapi/v1.yaml` declares `get` as the sole method on `/api/v1/agents`. There
is no `POST /api/v1/agents` handler anywhere in `aa-api`, and the string
`proxy_addr` — the response field the launcher keys its proxy wiring on — does not
occur anywhere in `aa-api`, `aa-gateway`, `aa-proto` or `openapi/`.

Consequence: against any shipped gateway, `aasm run claude` **exits 1 without ever
launching Claude Code**. Test 1 passes only because its mock gateway synthesises an
endpoint and a response field that the product does not have.

> **AC4 verdict: NOT EVIDENCED — verification FAILED.**
> The AC's three components are each demonstrated *conditionally* (test 1 proves
> identity, proxy and session monitoring all flow correctly **given** a gateway that
> answers `POST /api/v1/agents`), but the end-to-end claim is false against the real
> product: the launcher cannot register, so Claude Code is never launched at all.

---

### AC5 — Unit tests for settings generation and MCP policy application

| Evidence | Executed? |
|---|---|
| Settings generation: `settings.rs:90/98/109/130/141` (5 tests, incl. a full-policy snapshot) | ✅ executed |
| Settings application: `apply.rs:151/168/187` (create, preserve-unmanaged, atomic-on-failure) | ✅ executed |
| MCP policy application: `settings.rs:119`, `apply.rs:205`, `lib.rs:611`, `settings_merge.rs:143` | ✅ executed |
| MCP discovery: `lib.rs:671/680` | ✅ executed |
| Capability→MCP translation: `capability_bridge.rs` × 5 | ✅ executed |
| Crate totals | `aa-devtool-claude-code` 134/134, `aa-devtool` 25/25 |

> **AC5 verdict: SATISFIED** (evidence from executing tests).

---

## 5. Findings

### Finding (1) — CRITICAL: `aasm run` registers against an endpoint the gateway does not serve

* **Severity:** High — AC4 of AAASM-201 is unachievable as shipped.
* **Expected:** `aasm run claude` registers the session, launches Claude Code with
  identity + proxy, and deregisters on exit.
* **Actual:** `POST /api/v1/agents` returns **HTTP 405 Method Not Allowed**;
  `register_with_gateway` (`aa-cli/src/commands/run.rs:209`) errors and
  `execute_with_adapters` returns before `build_launch_command`. Claude Code is
  never launched. Exit code 1.
* **Repro:** `cargo nextest run -p aa-integration-tests --test cli_run_claude_governed_launch -E 'test(real_gateway)' --no-capture`
* **Root cause:** `aa-api/src/routes/mod.rs:124` mounts only
  `get(agents::list_agents)` on `/agents`. `openapi/v1.yaml` agrees. Agent
  registration is a gRPC-only surface; the REST route the CLI calls was never added.
* **Secondary:** the response field `proxy_addr` that `run.rs` reads to wire the
  proxy does not exist in any gateway schema, so even with the route added the proxy
  leg would stay dark.
* **Recommended Bug Subtask** (under AAASM-201, component `agent-assembly`):
  *`🐛 aasm run claude cannot register — POST /api/v1/agents returns 405, tool is never launched`*.
  Fix direction is a product decision: add the REST registration route (returning
  `registration_id` / `trace_id` / `session_id` / `proxy_addr`), or repoint
  `aasm run` at the gRPC registration path the SDKs use. Either way `proxy_addr`
  must become part of the contract or the proxy clause of AC4 stays unevidenced.

### Finding (2) — MEDIUM: the launcher hands the tool a scheme-less proxy value

* **Severity:** Medium — latent; masked today by Finding (1).
* **Expected:** the child receives `HTTPS_PROXY=http://<host>:<port>`.
  `ClaudeCodeAdapter::build_launch_command` (`aa-devtool-claude-code/src/lib.rs:373-381`)
  normalises `host:port` → `http://host:port` deliberately, with a WHY comment.
* **Actual:** the child receives the bare `host:port`. Measured directly:
  `HTTPS_PROXY=127.0.0.1:19999`, `HTTP_PROXY=127.0.0.1:19999`.
* **Corrected root cause (this report originally got it wrong).** The first
  version of this finding described an *overlay* — `build_child_env`'s value
  applied on top of the adapter's. It is not an overlay, it is a **total
  discard**, and the proxy URL is only its most visible casualty.
  `spawn_and_wait` (`run.rs:431`) does not launch the `Command` the adapter
  built. It constructs a fresh `tokio::process::Command` from
  `cmd.get_program()` and `cmd.get_args()` and applies **only** `child_env`;
  `cmd.get_envs()` is never read. Everything `build_launch_command` set is
  therefore thrown away — including `NODE_EXTRA_CA_CERTS`, the sole mechanism
  by which Claude Code's Node runtime trusts the AASM certificate authority.
  `cmd.envs(&child_env)` at `run.rs:547` is dead code. Tracked as
  **AAASM-5327**, which supersedes this finding's analysis.
  The distinction matters: re-ordering `cmd.envs()` — the fix the original
  wording pointed at — would have changed nothing, because the `Command`
  carrying those variables is discarded wholesale.
* **Why it was missed:** `build_child_env_sets_proxy` (`run.rs:883`) supplies
  `"http://proxy:8080"` — a value that already has a scheme — so the branch that
  matters is never exercised.
* **Impact:** Claude Code is a Node application; Node proxy agents generally require
  a parseable URL and reject or ignore a scheme-less value. A tool that ignores
  `HTTPS_PROXY` goes direct, and a proxy that never sees the traffic cannot inspect
  it — the silent-bypass failure mode AAASM-5276 already documented for
  `NODE_EXTRA_CA_CERTS`. That comparison turned out to be literal rather than
  analogous: `NODE_EXTRA_CA_CERTS` is discarded on the same code path, so even a
  tool that honoured the proxy could not have its TLS terminated.
* **Recommended Bug Subtask** (under AAASM-201, component `agent-assembly`):
  *`🐛 aasm run: build_child_env overwrites the adapter's normalised proxy URL with a scheme-less host:port`*.
* **Status:** pinned by an assertion in the new test so a fix cannot land silently
  (the test fails and forces this report's AC4 verdict to be re-derived).

### Observation (3) — `aasm run` never applies a real policy

`load_policy()` (`aa-cli/src/commands/run.rs:310`) returns a hard-coded
`PolicyDocument` with an empty rule list, so the managed settings `aasm run` writes
carry no permissions and no MCP allow/deny entries. Not counted against AC2/AC3
(both are about the adapter's generation/application, which is proven), but it is a
third reason AC4's "end-to-end" wording overstates the shipped behaviour. Worth a
follow-up ticket rather than a Bug Subtask.

### Observation (4) — `apply_capability_set` has no production caller

`aa-devtool/src/capability_bridge.rs:33` translates a policy `CapabilitySet` into an
`apply_mcp_governance` call. It is fully unit-tested and invoked by nothing outside
those tests. Recorded under AC3; not a defect against the AC as written.

---

## 6. Test added by this verification

**File:** `aa-integration-tests/tests/cli_run_claude_governed_launch.rs` (new)

Added because AC4 had no executing test that demonstrated it. Two tests:

1. `run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session` —
   AC4's positive half, against a mock gateway that supplies the contract the
   launcher expects.
2. `against_the_real_gateway_the_launcher_cannot_register_and_never_starts_the_tool` —
   AC4's honest floor, against the real `aa-api` router. Asserting the failure is
   deliberate: a run that cannot register must not read as a governed launch, and if
   the endpoint is ever added this test fails and forces AC4's verdict to be
   re-derived rather than silently inherited.

A visible `SKIP` is printed on non-Unix hosts (the test needs a POSIX shell
stand-in for the `claude` binary); it does not compile away to a silently empty
test binary.

### Load-bearing proof

Both guards were broken, watched to fail, and reverted.

| Mutation | Expected | Observed |
|---|---|---|
| Add `--no-proxy` to the launch args in test 1 (production behaviour changes: proxy env is not injected) | proxy assertion fails | **FAILED** — `left: Some("") right: Some("127.0.0.1:19999")`, plus the dump showing `HTTPS_PROXY=` and `HTTP_PROXY=` empty |
| Invert `assert!(!dump.exists())` → `assert!(dump.exists())` in test 2 | never-launched guard fails | **FAILED** — `the tool must not have been launched when registration failed — an ungoverned launch is worse than no launch` |

After reverting both, `2 tests run: 2 passed, 0 skipped`.

`cargo fmt --all -- --check` clean;
`cargo clippy -p aa-integration-tests --all-targets --all-features -- -D warnings` clean.

---

## 7. Rerun evidence after changes

No production code was changed by this verification — the two findings are reported
for the orchestrator to file, not fixed here. Suites re-run after the new test file
landed and after `cargo fmt`:

| Command | Result |
|---|---|
| `cargo nextest run -p aa-integration-tests --test cli_run_claude_governed_launch` | `2 tests run: 2 passed, 0 skipped` |
| `cargo nextest run -p aa-integration-tests --test conformance_claude_code` | `26 tests run: 26 passed, 0 skipped` |
| `cargo nextest run -p aa-devtool-claude-code` | `134 tests run: 134 passed, 0 skipped` |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -p aa-integration-tests --all-targets --all-features -- -D warnings` | clean |

---

## 8. Sign-off

| AC | Verdict | Evidence executed? |
|---|---|---|
| AC1 — detect binary (`which claude`, `~/.claude/`) | **Satisfied** | Yes |
| AC2 — generate managed `settings.json` from policy | **Satisfied** | Yes |
| AC3 — apply MCP allow/deny lists | **Satisfied** | Yes |
| AC4 — `aa run claude` launches with identity, proxy, monitoring end-to-end | **NOT EVIDENCED — FAILED** | Yes (the failure was measured, not inferred) |
| AC5 — unit tests for settings generation and MCP policy application | **Satisfied** | Yes |

**4 of 5 parent acceptance criteria are satisfied. AC4 fails verification.**

> **AAASM-1112 is NOT signed off.** Its own acceptance criteria require sign-off
> only "when 100% of parent Story AC are satisfied", and require a Bug Subtask to be
> opened under the parent Story for any AC that fails verification. Two Bug Subtasks
> are recommended in §5 (Finding 1 — High; Finding 2 — Medium).
>
> **AAASM-201 must NOT be closed on this evidence.** AC4 is not a documentation or
> coverage gap: `aasm run claude` against a shipped Agent Assembly gateway exits 1
> with `HTTP 405 Method Not Allowed` and never launches Claude Code.

AAASM-1112 can be signed off, and AAASM-201 closed, once Finding (1) is fixed,
Finding (2) is fixed or explicitly accepted, and
`cli_run_claude_governed_launch.rs` is updated so that the real-gateway test asserts
a successful governed launch rather than the current honest floor.
