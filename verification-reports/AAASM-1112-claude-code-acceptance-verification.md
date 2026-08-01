# Verification Report — AAASM-1112

**Subtask:** AAASM-1112 — Verify F74: Claude Code adapter acceptance criteria
**Parent Story:** AAASM-201 — F74: Claude Code adapter — managed settings, MCP governance, wrapper integration

This report walks every acceptance-criterion bullet of the parent Story, records
the exact commands run and their full result summaries, names every skipped or
not-measured scenario with its reason, and gives a per-AC verdict.

## Runs recorded in this document

| # | Date | Commit | Outcome |
|---|---|---|---|
| 1 | 2026-07-31 | `2e543884` | **AC4 FAILED.** 4 of 5 AC satisfied. §1–§8 below. |
| 2 | 2026-08-01 | `14de683b` | **All 5 AC satisfied.** Re-derived from scratch on merged `main`. [§9](#9-re-verification-2026-08-01--merged-main-14de683b). |

> **Current verdict — run 2, 2026-08-01: AAASM-1112 can be signed off and
> AAASM-201 can be closed.** See [§9.9 Sign-off](#99-sign-off-re-derived).
>
> **Run 1's AC4 failure was correct when written and is retained in full.** Every
> section from §1 to §8 records the state of the tree at `2e543884` and has *not*
> been edited to match the current outcome — a verification report that rewrites
> its own history is worthless. Run 2 is an independent re-derivation, not an
> amendment: no verdict was carried forward, and every command was re-executed.

---

# Run 1 — 2026-07-31, commit `2e543884` (superseded, retained verbatim)

**Branch:** `v0.0.1/AAASM-1112/test/verification_evidence`
**Date:** 2026-07-31

> **Verdict up front: AAASM-1112 CANNOT be signed off, and AAASM-201 must not be
> closed.** AC4 fails verification. See [Findings](#findings) and
> [Sign-off](#sign-off).
>
> *(Retained as written on 2026-07-31. Superseded by [§9](#9-re-verification-2026-08-01--merged-main-14de683b);
> every defect named below has since been fixed and merged.)*

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

*(End of run 1. The conditions this paragraph set out have since been met — see
[§9.6](#96-the-conditions-run-1-set-for-sign-off).)*

---
---

# 9. Re-verification 2026-08-01 — merged `main` `14de683b`

**Branch:** `v0.0.1/AAASM-1112/test/reverify_ac4`
**Date:** 2026-08-01

Every acceptance criterion of AAASM-201 was **re-derived from scratch** against
merged `main`. No verdict from run 1 was carried forward: the AC wording was
re-read from Jira (not from run 1's paraphrase), every command was re-executed on
this commit, and every per-AC verdict below rests on output produced on
2026-08-01. Where run 1's conclusion happens to be reproduced, it is because the
evidence reproduced it.

## 9.1 Environment record

| Fact | Value |
|---|---|
| Commit under test | `14de683bf10fa9032bd2fa42ee39e55313e9c02b` (merged `main`, tip) |
| Branch cut from | `remote/main` |
| Worktree | `agent-assembly-ws13-reverify` |
| OS | macOS 26.4.1, build 25E253 (`sw_vers`) |
| Architecture | arm64 (Apple silicon, `uname -m`) |
| `rustc --version` | `rustc 1.97.0 (2d8144b78 2026-07-07)` |
| `cargo --version` | `cargo 1.97.0 (c980f4866 2026-06-30)` |
| `cargo nextest --version` | `cargo-nextest 0.9.133 (65e806bd5 2026-04-14)`, host `aarch64-apple-darwin` |
| `which claude` | `/opt/homebrew/bin/claude` |
| `claude --version` | `2.1.220 (Claude Code)` |
| `~/.claude` exists | **yes** (`/Users/bryant/.claude/`) |
| Workspace version | `0.0.1-rc.6` |

Source build, as in run 1: `aasm run` and `aasm tools` are stripped from the
crates.io-published crate (AAASM-5309) but **not** from the GitHub-Release or
Homebrew artifacts, so a source build is the correct — and representative —
context for a behavioural AC about the launcher.

### The AC wording, read from Jira on 2026-08-01

Fetched with `getJiraIssue` against `lightning-dust-mite.atlassian.net`,
`AAASM-201`, field `description`. The five bullets, verbatim:

* Detect Claude Code binary on the system (`which claude`, `~/.claude/`)
* Generate managed `settings.json` from Agent Assembly policy
* Apply MCP allow/deny lists to Claude Code's MCP configuration
* `aa run claude` launches Claude Code with identity, proxy, and monitoring — end-to-end
* Unit tests for settings generation and MCP policy application

AAASM-1112's own AC additionally require: walking every parent bullet with
evidence; running all named tests with realistic data; opening a Bug Subtask for
any AC that fails; and signing off only when 100% of parent AC are satisfied.

### What landed between run 1 and run 2

| Ticket | Merge | Change |
|---|---|---|
| AAASM-5327 | `f2ecb4dc` (#1855) | `spawn_and_wait` no longer discards the adapter's environment — `NODE_EXTRA_CA_CERTS` and the normalised proxy URL now reach the child |
| AAASM-5324 | via `f2ecb4dc` | Proxy URL normalisation (`host:port` → `http://host:port`) survives to the child |
| AAASM-5323 (1) | `182c149a` (#1861) | `aasm run` resolves the proxy endpoint host-side from a verified proxy state record, and **refuses to launch** when it cannot |
| AAASM-5323 (2) | `9fffa6c1` (#1863) | `aasm run` registers over gRPC through `aa-sdk-client`, under the same Ed25519/DID possession gate as the SDKs |
| AAASM-5326 | `14de683b` (#1869) | Conformance workflow parses on `main`; the real-tool lane's zero-measurement escape is closed (see §9.4) |

These are recorded as context, not as evidence. **A fixed defect is not a
verification.** Every verdict below is derived from output produced on this
commit.

## 9.2 Commands run and results

All commands executed from the worktree root at `14de683b`.

| # | Command | Result |
|---|---|---|
| 1 | `cargo build --workspace --tests` | **PASS** — `0 errors, 6 warnings` (the 6 pre-existing `default-features is ignored for workspace deps` manifest warnings in `aa-integration-tests` ×2, `aa-storage-postgres` ×1, `aa-core` ×3) |
| 2 | `cargo nextest run -p aa-cli -p aa-devtool-claude-code -p aa-core -p aa-runtime -p aa-devtool` | **PASS** — `Summary [17.019s] 2025 tests run: 2025 passed, 2 skipped` |
| 3 | `cargo nextest run -p aa-integration-tests --test cli_run --test cli_run_claude_launch_env --test cli_run_trusted_proxy --test cli_run_claude_governed_launch --test claude_code_integration_lifecycle` | **PASS** — `Summary [304.460s] 36 tests run: 36 passed (23 slow), 0 skipped` |
| 4 | `cargo nextest run -p aa-cli --test run_registration_gateway --test run_command` | **PASS** — `Summary [0.022s] 10 tests run: 10 passed, 0 skipped` |
| 5 | `cargo nextest run -p aa-integration-tests --test conformance_claude_code --no-capture` | **PASS** — `Summary [0.966s] 26 tests run: 26 passed, 0 skipped` |
| 6 | `cargo fmt --all -- --check` | **PASS** — clean |

**Nothing failed.** Total distinct tests executed on this commit: **2 097**
(2 025 + 36 + 10 + 26), all passing, 2 skipped (both `#[ignore]` benchmarks —
see §9.7).

Per-crate breakdown of command 2, each run individually to attribute the totals:

| Crate | Result |
|---|---|
| `aa-devtool-claude-code` | `134 tests run: 134 passed, 0 skipped` |
| `aa-devtool` | `25 tests run: 25 passed, 0 skipped` |
| `aa-core` | `406 tests run: 406 passed, 0 skipped` |
| `aa-runtime` | `532 tests run: 532 passed, 2 skipped` |
| `aa-cli` | `928 tests run: 928 passed, 0 skipped` |

The ten tests in command 4, named individually because AC4 turns on them:

```
PASS aa-cli::run_command             run_command_refuses_to_launch_when_registration_is_impossible
PASS aa-cli::run_command             run_command_refuses_a_lineage_the_gateway_will_not_accept
PASS aa-cli::run_command             run_command_exits_zero_and_deregisters
PASS aa-cli::run_command             run_command_propagates_nonzero_exit_and_deregisters
PASS aa-cli::run_registration_gateway  the_cli_registers_with_the_real_gateway
PASS aa-cli::run_registration_gateway  registering_the_clis_did_under_a_foreign_key_is_refused
PASS aa-cli::run_registration_gateway  replaying_the_clis_own_registration_is_refused
PASS aa-cli::run_registration_gateway  a_registration_without_a_possession_proof_is_refused
PASS aa-cli::run_registration_gateway  the_cli_takes_a_fresh_challenge_for_every_registration
PASS aa-cli::run_registration_gateway  the_cli_and_the_sdk_get_the_same_verdicts
```

## 9.3 The local conformance run, verbatim

Command 5's `--no-capture` output contained **no `SKIP [...]` line and no
`NOT MEASURED` line anywhere**. Both optional guards (`require_claude`,
`require_macos`) passed, so the real-tool lane executed rather than declining:

```
MEASURED real binary: exit=None stopped_by_harness=true elapsed=410.484834ms
MEASURED real-binary requests reaching the provider: 3
MEASURED real-binary request lines: [("POST", "/v1/messages?beta=true"),
  ("GET", "/mcp-registry/v0/servers?version=latest&limit=100&visibility=commercial%2Cgsuite%2Centerprise%2Chealth"),
  ("POST", "/v1/messages?beta=true")]
MEASURED real-binary bodies carrying the placeholder: 2 of 3
OUTCOME [real-tool lane]: measured — 3 request(s) observed, 2 of 3 carried the redaction placeholder
```

## 9.4 The same measurement in CI — and the escape hatch that closed

Not re-dispatched; the existing run against this exact commit was verified
directly with `gh run view 30684364750`.

| | |
|---|---|
| Run | <https://github.com/ai-agent-assembly/agent-assembly/actions/runs/30684364750> |
| `headSha` | `14de683bf10fa9032bd2fa42ee39e55313e9c02b` — **the commit under test**, not an ancestor |
| Event / conclusion | `workflow_dispatch` / `success`, created `2026-08-01T04:39:35Z` |
| Runner | `macos-26-arm64`, image `20260728.0273.1`, macOS 26.5.2 (25F84) |
| Tool | `claude --version` → `2.1.220 (Claude Code)` |
| Result | `Summary [2.796s] 26 tests run: 26 passed, 0 skipped` |

```
MEASURED real binary: exit=None stopped_by_harness=true elapsed=1.227962209s
MEASURED real-binary requests reaching the provider: 3
MEASURED real-binary bodies carrying the placeholder: 2 of 3
OUTCOME [real-tool lane]: measured — 3 request(s) observed, 2 of 3 carried the redaction placeholder
the real-tool scenario measured: 3 request(s) observed, 2 of 3 carried the redaction placeholder
```

**Run 1's caveat on this lane no longer applies, and the change is material.**
Run 1 recorded that the lane's empty-capture guard returned `Ok(())`, so a run
that measured nothing would have been green too (tracked as AAASM-5326). On this
commit both halves of that escape are closed:

* In the suite: the zero-traffic branch now ends in
  `anyhow::bail!("NOT MEASURED [real-tool lane]: …")` — a scenario that
  committed to measuring and observed nothing **fails**.
* In the workflow: a dedicated step, `Assert the lane actually measured the real
  binary`, reads the scenario's outcome ledger and `exit 1`s unless
  `.outcome == "measured"`. It ran and succeeded in run `30684364750`.
* The job-level `continue-on-error` is gone. The only tolerated step is
  `npm install -g @anthropic-ai/claude-code` — the one dependency the repo does
  not control — and when it fails the lane reports "did not run" rather than
  passing.

The lane remains `workflow_dispatch`-only and does not gate `main`, so it is a
**dispatched snapshot rather than a standing gate**. That is unchanged. What
changed is that a green snapshot now means a measurement was actually taken.

## 9.5 Per-AC evidence, re-derived

### AC1 — Detect Claude Code binary on the system (`which claude`, `~/.claude/`)

**Implementation, re-read on this commit:** `aa-devtool-claude-code/src/lib.rs:293`
(`detect`) → `resolve_binary` (`:187`) → `probe_which` (`:225`, literally
`Command::new("which").arg(bin)`); `dot_claude_marker` at `:203`.

| Evidence | Executed on `14de683b`? |
|---|---|
| `lib.rs:506` `detect_returns_none_for_nonexistent_binary_override` | ✅ (in the 134) |
| `lib.rs:525` `detect_returns_none_for_version_below_minimum` | ✅ |
| `lib.rs:535` `detect_returns_some_for_valid_version` | ✅ |
| `lib.rs:550` `detect_normalizes_version_with_prefix` | ✅ |
| `lib.rs:561` `detect_returns_none_when_probe_returns_none` | ✅ |
| `lib.rs:572` `dot_claude_marker_found_when_dir_exists` | ✅ |
| `lib.rs:582` `dot_claude_marker_absent_when_dir_missing` | ✅ |
| `cli_run_claude_governed_launch.rs` — resolves the adapter through `aa_devtool::registry` with **no** binary override, so `probe_which` runs for real against a `PATH`-prefixed stub. The version it discovers is carried all the way into the gateway's `RegisterRequest` and asserted there: `request.version == "2.1.999"` (`:283`) | ✅ |

That last row is what makes AC1 more than a unit-test claim on this run. `2.1.999`
is a version no real release uses, so the assertion cannot be satisfied by the
developer's own `claude 2.1.220` — the value could only have come from the
`which` probe finding the test's stub and the version probe reading it.

**Residual observation, re-confirmed, not a defect:** `detect()` still computes
`dot_claude_marker()` into `let _marker` (`lib.rs:299`) and discards it. The
`~/.claude/` probe exists and is tested, but influences no output. The code
documents this as intentional — CI hosts may have `claude` on `PATH` before a
first interactive run, so gating detection on the marker would be wrong. The AC
names both probes; both exist and both are covered.

> **AC1 verdict: SATISFIED.**

### AC2 — Generate managed `settings.json` from Agent Assembly policy

**Implementation:** `settings.rs:19` (`map_policy_to_settings`) → `lib.rs:327`
(`generate_managed_settings`) → `lib.rs:332` (`apply_settings`) → `apply.rs`
atomic managed-key merge.

| Evidence | Executed on `14de683b`? |
|---|---|
| `settings.rs:90` `policy_with_bash_allow_emits_allow_bash` | ✅ |
| `settings.rs:98` `enforce_policy_maps_to_default_mode` | ✅ |
| `settings.rs:109` `permissive_policy_maps_to_accept_edits` | ✅ |
| `settings.rs:130` `require_approval_maps_to_plan_mode` | ✅ |
| `settings.rs:141` `snapshot_full_policy_fixture` | ✅ |
| `apply.rs:151/168/187` create / preserve-unmanaged / atomic-on-failure | ✅ |
| `tests/settings_merge.rs:40/56/74/105` scope resolution + user-key preservation | ✅ |
| `conformance_claude_code.rs` `install_is_idempotent_and_records_a_receipt` | ✅ |
| `conformance_claude_code.rs` `unrelated_user_configuration_survives_install_repair_and_remove` | ✅ |
| `conformance_claude_code.rs` `the_profile_selects_the_tool_action_governance_the_install_writes` | ✅ |
| `conformance_claude_code.rs` `repair_restores_every_managed_key_and_touches_no_user_key` | ✅ |
| **New on this run:** `cli_run_claude_governed_launch.rs:303` — after a live `aasm run claude`, the redirected `HOME/.claude/settings.json` **is a file**. Generation and application happen on the launcher path, not only the integrations path | ✅ |

Idempotence is asserted on the **bytes** of the settings file, and the document
is written through a real install/repair/remove cycle rather than serialised in
memory.

**Observation carried forward and re-confirmed (does not change the verdict):**
`load_policy()` at `aa-cli/src/commands/run.rs:382` still returns a hard-coded
`PolicyDocument { version: 1, name: "default", rules: Vec::new(), … }`. The
generator is correct and proven; the `run` path still feeds it an empty rule
list. The AC is about generation *from Agent Assembly policy*, which the
integrations/lifecycle path drives from a real profile — so this is recorded, not
counted against AC2. It is the one place where run 1's "additional reason AC4's
end-to-end claim does not hold" survives; see §9.6 for why it does not defeat AC4
as worded.

> **AC2 verdict: SATISFIED.**

### AC3 — Apply MCP allow/deny lists to Claude Code's MCP configuration

**Implementation, two mechanisms:** policy `mcp:<server>` rules →
`enabledMcpjsonServers` / `disabledMcpjsonServers` (`settings.rs:29-33`); and
direct governance `lib.rs:406` `apply_mcp_governance` → `apply.rs:104`
`apply_mcp_governance_at`, planned and receipted as
`StepAction::ConfigureMcpServers`.

| Evidence | Executed on `14de683b`? |
|---|---|
| `settings.rs:119` `mcp_allow_list_emits_enabled_servers` — `mcp:filesystem` Allow / `mcp:search` Deny → `enabled=["filesystem"]`, `disabled=["search"]` | ✅ |
| `apply.rs:205` `apply_mcp_governance_replaces_lists` | ✅ |
| `lib.rs:611` `apply_mcp_governance_writes_to_resolved_path` | ✅ |
| `lib.rs:671/680` `list_mcp_servers_*` (discovery: global config + `.claude/.mcp.json`) | ✅ |
| `tests/settings_merge.rs:143` `mcp_governance_only_touches_active_scope` | ✅ |
| `aa-devtool/src/capability_bridge.rs:100–163` — five `apply_*` tests (CapabilitySet → allow/deny translation) | ✅ (in the 25) |
| `conformance_claude_code.rs` — install writes **both** MCP keys as arrays | ✅ |
| `conformance_claude_code.rs` `repair_restores_every_managed_key_and_touches_no_user_key` — both MCP keys drifted and restored | ✅ |

**Both of run 1's observations re-confirmed on this commit (neither changes the
verdict):**

* No conformance scenario populates a **non-empty** MCP allow/deny list from a
  policy through the installed lifecycle. The lifecycle's default document writes
  empty arrays; the scenarios assert the keys are present, correctly typed and
  repairable. The non-empty case is covered at unit/adapter level only.
* The `CapabilitySet` → `apply_mcp_governance` translator has **no production
  caller**. `grep` across `aa-cli`, `aa-api`, `aa-runtime`, `aa-gateway`,
  `aa-devtool` and `aa-devtool-claude-code` returns its definition
  (`capability_bridge.rs:8`) and five call sites, all inside its own `#[cfg(test)]`
  module. *Correction to run 1: the function is named `apply_capability_policy`,
  not `apply_capability_set`.* The translation is correct and tested; nothing
  shipped invokes it.

Both sit under the AC as written — "apply MCP allow/deny lists to Claude Code's
MCP configuration" — which the adapter demonstrably does.

> **AC3 verdict: SATISFIED**, with the two integration-reach observations
> recorded and unchanged.

### AC4 — `aa run claude` launches Claude Code with identity, proxy, and monitoring — end-to-end

This is the criterion that failed run 1, and the one this re-verification exists
to settle. It is assessed below on evidence produced at `14de683b`, not on the
fact that the defects were fixed.

#### What does not establish AC4

**The conformance suite does not.** `the_real_binary_launched_through_the_installed_environment_is_protected`
(`conformance_claude_code.rs:1597`) launches the real binary via
`spike_support::proxy_harness::ClaudeLaunch` with the environment
`ConformanceHarness::injected_env()` produces. It never invokes `aasm run`. That
is precisely why it stayed green through the entire life of the AAASM-5327
discard defect, and it is why it is **not** cited as AC4 evidence here.
Confirmed structurally on this commit: the set of test files referencing
`require_claude`/`AA_SPIKE_CLAUDE_BIN` and the set invoking `aasm run` are
**disjoint**.

**`cli_run.rs` does not.** All 9 of its tests drive `--dry-run`, which
short-circuits at `run.rs:588` before `detect()`, before `resolve_launch_proxy`,
before registration and before any child exists.

#### What does establish it — the CLI path on merged `main`

The load-bearing test is
`cli_run_claude_governed_launch.rs::run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session`.
Every component is the production one:

| Component | What the test uses |
|---|---|
| Launcher | the real `aasm` binary, **rebuilt unconditionally** by `proxy_trust_support::build_binary` (so a stale artefact cannot be measured — the hazard `aa-integration-tests` has no `aa-cli` dependency creates) |
| Adapter | the real `ClaudeCodeAdapter`, resolved through `aa_devtool::registry::adapter_for` — no override constructor, the same table `aasm tools list` uses |
| Gateway | the real `aa_gateway::service::AgentLifecycleServiceImpl` over gRPC on loopback, backed by a real `AgentRegistry` |
| Proxy | a **real `aa-proxy` process**, started through `aasm proxy start`, whose state record `aasm run` independently verifies |
| Child | a real spawned process reporting its **own** environment |

**Identity — measured.** The child observed `AA_AGENT_ID`, `AA_AGENT_DID`,
`AA_REGISTRATION_ID` and `AA_TEAM_ID` equal to values *derived the way the CLI
derives them* (`expected_did`, `expected_registration_id`), not to values a mock
handed back — the distinction run 1's mock-gateway test could not make. Reaching
those assertions at all requires the gRPC handshake to have succeeded, because a
launch that cannot register never spawns anything. `AA_TRACE_ID` and
`AA_SESSION_ID` are asserted present, non-empty and mutually distinct.

**Proxy — measured.** The child observed
`HTTPS_PROXY = HTTP_PROXY = http://127.0.0.1:<port>`, where `<port>` is the live
`aa-proxy` this host started and verified. Two things follow that run 1 could not
assert: the value carries a scheme (run 1's Finding (2), AAASM-5324), and it
names the endpoint **this host vouched for** rather than one a remote gateway
supplied — the `proxy_addr` response field was removed from the contract
entirely, and the test keeps a deliberately dead `PROXY_ADDR` constant so a
regression reinstating any remote source surfaces as a wrong value rather than a
silent pass.

`cli_run_claude_launch_env.rs::the_adapters_launch_environment_reaches_the_launched_process`
adds the variable the whole interception model depends on: the child observed
`NODE_EXTRA_CA_CERTS` carrying the value the adapter injected from the launch-env
store. Its sibling
`fixture_can_tell_an_absent_variable_from_an_empty_one` proves the fixture can
fail — the stub uses `${VAR-__UNSET__}` (no colon), so "absent" and "empty" render
differently, and both renderings are pinned as reachable.

`cli_run_trusted_proxy.rs` supplies the fail-closed half: **ten** distinct ways
the proxy record can be untrustworthy — no proxy running, recorded process gone,
no identity evidence, over-permissive mode, state file is a symlink, PID
recycled into a different incarnation, PID running a different executable, record
naming something other than the proxy, non-loopback endpoint, nothing listening —
each asserted to produce **both** a non-zero exit **and** no launched tool, and
each distinguished by the *reason* given rather than merely by failing. All ten
passed.

**Monitoring — measured.** Read off a real registry, not a mock's recording:
exactly one `RegisterRequest`, under the DID the tool was launched with, carrying
`name = "claude_code"`, `version = "2.1.999"` (the detected version, not a
placeholder), and non-empty `possession_proof` **and** `registration_nonce`;
exactly one deregistration under that same DID; and
`!gateway.holds(Some(TEAM_ID), &did)` afterwards, so the session is provably
closed rather than merely reported closed.

`run_registration_gateway.rs` establishes that this registration is not a
CLI-shaped shortcut. Its method is the part that matters: it takes the **literal
bytes the CLI sent**, captured off the wire, degrades exactly one property, and
resubmits. Foreign key → refused. Replay → refused. Missing possession proof →
refused. Fresh challenge per registration → enforced. And
`the_cli_and_the_sdk_get_the_same_verdicts` pins that the CLI is held to the SDK's
gate, not a weaker one. `the_http_surface_still_offers_no_registration_route`
asserts the rejected alternative stays rejected: a `POST /api/v1/agents` carrying
no key, no challenge and no proof must not succeed.

**Fail-closed — measured.**
`a_launch_that_cannot_register_never_starts_the_tool` points the launcher at a
bound-then-released port, and asserts non-zero exit, the message
`refusing to launch unregistered`, and `!dump.exists()` — no tool started. This
is the assertion run 1 added as an "honest floor"; on this commit it survives as
a genuine guard rather than as a pin on the 405 defect.

#### The one thing not measured, stated precisely

**No test launches the real `claude` binary through `aasm run` and observes its
traffic arriving at the proxy.** Every `aasm run` test uses a POSIX shell stub
named `claude`; the only real-binary evidence lives in the conformance lane,
which does not go through `aasm run`. The end-to-end claim is therefore
established by composing two measured halves:

* **(A)** `aasm run` delivers environment *E′* to a real spawned child —
  measured, `cli_run_claude_launch_env.rs` + `cli_run_claude_governed_launch.rs`.
* **(B)** the real `claude 2.1.220` under environment *E* routes through the
  proxy and has its secret redacted — measured twice, locally (§9.3) and in CI at
  this exact commit (§9.4).

The join is **structural, not assumed**. `ClaudeCodeAdapter::build_launch_command`
(`lib.rs:370`) builds its launch environment by iterating
`launch_env::installed_environment(&self.launch_paths())` — and
`ConformanceHarness::injected_env()` (`conformance_support/harness.rs:358`) is a
one-line call to *that same production function*, whose result `ClaudeLaunch`
applies verbatim (`proxy_harness.rs:396`). So *E′* is *E* plus `AA_AGENT_ID`,
`AA_TEAM_ID` and the host-verified proxy URL — a superset, produced by the same
code, differing only in repointing the proxy variables from the installed record
to the endpoint this host verified, in the same `http://host:port` form the
child-environment assertions pin.

What the composition does not cover: nothing asserts the join itself. If
`build_launch_command` stopped calling `installed_environment`, or the two proxy
values diverged in form, the CLI-path suites would still pass (they would measure
the new value) and the conformance lane would still pass (it never goes through
`aasm run`) — and the composition would break silently.

**Closing it** is a small, well-shaped addition rather than a redesign: one
scenario in `cli_run_claude_governed_launch.rs` that runs `aasm run claude` with
the *real* binary on `PATH` — gated exactly as the conformance lane is, on
`require_claude()` + `require_macos()` — against a real `aa-proxy` fronting the
existing `proxy_harness` mock upstream, asserting traffic was observed. It reuses
machinery that already exists in both files.

#### The verdict, and why it is not the cautious one

AC4 names three things: identity, proxy, monitoring. **All three are measured on
this commit through the real `aasm run`, on a real child process, against a real
gateway and a real proxy.** None is inferred from a `HashMap`, a printed plan, or
a mock's echo — the three shapes of evidence run 1 correctly rejected.

The stub substitution is at the leaf, and it does not stand in for any behaviour
AC4 names. AC4 is a claim about what `aasm run` *does to* the launched tool, not
about Claude Code's internals; from the launcher's side a stub and the real binary
are the same object — an executable named `claude` on `PATH` that answers
`--version`. The single thing the stub cannot demonstrate — that a Node runtime
honours an injected CA and proxy — is exactly what the real-tool lane measures,
under an environment the same production function produces.

The residual is a *robustness-of-the-join* gap, not an unevidenced claim. Calling
AC4 unsatisfied on that basis would be withholding a verdict the evidence
supports.

For completeness, the failure mode AC4 exists to prevent — an operator typing
`aasm run claude`, seeing it start, and believing the session is governed when it
is not — is closed and measured at every step on this commit: registration fails
→ refuses; proxy unverifiable → refuses (ten ways); launch proceeds → the child
provably carries the identity, the verified proxy URL and the CA path; and a real
`claude` given that CA path and proxy URL is provably intercepted and redacted.

> **AC4 verdict: SATISFIED.** Measured, not inferred. The composition gap in
> §9.5 is recorded as a follow-up, not as a defect and not as a blocker.

### AC5 — Unit tests for settings generation and MCP policy application

| Evidence | Executed on `14de683b`? |
|---|---|
| Settings generation: `settings.rs:90/98/109/130/141` — 5 tests including a full-policy snapshot | ✅ |
| Settings application: `apply.rs:151/168/187` — create, preserve-unmanaged, atomic-on-failure | ✅ |
| MCP policy application: `settings.rs:119`, `apply.rs:205`, `lib.rs:611`, `settings_merge.rs:143` | ✅ |
| MCP discovery: `lib.rs:671/680` | ✅ |
| Capability → MCP translation: `capability_bridge.rs` × 5 | ✅ |
| Crate totals | `aa-devtool-claude-code` **134/134**, `aa-devtool` **25/25** |

> **AC5 verdict: SATISFIED.**

## 9.6 The conditions run 1 set for sign-off

Run 1 closed by naming three conditions. Each is assessed on this commit:

| Run 1 condition | Status at `14de683b` |
|---|---|
| Finding (1) fixed — `aasm run` can register | **Met, and by the stronger route.** The HTTP registration endpoint was deliberately *not* added; the CLI was moved onto the gRPC gate the SDKs use (AAASM-5323, `9fffa6c1`). `the_http_surface_still_offers_no_registration_route` now asserts the rejected alternative stays rejected. |
| Finding (2) fixed or accepted — scheme-bearing proxy URL reaches the child | **Met.** Fixed twice over: AAASM-5327 stopped the wholesale discard of the adapter's environment, and AAASM-5323 changed the source of the value to the host-verified endpoint. Measured on the child in two suites. |
| `cli_run_claude_governed_launch.rs` updated to assert a successful governed launch rather than the honest floor | **Met.** `run_claude_launches_the_tool_with_identity_proxy_and_a_monitored_session` asserts the successful governed launch; the floor survives as `a_launch_that_cannot_register_never_starts_the_tool`, which is the claim worth keeping rather than a pin on the old 405. |

Run 1's Observation (3) — `load_policy()` returns an empty rule list — and
Observation (4) — the capability→MCP translator has no production caller — both
persist unchanged. Neither is an AC4 component; both are recorded in §9.5 under
AC2 and AC3 respectively and are follow-up material, not blockers.

## 9.7 Everything skipped or not measured on this run

A skipped scenario proves nothing. The complete list:

| Scope | Item | Mechanism | Reason | Bearing on AAASM-201 |
|---|---|---|---|---|
| `aa-runtime` | `ipc::server::tests::round_trip_latency_under_1ms` | `#[ignore]` | Latency benchmark, not run by default | None — no AC concerns IPC latency |
| `aa-runtime` | `pipeline::tests::pipeline_load_benchmark` | `#[ignore]` | Load benchmark, not run by default | None |
| conformance | — | `require_claude()` / `require_macos()` | **Not triggered.** Host is macOS and `which claude` found `/opt/homebrew/bin/claude` | — |
| conformance | — | `NOT MEASURED` empty-capture guard | **Not triggered.** The real binary produced 3 requests | — |
| `cli_run_claude_governed_launch` / `cli_run_claude_launch_env` / `cli_run_trusted_proxy` | `#[cfg(not(unix))]` skip stubs | conditional compilation | **Not triggered.** Host is Unix; all 36 tests executed | — |
| **AC4** | real `claude` binary driven **through `aasm run`** | no such test exists | The composition gap analysed in §9.5. Real-binary evidence exists but only via the conformance lane, which bypasses `aasm run` | Recorded; does not defeat AC4 (§9.5) |
| Scope | `cargo nextest run --workspace` | not run | Only the five named crates plus the named integration suites were run — 2 097 tests. The workspace suite was not executed on this commit; unrelated crates (`aa-proxy`, `aa-ebpf*`, `aa-storage*`, `aa-gateway`, `aa-api`) are unverified **by this report**, though CI covers them | None on AAASM-201's AC, all of which live in the crates that were run |
| Scope | `cargo clippy` | not run | This branch changes Markdown only; no Rust source was touched. `cargo fmt --all -- --check` was run and is clean | None |
| Real-tool CI lane | re-dispatch | not re-dispatched | Run `30684364750` already targets `headSha 14de683b` — the exact commit under test. Verified with `gh run view`, not assumed | None |

## 9.8 Defects found on this run

**No new product defect was found.** One documentation defect, reported and
**not fixed** (outside this ticket's scope, and no product code was modified):

* **Stale cross-reference.** `aa-cli/tests/run_registration_gateway.rs:21-23`
  tells the reader that "the complementary end-to-end claim — that the `aasm`
  binary starts no tool when registration fails — is in
  `aa-integration-tests/tests/cli_run_grpc_registration.rs`". **That file does not
  exist**; `grep` across the tree finds no reference to it other than this
  comment. The claim itself is true and *is* covered — by
  `cli_run_claude_governed_launch.rs::a_launch_that_cannot_register_never_starts_the_tool`
  — so this is a wrong filename, not missing evidence. Severity: low. It points a
  reviewer looking for the fail-closed proof at nothing.

## 9.9 Sign-off (re-derived)

| AC | Verdict | Evidence executed on `14de683b`? |
|---|---|---|
| AC1 — detect binary (`which claude`, `~/.claude/`) | **Satisfied** | Yes — 7 unit tests + the CLI path driving `probe_which` for real |
| AC2 — generate managed `settings.json` from policy | **Satisfied** | Yes — 11 unit/integration tests + settings landing on the `aasm run` path |
| AC3 — apply MCP allow/deny lists | **Satisfied** | Yes — 8 evidence rows; two integration-reach observations recorded |
| AC4 — `aa run claude` launches with identity, proxy, monitoring end-to-end | **Satisfied** | Yes — all three components measured on a real child through the real `aasm`, real adapter, real gRPC gateway, real `aa-proxy`; one composition gap named |
| AC5 — unit tests for settings generation and MCP policy application | **Satisfied** | Yes — 134/134 + 25/25 |

**5 of 5 parent acceptance criteria are satisfied.**

> **AAASM-1112 can be signed off.** Its own acceptance criteria require sign-off
> "when 100% of parent Story AC are satisfied", and a Bug Subtask for any AC that
> fails verification. No AC fails on this commit, so no Bug Subtask is required.
> The two Bug Subtasks run 1 recommended are moot: both defects are fixed and
> merged (AAASM-5327 / AAASM-5323), and each landed with its own measuring test.
>
> **AAASM-201 can be closed on this evidence.**

Three items are recommended as **follow-ups, not blockers** — none of them is an
unsatisfied AC, and none should hold the sign-off:

1. **Close the AC4 composition gap** — one real-binary scenario through
   `aasm run`, gated as the conformance lane is (§9.5).
2. **Wire a real policy into `aasm run`** — `load_policy()` still returns an
   empty rule list, so the managed settings the launcher writes carry no
   permissions and no MCP entries (Observation (3), still open).
3. **Give the capability→MCP translator a production caller, or remove it** —
   `apply_capability_policy` is fully tested and invoked by nothing shipped
   (Observation (4), still open).

Plus the low-severity stale cross-reference in §9.8.

**Note on the real-tool lane.** It is `workflow_dispatch`-only and does not gate
`main`. Anyone relying on §9.4 should know it is a snapshot taken against
`14de683b`, not a check that will re-run. What it now guarantees, which it did not
at run 1, is that a green snapshot means a measurement was actually taken.
