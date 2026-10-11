# AAASM-6297 (ST-10) — real coding-agent workflow: evidence and founder DogFood package

Campaign: AAASM-6174 (Agent Execution Runtime 2.0 QA). Subtask: AAASM-6297, area 10.

> **Read this first.**
>
> * **No real coding agent was run by QA for this ticket.** Everything automated
>   here drives a deterministic **STUB** (a shell script, or an empty `claude`
>   placeholder). A stub run is evidence for the *governed-launch plumbing*
>   (`aasm run`, the transactional workspace, the per-launch proxy, the gateway
>   policy, per-session attribution). It is **not** evidence that Claude Code,
>   Codex, Copilot or Windsurf behave this way. Every stub test is named
>   `stub_*` and says so in its module comment.
> * **The real-agent legs are BLOCKED-ON-FOUNDER-DOGFOOD.** Running them needs
>   your authenticated accounts, which QA must not use. Part 2 below is what you
>   run. Nothing in this document claims founder acceptance; the result tables
>   are blank on purpose.
> * Everything marked **MEASURED** was observed by QA on the authoring host
>   (macOS, Apple Silicon, `codex-cli 0.160.0`, `claude` present on `PATH`).
>   Everything marked **FROM SOURCE** was read, not run.

## Part 1 — what QA established

### 1.1 Acceptance criteria

| AC (AAASM-6297) | Verdict | Basis |
|---|---|---|
| 1. `cli_run_claude_deterministic_conformance` (real `claude`, scripted model upstream, real gateway allow/deny) | **BLOCKED-ON-FOUNDER-DOGFOOD** | Built (`--no-run`) but deliberately **not run** by QA: it launches the real `claude` binary, and QA could not rule out the binary consulting the login keychain regardless of `HOME`. Founder step D1. |
| 2. Live run: real `claude` + `codex` on a fixture repo, `--workspace-tx`, credential sentinel, receipt; commit + discard; receipt verifies, sentinel absent | **BLOCKED-ON-FOUNDER-DOGFOOD** (real agents) and **BLOCKED-NO-INFRA** (receipt leg: needs x86_64 Linux + native backend). **PARTIAL by stub**: the same plumbing is exercised with a stub agent (commit, discard, denied call, concurrent attribution). | Stub tests below; founder steps D2 and D3. |
| 3. `aasm run --isolation process -- claude` on macOS refuses cleanly instead of booting a guest that cannot run the binary | **PARTIAL** | MEASURED: with a stub `claude`, the launch refuses before the agent starts, exit non-zero, no receipt, marker absent; a paired `--isolation none` control starts the same stub. The refusal here is *host availability* (the `sandlock` backend is Linux-only; no macOS VM substrate configured), not the pre-boot reachability gate. The reachability gate (`paths::to_guest_path`, `aa-isolation-macos-vm/src/lib.rs:390`) is exercised directly and refuses a host `claude` outside the share, **but it checks reachability only, never executable format** (finding F3). The booted-guest arm is NOT MEASURED (no VM substrate). |

### 1.2 Executable evidence added (all repeatable)

| Test | What it proves | Fidelity |
|---|---|---|
| `aa-integration-tests/tests/cli_run_stub_coding_agent_workflow.rs::stub_coding_agent::stub_agent_edit_shell_and_denied_call_commit_exactly_the_change_set_and_denial_is_policy_caused` | One `aasm run --workspace-tx exec` of a stub agent: file edit + shell command + an **allowed** MCP `tools/call` (reaches the upstream) + a **policy-denied** `tools/call` (never reaches it). Base tree after commit equals exactly the expected set. The denial is attested by the persisted proxy audit record (`RefusalRule::McpToolCall`, `Blocked`, attributed to the session). `--isolation none` ⇒ **no execution receipt** is asserted. | real `aasm`, real per-launch proxy, real gateway `PolicyService`; **stub agent** |
| `…::stub_control_flipping_only_the_policy_lets_the_same_call_through` | Paired control: flipping only `deny_test` allow:false→true makes the same call reach the upstream, so the denial above is the *policy's*, not an unavailable upstream. | same |
| `…::stub_concurrent_sessions_do_not_cross_attribute_edits_or_denials` | Two concurrent sessions, one shared state dir: each base receives only its own edit; only session A's denial exists and is attributed to A; B's audit file holds nothing foreign. | same |
| `…::stub_failed_session_is_discarded_and_base_stays_untouched` | A failing agent (exit 7) leaves the base byte-identical; the run reports `committed=false` and states what is not transactional; the allowed call's out-of-workspace effect is *not* undone. | same |
| `…::stub_claude_isolation::*` (macOS) | AC3 live refusal + `--isolation none` control. | stub `claude` |
| `aa-isolation-macos-vm/tests/host_agent_binary_reachability.rs` | The pre-boot reachability gate, with positive controls; characterises F3. | pure function |
| `aa-integration-tests/tests/devtool_adapter_nondestructive_install.rs` | Adapter install safety (Part 1.4). | real engine/adapters, throwaway `$HOME` |
| `aa-proxy/tests/macos_system_trust_probe_truth.rs` | Finding F4. | real `security` CLI, read-only |

Already-merged evidence reused, not repeated: `cli_run_workspace_tx.rs` (4 tests),
`cli_run_concurrent_isolation.rs` (1), `cli_run_execution_receipt.rs` (6). QA re-ran them on
this revision; all passed.

### 1.3 Findings (not fixed here; each has a passing characterisation test and an `#[ignore]`d `desired_*` test)

* **F1 — Codex install writes configuration that the current Codex CLI rejects.**
  `aa-devtool-codex/src/lifecycle.rs` `managed_settings_toml` writes
  `sandbox_mode = "suggest"` and an `[approval_policy]` **table**.
  MEASURED against `codex-cli 0.160.0` with a throwaway `CODEX_HOME` and
  `codex mcp list` (a config load; no agent run, no account): each value is
  rejected independently (`unknown variant 'suggest', expected one of 'read-only',
  'workspace-write', 'danger-full-access'`; `unknown variant 'file_writes', expected
  one of 'untrusted', 'on-failure', 'on-request', 'granular', 'never'`), while an empty
  config, `sandbox_mode = "read-only"` and `approval_policy = "on-request"` all load.
  Net effect: after the Codex integration is installed, `codex` cannot load its own
  configuration. **Do not run `aasm integrations install codex` against your real
  `~/.codex` until fixed.**
* **F2 — Codex TOML merge discards comments and re-orders keys, permanently.**
  `aa-core` round-trips `config.toml` through `toml::Table`. User *values* are
  preserved and restored (including the user's own prior value of a managed key),
  but comments are lost on install and are not restored by remove.
* **F3 — the macOS VM pre-boot gate checks reachability, not format.**
  `aa-isolation-macos-vm/src/paths.rs` `to_guest_path`. A Mach-O `claude` placed
  under the shared project directory would be mapped into a Linux guest. FROM
  SOURCE plus a pure-function test; NOT booted live.
* **F4 — the System Keychain trust probe always answers "trusted".**
  `aa-proxy/src/tls/keychain.rs:75` reads the exit status of
  `security find-certificate -c <CN> -a <keychain>`, which is `0` on no match when
  `-a` is given (MEASURED: exit 0 with `-a`, exit 44 without). So
  `CaStore::install()` is a silent no-op on this host and the CA trust install
  never runs for launches that rely on it (generic `exec` launches). Side effect
  for QA safety: it is why no Keychain prompt appeared during these runs.
* **F5 — Copilot governance can loosen a stricter user setting, with no undo.**
  A deny-only policy makes `generate_managed_settings` emit
  `chat.tools.autoApprove: true` and `chat.mcp.requireApproval: "never"`
  (`aa-devtool-copilot/src/lib.rs` `auto_approve`), and `apply_settings`
  overwrites the user's stricter values. Copilot and Windsurf have **no receipt,
  no plan and no remove**: uninstall is UNSUPPORTED. `apply_mcp_governance`
  permanently deletes denied servers. VS Code's JSONC `settings.json` (comments)
  makes Copilot/Windsurf apply **refuse** (safe, but unusable on a real file).
  Copilot's doc comment says "written atomically" but `write_settings` is a plain
  `tokio::fs::write`.

### 1.4 Non-destructive install, per adapter

| Property | Claude Code | Codex | Copilot | Windsurf |
|---|---|---|---|---|
| Preserves user's unrelated keys | covered by J70 | **yes** (parsed comparison) | yes | yes |
| Idempotent (2nd install byte-identical, reports unchanged) | covered by J70 | **yes** | yes (re-apply) | yes |
| Remove restores the user's prior values | covered by J70 | **yes**, incl. the user's own value of a managed key | **no remove exists** | **no remove exists** |
| Comments / formatting preserved | JSON | **no** (F2) | n/a (JSONC refused) | n/a (JSONC refused) |
| Refuses (leaves file untouched) on unparseable input | covered by J70 | **yes** | yes | yes |
| Install order independence / coexistence | — | owned paths **disjoint** from Claude Code's under one state root; a Codex install+remove leaves a planted Claude file untouched | not applicable | not applicable |
| Values written are accepted by the real tool | — | **no** (F1) | not measured | not measured |

## Part 2 — founder DogFood package (you run these; QA did not)

Conventions: every command is for macOS or Linux, run from a shell **you** open.
D1 points the real agent at a throwaway `HOME`. D2, D3 and the Codex leg run
real `claude` / `codex` with your real `$HOME`, `~/.claude` and `~/.codex`, so
those agents will write their own session and state files there; aasm's own state
goes to `$AASM_STATE_DIR`. Do **not** run `aasm integrations install codex` against
your real `~/.codex` (AAASM-6319). A step that makes macOS show a Keychain, TCC or admin prompt must be
**denied**, and recorded as BLOCKED with the prompt text. A synthetic sentinel string
below is not a secret; do **not** put any real secret in these steps.

### D0 — build and provenance

```bash
cd ~/Bryant-Developments/AI-agent-assembly/agent-assembly   # your checkout of this PR's branch
git fetch remote && git worktree add ../agent-assembly-dogfood-6297 v0.0.1/AAASM-6297/qa/coding_agent_workflow && cd ../agent-assembly-dogfood-6297   # a worktree, so local changes in your checkout cannot collide
export CARGO_TARGET_DIR=$HOME/.cargo/target-aaasm-6297-founder
cargo build -p aa-cli -p aa-proxy
export AASM=$CARGO_TARGET_DIR/debug/aasm
export DF=$(mktemp -d /tmp/aaasm6297-dogfood.XXXXXX)
export AASM_STATE_DIR=$DF/state AA_DATA_DIR=$DF/data AA_CA_DIR=$DF/ca
git rev-parse HEAD; "$AASM" --version; claude --version; codex --version
```

Expected: a 40-char SHA, `aasm 0.0.1-rc.7` (or later), and the two tool versions.
Record them in the result table.

### D1 — AC1: the deterministic conformance test (real `claude` binary, scripted model)

This is the only step that runs the real `claude` binary without your account:
a scripted fake model upstream, a **dummy** auth token, a throwaway `HOME`.

```bash
cargo nextest run -p aa-integration-tests \
  --test cli_run_claude_deterministic_conformance --no-capture 2>&1 | tee $DF/d1.log
grep -E "Summary|MEASURED|NOT MEASURED|SKIP" $DF/d1.log
```

Expected: `Summary … 1 test run: 1 passed`, and `MEASURED governed launch:` and
`MEASURED tool_calls actually reaching the MCP server: {"allow_test"}` lines.
**Failure looks like:** `NOT MEASURED … the allowed tool call never reached the MCP
server` (a known evidence gap, AAASM-5930, not a pass); a `deny_test` in the
"reaching the MCP server" set (a real enforcement failure — stop and report); or a
macOS Keychain prompt (deny it; record BLOCKED).

### D2 — AC2: live real `claude`, fixture repo, `--workspace-tx`, sentinel, commit and discard

This **uses your real Claude account and quota**. Skip it (mark BLOCKED) if you
do not want that.

```bash
# fixture repo + a minimal allow-all-ish policy
mkdir -p $DF/repo/src && cd $DF/repo && git init -q
printf 'original content\n' > src/lib.txt && git add -A && git -c user.email=f@x -c user.name=f commit -qm init
cat > $DF/policy.yaml <<'EOF'
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: aaasm6297-dogfood
spec:
  tools:
    read_file:
      allow: true
EOF
export AASM_DOGFOOD_SENTINEL="AAASM6297-SENTINEL-NOT-A-SECRET-$(date +%s)"   # synthetic
"$AASM" run --dry-run --policy $DF/policy.yaml --agent-id dogfood-claude claude   # read the resolved launch first
```

Commit leg:

```bash
cd $DF/repo
"$AASM" run --workspace-tx --policy $DF/policy.yaml --agent-id dogfood-claude \
  claude -- -p "Append the single line hello-from-claude to src/lib.txt, then stop." 2> $DF/d2-commit.err
echo "exit=$?"; grep -E "workspace_tx\." $DF/d2-commit.err; cat src/lib.txt; git status --short
```

Expected: `exit=0`, `workspace_tx.committed=true`, a `workspace_tx.not_transactional`
line, `src/lib.txt` ending in `hello-from-claude`, and **only** `src/lib.txt` modified.

Discard leg (interrupt the agent): start the same command without `-p` (interactive),
let it edit the file, then press Ctrl-C. Expected: `workspace_tx.committed=false`,
and `git status --short` empty (the base is untouched).

Sentinel and receipt checks (macOS). **The sentinel grep below is a vacuous check
unless the agent was actually given the sentinel**: nothing in the prompt above
makes the agent read `AASM_DOGFOOD_SENTINEL`, so "absent" only shows aasm did not
write it. For a real leak test, first give the agent a task that reads the variable
(for example "print the value of $AASM_DOGFOOD_SENTINEL into src/lib.txt") and
confirm the sentinel DOES appear where it should; record the check as not run
otherwise.

```bash
grep -rl "$AASM_DOGFOOD_SENTINEL" "$AASM_STATE_DIR" $DF/d2-commit.err || echo "sentinel absent from state and output (good)"
ls "$AASM_STATE_DIR/execution-receipts" 2>&1   # macOS, --isolation none: expected to not exist / be empty
```

Expected on macOS: no receipt (nothing was confined, and the record must not claim
otherwise). **Failure looks like:** the sentinel string printed by `grep -rl`; an
execution receipt appearing for an unconfined run; a changed base after a discard.

Repeat with Codex only if you accept the F1 caveat (do **not** run
`aasm integrations install codex`):

```bash
cd $DF/repo
"$AASM" run --workspace-tx --policy $DF/policy.yaml --agent-id dogfood-codex \
  codex -- exec "Append the single line hello-from-codex to src/lib.txt, then stop." 2> $DF/d2-codex.err
echo "exit=$?"; grep -E "workspace_tx\." $DF/d2-codex.err; cat src/lib.txt
```

### D3 — AC3: `--isolation process -- claude` must refuse cleanly on macOS

```bash
cd $DF/repo
"$AASM" run --isolation process --policy $DF/policy.yaml --agent-id dogfood-iso claude -- --version
echo "exit=$?"; ls "$AASM_STATE_DIR/execution-receipts" 2>&1
```

Expected: non-zero exit and a single line reading `error: refusing to launch: an
execution-isolation boundary was requested and the` sandlock `backend cannot be
selected on this host`; **no** `claude` output; no VM boot; no receipt. **Failure looks like:** `claude`'s own banner appearing, a long wait followed
by a guest-boot error, or a receipt being written.

### D4 — Linux half (needs x86_64 Linux + the native backend + a Linux `claude`): BLOCKED-NO-INFRA for QA

On such a host: repeat D2's commit leg adding
`--isolation process --isolation-backend aasm-native`, then
`"$AASM" receipt verify "$AASM_STATE_DIR"/execution-receipts/*.json`. Expected:
verification succeeds, the receipt's `workspace` binding carries the digests and
counts, and the sentinel is absent from the receipt. QA has not seen this run.

### D5 — adapter safety quick checks (optional, no accounts)

```bash
cargo nextest run -p aa-integration-tests --test devtool_adapter_nondestructive_install
cargo nextest run -p aa-integration-tests --test devtool_adapter_nondestructive_install --run-ignored only
```

Expected: first command all pass. The second **must fail 4 tests** — they are the
open findings F1, F2, F5 (it is the failures that confirm the defects still exist; when
a fix lands those tests should start passing and their `#[ignore]` removed).

### Result table (founder fills in)

| Step | Date | Result (PASS / FAIL / BLOCKED) | Notes / output excerpt |
|---|---|---|---|
| D0 | | | |
| D1 | | | |
| D2 claude commit | | | |
| D2 claude discard | | | |
| D2 sentinel + receipt | | | |
| D2 codex | | | |
| D3 | | | |
| D4 (Linux) | | | |
| D5 | | | |
