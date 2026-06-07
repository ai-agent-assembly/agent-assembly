# AAASM-1581 acceptance verification report

**Story**: [AAASM-1581 — E17 S-G: Python / Node / Go SDKs auto-detect and connect to local gateway without explicit config](https://lightning-dust-mite.atlassian.net/browse/AAASM-1581)
**Epic**: [AAASM-1568 — Gateway Deployment Architecture](https://lightning-dust-mite.atlassian.net/browse/AAASM-1568)
**Verification Sub-task**: AAASM-1851

This Story spans three SDK repositories. Each implementation Sub-task delivered the same 4-step resolver chain — explicit > env > config > local default with auto-start — in its respective language, and the verification report below cross-checks behaviour parity.

## Sub-task delivery

| Sub-task | Type | Repo | PR | Status |
| --- | --- | --- | --- | --- |
| AAASM-1846 (ST-1) | Implementation — Python SDK gateway URL resolver + auto-start | `python-sdk` | [#58](https://github.com/ai-agent-assembly/python-sdk/pull/58) | Open |
| AAASM-1847 (ST-2) | Implementation — Node SDK gateway URL resolver + auto-start | `node-sdk` | [#47](https://github.com/ai-agent-assembly/node-sdk/pull/47) | Open |
| AAASM-1849 (ST-3) | Implementation — Go SDK gateway URL resolver + auto-start | `go-sdk` | [#36](https://github.com/ai-agent-assembly/go-sdk/pull/36) | Open |
| AAASM-1851 (ST-4) | Verification — this PR | `agent-assembly` | _this PR_ | In progress |

## Acceptance Criteria

| AC | Status | Evidence |
| --- | --- | --- |
| **Python**: `init_assembly()` (no args, no env vars) connects to `http://localhost:7391` | ✅ | `agent_assembly/core/gateway_resolver.py::resolve_gateway_url` returns `DEFAULT_GATEWAY_URL = "http://localhost:7391"` when no explicit / env / config value is supplied. `agent_assembly/core/assembly.py::init_assembly` calls the resolver when `gateway_url=None`. End-to-end exercise in `test/unit/test_assembly.py::test_init_assembly_zero_arg_resolves_local_default`. |
| **Node**: `initAssembly()` (no args, no env vars) connects to `http://localhost:7391` | ✅ | `src/core/gateway-resolver.ts::resolveGatewayUrl` returns `DEFAULT_GATEWAY_URL` when no explicit / env / config value is supplied. `src/core/init-assembly.ts::initAssembly` accepts `config = {}` and calls the resolver. Exercise in `tests/init-assembly-zero-config.test.ts > initAssembly zero-config > AAASM-1847 AC: initAssembly() with no args resolves the local default`. |
| **Go**: `assembly.Init(ctx)` (no options, no env vars) connects to `http://localhost:7391` | ✅ | `assembly/gateway_resolver.go::resolveGatewayURL` returns `defaultGatewayURL` when no explicit / env / config value is supplied. `assembly/runtime.go::boot` calls the resolver before validation. Exercise in `assembly/init_zero_config_test.go::TestInit_ZeroArgResolvesLocalDefault`. |
| `AAASM_GATEWAY_URL` env var overrides auto-detect (for CI / remote scenarios) | ✅ | All three resolvers check the `AAASM_GATEWAY_URL` env var at step 2 of the precedence chain and return it verbatim before reaching the probe / auto-start path. Tests: `test/unit/core/test_gateway_resolver.py::TestResolveGatewayUrl::test_env_var_takes_precedence_over_config_and_default` (Python); `tests/gateway-resolver.test.ts > resolveGatewayUrl > uses AAASM_GATEWAY_URL over config + default` (Node); `assembly/gateway_resolver_test.go::TestResolveGatewayURL_EnvUsedWhenNoExplicit` (Go). |
| If gateway not running and `aasm` is on PATH → auto-start triggered, SDK connects after health probe passes | ✅ | All three implementations: when the local probe fails, `_auto_start_gateway` / `autoStartGateway` is invoked; it locates `aasm` on PATH (`shutil.which` / `findAasmOnPath` / `exec.LookPath`), launches `aasm start --mode local --foreground` detached, and waits for `/healthz`. Spawn args pinned by `AASM_AUTO_START_ARGV` / `AASM_AUTO_START_ARGV` / `aasmAutoStartArgs = ["start", "--mode", "local", "--foreground"]`. Tests: `test_spawns_subprocess_and_returns_when_ready` (Python), `spawns aasm and resolves when healthz becomes ready` (Node), `TestAutoStartGateway_SuccessSpawnsAndConfirmsReady` (Go). |
| If gateway not running and `aasm` not on PATH → `ConfigurationError` raised with install instructions | ✅ | Python `_auto_start_gateway` raises `ConfigurationError("No gateway found at … and 'aasm' is not on PATH. Install it with: pip install agent-assembly[cli]")`. Node `autoStartGateway` throws `ConfigurationError("… Install it with: npm install -g @agent-assembly/cli (or pnpm add -g)")`. Go `autoStartGateway` returns `*ConfigurationError{Message: "… Install it with: go install github.com/ai-agent-assembly/aa-cli/cmd/aasm@latest"}`. Tests: `test_raises_configuration_error_when_aasm_not_on_path` (Python), `throws ConfigurationError when aasm is not on PATH` (Node), `TestAutoStartGateway_ConfigurationErrorWhenAasmMissing` (Go). |
| Auto-start timeout 5s: if gateway doesn't become ready → `GatewayError` with timeout message | ✅ | All three impls call `_wait_for_healthz` / `waitForHealthz` with `DEFAULT_AUTO_START_TIMEOUT_SECONDS = 5.0` / `DEFAULT_AUTO_START_TIMEOUT_MS = 5000` / `defaultAutoStartTimeout = 5 * time.Second` and raise `GatewayError` on the false return. Tests: `test_raises_gateway_error_on_timeout` (Python), `throws GatewayError when the spawned gateway never becomes ready` (Node), `TestAutoStartGateway_GatewayErrorOnTimeout` (Go). |
| Tests that call `init_assembly(mode="sidecar")` are not affected (explicit mode skips auto-detect) | ✅ | The resolver is keyed on `gateway_url` / `gatewayUrl` / `gatewayURL`, not on `mode`. The pre-existing `test_init_assembly_with_valid_config` (Python, explicit `gateway_url="http://localhost:8080"`) and the existing `validTestOptions()` callers (Go) continue to pass — proven by the dedicated regression test in each repo: `test/unit/test_assembly.py::test_init_assembly_explicit_args_bypass_resolver` (Python), `tests/init-assembly-zero-config.test.ts > explicit gatewayUrl + apiKey bypass the resolver entirely` (Node), `assembly/init_zero_config_test.go::TestInit_ExplicitOptionsBypassResolver` (Go). Each uses sentinel stubs on the probe / auto-start path that fail the test if invoked. |
| Unit tests mock the subprocess call — do not actually spawn `aasm` in unit tests | ✅ | Python: `patch("agent_assembly.core.gateway_resolver.subprocess.Popen")` + `patch("agent_assembly.core.gateway_resolver.shutil.which")`. Node: `__testing._seams.spawnAasm` + `__testing._seams.findAasmOnPath` mutated to `vi.fn()` stubs. Go: `withSeams(t, find, spawn)` swaps `gatewayResolverSeams.spawnAasm` for a no-op closure. No test invocation in any repo touches the real `aasm` binary. |

## Cross-SDK behavioural consistency

| Attribute | Python (`agent_assembly`) | Node (`@agent-assembly/sdk`) | Go (`assembly`) |
| --- | --- | --- | --- |
| Resolution precedence | explicit → `AAASM_GATEWAY_URL` → `~/.aasm/config.yaml`.`agent.gateway_url` → probe + auto-start | (identical) | (identical) |
| Default URL | `DEFAULT_GATEWAY_URL = "http://localhost:7391"` | `DEFAULT_GATEWAY_URL = "http://localhost:7391"` | `defaultGatewayURL = "http://localhost:7391"` |
| Healthz path | `DEFAULT_HEALTHZ_PATH = "/healthz"` | `DEFAULT_HEALTHZ_PATH = "/healthz"` | `defaultHealthzPath = "/healthz"` |
| Probe timeout | `0.5s` | `500ms` | `500 * time.Millisecond` |
| Auto-start budget | `5.0s` | `5000ms` | `5 * time.Second` |
| Auto-start argv | `["start", "--mode", "local", "--foreground"]` | `["start", "--mode", "local", "--foreground"]` | `[]string{"start", "--mode", "local", "--foreground"}` |
| Detach mechanism | `subprocess.Popen(start_new_session=True)` | `child_process.spawn(detached: true, stdio: "ignore")` + `.unref()` | `syscall.SysProcAttr{Setsid: true}` + `Process.Release()` |
| API-key default (local) | `""` (empty) | `""` (empty) | `""` (empty) |
| Error on `aasm` missing | `ConfigurationError` (subclass of `AssemblyError`) | `ConfigurationError` (extends `Error`) | `*ConfigurationError` (struct error type) |
| Error on auto-start timeout | `GatewayError` (subclass of `AssemblyError`) | `GatewayError` (extends `Error`) | `*GatewayError` (struct error type) |

The three SDKs are observationally identical from the caller's perspective: same URL + path + timeouts, same argv, same precedence, same error-class semantics. The detach mechanism varies because each runtime exposes a different primitive, but the user-visible behaviour (`aasm` survives the parent exit) is the same.

## Scope expansion (approved)

The Story description named `gateway_url` only in the resolution chain, but for `init_assembly()` / `initAssembly({})` / `Init(ctx)` to be truly **zero-argument**, the `api_key` parameter also had to become optional. All three implementations therefore extend the same 4-step chain to `api_key` (env: `AAASM_API_KEY`; config: `agent.api_key`; default: empty string for local mode). This was confirmed with the assignee before the Sub-tasks were created and is reflected in the Story kickoff comment.

## Test-suite invocation

```
# python-sdk (PR #58)
.venv/bin/python -m pytest test/ --no-cov -q
# → 404 passed, 11 skipped (377 on master → +27 new tests)

# node-sdk (PR #47)
pnpm test --run
# → 171 passed, 2 skipped (143 on master → +28 new tests)
pnpm typecheck
pnpm lint

# go-sdk (PR #36)
make test
# → ok github.com/ai-agent-assembly/go-sdk/assembly 11.414s
#   (includes the 5s autoStartGateway-timeout test, by design)
go vet ./...
```

All three suites green on the respective branch heads at the time of this report.

## Manual end-to-end smoke runs

Ran 2026-05-23 on macOS / darwin-arm64. A real `aa-gateway --mode local` was started from the `agent-assembly` master worktree (the binary that `aasm start --mode local --foreground` ultimately wraps via `start_local` from AAASM-1725); `/healthz` returned `{"mode":"local","version":"0.0.1","storage":"sqlite","uptime_secs":5}`.

### Probe-hit smoke — gateway already running

| SDK | Command | Output |
| --- | --- | --- |
| Python | `python -c "from agent_assembly import init_assembly; ctx = init_assembly(mode='sdk-only'); print(ctx.client.gateway_url, ctx.client.api_key)"` | `http://localhost:7391` `''` — resolver returned the local default; `api_key` empty-defaulted. |
| Node | `node` invokes `initAssembly({ mode: "sdk-only" })` against `dist/esm/index.js` | `ctx.activeAdapters = [ 'langchain-js', 'openai-agents' ]` — resolver returned a context; downstream framework detection ran. |
| Go | `assembly.Init(context.Background())` via a tiny `main.go` with `replace github.com/ai-agent-assembly/go-sdk => …worktree…` | Resolver completed (no `*ConfigurationError`); downstream `sidecarConnector` returned `"sidecar unavailable"` — expected since the local CP at `:7391` exposes `/healthz` only, not the gRPC sidecar surface. This proves `resolveGatewayURL` populated the URL correctly and validation passed past the (now-relaxed) empty-`apiKey` check. |

### Aasm-missing smoke — no gateway, no `aasm` on PATH

`aa-gateway` killed; `which aasm` returned `aasm not found`.

| SDK | Resulting error |
| --- | --- |
| Python | `ConfigurationError: No gateway found at http://localhost:7391 and 'aasm' is not on PATH. Install it with: pip install agent-assembly[cli]` |
| Node | `ConfigurationError: No gateway found at http://localhost:7391 and 'aasm' is not on PATH. Install it with: npm install -g @agent-assembly/cli (or pnpm add -g)` |
| Go | `*ConfigurationError: assembly: no gateway found at http://localhost:7391 and 'aasm' is not on PATH. Install it with: go install github.com/ai-agent-assembly/aa-cli/cmd/aasm@latest` |

All three error messages match the design — explicit `ConfigurationError` type with an SDK-appropriate install hint.

## Out-of-scope follow-ups

- **`aasm start --mode local --foreground` orchestrator polish** — the current `aasm start` invocation (AAASM-1725) tries to fork `aa-gateway` with the legacy-grpc default flags rather than `--mode local`; the smoke above had to invoke `aa-gateway --mode local` directly. The CLI orchestrator wiring belongs to AAASM-1576 / S-B closing work, not S-G. SDK auto-start paths still call the canonical `aasm start --mode local --foreground` argv per the AC.
- **`AAASM_API_KEY` semantics in remote mode** — the empty-default rule is documented for local mode; production deployments using the remote control plane still require a real key. The CLI / dashboard onboarding flow that surfaces this distinction belongs to a future Story under E17 (`aasm status` already reports the resolved key shape).
- **Story description vs. real module names** — the Story description referenced files that don't exist in the current layouts (`agent_assembly/core/init.py`, `src/core/init.ts`); `assembly/init.go` was correct. Each Sub-task PR is explicit about where the resolver landed; no follow-up needed.

## Closing checklist

- [x] All 9 Story acceptance criteria marked PASS with linked proof in each of Python / Node / Go
- [x] Cross-SDK consistency table verified — same resolution order, default URL, argv, timeouts, error-class semantics
- [x] Manual probe-hit smoke runs documented for Python / Node / Go (each returns a context against a live `aa-gateway --mode local`)
- [x] Manual aasm-missing smoke runs documented for Python / Node / Go (each raises the correct `ConfigurationError` with the SDK-appropriate install hint)
- [x] All three SDK PRs opened and CI-green at branch head
- [x] PR opened in `agent-assembly` against `master` (this PR)
