# AAASM-5528 — public claim inventory

Cross-repository inventory of public documentation claims that exceed the
guarantees the shipped implementation supports.

- **Ticket:** [AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528)
  (P0 Bug) · **Epic:** [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526)
- **Goal:** CBLPCRLM-13 — Verified Product Truth and Protection Boundaries
- **Fix version:** agent-assembly v0.0.1-rc.7
- **Compiled:** 2026-08-06

## Why this file lives here

This is an evidence artifact, not book content. It sits in `verification-reports/`
alongside `AAASM-5276-claude-code-mechanism-matrix.md` — the precedent this
repository already uses for measured evidence cited by
[ADR 0030](../docs/src/adr/0030-developer-integration-boundaries-and-trust-model.md)
and [the limitations page](../docs/src/devtools/limitations.md). It is deliberately
**not** under `docs/src/`: a page there must be registered in `docs/src/SUMMARY.md`
to be reachable, and that file is owned by a concurrent ticket (AAASM-5604), so a
page added there now would render as an orphan.

`agent-assembly` is the right repository for the artifact because it owns both the
[capability matrix](../docs/src/governance/capability-matrix.md) and the
[protection ladder](../docs/src/devtools/protection-levels.md) that the corrected
copy is measured against.

## Method

Every claim below was checked against the implementation, not against another
document or a code comment. Where a doc and the code disagreed, the code won.
Line numbers are from the base commit of the AAASM-5528 branches, **except** for
rows marked *(branch position)* — self-correction rows added during review, whose
subject text did not exist at the base commit and whose line numbers therefore
refer to the branch.

Every source path cited in this artifact was checked against `git ls-files` and
`git check-ignore`: all are committed, and none is generated or build-produced.
That check exists because the parallel AAASM-5638 audit found a pre-existing ADR
citation to `aa-proto/_embedded/proto/audit.proto`, which is gitignored and
produced by `build.rs` — it resolved for one reviewer only because their builds
had created the directory, and fails on a clean tree. Whether a generated path
resolves depends on what you ran, not on what is committed, so any such citation
must be marked generated.

### Claim classes

| Class | Meaning |
|---|---|
| **absolute** | Universal quantifier over agent behaviour (`every`, `everything`, `cannot bypass`, `nowhere to hide`). |
| **unbounded scope** | Real capability described without the routing / transport / host boundary that limits it. |
| **observe-presented-as-prevent** | A telemetry-only mechanism described as blocking or catching. |
| **platform-overreach** | Support asserted more broadly than the platform gate in code allows. |
| **no-code-change** | "No code changes" without naming the launch, env and trust-store prerequisites. |
| **overstated-crypto-guarantee** | A cryptographic property asserted stronger than the primitive in use (a signature where there is an unkeyed digest; immutability where there is convention). |
| **feature-not-shipped** | A capability advertised as current that cannot be reached in a released build. |
| **mislabelled-mechanism** | The right guarantee attributed to the wrong component, so a reader cannot locate or verify it. |

### Verdicts

`remove` — claim deleted · `qualify` — rewritten with its boundary ·
`keep-with-boundary` — retained because it already names its boundary, or the word
is used in a non-claim sense.

## Evidence base

The five findings that drive the replacements. Each was read in the
implementation and independently re-checked before being used in public copy.

### E1 — the eBPF layer is observe-only, OpenSSL-only, x86_64-only, and fails open

| Fact | Evidence |
|---|---|
| TLS uprobes/uretprobes attach to `SSL_write` / `SSL_read` **only** | `aa-ebpf/src/uprobe.rs:68,80,92` |
| Library resolved by scanning `/proc/<pid>/maps` for the substring `libssl.so`, fallback list is `libssl.so.3` / `libssl.so.1.1` only | `aa-ebpf/src/uprobe.rs:149-164,199` |
| Go `crypto/tls`, rustls, BoringSSL, GnuTLS, NSS are **not** covered | stated in-probe at `aa-ebpf-probes/src/ssl_probes.rs:17-32` (AAASM-3872) |
| **Only the file-I/O kprobes** are x86_64 — 14 hardcoded `__x64_sys_*` symbols. There is no `cfg(target_arch)` or runtime arch check anywhere in the eBPF crates: TLS uprobes attach by symbol from `/proc/<pid>/maps` and exec tracepoints resolve offsets from live BTF, so both work on aarch64 | `aa-ebpf/src/kprobe.rs:145-160`, test at `:240-247`; `aa-ebpf/src/uprobe.rs:199`; absence of `target_arch` verified across `aa-ebpf*/src/` |
| TLS, file-I/O and exec probes are **observe-only**; the path "blocklist" only sets `event.flags = 1` | `aa-ebpf-probes/src/main.rs:119-122`; `aa-ebpf/src/maps.rs:31`; `aa-runtime/src/ebpf_control.rs:24-29` |
| No LSM, no seccomp-BPF anywhere — **no code path returns a denial** | absence verified across all `.rs` |
| The only enforcing path is the opt-in syscall guard, via **asynchronous** `bpf_send_signal(SIGKILL)` — the offending syscall still completes | `aa-ebpf-probes/src/syscall_guard.rs:55-60,189-195` |
| Guard is off unless `AA_EBPF_CONFINE_PID` is set **and** policy lowers a non-empty allowlist | `aa-runtime/src/ebpf_control.rs:137-140,157-162` |
| Platform gate is **three** conditions — kernel ≥ 5.8, BTF, **and** a reachable loader-daemon socket (`/run/aa-ebpf-loaderd.sock`) — and `AA_LAYERS` bypasses the probe entirely. `aa-runtime` deliberately holds **no** `CAP_BPF`/`CAP_PERFMON`; the privileged loader daemon owns every BPF operation (AAASM-3605), so "the runtime needs elevated privileges" is inverted | `aa-runtime/src/layer.rs:114-135,165-167` |
| Load/attach failure **fails open** — degrade, warn, agent proceeds | `aa-runtime/src/ebpf_control.rs:204-213,320-352,378-385` |
| Fork propagation fails open at 1024 PIDs; confined child runs unconfined | `aa-ebpf-probes/src/syscall_guard.rs:94,235-241` |

### E2 — the proxy sees only explicitly-routed traffic, and by default MitMs three hosts

| Fact | Evidence |
|---|---|
| `llm_only` defaults to **`true`** | `aa-proxy/src/config.rs:48` |
| Under it, only `api.openai.com`, `api.anthropic.com`, `api.cohere.com` are TLS-intercepted | `aa-proxy/src/intercept/detect.rs:27-35` |
| Every other host takes a raw bidirectional tunnel with **no inspection** | `aa-proxy/src/proxy/mod.rs:1058-1060,1129-1137` |
| **No** transparent redirect exists (no iptables/pfctl/TPROXY/`SO_ORIGINAL_DST`) — traffic arrives only if the client speaks the HTTP proxy protocol | absence verified repo-wide |
| `HTTP_PROXY`/`HTTPS_PROXY` are injected by `aasm run` **and** by installed developer integrations, which write them into the tool's own configuration so they persist independently of `aasm run` | `aa-cli/src/commands/run.rs:322-323`; `aa-devtool-claude-code/src/lib.rs:379-380` and `lifecycle.rs:929-930`; `aa-devtool-codex/src/lib.rs:301`; `aa-devtool-windsurf/src/lib.rs:312` |
| A tool launched outside `aasm run` inherits neither the proxy nor `NODE_EXTRA_CA_CERTS` and is not protected | `aa-devtool-claude-code/src/lifecycle.rs:1010-1013`; measured, `docs/src/devtools/limitations.md` |
| One local **root** CA, CN `Agent Assembly CA`, at `~/.aa/ca/` — per-domain **leaf** certs are minted from it. "Per-host CA" is the wrong description | `aa-proxy/src/tls/ca.rs:28-34,78-84,184-210` |
| On macOS a System Keychain trust install is **attempted automatically at proxy start**, gated only on whether the certificate is already installed. The block runs unconditionally on macOS from `pub async fn run` | `aa-proxy/src/lib.rs:41,62-67` |
| `CaStore::install` no-ops if already trusted, else calls `keychain::add_trusted_cert` | `aa-proxy/src/tls/ca.rs:215,219` |
| That shells out to `security add-trusted-cert`, which **requires admin authorization** — macOS prompts | `aa-proxy/src/tls/keychain.rs:16,18,23-32` |
| Because `ca.install()?` propagates out of `run`, **a refused prompt fails proxy startup**. "Installed automatically" reads as silent and unattended, and is wrong | `aa-proxy/src/lib.rs:65` |
| The Claude Code integration deliberately **does not rely on** this trust store — it establishes trust per-launch through `NODE_EXTRA_CA_CERTS`. Note "does not *rely on*", not "does not *use*": the integration path does not depend on it, but the proxy binary does attempt it at startup, so the stronger phrasing would contradict `lib.rs:62-67` | `aa-devtool-claude-code/src/lifecycle.rs:653-659` |
| CA install is **also implemented on Linux** — `sudo aasm proxy install-ca` copies to `/usr/local/share/ca-certificates/aa-proxy.crt` and runs `update-ca-certificates`. Windows is unsupported | `aa-cli/src/commands/proxy/ca.rs:79-82,150-188`; `uninstall_linux` at `:191`; wired at `proxy/mod.rs:26,45`; Windows arm at `ca.rs:87` |
| **On MitM'd hosts**, HTTP/1.1 with `Content-Length` only; no ALPN is configured, so HTTP/2, gRPC and WebSocket cannot be inspected there, and a chunked request is dropped with no HTTP response rather than a 403. On hosts not under MitM those protocols work, tunnelled and uninspected — there is no WebSocket handling in `aa-proxy/src` at all | `aa-proxy/src/proxy/http.rs:266-270`; ALPN absent from `aa-proxy/src` |
| Egress allow/deny comes from `AA_PROXY_DENIED_HOSTS` / `AA_PROXY_NETWORK_ALLOWLIST`, both **empty by default**. That is *not* "denies nothing": an SSRF guard denies unconditionally ahead of both lists | lists at `aa-proxy/src/config.rs:75-85`; SSRF guard at `aa-proxy/src/proxy/mod.rs:940-947`, pinned by the test at `:1967` |
| The `--policy` document does not configure the running proxy | `aa-policy/src/resolve.rs:234-244` |
| Credential DLP default is `RedactOnly` (forward), not `Block` | `aa-proxy/src/config.rs:20-23` |
| Gateway is consulted at exactly one call site — the MCP path | `aa-proxy/src/proxy/mod.rs:1098` |
| `mitm_hosts` is the **union** of `AA_PROXY_MITM_HOSTS` and host lists installed integrations drop into `~/.aasm/integrations/mitm-hosts.d/`, so the MitM surface can widen with no operator env var | `aa-proxy/src/config.rs:173` |
| Synchronous pre-execution denial **does** exist: CONNECT-time 403, in-tunnel host re-check, credential `Block`, and MCP `tools/call` — each returns before dialling upstream | `aa-proxy/src/proxy/mod.rs:1033-1040,822-833,895-908,627-633` |

### E3 — SDK denial is real but bounded to patched framework tool seams

| Fact | Evidence |
|---|---|
| A deny raises **before** the wrapped tool body runs, in all three SDKs | `python-sdk/.../_shared/tool_governance.py:225-228` (body at `:237`); `node-sdk/src/wrappers/with-assembly.ts:164-165,216-217`; `go-sdk/assembly/tool_wrapper.go:82-87,127-128` |
| Requires an explicit `init_assembly()` / `initAssembly()` / `assembly.Init()`; Go additionally requires explicit `WrapTools` | `python-sdk/agent_assembly/__init__.py:24`; `node-sdk/src/init-assembly.ts:162-165`; `go-sdk/assembly/wrap_tools.go:13,28` |
| Raw HTTP, `subprocess`, and filesystem access are **not** intercepted by any SDK | nothing patches `requests`/`httpx`/`urllib`/`subprocess` |
| Node's LangChain **callback** handler is audit-only — it records a denial and does not throw | `node-sdk/src/adapters/langchain/assembly-callback-handler.ts:12-21,35-59` |
| The SDK is explicitly not the authoritative gate | `aa-sdk-client/src/decision.rs:32-33`; ADR 0002 |

### E4 — credential *injection* is unreachable in a shipped build, and the agent process holds the raw value

The "secrets are injected at runtime and never enter the model context" family of
claims rests on a capability that cannot be reached by a user of a released
build. Every citation below was re-verified directly.

| Fact | Evidence |
|---|---|
| The dispatch path exists and is unit-tested | `proto/secrets.proto:12` (`SecretsService.DispatchTool`); `aa-gateway/src/secrets/resolver.rs:95`; `aa-gateway/src/secrets/store.rs:31`; HTTP `aa-api/src/routes/dispatch.rs:125`; gRPC `aa-gateway/src/service/secrets_service.rs:39` |
| **Nothing can populate the store.** Both production constructions instantiate a fresh empty `InMemorySecretsStore` | `aa-api/src/state.rs:449`; `aa-gateway/src/server.rs:693` |
| There is **no registration route** — `openapi/v1.yaml` exposes only `/api/v1/dispatch_tool` | `openapi/v1.yaml:2661` |
| There is **no `aasm secrets` command** | absence verified in `aa-cli/src/commands/` |
| Registration exists only in a test helper | `aa-integration-tests/tests/common/mod.rs:246` |
| Consequence: every `${NAME}` resolves to `UnknownPlaceholder` → 422 / `FailedPrecondition` | resolver behaviour |
| No placeholder substitution exists in `aa-runtime`; no `SecretResolution` type exists anywhere | absence verified |
| **The gateway returns the resolved plaintext to the caller** — it does not make the outbound call itself | `aa-api/src/routes/dispatch.rs:179-183`; `proto/secrets.proto:36-39` |
| **`aasm run` hands the child the entire parent environment**, so a shell or file tool in the agent can read any credential the operator exported. The masking helper is used only for `--dry-run` preview text | `aa-cli/src/commands/run.rs:306` (`std::env::vars().collect()`); masking at `:434`, `:480` |
| There is **no Stripe detector** — no `Stripe` entry in `CredentialKind` or the literal table; the OpenAI detector keys on `sk-` (hyphen) while Stripe uses `sk_` (underscore) | `aa-security/src/scanner.rs:14-55,95-162` |
| Model **responses** are never scanned — the upstream body is a raw `tokio::io::copy` | `aa-proxy/src/proxy/mod.rs:958` |
| `AlertAndRedact` / `AlertOnly` emission is unimplemented, so `AlertOnly` forwards the raw secret **and** raises no alert | `aa-gateway/src/engine/mod.rs:1468-1473,1478,1487` |
| A secret split by a separator (`中`, emoji, space, tab, newline) scans clean — accepted residual | `aa-security/src/scanner.rs:1071-1092,3012-3030` (AAASM-5368) |

The net accurate statement is the inverse of the published one: the product does
not today keep a credential out of the agent's reach. What it does is **scan
outbound requests on the inspected hosts and redact recognised credentials
before forwarding** — with `RedactOnly` as the default, `Block` opt-in, and
detection bounded to the scanner's pattern set.

### E5 — the audit chain is an unkeyed SHA-256 chain over the JSONL sink, not a signature

| Fact | Evidence |
|---|---|
| The chain is an **unkeyed SHA-256** digest chain. `aa-core`'s audit module imports `sha2::{Digest, Sha256}` and there is no `hmac` import anywhere in the crate | `aa-core/src/audit.rs:10,713`; absence of `hmac` verified across `aa-core/src/` |
| The only HMAC in the repository is unrelated — REST/admin JWT signing and outbound webhook signatures | — |
| Consequence: it is tamper-**evident**, not a signature. Anyone able to rewrite the log can recompute the chain | property of an unkeyed chain |
| It **is** genuinely verifiable, and this ships in the OSS build — do not understate it | `AuditWriter::verify_chain` at `aa-gateway/src/audit.rs:142`; CLI `aasm audit verify-chain` wired at `aa-cli/src/commands/audit/mod.rs:14,31,44` |
| The chain covers the **JSONL sink only** — the DB conversion explicitly drops `seq`, `previous_hash` and `entry_hash` | `aa-gateway/src/storage/audit_bridge.rs:10-12` |
| "Immutable" is false — retention pruning deletes audit rows | `aa-gateway/src/storage/sqlite.rs:715`, `aa-gateway/src/storage/postgres.rs:854` |
| Emission is best-effort (`try_send`, drops counted), and `seq`/`last_hash` commit *before* the send, so the chain head advances even when an entry is lost — a dropped entry is indistinguishable from tampering | `audit_service.rs:86,161-179`; filed as AAASM-5626 |

Wording is deliberately aligned with what AAASM-5612 is publishing on
`docs/src/security-model.md` (PR #134), so the hub does not ship two different
descriptions of one mechanism.

### E7 — the SDK layer is advisory; the proxy is the enforcement point

Reconciles with E3 rather than contradicting it. E3 established that the
*language wrapper* raises before the wrapped body. This block records what that
does and does not amount to.

| Fact | Evidence |
|---|---|
| `resolve_decision` has **no in-tree caller that refuses to execute** — refusal lives in the out-of-repo FFI shims | `aa-sdk-client/src/decision.rs:32-33`: *"The SDK remains advisory: `aa-runtime` / proxy / eBPF are the authoritative enforcement points. This is a defense-in-depth posture, not the primary gate."* |
| `query_policy` is a **voluntary** call over UDS; a non-cooperating process simply does not make it | `aa-sdk-client/src/client.rs:247-279` |
| `aa-runtime`'s `handle_policy_query` is *Denied before execution* **only if the shim honours the answer** | ADR 0033 §"canonical verb" table |
| `RuntimeScanner` runs on `IpcFrame::EventReport` — *after* the action — and returns counters, not a verdict | `aa-runtime/src/pipeline/mod.rs:127`; `enforcement.rs:115-127` |
| The proxy, by contrast, denies **out of process** and before dialling upstream | `aa-proxy/src/proxy/mod.rs:1033-1040,822-833,895-908,627-633` |

Correct public register: the **proxy** *denies before execution*; the **SDK**
*evaluates* and is **advisory**; **eBPF** *observes* / *detects*.

---

## Inventory — `ai-agent-assembly/official-website`

| # | File:line | Exact quoted claim | Class | Verdict | Replacement | Evidence |
|---|---|---|---|---|---|---|
| W1 | `src/components/home/index.tsx:319` | "Kernel uprobes on SSL libraries plus exec/file syscall hooks catch everything, including bypass attempts (Linux)." | absolute · observe-presented-as-prevent · platform-overreach | qualify | "Observe-only kernel probes — OpenSSL uprobes plus exec/file syscall hooks — surface activity the layers above never saw. Linux only; it reports, it does not block." | E1 |
| W2 | `src/components/home/index.tsx:311` | "A sidecar MitM proxy enforces network-egress policy with no code changes — catches what the SDK misses." | no-code-change · unbounded scope | qualify | Names proxy-env routing and CA trust as prerequisites, supplied by `aasm run` or an installed integration. | E2 |
| W3 | `src/components/home/index.tsx:303` | "In-process hooks (Python, Node.js, Go) emit events and apply pre-execution allow/deny." | unbounded scope | qualify | Bounds to wrapped framework tool calls after explicit init. | E3 |
| W4 | `src/components/home/index.tsx:48-53` | "sits between your agents and the outside world and enforces policy, tracks cost, and intercepts unsafe actions — at the SDK, the network proxy, and the kernel." | unbounded scope | qualify | Bounds mediation to the paths it is wired into. | E1 · E2 · E3 |
| W5 | `src/components/home/index.tsx:275` | "Three boundaries for every agent" | absolute | qualify | "Three boundaries for a governed agent" | E3 |
| W6 | `src/components/home/index.tsx:233` | "Every agent gets a verifiable identity scoped to a team" | absolute | qualify | "Each registered agent carries a team-scoped identity" — scope bounded to registration. | registry is populated on register, not ambiently |
| W7 | `src/components/home/index.tsx:350` | "from a one-line SDK import to kernel-level enforcement" | observe-presented-as-prevent | qualify | "…to kernel-level observation" | E1 |
| W8 | `src/pages/product.tsx:36-38` | "sits between your agents and the outside world — it enforces policy, tracks cost, and intercepts unsafe actions at runtime." | unbounded scope | qualify | Adds the managed-path boundary. | E2 · E3 |
| W9 | `src/pages/product.tsx:52-53` | "Agent Assembly adds that boundary without you rewriting your agents." | no-code-change | qualify | Names the launch/routing requirement. | E2 |
| W10 | `src/pages/product.tsx:150` | "Three independently-deployable layers … Adopt the depth you need." | unbounded scope | qualify | Distinguishes the enforcing layers from the observing one. | E1 |
| W11 | `blog/2026-06-25-sdks-are-not-security-boundaries/index.md:17-18` | "uprobes on SSL libraries plus exec/file syscall hooks catch everything, including deliberate bypass attempts." | absolute · observe-presented-as-prevent | qualify | Same correction as W1, at the post's technical depth. | E1 |
| W12 | `blog/2026-06-25-sdks-are-not-security-boundaries/index.md:16` | "enforces network egress with no code changes; catches what the SDK misses." | no-code-change | qualify | Names routing + CA trust. | E2 |
| W13 | `blog/2026-06-25-sdks-are-not-security-boundaries/index.md:20-22` | "the proxy and eBPF layers are where the boundary becomes hard to cross" | absolute | qualify | eBPF raises detection, not the boundary. | E1 |
| W14 | `i18n/zh-Hant/code.json` | zh-Hant mirrors of W1–W7 | (inherits) | qualify | Translated in lockstep. | — |
| W15 | `src/components/home/index.tsx:131-135` | Hero terminal mock: "secret STRIPE_KEY injected at runtime — never in context" | absolute · feature-not-shipped | qualify | Advertises an unreachable capability using a credential type with no detector. Replaced with an `AKIA…` key ID, which the scanner matches **by prefix** (`aa-security/src/scanner.rs:17`), being redacted. First replacement attempt named `AWS_SECRET_ACCESS_KEY`, which the scanner does **not** match — it detects AWS by key-ID prefix (`AKIA`/`ASIA`), never by env-var name, and no `AwsSecretAccessKey` variant exists. Corrected. | E4 · E6 |
| W18 | `src/components/home/index.tsx` hero, `src/pages/index.tsx` meta, `src/pages/product.tsx` layers, `i18n/zh-Hant/code.json` `product.layers.body` (branch positions) | "The SDK and proxy can deny an action before it runs" / zh-Hant "SDK 與 proxy 可以在行為執行前予以拒絕" | observe-presented-as-prevent | qualify | Proxy denies; SDK evaluates and is advisory. The zh-Hant string was the sharpest form of the claim and had **no English counterpart carrying it** after the surrounding English was bounded — it was consistent with the *old* English and became stronger than the new. | E7 |
| W16 | `src/components/home/index.tsx:257` | "Real credentials are injected at execution time and never enter the model context the agent can see." | absolute · feature-not-shipped | remove | "Agent Assembly scans your agents' outbound traffic and redacts credentials before they reach a model or an API." | E4 |
| W17 | `src/pages/product.tsx:109-116` | "Credentials injected at execution time" / "Secrets never enter the model context" | absolute · feature-not-shipped | remove | Replaced with the redact-before-forward description and its default. | E4 |

## Inventory — `ai-agent-assembly/agent-assembly` (mdBook, `docs/src/`)

| # | File:line | Exact quoted claim | Class | Verdict | Replacement | Evidence |
|---|---|---|---|---|---|---|
| A1 | `introduction/overview.md:5` | "it checks every action an agent tries to take against rules you define" | absolute | qualify | Bounds to actions on a governed path. | E1 · E2 · E3 |
| A2 | `introduction/overview.md:7-8` | "a security checkpoint that an AI agent cannot walk around." | absolute | remove | Replaced with a checkpoint-on-the-governed-path formulation. | E2 (unmanaged launch is a measured bypass) |
| A3 | `introduction/overview.md:21-24` | "Every time an agent tries to call a tool, reach the network, or spend money on a model call, the runtime evaluates that action" | absolute | qualify | "Each time a governed action reaches the runtime…" | E3 |
| A4 | `introduction/README.md:5` | "evaluates every action against policy and budget" | absolute | qualify | "evaluates the actions routed to it" | E3 |
| A5 | `introduction/README.md:20` | "so nothing slips through" | absolute | qualify | "so each layer narrows what the layer above it missed" | E1 |
| A6 | `introduction/three-layer-model.md:19` | "Outbound HTTPS, with no code change" | no-code-change | qualify | Adds routing + CA + transport constraints. | E2 |
| A7 | `introduction/three-layer-model.md:20` | "Everything else, including bypass attempts" | absolute · observe-presented-as-prevent | qualify | "OpenSSL TLS plaintext, exec and file syscalls — observed, not blocked" | E1 |
| A8 | `introduction/three-layer-model.md:37` | "Run all three and an action has nowhere to hide." | absolute | remove | Replaced with a union-coverage statement that names the residual gaps. | E1 · E2 |
| A9 | `introduction/concepts.md:58` | "**audit** records everything" | absolute | qualify | "records each evaluated action" | E3 |
| A10 | `security/three-layer-defense.md:20` | "Outbound HTTPS, no code change" | no-code-change | qualify | As A6. | E2 |
| A11 | `security/three-layer-defense.md:21` | "Everything else, including bypass attempts" | absolute · observe-presented-as-prevent | qualify | As A7, plus "Detection authority" recast as detection, not enforcement. | E1 |
| A12 | `security/three-layer-defense.md:56-63` | "it sees TLS plaintext and process activity **even when the agent never adopted the SDK and never routed through the proxy**. It is the floor." | unbounded scope · platform-overreach | qualify | Bounds to OpenSSL-linked processes on Linux, observe-only; notes the loader-daemon requirement and that the runtime itself holds no BPF capability. | E1 |
| A13 | `security/three-layer-defense.md:77-78` | "Run all three and an action has nowhere to hide — an attempt to evade a higher layer simply surfaces at a lower one." | absolute | remove | Replaced with the enumerated residual-gap list. | E1 |
| A14 | `security/three-layer-defense.md:125-127` | "an action only escapes governance if it evades *every deployed* layer. With eBPF present, the bypass path collapses to 'caught at Layer 3.'" | absolute | qualify | Names the four ways an action still escapes with eBPF deployed. | E1 |
| A15 | `architecture/infra-overview.md:15` | "decides, records, and persists every action" | absolute | qualify | "every action it receives" | E3 |
| A16 | `architecture/infra-overview.md:22` | "enforces network-egress policy with no code changes." | no-code-change | qualify | As A6. | E2 |
| A17 | `architecture/infra-overview.md:24` | "catches everything, including bypass attempts. **Linux-only.**" | absolute · platform-overreach | qualify | As A7; Linux, with the file-I/O kprobes noted as x86_64-only. | E1 |
| A18 | `architecture/infra-overview.md:60` | Mermaid node label "*no code changes*" | no-code-change | qualify | "requires proxy routing" | E2 |
| A19 | `architecture/README.md:5` | "routing every action through one central **gateway**" | absolute | qualify | "routing governed actions through one central gateway" | E3 |
| A20 | `governance/capability-matrix.md:22` | "The tool cannot bypass enforcement, but may operate without constraint if AAASM is offline." | absolute | remove | Absolute deleted, not softened. The tier now names what mediates (SDK/wrapper seam, `aa-proxy`), the platform (macOS and Linux, with the CA install differing per platform), and the decision timing (both synchronous), followed by a boundary note enumerating unmanaged launch, direct calls, unsupported transports, hosts not under MitM, opaque SaaS hosts, and AAASM-offline. | E1 · E2 · E3 |
| A36 | `security/three-layer-defense.md:26-27` | "so it **catches** actions the higher layers never saw" | observe-presented-as-prevent | qualify | "so it can *report* actions…" — the identical sentence was corrected on the sibling page (`introduction/three-layer-model.md:26`) and missed here, on the page a security evaluator actually reads. Contains no banned token, which is why the vocabulary scan never saw it. | E1 |
| A37 | `introduction/overview.md:19` (branch position) | "review exactly what **every agent** did and why." | absolute | qualify | "review exactly what was observed and decided." Surviving absolute in the landing blockquote, three lines below the corrected statement that unrouted paths need their own controls — the same claim already removed at A9, A21 and A25. | E3 |
| A38 | **All 8 surfaces carrying the claim** (branch positions) — `agent-assembly`: `.claude/CLAUDE.md`, `security/three-layer-defense.md`, `governance/capability-matrix.md`, `quick-start/requirements.md`; `docs`: `docs/src/README.md` (row D5), `docs/src/comparison.md` `[^proxy]`; `official-website`: `src/components/home/index.tsx` proxy card, `i18n/zh-Hant/code.json` `home.layers.proxy.text` | "CA trust-store install is automatic at proxy start on macOS" | platform-overreach | qualify | Replaced on every surface with the attempted / admin-authorization / refusal-fails-startup formulation. **This was the same defect as A-row B2, committed inside the fix for it** — a platform claim generalised from a `cfg(target_os)` guard without reading what the guarded call requires. Aligned with ADR 0033 as corrected by AAASM-5638 (`agent-assembly` #1955). Not counted here: `usage-guide/enforce-egress-policy.md:137` and `usage-guide/interception-layers.md:63`, which carry only the `sudo aasm proxy install-ca` command example and never state the macOS attempt. | E2 |
| A35 | `introduction/three-layer-model.md:30`, `governance/capability-matrix.md:31,36`, `usage-guide/interception-layers.md:103` (branch positions) | "layers 1 and 2 can **deny an action before it runs**" / "Two mechanisms, both deciding *before* the action proceeds" | observe-presented-as-prevent | qualify | Splits the enforcing layer (proxy) from the advisory one (SDK), citing `decision.rs:32-33` and ADR 0002. | E7 |
| A33 | `.claude/CLAUDE.md` (three-layer section) | "kernel uprobes on SSL libs + exec/file syscalls; catches **everything**, including bypass attempts. **Linux-only.**" | absolute · observe-presented-as-prevent · platform-overreach | qualify | Observe-only, OpenSSL, Linux (file-I/O kprobes x86_64-only), fails open; described as one possible host mechanism. | E1 |
| A34 | `.claude/CLAUDE.md` (crate map + prose) | "`aa-runtime` — Authoritative enforcement pipeline (`RuntimeScanner`)" | mislabelled-mechanism | qualify | Splits the allow/deny/pending gate (`handle_policy_query`, `aa-runtime/src/pipeline/mod.rs:407`) from the scan/redact stage (`RuntimeScanner`, `aa-runtime/src/pipeline/enforcement.rs:182`), which is authoritative *versus the SDK's own scan*, not the policy gate. | verified directly |
| A21 | `governance/capability-matrix.md:34` | "every action emits an audit event" | absolute | qualify | "every observed action emits an audit event" | E3 |
| A22 | `governance/capability-matrix.md:246` | "All outbound HTTPS from the machine" | unbounded scope | qualify | "Outbound HTTPS **routed through it**; under the default `llm_only` only the three built-in LLM hosts are inspected" | E2 |
| A23 | `quick-start/requirements.md:79` | "Intercepts outbound HTTPS via MitM with a per-host CA — no code changes" | no-code-change | qualify | Corrects the CA model and names the prerequisites. | E2 |
| A24 | `quick-start/requirements.md:80` | "Catches everything else, including bypass attempts" | absolute · observe-presented-as-prevent | qualify | As A7. | E1 |
| A25 | `quick-start/first-run.md:125` | "The shim reports every action to the gateway over gRPC." | absolute | qualify | "reports the calls it wraps" | E3 |
| A26 | `quick-start/first-run.md:126` | "**Sidecar proxy (no code changes):**" | no-code-change | qualify | "(no agent code changes; requires proxy routing)" | E2 |
| A27 | `quick-start/first-run.md:128` | "kernel hooks catch everything else, including bypass attempts." | absolute | qualify | As A7. | E1 |
| A28 | `usage-guide/self-hosting.md:24` | "which checks every action with the gateway" | absolute | qualify | "which checks the actions it receives with the gateway" | E3 |
| A29 | `usage-guide/interception-layers.md:15` | "Enforces network-egress policy with no code change." | no-code-change | qualify | As A6. | E2 |
| A30 | `usage-guide/interception-layers.md:16` | "Everything else, including deliberate bypass attempts." | absolute | qualify | As A7. | E1 |
| A31 | `usage-guide/interception-layers.md:30-32` | "defense-in-depth that an agent cannot bypass … This is the catch-all backstop." | absolute | qualify | "raises the chance of detecting a bypass … a detection backstop, not a catch-all" | E1 |
| A32 | `usage-guide/interception-layers.md:39` | "eBPF sits underneath both as the bypass-proof floor." | absolute | remove | "eBPF sits underneath both as an observation floor." | E1 |

### Kept without change (`agent-assembly`)

| File:line | Text | Why kept |
|---|---|---|
| `introduction/three-layer-model.md:5,64` | "routes every **observed** action"; diagram edge "audit-only events" | Already boundary-correct, and the diagram edge is positive evidence for the eBPF fix. |
| `security/trust-boundaries.md:102` | "Everything left of the runtime is untrusted…" | `everything` scopes a diagram region, not a product guarantee; the statement is accurate. |
| `architecture/system-architecture.md:120`, `architecture/components.md:186`, `architecture/building.md:38` | "the two foundation leaves everything else builds on", "Build everything" | Non-claim uses (dependency graph, a make target). |
| `quick-start/first-run.md:33` | "`low-risk` allows and audits everything" | Accurately describes a specific bundled policy file. |
| `usage-guide/self-hosting.md:12,21,71,79` | "runs everything *for* you", "reads everything through the REST API" | Non-claim uses about deployment scope and a read path. |
| `devtools/product-brief.md` §8, `devtools/limitations.md`, `devtools/protection-levels.md` | Guarantee/limit pairs | Already the model of correctly-bounded copy; used as the target register for the rewrites and as the link destination. |
| `usage-guide/govern-an-agent.md:236` | "**Routing is not proof.**" | Already correct; not in this ticket's path ownership. |

## Inventory — `ai-agent-assembly/docs`

| # | File:line | Exact quoted claim | Class | Verdict | Replacement | Evidence |
|---|---|---|---|---|---|---|
| D1 | `docs/src/README.md:26` | "It works across your whole fleet of agents and does not require you to rewrite your existing agent code." | absolute · no-code-change | remove | Replaced with a per-agent, per-path statement naming the launch requirement. | E2 · E3 |
| D2 | `docs/src/README.md:22` | "decides, before each action runs, whether an agent is allowed…" | unbounded scope | qualify | "before each **governed** action runs" | E3 |
| D3 | `docs/src/README.md:24` | "catches risky calls (and bypass attempts) at the SDK, network, and kernel levels." | unbounded scope · observe-presented-as-prevent | qualify | Splits enforcement (SDK, proxy) from detection (kernel). | E1 |
| D4 | `docs/src/README.md:83` | "applies allow/deny decisions before any network request leaves the process" | absolute | qualify | Bounds to wrapped tool calls; notes raw HTTP is not intercepted. | E3 |
| D5 | `docs/src/README.md:84` | "intercepts outbound HTTPS using a per-host CA … No code changes required." | no-code-change | qualify | Corrects the CA model; names routing and the per-platform CA install — on macOS *attempted* at proxy start via `security add-trusted-cert`, which requires admin authorization and whose refusal fails proxy startup; `sudo aasm proxy install-ca` on Linux; Windows unsupported. (Superseded the round-3 "automatic on macOS" wording — see A38.) | E2 |
| D6 | `docs/src/README.md:85` | "kernel-level hooks that watch SSL libraries and process syscalls to catch bypass attempts at the OS level. Linux only." | observe-presented-as-prevent · platform-overreach | qualify | "observe-only … OpenSSL … Linux" (file-I/O kprobes x86_64-only) | E1 |
| D7 | `docs/src/comparison.md:3` | "a security checkpoint in front of every agent action" | absolute | qualify | "in front of each governed agent action" | E3 |
| D8 | `docs/src/comparison.md:31` | "Network-level interception (no code change)" | no-code-change | qualify | Footnoted with the routing/CA/transport prerequisites. | E2 |
| D13 | `docs/src/README.md:24,83` (branch positions) | "blocks risky calls at the SDK and proxy layers"; SDK "applies an allow/deny decision before the wrapped call runs" | observe-presented-as-prevent | qualify | Proxy blocks; SDK advises. | E7 |
| D9 | `docs/src/comparison.md:55` | "Immutable audit log with tamper-evident signatures — ✓ 🚧 (HMAC-SHA256)" | overstated-crypto-guarantee · absolute | qualify | Row renamed to "Hash-chained, verifiable audit log", cell to `partial (unkeyed SHA-256 chain over the JSONL sink)`, with a footnote carrying the full bounds. | E5 |
| D10 | `docs/src/comparison.md:82` | "AAASM's audit log entries are signed with HMAC-SHA256, making post-hoc alteration detectable" (marked 🚧 Enterprise) | overstated-crypto-guarantee | qualify | Restated as an unkeyed SHA-256 hash chain over the JSONL sink, verifiable with `aasm audit verify-chain`, **shipping in OSS** — the 🚧 Enterprise marker also *understated* it. | E5 |
| D11 | `docs/src/comparison.md:79` | "No competitor in this matrix offers kernel-level **enforcement**." | observe-presented-as-prevent | qualify | eBPF is a detection layer; restated as "kernel-level visibility". | E1 |
| D12 | `docs/src/comparison.md:80` | "MitM HTTPS interception via a per-host CA" | unbounded scope | qualify | Corrects the CA model and adds the launch/routing/trust precondition. | E2 |

### Kept without change (`docs`)

| File:line | Text | Why kept |
|---|---|---|
| `docs/src/comparison.md:32` | "Kernel-level bypass **detection** (eBPF) ✓" | Already says detection, which is what the layer does. |
| `docs/src/README.md:87` | "All three layers report to the gateway" | Accurate: it scopes the layers, not agent behaviour. |

## Findings in repositories this ticket does not own

Reported, not edited.

| Repo | File:line | Claim | Class | Recommended owner |
|---|---|---|---|---|
| `examples` | `docs/concepts.md:33` | "Catch everything, including attempts to bypass the SDK or proxy layers. Linux-only; requires elevated privileges." | absolute · observe-presented-as-prevent · platform-overreach | Same correction as A7/W1. Needs a follow-up ticket under AAASM-5526. |
| `examples` | `README.md:7` | "intercepts, inspects, and enforces policies on tool calls made by AI agents — without requiring you to rewrite your agent code" | no-code-change | Follow-up ticket. |
| `agent-assembly` | `.claude/CLAUDE.md` | *Fixed in this ticket* — see rows A33/A34. It is the propagation root: every coding agent reads it before writing public copy. |
| workspace root | `CLAUDE.md` (architecture section) | "Catches everything else, including bypass attempts." | absolute | Same as above. |
| `agent-assembly` | `docs/src/devtools/governance-limits/claude-code.md` | eBPF uprobes described as "the only **enforcement** path" for file read/write | observe-presented-as-prevent | Same class as A7/A36. Not edited here — the file is outside this ticket's changed set and its correction belongs with the governance-limits page owner. Needs a follow-up under AAASM-5526. |
| `agent-assembly` | `docs/src/protocol/CHANGELOG.md` | historical "immutable audit record" | overstated-crypto-guarantee | Left as-is: a changelog records what was said at the time. |
| `agent-assembly` | `aa-devtool-claude-code/src/lifecycle.rs:657-659` (`HOST_ENFORCEMENT_REASON`, a user-visible CLI string) | "Agent Assembly **never adds** its certificate authority to the macOS system trust store" | absolute · unbounded scope | True of the *integration* path, which uses `NODE_EXTRA_CA_CERTS`; false at product scope, because `aa-proxy/src/lib.rs:62-67` attempts exactly that install at proxy start. Surfaced by the AAASM-5638 citation audit. Not edited here — it is Rust source outside this ticket's changed set. Needs a follow-up under AAASM-5526. |
| `cloud` | — | No public over-claim found. | — | none |
| `horonomy-official-website` | `design/v1/homepage-directions/…dc.html:678` | "with every action inside an explicit boundary" | absolute | Different product (Horonomy), and a design artifact rather than shipped copy. Flagged only. |

Vendored `.venv` / `node_modules` / generated OpenAPI-schema matches were excluded —
they are third-party or generated text, not authored product claims.

## Summary by claim class

Machine-counted from the rows above (69 rows). A row carrying two classes is
counted under each, so the class table sums higher than the row count. Row W14
carries the class marker `(inherits)` — it is the zh-Hant mirror of W1-W7 and is
excluded from the class table.

| Class | official-website | agent-assembly | docs | Total |
|---|---|---|---|---|
| absolute | 8 | 25 | 4 | **37** |
| no-code-change | 3 | 7 | 3 | **13** |
| observe-presented-as-prevent | 4 | 6 | 4 | **14** |
| unbounded scope | 5 | 2 | 3 | **10** |
| platform-overreach | 1 | 4 | 1 | **6** |
| feature-not-shipped | 3 | 0 | 0 | **3** |
| overstated-crypto-guarantee | 0 | 0 | 2 | **2** |
| mislabelled-mechanism | 0 | 1 | 0 | **1** |

| Verdict | official-website | agent-assembly | docs | Total |
|---|---|---|---|---|
| remove | 2 | 5 | 1 | **8** |
| qualify | 16 | 33 | 12 | **61** |
| **Rows** | **18** | **38** | **13** | **69** |

`keep-with-boundary` entries are listed separately per repo below the tables
they belong to and are not numbered rows, so they are excluded from these
counts: 7 in `agent-assembly`, 2 in `docs`.

### Method note added during review

Two defects in this artifact's own process are worth recording, because both are
generalisable:

1. **Scan by claim class, not by vocabulary.** The first built-output re-grep
   reported clean because `immutable` was not in the banned-word list, while five
   rewritten sentences still carried it. A token list only finds the tokens you
   already thought of.
2. **Re-read the whole translation file, not the changed strings.** The zh-Hant
   `product.layers.body` asserted SDK pre-execution refusal. It was *pre-existing*
   and consistent with the old English, so it never appeared in a changed-strings
   diff — it became an over-claim only once the English around it was bounded.
3. **A `cfg` guard tells you where code compiles, not what it needs.** Twice in
   this ticket a platform claim was written from a `cfg(target_os)` block without
   reading the call inside it: first "CA install is macOS-only" (Linux has a full
   implementation), then, *inside the fix for that*, "installed automatically on
   macOS" (it shells out to `security add-trusted-cert`, needs admin
   authorization, and a refused prompt fails proxy startup). Read the callee.
4. **Correcting one instance of a sentence does not correct its copies.** The
   eBPF "catches actions the higher layers never saw" line was fixed on
   `three-layer-model.md` and missed on `three-layer-defense.md`. Neither
   contains a banned token, so no vocabulary or class scan would find them —
   only diffing sibling pages against each other does.
5. **Assert over the rendered artifact, not the source string.** Literal
   backticks reached the built homepage because `translate({message})` renders
   plain text. The visual pass checked that expected strings were *present*, not
   that no stray markup was.

## Deferred

| Item | Reason |
|---|---|
| Removing the unreachable `DispatchTool` surface, or wiring a real secret store | Out of scope: this ticket corrects *claims*, not implementation (see the ticket's "Out of scope"). E4 is recorded here so the capability is not re-advertised, and warrants its own ticket under AAASM-5526. |
| `docs/src/adr/**`, `docs/src/SUMMARY.md` | Owned by AAASM-5604 concurrently. |
| `docs/src/quickstart-saas.md`, `cloud-deployment.md`, `open-core-boundary.md` (`docs` repo) | Owned by AAASM-5612 concurrently. |
