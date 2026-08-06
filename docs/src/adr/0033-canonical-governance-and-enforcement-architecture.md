# ADR 0033: Canonical Governance & Enforcement Architecture

**Status**: Accepted
**Date**: 2026-08
**Ticket**: [AAASM-5604](https://lightning-dust-mite.atlassian.net/browse/AAASM-5604) (Epic [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526))

This ADR is the **canonical architecture source** for how Agent Assembly governs and
enforces AI-agent behaviour. It replaces the "three universal interception layers"
framing — the fixed `SDK → Proxy → eBPF` pipeline — with six named architectural
elements, and it separates the **logical** architecture from the **deployment**
topology and from **platform-specific** implementation mechanisms. It fixes the
placement of the gateway as a control-plane/runtime service rather than a fourth
interception layer, and it re-describes Linux eBPF as *one possible implementation
mechanism* behind a Platform-Specific Host Enforcement Adapter rather than as the
abstraction itself.

It **complements and does not supersede**
[ADR 0002](0002-sdk-security-boundary.md) (the SDK is not a security boundary),
[ADR 0004](0004-governance-enforcement-flow.md) (all client↔core governance traffic
crosses the single `aa-sdk-client` transport boundary),
[ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md) (fail-closed
redaction),
[ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) (the
five-way `RuntimeVerdict`),
[ADR 0029](0029-capability-over-permission-derivation.md) (declared vs. effective
capability — note 0029 is itself still `Proposed`),
[ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) (developer
integration boundaries, the protection-state ladder and its evidence rules) and
[ADR 0032](0032-local-first-sensitive-data-provider-architecture.md) (local-first
sensitive-data detection). Where any of those ADRs states a mechanism, this ADR
places that mechanism in the canonical model; it does not restate or relax it.

It deliberately does **not** define documentation source-of-truth, claim-precedence
or waiver rules. Those are owned by
[AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) and its ADR.
This ADR supplies the *architecture vocabulary* that the documentation-governance
model will police; it does not police documentation itself.

---

## Context

### What the superseded model asserts

The current material states the model as a fixed, ordered pipeline. From
`docs/src/introduction/three-layer-model.md:1-9`: *"Agent Assembly intercepts agent
actions at **three independent layers**, each catching what the layers above it
might miss."* The same page orders them *"lowest latency first, highest detection
authority first"* and describes layer 3 as catching *"Everything else, including
bypass attempts."* `docs/src/architecture/README.md:32-40` renders it as a single
`3 interception layers (SDK · proxy · eBPF)` box feeding the runtime. The repository's own
`.claude/CLAUDE.md` repeats it verbatim (*"catches everything, including bypass
attempts"*), and `README.md` carries it to every first-time reader.

### Why it is wrong

The model is not merely imprecise; each of its load-bearing claims is contradicted by
the implementation.

1. **It conflates a logical role with an implementation mechanism.** "eBPF" is a Linux
   kernel facility, not an architectural role. Naming the layer after the mechanism
   makes the architecture untranslatable to any platform that lacks that mechanism —
   which is every platform except Linux.

2. **It presents a Linux-only, x86_64-only mechanism as the universal final layer.**
   `aa-runtime` depends on `aa-ebpf` only under
   `[target.'cfg(target_os = "linux")'.dependencies]` (`aa-runtime/Cargo.toml:81-82`).
   Off Linux every loader entry point returns
   `EbpfError::ProgramLoad("eBPF is only supported on Linux")`
   (`aa-ebpf/src/loader.rs:90-93`, `:128-131`, `:530-533`, `:578-581`, `:630-634`) and
   the runtime emits a `LayerDegradation` (`aa-runtime/src/runtime.rs:393-405`,
   `:492-506`, `:550-563`). Even on Linux the file-I/O kprobes attach exclusively to
   x86_64 syscall entry symbols — all fourteen targets in
   `aa-ebpf/src/kprobe.rs:145-160` are `__x64_sys_*`, and no `__arm64_sys_*` target
   exists anywhere in the eBPF crates. A "final layer that catches everything" is in
   fact a mechanism available on one OS and one CPU architecture.

3. **It implies a fixed ordered pipeline where the code models an independently
   probed capability set.** `aa-runtime/src/layer.rs:10-21` defines `LayerSet` as a
   *bitflag*, and `LayerDetector::detect` (`:164-179`) probes each member
   independently: eBPF requires kernel ≥ 5.8, a BTF blob at `/sys/kernel/btf/vmlinux`,
   and a reachable privileged loader-daemon socket (`:133-135`); the proxy requires
   Linux-or-macOS and an `aa-proxy` binary on `$PATH` (`:142-145`); SDK is recorded as
   *"always available"* (`:19`, `:169`). There is no ordering, no fall-through, and no
   guarantee that any given member is present. Absent members are not "covered by the
   layer below" — they are simply absent.

4. **It implies uniform prevention authority.** The three named layers do not have
   comparable authority, and two of them cannot prevent anything at all:
   - Every TLS, file-I/O and exec eBPF program is observe-only and returns `0` after
     submitting telemetry (`aa-ebpf-probes/src/syscall_guard.rs:3-4`). The path
     blocklist sets an alert bit and lets the syscall proceed
     (`aa-ebpf-probes/src/main.rs:119-121`; `aa-ebpf-probes/src/maps.rs:94-95`:
     *"this layer is **OBSERVE-ONLY** (it sets an alert flag; it does not deny)"*).
     `PathVerdict::Deny` (`aa-ebpf/src/maps.rs:16`) is a misleading name for an event
     trigger.
   - The single enforcing program, the syscall guard, does not perform a synchronous
     deny. It sends `bpf_send_signal(SIGKILL)`
     (`aa-ebpf-probes/src/syscall_guard.rs:174-176`, `:193-195`), and its own
     documentation records the consequence (`:55-60`): *"the offending syscall still
     executes once before the task dies — a single `connect`/`sendto`/`write`/`unlink`
     can land. A truly synchronous deny (return `-EPERM` before the handler runs) needs
     seccomp-BPF or an LSM `bpf_lsm` hook, which is out of scope here."* No `bpf_lsm`
     hook, `SEC("lsm/…")` program or `bpf_override_return` call exists in the tree.
   - `aa-gateway` has no *direct* dependency on `aa-ebpf` (it depends on `aa-runtime` unconditionally, `aa-gateway/Cargo.toml:46`, which in turn takes `aa-ebpf` only under `cfg(target_os = "linux")`). No eBPF signal is consulted in any
     allow/deny decision; eBPF events terminate in the audit publisher and the
     correlation engine.

5. **It leaves the gateway unplaced**, which invites readers to file it as a fourth
   interception layer. The gateway does not intercept anything: it holds the policy
   source of truth, the agent registry, budgets, approvals and audit, and it answers
   decision requests. Interception happens elsewhere and is *routed to* it.

6. **It presents self-reported availability as coverage.** `AA_LAYERS`
   (`aa-runtime/src/layer.rs:182-197`) replaces the entire probe result with an
   environment variable. `probe_proxy` is satisfied by a binary being on `$PATH`
   (`:142-145`), which says nothing about whether any traffic is routed through it.
   `SDK` is asserted unconditionally, whether or not any agent adopted it.

### The constraint that forces the design

Two facts cannot both be accommodated by a single ordered pipeline:

- **Coverage is a property of the deployment, not of the product.** Whether an action
  is governed depends on whether the process was launched onto a managed path, whether
  its traffic was routed through the mediator, whether the platform has a host adapter,
  and whether that adapter is healthy. Every one of those is a per-host, per-tool,
  per-launch fact.
- **Different mechanisms decide at different times relative to the action.** A
  pre-execution wrapper decides *before*; a transport mediator decides *before egress
  but after the caller committed*; the syscall guard reacts *after the syscall ran*;
  an audit consumer learns *afterwards*. Collapsing these into "layers" of one pipeline
  erases the distinction that determines what may truthfully be claimed.

An architecture description that cannot express "this mechanism is absent on this
platform" or "this mechanism detects but does not prevent" will keep producing
overstated claims, because the vocabulary has no way to state the limitation.

### Threat model

Three adversaries want different answers from this architecture.

| Adversary | Capability | What must still hold |
| --- | --- | --- |
| **An unmanaged process** — an agent that never adopted the SDK, was not launched through `aasm run`, or had its proxy environment removed | Runs as the developer's own UID; can unset `HTTPS_PROXY`, use a TLS stack the uprobes do not hook (Go `crypto/tls`, Node's statically linked BoringSSL — `aa-ebpf-probes/src/ssl_probes.rs:19-27`), or simply never link the SDK | The product must report this as **outside the governed path**, not as governed. Absence of an event must never render as absence of activity. |
| **A steered agent inside the boundary** (the ADR 0015 adversary) | Controls payload content; may try to make the product *report* protection it does not have | Reported protection state must never exceed the evidence (ADR 0030 §4.2). Missing evidence resolves downward. |
| **An evaluator misled by the product's own description** | Reads the website, Docs Hub or repo README and provisions on that basis | Every claim must name its platform, its decision timing and its failure posture. A reader must not be able to conclude "eBPF catches bypass attempts on my Mac" or "this cannot be bypassed" from any published sentence. |

The third adversary is the one this ADR exists for. The other two are already
addressed by ADR 0015 and ADR 0030; this ADR ensures the architecture *vocabulary*
does not undo them.

The developer's own UID is not an adversary here — consistent with ADR 0030, host-level
tamper prevention against the user's own account is an explicit non-goal.

---

## Decision

### 1. The canonical model is six elements, not three layers

Agent Assembly's governance architecture is described by the following six elements.
They are **roles**, not products, not crates and not an ordered pipeline. A deployment
instantiates some subset of them; which subset is a deployment fact, and the product
must report it rather than assume it.

| # | Element | What it is | Implemented today by | Availability |
| --- | --- | --- | --- | --- |
| **E1** | **Governance Control Plane** | The authority that holds policy, identity, budgets, approvals and audit, and answers decision requests. Holds no traffic. | `aa-gateway` (gRPC: `PolicyService`, `AgentLifecycleService`, `AuditService`, `ApprovalService`, `SecretsService`, `TopologyService`, `InvalidationService` — `aa-gateway/src/server.rs:22-28`), `aa-api` (HTTP/OpenAPI read surface), `aa-storage*` | Platform-independent |
| **E2** | **Managed Execution Checkpoints** | Points on a *managed path* where an action is presented for a decision before it runs. | `aa-runtime`'s `handle_policy_query` (`aa-runtime/src/pipeline/mod.rs:159-175`, body `:407-542`); `aa-sdk-client::query_policy` + `resolve_decision` (`aa-sdk-client/src/client.rs:247-279`, `aa-sdk-client/src/decision.rs:58-97`); `aasm run` managed launch (`aa-cli/src/commands/run.rs`); `aa-sandbox` for WASM-marked tools | Checkpoint reachable only if the agent opts in (see §4) |
| **E3** | **Protocol / Transport Mediation** | A mediator placed on the wire that can refuse, redact or rewrite a request before it leaves the machine. | `aa-proxy` — CONNECT-time egress control, in-tunnel host re-check, credential/DLP scan, MCP `tools/call` adjudication | Unix only; see §5 |
| **E4** | **Platform-Specific Host Enforcement Adapters** | The *abstraction* for OS-level mediation of processes, files, syscalls and TLS. Each platform needs its own mechanism, and a platform without one has none. | **Linux:** eBPF via the privileged `aa-ebpf-loaderd` (`aa-ebpf/src/bin/loaderd.rs`). **macOS:** CA-trust-store integration only (`aa-proxy/src/tls/keychain.rs`), plus an opt-in root-owned managed-settings write. **Windows:** none. | Per-platform; see §5 |
| **E5** | **Credential / Capability Boundary** | What a component is *allowed to ask for*, and how a credential or capability is bound to an identity. | `aa-security` (scanner, redaction, canonical policy AST — a leaf crate with no inherent authority); `credential_token` validation in `PolicyService::check_action` (`aa-gateway/src/service/policy_service.rs:1623-1625`); `did:key` registration (ADR 0004); DI-API capability tokens and the compile-time `aa-devtool-contract` boundary (ADR 0030) | Platform-independent |
| **E6** | **Evidence & Protection-State Pipeline** | How a protection *claim* is substantiated, degraded, and reported. | ADR 0030 §4's protection-state ladder; adjudication reported by the component that actually decided (`aa-proxy/src/probe_adjudication.rs:1-14`); audit publication; `LayerDegradation` reporting | Platform-independent |

Two structural rules follow, and they are the point of the model:

- **An element may be absent.** Absence is a reportable state (E6), never a silent
  fall-through to another element. There is no "layer below" that picks up what an
  absent element would have done.
- **An element's authority is a property of the element, not of the model.** E1 decides
  but holds no traffic. E3 holds traffic and can refuse it. E4's Linux implementation
  today mostly observes. Nothing in the model implies that these are interchangeable.

### 2. The Governance Control Plane is not an interception layer

`aa-gateway` is a **control-plane / runtime service**. It is a request/response policy
oracle: `PolicyService::check_action` (`aa-gateway/src/service/policy_service.rs:1599`)
→ `PolicyEngine::evaluate` (`aa-gateway/src/engine/mod.rs:946`, routing to
`evaluate_primary` or `evaluate_with_cascade` at `:974-978`). The agent's bytes never
traverse it.

`check_action` is a real decision pipeline, not a logger — credential-token validation
short-circuits to `Deny` (`policy_service.rs:1623-1625`), observe-mode applies a shadow
transform (`:1646-1648`), approval submission blocks (`:1652-1657`), anomaly detection
can be promoted to a hard `Deny` (`:1662-1663`), atomic budget reservation can `Deny`
(`:1669`), and agent suspension is enforced (`:1700`).

But its Deny stops nothing by itself. **The gateway prevents only transitively, and is
exactly as strong as the caller that blocks on its answer.** The set of callers that do
so is narrower than "the proxy":

| Caller | Blocks on a gateway answer? | Consequence of `Deny` |
| --- | --- | --- |
| `aa-proxy`, **MCP `tools/call` on a non-LLM MitM'd host, gateway configured** | Yes, synchronously, before dialling upstream | `evaluate_mcp_request` (`aa-proxy/src/proxy/mod.rs:834`) returns `McpEvalOutcome::Deny`; the handler answers the client and returns **without** reaching `dial_upstream_tls` (`:836-846` vs. the dial at `:910`). This is the only gateway-bound pre-dial block in the system. |
| `aa-proxy`, **LLM-provider hosts** (the only hosts MitM'd under the `llm_only` default) | **No** | `handle_llm_mitm` (`:1038-1240`) contains no gateway reference at all. Its refusal at `:1153` is the local `Interceptor`'s `VerdictDecision::Block`, not a gateway decision. |
| `aa-proxy`, **CONNECT-time egress** | **No** | Refusal comes from local configuration — `self.config.network_allowlist` and the denied-host list (`:960-966`) — not from the control plane. |
| `aa-runtime` `handle_policy_query` (`aa-runtime/src/pipeline/mod.rs:159-175`) | Yes | A `Deny` is returned to the SDK — which must then honour it (§4). |

The distinction matters for anyone choosing an enforcement path: a gateway `Deny` stops
bytes **only** for MCP tool-call envelopes on non-LLM MitM'd hosts with a gateway
endpoint configured. Everything else the proxy refuses, it refuses on its own local
policy — which is real prevention, but it is *not* the control plane deciding.

Therefore: **the gateway is E1 and only E1.** Describing it as a fourth interception
layer misstates both what it holds (no traffic) and what it can do alone (nothing to
the traffic). Conversely, describing the interception elements without the gateway
misstates where the decision is actually made.

### 3. Three views, kept distinct

Most of the confusion this ADR corrects comes from collapsing three different pictures
into one diagram. They must be published separately and labelled.

#### 3.1 Logical view — roles and the decision relationship

```mermaid
flowchart TB
    subgraph MP["Managed path"]
        E2["E2 · Managed Execution Checkpoints<br/>decide BEFORE the action"]
        E3["E3 · Protocol / Transport Mediation<br/>decide BEFORE egress"]
        E4["E4 · Platform-Specific Host<br/>Enforcement Adapters<br/>platform-dependent, may be absent"]
    end
    E1["E1 · Governance Control Plane<br/>policy · identity · budget · approval · audit<br/>holds NO traffic"]
    E5["E5 · Credential / Capability Boundary"]
    E6["E6 · Evidence & Protection-State Pipeline"]
    OUT["Outside the governed path<br/>unmanaged launch · unrouted traffic<br/>unhooked TLS stack · unsupported platform"]

    E2 -->|"decision request"| E1
    E3 -->|"decision request"| E1
    E4 -.->|"telemetry only today"| E6
    E1 --> E6
    E2 --> E6
    E3 --> E6
    E5 --- E1
    E5 --- E2
    OUT -.->|"NOT observed · NOT decided"| E6

    classDef plane fill:#eef4fd,stroke:#2c5aa0,stroke-width:2px,color:#10233f
    classDef outside fill:#fdecea,stroke:#c0392b,stroke-width:2px,color:#3c1512
    class E1 plane
    class OUT outside
```

The dashed edge from E4 is not a drafting shortcut: on Linux today the host adapter
feeds the evidence pipeline and is **not** consulted in any allow/deny decision (§5.1).

#### 3.2 Deployment view — what is actually running

The deployment view answers "which processes exist on this host, and what is wired to
what". It is the only view in which coverage can be assessed, because coverage depends
on process launch and traffic routing, not on architecture.

| Process | Role | Present when |
| --- | --- | --- |
| `aa-gateway` | E1 | Operator runs it (local or remote mode) |
| `aa-runtime` | E2 chokepoint; UDS server at `/tmp/aa-runtime-{agent_id}.sock` (`aa-runtime/src/ipc/server.rs:38`) | Operator runs it |
| `aa-proxy` | E3 | Binary on `$PATH` **and** started (`aasm proxy start`, PID file at `$AA_DATA_DIR/proxy.pid` — `aa-cli/src/commands/proxy/pid.rs:55-65`) or spawned by `aa-runtime` |
| `aa-ebpf-loaderd` | E4 (Linux) | Linux, privileged, socket present at `/run/aa-ebpf-loaderd.sock` |
| The agent / dev tool process | The governed subject | Launched by the operator — **on or off the managed path** |

`LayerDetector::detect` (`aa-runtime/src/layer.rs:164-179`) reports a *deployment* fact,
and reports it weakly: `probe_proxy` is satisfied by `which::which("aa-proxy")`
(`:142-145`), and `AA_LAYERS` (`:182-197`) overrides the probes entirely. A detected
layer set is therefore **an availability hint, not evidence of coverage** (§7).

#### 3.3 Platform-specific view — mechanisms, per OS

This view must never be merged into the logical view, because a mechanism named in it
does not exist on every platform. See §5 for the verified matrix.

### 4. Governed path and outside-boundary semantics

**Definition.** An action is on the **governed (managed) path** when, before it takes
effect, it is presented to a checkpoint (E2) or a mediator (E3) that is configured to
consult the control plane (E1) and to honour the answer.

An action is **outside the boundary** when any link in that chain is missing. The
verified ways this happens today:

| Condition | Mechanism | Evidence |
| --- | --- | --- |
| The agent never calls the checkpoint | `query_policy` is a voluntary call over UDS; a non-cooperating process simply does not make it | `aa-sdk-client/src/client.rs:247-279` |
| The SDK's answer is not honoured | `resolve_decision` has **no in-tree caller that refuses to execute**; refusal lives in the out-of-repo FFI shims | `aa-sdk-client/src/decision.rs:32-33`: *"The SDK remains advisory: `aa-runtime` / proxy / eBPF are the authoritative enforcement points. This is a defense-in-depth posture, not the primary gate."* |
| Traffic is not routed to the mediator | `HTTPS_PROXY` is injected only on the managed launch path; an ambient or removed value changes coverage | `aa-cli/src/commands/run.rs:322-326`; adapters at `aa-devtool-codex/src/lib.rs:301`, `aa-devtool-windsurf/src/lib.rs:312`, `aa-devtool-claude-code/src/lib.rs:379` |
| The tool has no managed launch at all | `aa-devtool-copilot::build_launch_command` returns `AdapterError::LaunchFailed` (`aa-devtool-copilot/src/lib.rs:347-357`); `aa-devtool-saas` is hard-capped at `L1Observe` (`aa-devtool-saas/src/adapter.rs:66,122`) | No proxy env is injected, so no data-path mediation exists for these tools |
| The host is mediated but the destination is not inspected | `llm_only` defaults to **true**: any host outside the built-in LLM set or operator `mitm_hosts` is **transparently tunnelled, uninspected** | `aa-proxy/src/proxy/mod.rs:1333-1336`; the default is `parse_llm_only` → `Err(_) => true` at `aa-proxy/src/config.rs:434-439` |
| The TLS stack is not hooked | The uprobes hook only OpenSSL `SSL_read`/`SSL_write`; Go `crypto/tls` and Node's statically linked BoringSSL expose no such symbols | `aa-ebpf-probes/src/ssl_probes.rs:19-27` |
| The platform has no host adapter | macOS and Windows — §5 | — |

**The semantic rule.** For anything outside the boundary the product knows *nothing*.
It must not report the action as allowed, as clean, or as absent. The only truthful
report is that the action was **not observed** and its governance state is
**Unmeasured**. This is ADR 0030 §4.2 rule 2 ("missing evidence lowers the state, never
raises it") applied to the architecture as a whole.

Correspondingly, an empty audit log is evidence about the *observer*, not about the
agent.

### 5. Host enforcement is platform-specific and optional; eBPF is one Linux mechanism

**eBPF is not an architectural layer. It is one implementation of E4, available on
Linux, and today it is predominantly an observation mechanism.**

#### 5.1 What the Linux eBPF implementation actually does

| Program | Attach | Behaviour |
| --- | --- | --- |
| `ssl_write`, `ssl_read_entry`, `ssl_read_exit` | uprobes/uretprobe on OpenSSL `SSL_write` / `SSL_read` (`aa-ebpf-probes/src/ssl_probes.rs:91,123,151`) | Observe only. Events are logged but **not bridged** to the audit pipeline (`aa-runtime/src/runtime.rs:302-305`, `:344-350`) |
| File-I/O kprobes | 14 targets, all `__x64_sys_*` (`aa-ebpf/src/kprobe.rs:145-160`) | Observe only. The path blocklist sets an alert bit; the syscall proceeds (`aa-ebpf-probes/src/main.rs:119-121`) |
| Exec tracepoints | `sched_process_{fork,exec,exit}` (`aa-ebpf-probes/src/exec_probes.rs:182,292,356`) | Observe only; no ring-buffer reader is wired yet (`aa-runtime/src/runtime.rs:510-512`) |
| **Syscall guard** | `raw_syscalls/sys_enter` + fork/exit (`aa-ebpf-probes/src/syscall_guard.rs`) | The **only** enforcing program. Default-denies syscalls outside the allowlist by `bpf_send_signal(SIGKILL)` (`:174-176`, `:193-195`) |

Four properties of that single enforcing program must be stated wherever it is
mentioned:

1. **It is not a synchronous deny.** `syscall_guard.rs:55-60`: *"the offending syscall
   still executes once before the task dies … A truly synchronous deny (return `-EPERM`
   before the handler runs) needs seccomp-BPF or an LSM `bpf_lsm` hook, which is out of
   scope here."* No `bpf_lsm` program, `SEC("lsm/…")` hook or `bpf_override_return`
   call exists in the tree.
2. **It is off by default.** It is planned only when `AA_EBPF_CONFINE_PID` names a PID
   *and* the lowered policy yields a non-empty allowlist
   (`aa-runtime/src/ebpf_control.rs:137-140`); `confine_pid()` treats `0`/unparseable
   as unset *"so the SIGKILL-capable guard stays off by default"* (`:154-162`).
3. **It has a documented load-time window.** `ebpf_control.rs:114-121` records a window
   between guard load and allowlist update in which the confined PID runs with an empty
   allowlist; a race-free fix needs a protocol change.
4. **The fork tracepoint cannot block a fork** — an acknowledged fail-open
   (`syscall_guard.rs:105`).

**No eBPF signal participates in any allow/deny decision.** `aa-gateway` has no *direct* dependency on `aa-ebpf`
(`aa-gateway/Cargo.toml:46` takes `aa-runtime` unconditionally; `aa-runtime` takes
`aa-ebpf` only under `cfg(target_os = "linux")`); events terminate in the audit publisher
(`aa-runtime/src/runtime.rs:689-722`) and the correlation engine
(`aa-runtime/src/correlation/mod.rs:64-66`). The only reverse link is policy lowering
pushing a syscall allowlist into the opt-in guard
(`aa-security/src/policy/ebpf.rs:161,173` → `aa-runtime/src/ebpf_control.rs:36,190`).

#### 5.2 Prerequisites, and what they mean for a claim

Linux eBPF is reachable only when **all** of: kernel ≥ 5.8, BTF at
`/sys/kernel/btf/vmlinux`, and a reachable `aa-ebpf-loaderd` socket
(`aa-runtime/src/layer.rs:133-135`); `bpf_send_signal` additionally requires ≥ 5.3.
`aa-runtime` holds no `CAP_BPF` — the loader daemon is the sole capability holder
(`aa-ebpf/Cargo.toml:49-50`), which is a deliberate privilege separation, not an
inconvenience. The file-I/O kprobes are additionally **x86_64-only**: there is no
`__arm64_sys_*` attach target anywhere in the eBPF crates, so aarch64 Linux gets no
file-I/O coverage from this mechanism.

#### 5.3 The verified platform matrix

| Platform | E3 Transport Mediation | E4 Host Enforcement | Status to publish |
| --- | --- | --- | --- |
| **Linux x86_64** | `aa-proxy`; CA trust via CLI `update-ca-certificates` (`aa-cli/src/commands/proxy/ca.rs:149,173`) | eBPF observation (TLS/file/exec); syscall guard as opt-in asynchronous kill | **Implemented**, with the §5.1 limits stated |
| **Linux aarch64** | `aa-proxy` | eBPF TLS/exec only; **no** file-I/O kprobe targets | **Implemented (partial)** — must say which probes are absent |
| **macOS** | `aa-proxy`; an **opt-in, admin-authorized** System Keychain trust install — `security add-trusted-cert` shelled out from `add_trusted_cert` (`aa-proxy/src/tls/keychain.rs:11-18`, reached via `aa-proxy/src/tls/ca.rs:214-232`). It is not automatic, and the Claude Code integration deliberately does not use it, establishing trust per-launch through `NODE_EXTRA_CA_CERTS` instead (`aa-devtool-claude-code/src/lifecycle.rs:653-659`) | **None.** Endpoint Security / Network Extension is an **explicit non-goal** — asserted in product docs (`docs/src/devtools/product-brief.md:448,655` — *"macOS Endpoint Security and Network Extension remain explicit non-goals"*, and `aa-ebpf` is *"Linux-only and is a **detection** layer that cannot modify traffic in flight"*) and pinned by a test asserting the literal limitation string (`aa-cli/src/commands/integrations/model.rs:1200,1204`) | Transport mediation **Implemented**; host enforcement **Unsupported** |
| **Windows** | **None** — `aa-proxy`'s accept loop uses `tokio::signal::unix` unconditionally (`aa-proxy/src/proxy/mod.rs:296,298`), so the crate has no Windows build path. Note the naive grep is misleading: `#[cfg(windows)]` blocks *do* exist (`aa-devtool-copilot/src/lib.rs:260,292`; `aa-cli/src/commands/dashboard/stop.rs:23`, which calls `windows_sys::…::OpenProcess`). The dispositive evidence is that **`windows_sys` is declared in no `Cargo.toml` in the workspace**, so those blocks cannot compile as written | **None.** No ETW, WFP or minifilter code exists | **Unsupported** |

The macOS "Host Enforced" protection state is reached, where it is reached at all, by
an opt-in root-owned managed-settings **file write** — a tool-governance control, not
host-level interception — and the adapter's own docs record that whether the tool
honours those keys at runtime is unmeasured and *"remains the open half of AAASM-5298"*
(`aa-devtool-claude-code/src/managed_settings.rs:50-57`).

DTrace was considered and rejected for macOS in the original design discussion as
observability-only, not enforcement; no DTrace code exists. Any future macOS or Windows
host adapter is **research** until an implementation exists, and must be labelled as
such (§6).

### 6. Claim vocabulary — decision timing and failure posture are part of every claim

A governance claim is incomplete without its timing and its posture. The following is
the canonical vocabulary; downstream material must pick one of these terms rather than
an undifferentiated verb like "protects", "enforces" or "catches".

| Term | Means | Evidence required |
| --- | --- | --- |
| **Observed** | An event reached the evidence pipeline | A durable event attributed to the action |
| **Detected** | A pattern of interest was found in observed material | A finding, with the detector named |
| **Evaluated** | The control plane produced a decision for this action | A decision record from `check_action` / `handle_policy_query` |
| **Denied before execution** | The action did not take effect, and the decision preceded the effect | A refusal by a component that sits *before* the effect (today: `aa-proxy` pre-dial, or an SDK shim that honoured a `Deny`) |
| **Redacted** | The action proceeded with content removed | A redaction record naming the fields |
| **Approval required** | The action was held pending a human decision | A pending approval record |
| **Degraded** | A planned control is configured but unavailable, so the achieved level is below the planned level | A `LayerDegradation` or ADR 0030 `Degraded` state carrying both levels |
| **Unmeasured** | No control observed this path; nothing is known | The honest state for anything outside the boundary (§4) |
| **Experimental** | Implemented but not validated for production use | Named implementation plus the validation that is missing |
| **Planned** | Decided but not implemented | A ticket reference; no capability claim |
| **Unsupported** | Not available on this platform/configuration, with no plan asserted | The platform matrix row (§5.3) |

Mapped onto the verified mechanisms:

| Mechanism | Highest term it can legitimately reach today |
| --- | --- |
| `aa-proxy` CONNECT / in-tunnel / DLP / MCP adjudication | **Denied before execution**, for traffic that traverses it and is MitM'd. Note the decision *source* differs by path (§2): CONNECT, DLP and LLM-host refusals are local policy; only MCP `tools/call` on a non-LLM MitM'd host is a gateway decision |
| `aa-gateway` `check_action` | **Evaluated**; reaches *Denied before execution* only through a blocking caller, and today that is the MCP path plus an SDK shim that honours the answer |
| `aa-runtime` `handle_policy_query` | **Evaluated**; *Denied before execution* only if the SDK shim honours the answer |
| `aa-runtime` `RuntimeScanner` | **Redacted** — it runs on `IpcFrame::EventReport` (`aa-runtime/src/pipeline/mod.rs:127`), i.e. *after* the action, and returns counters, not a verdict (`aa-runtime/src/pipeline/enforcement.rs:115-127` — the outcome is *"a counter on this internal outcome, **not** a verdict"*) |
| `aa-sdk-client` | **Evaluated** (advisory); it is not an enforcement point in this repo |
| eBPF TLS / file / exec probes | **Observed** / **Detected** |
| eBPF syscall guard | **Detected**, plus asynchronous process termination — explicitly **not** *Denied before execution* (§5.1) |
| `aa-devtool-*` config writes | **Not a data-path claim at all.** Writing a tool's own settings file is tool-governance; it takes effect only if the tool honours those keys, which for the macOS managed-settings path is explicitly unmeasured. Any data-path prevention these adapters deliver is `aa-proxy`'s, borrowed via injected launch environment |
| `aa-sandbox` | **Denied before execution**, for WASM-marked tools handed to it; it is not in any agent's normal tool-call path |

Note one consequence for the read surface: ADR 0018's five-way `RuntimeVerdict`
(`allow`/`narrow`/`scrub`/`pending`/`deny`) is a **frozen API vocabulary**, and
`aa-api/src/models/verdict.rs:21-24` states that deriving it at decision time *"is not
implemented here … until then the field is surfaced as `null`"*. The enforced wire
enum remains the coarser audit `Decision`. Material must not present the five-way
verdict as a live per-action outcome.

### 7. Self-reported availability is not evidence of coverage

Three signals in the current implementation look like coverage and are not. None may be
used to substantiate a protection claim:

- **`AA_LAYERS`** replaces the entire probe result with an environment variable
  (`aa-runtime/src/layer.rs:182-197`).
- **`probe_proxy`** is satisfied by a binary existing on `$PATH`
  (`aa-runtime/src/layer.rs:142-145`) — it does not establish that any process routes
  traffic through it.
- **`LayerSet::SDK`** is asserted unconditionally (`aa-runtime/src/layer.rs:19`,
  `:169`), independent of whether any agent adopted the SDK.

Coverage claims come from the E6 evidence pipeline — an adjudication reported by the
component that actually decided (`aa-proxy/src/probe_adjudication.rs:1-14`: *"A
protection probe sits on the **near** side of the MitM. It can observe that its request
went out and that nothing obviously failed, and neither fact is evidence"*) — and from
ADR 0030's ladder, never from a capability bitflag.

---

## Alternatives considered

### Keep the three-layer model and add caveats (rejected)

The cheapest option: leave `SDK → Proxy → eBPF` in place and attach platform footnotes.
Rejected because the defect is in the *structure*, not the wording. An ordered pipeline
whose members "catch what the layer above missed" has no way to express an absent
member — a caveat cannot repair a model whose shape asserts completeness. It also
leaves the gateway unplaced, which is what produces the recurring "fourth layer"
reading.

### Rename the third layer to "kernel layer" (rejected)

Slightly better than "eBPF", but still wrong in the same way: it promises a kernel
mechanism on platforms that have none, and it implies the mechanism's authority is
uniform when the verified authority is "observe, plus one opt-in asynchronous kill".
E4 names the *role* and forces the per-platform matrix (§5.3) to be published
alongside it.

### Model layers as an ordered fallback chain (rejected)

A tempting refinement: keep the ordering but state that a missing layer falls through
to the next. Rejected because it is false. `LayerSet` members are probed independently
(`aa-runtime/src/layer.rs:164-179`); nothing hands an un-intercepted action to another
mechanism. Worse, the fallback framing would license exactly the inference this Epic
exists to stop — that an action not seen by the SDK was therefore seen by eBPF.

### Define the model from the roadmap rather than from the implementation (rejected)

Describing the intended end state (synchronous LSM-based deny, macOS Endpoint Security,
a Windows adapter) would make a tidier architecture. Rejected: this ADR is cited as the
canonical source by the website, Docs Hub and Core, so it must describe what is
verified. Roadmap items are admissible only under the **Planned** or **Research** terms
of §6, with no capability claim attached.

### Fold documentation-governance rules into this ADR (rejected — different owner)

Claim precedence, source-of-truth ordering and waiver handling are genuinely needed,
but they belong to
[AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621). Defining them
here would create two competing authorities. This ADR supplies vocabulary; 5621 supplies
the governance process that enforces its use.

## Accepted risks

- **The model is more complex than the thing it replaces.** Six elements and three views
  cost more to teach than one three-box diagram. Accepted: the simpler model was
  producing false claims, and the complexity is inherent to a product whose coverage is
  a per-host, per-platform, per-launch fact.
- **The verified-state tables will age.** §5.3 and §6 are snapshots of the
  implementation at v0.0.1-rc.7. Accepted, with the mitigation that
  [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) is chartered
  to make the capability/evidence manifest machine-readable and
  [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) to gate stale
  evidence in CI. Until those land, the tables are maintained by review.
- **Honest limits are competitively unflattering.** Publishing "macOS host enforcement:
  Unsupported" and "the syscall guard does not prevent the offending syscall" weakens
  marketing copy. Accepted deliberately: an evaluator who discovers an overstated claim
  after provisioning is a worse outcome than one who reads an accurate limitation
  up front.
- **This ADR does not fix the affected pages.** It supersedes the model and lists the
  migration surface; the rewrites are owned by
  [AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528),
  [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605),
  [AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) and
  [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609). Between
  this ADR merging and those completing, the repository contains material that
  contradicts its own canonical architecture source. Accepted as a short, tracked
  window; the Migration checklist below is the closure condition.

## Explicitly forbidden designs

These must not be reintroduced, in code comments, documentation, diagrams, marketing
copy or ticket text.

1. **The fixed `SDK → Proxy → eBPF` pipeline** as the architecture, in prose or as a
   three-box diagram.
2. **eBPF (or "the kernel layer") as a cross-platform or universal final layer**, or as
   a mechanism that "catches everything, including bypass attempts".
3. **The gateway as a fourth interception layer.** It is E1 and holds no traffic.
4. **Inferring prevention from an audit event.** An event proves *Observed*; it never
   proves the action was stopped.
5. **Inferring platform support** from JavaScript or platform-neutral tests, from
   platform-neutral bindings, from an OS API *proposal*, or from a Linux-only
   implementation.
6. **Treating a capability bitflag, a `$PATH` lookup, an `AA_LAYERS` value, or the
   existence of a settings file as evidence** of coverage (§7; ADR 0030 §4.2 rule 1).
7. **Unqualified absolutes.** Specifically banned: "catch everything", "cannot be
   bypassed", "nowhere to hide", "every action", "every tool call", "no code changes",
   "immutable audit", "full fleet". Each either overstates coverage or asserts a
   property no component in this repo provides.
8. **Presenting the five-way `RuntimeVerdict` as a live per-action outcome** while its
   derivation is unimplemented (§6).
9. **Describing `RuntimeScanner` as the authoritative enforcement pipeline.** It is a
   post-action redactor; the pre-execution gate is `handle_policy_query`.

## Consequences

**For the product website, Docs Hub and Core docs.** There is now one citable source
for the architecture, and the six element names are the shared vocabulary. Pages must
state platform, decision timing and failure posture using §6's terms. The three views
(§3) must not be merged into a single diagram.

**For evaluators.** Coverage becomes legible: what is governed depends on the managed
path (§4) and the platform matrix (§5.3), both of which are now published rather than
implied.

**For contributors.** A new interception or mediation mechanism must declare which
element it implements, which platforms it covers, and the highest §6 term it can reach.
Adding a mechanism does not extend a claim on a platform where it does not run.

**For the SDKs.** ADR 0002's position — the SDK is not a security boundary — is now
visible in the architecture rather than only in a security ADR: E2 checkpoints are
reachable only when the agent opts in, and honouring a `Deny` is out-of-repo shim
behaviour.

**Costs.** Every diagram in the migration checklist must be redrawn; the repository's
own `CLAUDE.md` files describe a model this ADR supersedes; and some published claims
must be narrowed, which is a visible change in tone.

## Operational guidance

- **Deploying the proxy does not by itself govern a tool.** The tool must be launched so
  that `HTTPS_PROXY` points at it and the CA is trusted (`NODE_EXTRA_CA_CERTS` for
  Node-based tools). A tool started outside `aasm run` is outside the boundary.
- **`llm_only` defaults to true.** Hosts outside the built-in LLM set are transparently
  tunnelled and never DLP-scanned. Operators who need broader coverage must configure
  `mitm_hosts` or disable `llm_only`, and should expect the corresponding latency and
  compatibility cost.
- **`aasm proxy start` refuses a non-loopback listener** even with
  `--allow-remote-clients` (`aa-cli/src/commands/proxy/start.rs:41,67-70`), because the
  proxy has no listener TLS and no client authentication. Do not work around this.
- **The eBPF syscall guard is off unless `AA_EBPF_CONFINE_PID` is set** and the policy
  lowers to a non-empty allowlist. Enabling it accepts the §5.1 window and the
  kill-after-syscall race.
- **On macOS and Windows, plan for transport mediation only** (macOS) or for no local
  mediation at all (Windows).

## Validation requirements

The following must exist for this ADR to be considered enforced. Items not yet backed
by an automated check are marked, with the ticket that owns them — this ADR does not
claim coverage it does not have.

| # | Requirement | Status |
| --- | --- | --- |
| V1 | The banned-absolutes list (the forbidden-designs list, item 7) is checked in CI across docs | **Not yet automated** — owned by [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) |
| V2 | Platform/capability claims are generated from a machine-readable manifest rather than hand-written | **Not yet automated** — owned by [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) |
| V3 | Protection state is never reported above its evidence | **Existing** — ADR 0030 §4 rules; `aa-devtool-claude-code/src/probe.rs` returns `Inconclusive` for an unadjudicated probe |
| V4 | Adjudication is reported by the deciding component, not the probe | **Existing** — `aa-proxy/src/probe_adjudication.rs` |
| V5 | An adversarial conformance harness exercises bypass paths across SDK, proxy, MCP and host mechanisms | **Not yet built** — owned by [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532) |
| V6 | Every SDK quick-start carries an enforcement-truth negative control | **Not yet built** — owned by [AAASM-5529](https://lightning-dust-mite.atlassian.net/browse/AAASM-5529) |
| V7 | The eBPF suite's CI status is stated wherever eBPF coverage is claimed | **Manual today.** `aa-ebpf` is excluded from mainline build, clippy, nextest and doc jobs (`ci.yml:335,432,571,699`; `docs.yml:350,353`), and the eBPF/three-layer e2e jobs are path-gated to `aa-ebpf*/**` changes, so per `ci.yml:131-133` the suite is *"normally SKIPPED on main"*, with a weekly schedule plus on-demand dispatch as the standing coverage |

## Reconsideration triggers

Re-open this ADR when any of the following occurs:

1. A **synchronous** deny becomes available on Linux (seccomp-BPF or a `bpf_lsm` hook —
   [AAASM-3872](https://lightning-dust-mite.atlassian.net/browse/AAASM-3872)). §5.1 and
   §6's mapping change materially.
2. A macOS host enforcement mechanism (Endpoint Security / Network Extension) is
   implemented rather than declared a non-goal.
3. Any Windows mediation ships — a proxy build path, a named-pipe DI-API, or a host
   adapter.
4. `RuntimeVerdict` derivation at decision time is implemented, making the five-way
   verdict a live outcome.
5. `aa-ebpf` file-I/O coverage is extended to aarch64, or the probe set changes such
   that §5.1's table is no longer accurate.
6. The `llm_only` default changes, or transport mediation gains a non-Unix build path.
7. [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534)'s
   host-wide mediation feasibility spike concludes with a recommendation that changes
   E4's per-platform story.
8. AAASM-5621's documentation-governance ADR is published and requires an interface
   change to this ADR's vocabulary.

---

## Migration checklist

**No prior ADR ever recorded the three-layer model.** It propagated through prose,
diagrams, crate docs and ticket titles without a decision record — which is why it
drifted from the implementation unchecked. Consequently this ADR supersedes *material*,
not another ADR. ADR 0030 §5.3's "Layer 1 / Layer 2" (`0030:542,545`) refer to the DI-API's OS +
capability-token trust stack and are unrelated; they need no change.

This ADR does **not** perform the migration. Each item below is owned by a downstream
ticket; the checklist is the closure condition for the Epic.

### A. Core docs — `docs/src/**` (owner: [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605), claim removal: [AAASM-5528](https://lightning-dust-mite.atlassian.net/browse/AAASM-5528))

Pages whose *structure* encodes the superseded model — these need rewriting, not editing:

- [ ] `docs/src/introduction/three-layer-model.md` — the page *is* the model (title, the
      "three independent layers" table, the latency-vs-authority framing, "Everything
      else, including bypass attempts"). Replace with the six-element model; retire the
      filename.
- [ ] `docs/src/security/three-layer-defense.md` — highest density of superseded claims
      in the book. Replace with §5.3's platform matrix and §6's claim vocabulary.
- [ ] `docs/src/usage-guide/interception-layers.md` — "Choosing interception layers"
      presumes the pipeline; reframe as choosing a *managed path* and a deployment.
- [ ] `docs/src/architecture/README.md:32-40` — the `3 interception layers (SDK · proxy
      · eBPF)` mermaid diagram.
- [ ] `docs/src/architecture/system-architecture.md` — the system mermaid diagram and
      the "three interception layers" narration.

Pages that reference the model and need their claims re-termed:

- [ ] `docs/src/README.md`, `docs/src/introduction/README.md`,
      `docs/src/introduction/overview.md`, `docs/src/introduction/concepts.md`
- [ ] `docs/src/architecture/components.md`, `docs/src/architecture/workflows.md`,
      `docs/src/architecture/infra-overview.md`
- [ ] `docs/src/security/overview.md`, `docs/src/security/protection-model.md`
      (its opening sentence routes readers to `three-layer-defense.md`),
      `docs/src/security/threat-model.md`,
      `docs/src/security/release-threat-model.md`,
      `docs/src/security/trust-boundaries.md`
- [ ] `docs/src/usage-guide/enforce-egress-policy.md`, `docs/src/usage-guide/examples.md`
- [ ] `docs/src/quick-start/first-run.md`, `docs/src/quick-start/requirements.md`
- [ ] `docs/src/cli/proxy.md`, `docs/src/compatibility.md`
- [ ] `docs/src/devtools/product-brief.md`,
      `docs/src/devtools/developer-integration-api.md`
- [ ] `docs/src/governance/capability-matrix.md` — beyond the model references, its **L2
      tier definition asserts "The tool cannot bypass enforcement"**, a banned absolute
      (the forbidden-designs list, item 7) that the verified bypass surface in §4 contradicts.
- [ ] `docs/src/SUMMARY.md` — TOC entries for the two retired pages and the
      "Choosing interception layers" entry.

**Deliberately excluded — historical records, do not rewrite:**
`docs/release/v0.0.1-beta.4.md`, `verification-reports/AAASM-1066.md`,
`docs/src/research/AAASM-5269-*.md`, `docs/superpowers/plans/2026-04-28-aaasm-132-*.md`.
These are point-in-time records of what was true or planned when written; rewriting them
falsifies the record. Annotate with a pointer to this ADR if anything at all.

### B. Repository and crate documentation (owner: AAASM-5605)

- [ ] `README.md` — the repo's front door carries the model.
- [ ] `CLAUDE.md` and `.claude/CLAUDE.md` — both contain a "three-layer interception
      model" section presented as the *"single most important architectural insight"*.
      `.claude/CLAUDE.md` additionally labels `aa-runtime` the "Authoritative enforcement
      pipeline (`RuntimeScanner`)", which §6 shows is a post-action redactor, and
      describes eBPF as catching *"everything, including bypass attempts"*.
- [ ] Crate READMEs: `aa-cli`, `aa-ebpf`, `aa-gateway`, `aa-proxy`, `aa-runtime`,
      `aa-sandbox`, `aa-sdk-client`.
- [ ] `aa-runtime/src/layer.rs:1-6` — module doc states "The runtime supports three
      interception layers"; should describe an independently probed availability set.
- [ ] `aa-proxy/src/lib.rs:3` — "implements the Layer 2 interception model".
- [ ] `aa-sandbox/src/lib.rs:10-11` — claims it is "consumed by `aa-proxy` via the
      `ToolRegistry` dispatch surface"; `aa-proxy/Cargo.toml` has no `aa-sandbox`
      dependency. Stale, independent of this ADR.
- [ ] `aa-ebpf-common/README.md:11` — describes `aa-ebpf-programs` as the live BPF
      producer; that crate is a dead stub (every program body returns `0` with a TODO,
      it is not a workspace member, and `aa-ebpf/build.rs:50,90` builds only
      `aa-ebpf-probes`). Stale, independent of this ADR.

### C. Dashboard and design assets (owner: AAASM-5605, coordinate with the design-fidelity Epic)

- [ ] `dashboard/src/pages/OverviewPage.tsx`,
      `dashboard/src/features/capability/api.ts`
- [ ] `design/v2/hi-fi/overview.jsx`, `design/v2/hi-fi/live-ops.jsx`
- [ ] `design/v1/**` (`overview.jsx`, `live-ops.jsx`, `hi-fi/`, `wireframes/`) —
      superseded design generation; annotate rather than redraw.

### D. Tests and fixtures (owner: AAASM-5605 / [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532))

- [ ] `aa-integration-tests/tests/e2e_three_layers_together.rs`,
      `aa-integration-tests/tests/e2e_ebpf.rs`,
      `aa-integration-tests/tests/fixtures/e2e/three_layers_driver.py` — the scenarios
      remain valid as *deployment* coverage; the naming and the narrative comments assert
      the superseded model.

### E. Product website and Docs Hub (owner: [AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586), [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609))

- [ ] Product / "How It Works" pages rewritten around managed enforcement paths (5586).
- [ ] "What Ships Today" and "Choose Your Enforcement Path" evaluator guides published
      against §5.3 and §6 (5609).
- [ ] Host adapter support boundaries documented per
      [AAASM-5606](https://lightning-dust-mite.atlassian.net/browse/AAASM-5606).

### F. Jira items to annotate as superseded (owner: [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607))

Model-defining or still-referenced — these need a superseded-by reference to this ADR,
and their vocabulary re-framed if they are reopened:

- [ ] [AAASM-4](https://lightning-dust-mite.atlassian.net/browse/AAASM-4) — "Three-Layer Agent Interception" (the originating item)
- [ ] [AAASM-44](https://lightning-dust-mite.atlassian.net/browse/AAASM-44) — "interception layer auto-detection and graceful fallback (eBPF → proxy → SDK)"; the *fallback* framing is explicitly rejected in Alternatives
- [ ] [AAASM-3214](https://lightning-dust-mite.atlassian.net/browse/AAASM-3214), [AAASM-3223](https://lightning-dust-mite.atlassian.net/browse/AAASM-3223) — test cases asserting the three-layer model is "described accurately"; their expected result is now this ADR
- [ ] [AAASM-3249](https://lightning-dust-mite.atlassian.net/browse/AAASM-3249), [AAASM-3264](https://lightning-dust-mite.atlassian.net/browse/AAASM-3264) — QA verification of the model and its "bypass coverage"
- [ ] [AAASM-4608](https://lightning-dust-mite.atlassian.net/browse/AAASM-4608) — user-journey "Understand & exercise the three-layer interception model"
- [ ] [AAASM-4644](https://lightning-dust-mite.atlassian.net/browse/AAASM-4644) — already-filed finding about rival mental models across surfaces; this ADR is its resolution

Point-in-time execution records — annotate with a pointer, do **not** rewrite:
[AAASM-1232](https://lightning-dust-mite.atlassian.net/browse/AAASM-1232),
[AAASM-1520](https://lightning-dust-mite.atlassian.net/browse/AAASM-1520),
[AAASM-1523](https://lightning-dust-mite.atlassian.net/browse/AAASM-1523),
[AAASM-1549](https://lightning-dust-mite.atlassian.net/browse/AAASM-1549),
[AAASM-1572](https://lightning-dust-mite.atlassian.net/browse/AAASM-1572),
[AAASM-3252](https://lightning-dust-mite.atlassian.net/browse/AAASM-3252),
[AAASM-3446](https://lightning-dust-mite.atlassian.net/browse/AAASM-3446).

---

## Traceability

| Reference | Relation |
| --- | --- |
| [AAASM-5604](https://lightning-dust-mite.atlassian.net/browse/AAASM-5604) | This ADR |
| [AAASM-5526](https://lightning-dust-mite.atlassian.net/browse/AAASM-5526) | Parent Epic — host-wide capability mediation and truthful governance guarantees |
| [AAASM-5605](https://lightning-dust-mite.atlassian.net/browse/AAASM-5605) · [AAASM-5606](https://lightning-dust-mite.atlassian.net/browse/AAASM-5606) · [AAASM-5607](https://lightning-dust-mite.atlassian.net/browse/AAASM-5607) · [AAASM-5586](https://lightning-dust-mite.atlassian.net/browse/AAASM-5586) · [AAASM-5609](https://lightning-dust-mite.atlassian.net/browse/AAASM-5609) | Blocked by this ADR; they perform the migration in the Migration checklist |
| [AAASM-5621](https://lightning-dust-mite.atlassian.net/browse/AAASM-5621) | Related — owns documentation-governance semantics (source-of-truth, claim precedence, waivers), deliberately out of scope here |
| [AAASM-5527](https://lightning-dust-mite.atlassian.net/browse/AAASM-5527) · [AAASM-5534](https://lightning-dust-mite.atlassian.net/browse/AAASM-5534) | Spikes feeding §5.3's platform matrix |
| [AAASM-5529](https://lightning-dust-mite.atlassian.net/browse/AAASM-5529) · [AAASM-5531](https://lightning-dust-mite.atlassian.net/browse/AAASM-5531) · [AAASM-5532](https://lightning-dust-mite.atlassian.net/browse/AAASM-5532) · [AAASM-5535](https://lightning-dust-mite.atlassian.net/browse/AAASM-5535) · [AAASM-5536](https://lightning-dust-mite.atlassian.net/browse/AAASM-5536) | Own the unautomated Validation requirements (V1, V2, V5, V6) |
| [AAASM-3872](https://lightning-dust-mite.atlassian.net/browse/AAASM-3872) | Kill-after-syscall race; reconsideration trigger 1 |
| [AAASM-5298](https://lightning-dust-mite.atlassian.net/browse/AAASM-5298) | macOS managed-settings runtime honouring — the unmeasured half of §5.3's macOS row |
| [ADR 0002](0002-sdk-security-boundary.md) | Complements — the SDK is not a security boundary |
| [ADR 0004](0004-governance-enforcement-flow.md) | Complements — single `aa-sdk-client` transport boundary |
| [ADR 0015](0015-dlp-trust-boundary-and-redaction-semantics.md) | Complements — fail-closed redaction discipline |
| [ADR 0018](0018-canonical-runtime-verdict-and-enriched-decision-record.md) | Complements — the five-way `RuntimeVerdict`, whose derivation is unimplemented (§6) |
| [ADR 0029](0029-capability-over-permission-derivation.md) | Complements — declared vs. effective capability. **Status `Proposed`**, so this ADR relies on it as direction, not as a ratified constraint |
| [ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) | Complements — protection-state ladder and evidence rules; this ADR places them as E6 |
| [ADR 0032](0032-local-first-sensitive-data-provider-architecture.md) | Complements — local-first sensitive-data detection |
| Superseded material | The `SDK → Proxy → eBPF` three-layer interception model wherever it appears; see the Migration checklist. No prior ADR recorded it. |
| Implementation PRs | This ADR is documentation-only; the migration PRs are tracked by the tickets in the Migration checklist |
