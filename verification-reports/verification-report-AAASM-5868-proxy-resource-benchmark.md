# Proxy Resource-Overhead Benchmark — AAASM-5868

**Epic:** AAASM-5857 — per-launch dedicated `aa-proxy` (increment 10/10)
**Component / repo:** `agent-assembly`
**Ticket policy:** benchmark-only. `docs/src/governance/capability-matrix.md`'s
conflation fix is a separate change, not touched here.

## Purpose

AAASM-5857's design requires resource-overhead evidence for the per-launch
dedicated `aa-proxy` model (`ProxyGuard`, `aa-cli/src/commands/proxy/
guard.rs`) — one governed launch = one spawned proxy process, in contrast to
the earlier shared/standalone-proxy shape. This report is that evidence: RSS,
CPU, FD count, startup/readiness latency, cleanup latency, and leak-freedom
at 1 / 5 / 10 / 20 concurrent `aasm run` launches, each with its own
dedicated proxy.

## Qualified revision

| | |
|---|---|
| Branch | `v0.0.1/AAASM-5868/test/proxy_resource_benchmark` |
| Base | `remote/main` @ `672b65059` (`[AAASM-5867] 📝 (docs): ADR 0033 update for per-launch dedicated proxy`) |
| Binaries measured | `aasm` and `aa-proxy`, built `--release` from this branch |
| Harness | `aa-integration-tests/examples/proxy_resource_overhead.rs` + `aa-integration-tests/examples/aa_proxy_no_keychain.rs` |

## Environment — read this before the numbers

**Single dev machine, not CI-isolated hardware.** This is not a clean-room
measurement:

| | |
|---|---|
| Machine | MacBook Pro, Apple M3 Max (`Mac15,8`) |
| CPU | Apple M3 Max, 16 logical cores |
| Memory | 128 GiB |
| OS | macOS 26.4.1 (build 25E253) |
| Architecture | arm64 (Apple Silicon) |

Per this machine's own `~/CLAUDE.md` operational notes, it routinely runs
several other concurrent Claude Code sessions with their own subprocess
trees and their own `cargo`/`aa-proxy` activity sharing the same CPU and
disk. The benchmark run itself used a **private `CARGO_TARGET_DIR`**
(`/private/tmp/.../scratchpad/cargo-target-5868`) to avoid build-artifact
contention with those sessions, but nothing isolates *runtime* CPU/scheduler
contention — a proxy's CPU-percentage numbers below are measured against a
shared, loaded scheduler, not an idle box. Treat the RSS/FD numbers (which
are not CPU-scheduler-sensitive) as the more load-bearing evidence, and the
CPU-percentage and latency numbers as directionally accurate but not a clean
isolated-hardware benchmark.

**Repetition: 1 run per concurrency level**, not the several-repetition
statistical protocol a clean benchmark would use — time-boxed per the
ticket's own allowance ("reduce concurrent-run repetition count ... as long
as you say so"). Every number below is a single measured sample, not a
mean-of-N with a reported variance. Treat single-outlier values (e.g. the
n=20 max startup latency) with that in mind.

## Why the proxy under test is not the shipped `aa-proxy` binary

The real `aa-proxy` installs its CA into the macOS System Keychain via
`security add-trusted-cert` on first use of an untrusted `ca_dir`
(`aa-proxy/src/lib.rs::run`, `aa-proxy/src/tls/keychain.rs`) — a call that
blocks on a GUI authentication dialog. Verified directly: invoking
`security add-trusted-cert` against a throwaway CA on this machine was
refused by this environment's own command-safety policy as a system-trust
mutation requiring explicit human confirmation, before this benchmark ever
reached the point of running it inside a spawned process. Running the real
binary against a fresh `ca_dir` (the default — 20 concurrent launches cannot
share the operator's already-trusted `~/.aa/ca` without also proving that
sharing is safe, which is out of this ticket's scope) was therefore not an
option without a human physically approving a Keychain prompt, which this
benchmark cannot do and must not attempt to route around.

`aa-integration-tests/examples/aa_proxy_no_keychain.rs` is the same
production `ProxyConfig::from_env()` loader and the same
`proxy::ProxyServer` MitM engine — reusing this crate's own established
pattern for this exact problem (`examples/proxy_with_mock_upstream.rs`,
which documents the same constraint for the standalone-proxy path) — with
only the two-line keychain-install block omitted. `ProxyGuard` cannot tell
the difference: it resolves whatever is on `PATH` named `aa-proxy` and
drives it through the identical `AA_PROXY_READY_FILE`/`AA_PROXY_PARENT_PID`
protocol either way. This means: **the resource cost measured here is the
real credential-scanning, MitM-decrypt, and gateway-network-policy-enforcing
`ProxyServer`** — the only thing not exercised is the one-time,
machine-global CA-keychain-trust step, which runs at most once per
operator machine in production and is not part of the per-launch cost this
ticket is measuring anyway.

A second, smaller substitution: `AA_PROXY_GATEWAY_ENDPOINT` is always set by
`ProxyGuard` (every managed launch is gateway-authoritative for network
egress since AAASM-5851), so the benchmark's own local gRPC gateway serves
both `AgentLifecycleService` (registration) and a real `PolicyServiceImpl`
loaded from a wildcard-allow (`spec.network.allowlist: ["*"]`) policy
fixture — otherwise the active-forwarding CONNECT this benchmark drives
would be denied by policy before reaching the proxy's forwarding code at
all, which would measure "gateway said no" instead of "the proxy forwarded
a request."

## Harness

`aa-integration-tests/examples/proxy_resource_overhead.rs` (standalone
driver, not a `#[test]` — see its own module doc for why). Per concurrency
level, for each of the N launches, concurrently:

1. Spawn a real `aasm run claude --policy ... --agent-id ...` (a stub
   `claude` binary standing in for the tool, matching
   `cli_run_leak_freedom.rs`'s pattern).
2. Find the dedicated proxy's OS pid as the `aasm run` process's own child
   (matching `cli_run_leak_freedom.rs::find_proxy_child_pid`) and time to
   the stub tool actually starting — the closest externally observable
   readiness bound (**startup latency**).
3. Sample **RSS** (`ps -o rss=`) and **FD count** (`lsof -a -p <pid> -n -P`,
   minus the header line).
4. Bracket a 3-second idle window, sampling `ps -o time=` (cumulative CPU
   time) before and after, converting Δcputime/Δwall to a percentage
   (**idle CPU**).
5. Signal the stub to make one real HTTPS request through its dedicated
   proxy (`curl --cacert <launch's CA cert> -x $HTTPS_PROXY
   https://example.com`) and bracket the same Δcputime/Δwall around the
   curl call's own wall-clock window (**active-forwarding CPU**). Because a
   gateway-managed launch forces `AA_PROXY_LLM_ONLY=false`, this CONNECT is
   genuinely MitM'd (decrypt, forward, re-encrypt) rather than a plain
   tunnel-relay — `--cacert` is what lets `curl` complete that TLS
   handshake against the launch's own throwaway CA.
6. SIGTERM the launcher and time until the dedicated proxy's pid is
   actually gone (`kill -0` fails) — **cleanup latency**.
7. After every launch in the scenario has terminated, scan the whole
   process table for anything still running under this benchmark run's own
   staged proxy-binary path (unique per run) — **leak-freedom**.

## Scenarios executed and results

| Concurrency | Launches OK | Mean proxy RSS (KiB) | Max proxy RSS (KiB) | Summed RSS (KiB)¹ | FD count (min–max) | Mean idle CPU | Mean / max active CPU | Mean / max startup latency (ms) | Mean / max cleanup latency (ms) | Leaked processes |
|---|---|---|---|---|---|---|---|---|---|---|
| 1  | 1/1   | 9,840 | 9,840 | 9,840   | 15–15 | 0.0% | 15.3% / 15.3% | 453 / 453   | 228 / 228 | 0 |
| 5  | 5/5   | 9,789 | 9,824 | 48,944  | 15–15 | 0.0% | 13.2% / 15.8% | 1,107 / 1,749 | 252 / 291 | 0 |
| 10 | 10/10 | 9,824 | 9,856 | 98,240  | 15–15 | 0.0% | 13.7% / 17.7% | 2,101 / 3,565 | 270 / 292 | 0 |
| 20 | 20/20 | 9,830 | 9,920 | 196,592 | 15–15 | 0.0% | 13.9% / 17.4% | 3,505 / 6,465 | 258 / 286 | 0 |

¹ Summed RSS double-counts each proxy's shared read-only text/library
segments (the `aa-proxy` binary and its dynamic dependencies are the same
mapped pages across every process) — it is not "20× the marginal cost of
one proxy," it is an upper bound. Per-proxy mean/max RSS is the primary,
non-inflated number.

Every one of the 36 launches across all four scenarios completed its
active-forwarding `curl` request with HTTP 200 — the full MitM round trip
(gateway network-policy check → CONNECT accept → leaf cert issuance → TLS
termination → forward → response) succeeded on every launch at every
concurrency level, not just a subset.

## Reading the numbers

- **RSS is flat with concurrency.** Per-proxy RSS stays within a ~150 KiB
  band (9,789–9,920 KiB) from 1 to 20 concurrent launches — no evidence of
  a shared-state cost that grows with launch count. Each dedicated proxy's
  memory footprint is small (~9.6 MiB) and independent of how many siblings
  are running.
- **FD count is flat and small** at 15 open descriptors per proxy,
  unaffected by concurrency.
- **Idle CPU is effectively zero** (0.0% at every level) — a dedicated
  proxy sitting with no traffic costs nothing measurable on the scheduler.
- **Active-forwarding CPU is modest and roughly flat** (~13–17% of one
  core, bracketed over each launch's own short curl window) — consistent
  with "N independent proxies each doing their own small amount of work,"
  not a resource contending across launches.
- **Startup latency grows with concurrency** — 453 ms at n=1 up to a mean of
  3,505 ms (max 6,465 ms) at n=20. This is the one dimension that shows real
  concurrency-driven contention: 20 `aa-proxy` processes cold-starting
  (binding a loopback listener, loading the shared CA, registering with the
  gateway) at once on one machine compete for CPU/scheduler time before any
  of them reports ready. All 20 still completed well inside the 45-second
  patience window this benchmark used — there was no readiness-timeout
  failure at any tested concurrency level, but the growth trend is real and
  should inform any decision about how many launches an operator runs
  concurrently on one host.
- **Cleanup latency is flat** (~220–290 ms) regardless of concurrency —
  each launch's SIGTERM→exit teardown does not appear to contend with
  its siblings'.
- **Zero leaked processes at every concurrency level.** After every launch
  in every scenario terminated, a full process-table scan for this
  benchmark run's own staged proxy binary found nothing left running —
  consistent with the leak-freedom evidence AAASM-5866 already established
  for single launches, now also true under concurrency up to 20.

## What was not measured, and why

- **No statistical repetition** (see Environment section) — one sample per
  concurrency level, time-boxed per the ticket's own allowance. A
  follow-up wanting confidence intervals would need several repetitions on
  quieter hardware.
- **CPU percentages are scheduler-contended**, not clean-room — this
  machine runs other concurrent sessions throughout. Treat the CPU numbers
  as directional, not a precise SLA figure.
- **No measurement above 20 concurrent launches** — out of this ticket's
  stated scope (1/5/10/20 only).
- **The one-time CA-keychain-trust cost is not measured** (the substitution
  in the previous section explains why) — it is a machine-global one-time
  operator step, not a per-launch cost, so it is out of scope for "per-
  launch dedicated proxy resource cost" regardless.

## No scaling/multiplexing problem found

Per the ticket's explicit instruction: if the numbers had demonstrated a
real product problem (RSS/FD growing per-launch, active-CPU contending
across launches, or leaks appearing at higher concurrency), it would be
recorded here plainly rather than used to justify designing a shared-proxy
multiplexing protocol. **No such problem was found.** RSS, FD count,
active CPU, and cleanup latency were all flat or near-flat from 1 to 20
concurrent launches; the only genuine growth (startup latency) stayed well
within the existing readiness timeout at every tested level and reflects
ordinary cold-start CPU contention, not a design defect in the per-launch
model. No multiplexing-protocol follow-up is warranted by this data.

## Verdict

The per-launch dedicated `aa-proxy` model (AAASM-5857) demonstrates flat,
small, per-proxy resource cost (RSS ~9.6–9.9 MiB, 15 FDs, ~0% idle CPU,
~14–17% active CPU during forwarding) and zero process/listener leaks from
1 through 20 concurrent governed launches on real hardware. Startup latency
grows with concurrency under cold-start contention on a single loaded dev
machine but stays comfortably inside the existing readiness timeout at
every tested level. This satisfies AAASM-5868's benchmark requirement and
provides the architecture acceptance evidence AAASM-5857's design calls for
— measured on a single dev machine (Apple M3 Max, macOS 26.4.1), not
CI-isolated hardware, per the caveats above.
