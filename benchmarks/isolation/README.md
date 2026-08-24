# Execution-isolation benchmark harness

Measures representative coding-agent workloads under a pluggable *launcher*, so
the cost of AASM's execution-isolation boundary can be compared against an
unconfined baseline on the same host.

Read [METHODOLOGY.md](METHODOLOGY.md) before running anything or quoting any
number from it. It carries the pre-registered thresholds, the admissibility
rules and the reason a cross-platform comparison is invalid.

## Status

The backend this exists to measure — Sandlock, AAASM-5708 — is merged,
`aasm run --isolation process` (AAASM-5711) is activated on `main`, and a
real confined-arm measurement now exists: captured on a Linux GitHub Actions
runner with sandlock 0.8.6 installed, same host and session as its
unconfined control. See METHODOLOGY.md's
[Confined-arm measurement](METHODOLOGY.md#confined-arm-measurement-aaasm-5713)
section for the full environment, the measured P1/P4/P5/P6/P7 values, and the
compatibility catalogue.

**The decision matrix is still blocked**, but for a specific, diagnosed
reason rather than an absent measurement: 5 of 8 default families fail under
confinement, all traced to the same root cause (the confined-arm policy's
write grant doesn't cover `/dev/null`, which every one of them redirects
noisy tool output to), which knocks P2 and P3 out of admissibility. The fix
is identified in METHODOLOGY.md's Follow-up section but not applied or
re-measured in this pass.

## Requirements

Python 3.9+ standard library only — no third-party packages, so the harness runs
on whatever a benchmark host happens to ship. Individual workload families need
`rg`, `git`, `node`, `pnpm`, `cargo` or `openssl`; a family whose tooling is
absent is recorded as skipped **with a reason** and counted in the run's
`denominators` block rather than silently dropped.

## Usage

```sh
cd benchmarks/isolation/harness

# Environment block only, to check what would be recorded.
python3 aabench.py env

# Baseline arm.
python3 aabench.py run \
    --label unconfined-baseline \
    --out ../results/baseline.json

# Confined arm — Linux + the sandlock backend only. A fixed --scratch-root is
# required so the policy's write grant can name it; render the policy against
# that same path before running. Every path handed to --launcher or to
# AABENCH_SANDLOCK_POLICY must be absolute: runner.py chdirs the launched
# child to the monorepo root before exec, so a path written relative to this
# directory resolves against the wrong one and the launch fails immediately
# for every family, including startup_nop (AAASM-5713 learned this the hard
# way on the first confined-arm CI run).
here="$(pwd)"
scratch=/tmp/aabench-confined-scratch
mkdir -p "$scratch"
sh "$here/../policy/render.sh" "$scratch" "$here/../policy/confined-arm.yaml"
AABENCH_SANDLOCK_POLICY="$here/../policy/confined-arm.yaml" \
python3 aabench.py run \
    --launcher "sh $here/../launchers/sandlock.sh" \
    --label sandlock \
    --scratch-root "$scratch" \
    --keep-scratch \
    --out ../results/confined.json

# Score one against the other.
python3 aabench.py compare \
    --baseline ../results/baseline.json \
    --candidate ../results/confined.json \
    --out ../results/comparison.json

# Negative control: exits non-zero unless the harness detects a known slowdown.
python3 aabench.py self-test
```

Useful flags: `--repetitions` / `--warmups` (default 10 and 2), `--families a,b`,
`--heavy` to include `rust_cargo_check`, `--no-network` to drop the loopback TLS
family, `--keep-scratch` to retain per-repetition logs for debugging.

## Layout

| Path | Contents |
| --- | --- |
| `METHODOLOGY.md` | Pre-registered plan, thresholds and decision rule |
| `harness/aabench.py` | CLI: `run`, `compare`, `env`, `self-test` |
| `harness/thresholds.py` | The thresholds as code, mirroring the doc |
| `harness/runner.py` | fork/execvp/wait4 measurement core |
| `harness/envinfo.py` | Environment capture and comparison fingerprint |
| `harness/stats.py` | Distribution summary and admissibility gate |
| `harness/compare.py` | Scoring, guards, and the blocked-verdict rule |
| `harness/selftest.py` | Negative control |
| `harness/tlsserver.py` | Loopback TLS server for the network family |
| `workloads/` | One shell script per family, plus `manifest.json` |
| `launchers/` | `unconfined.sh` (baseline), `throttled.sh` (control only), `sandlock.sh` (Sandlock confined arm, Linux only), `native.sh` (AASM-native confined arm, Linux only, AAASM-5805), `macos-vm.sh` (aasm-macos-vm confined arm, macOS/Apple-Silicon only, **informational, `startup_nop` family only** — AAASM-5814, see below) |
| `policy/` | `confined-arm.yaml.tmpl` (two-arm sandlock comparison), `three-arm.yaml.tmpl` (AAASM-5805, no `network:` node — see that template for why the native arm needs it), `render.sh` (renders either, defaults to `confined-arm.yaml.tmpl`), `allow-all.yaml` (smoke-test only, not a data arm) |
| `policy-macos-vm/` | `startup-nop.yaml` — the `macos-vm.sh` launcher's own policy. Grants `network_outbound` (this backend has no network device to satisfy any network requirement with, granted or not — see the file's own header) and `terminal_exec` (required for any exec to succeed under this backend at all) |
| `dogfood/policy-macos-vm/` | Templated policies (`confined`/`confined-no-exec`/`permissive`) for `dogfood/run-scenarios-macos-vm.sh`, the macOS-VM sibling of `dogfood/run-scenarios.sh` (AAASM-5809/AAASM-5814) |
| `results/` | Committed baseline and self-test evidence |

## Two guards worth knowing about before you run this

**A comparison across environments is refused.** `compare` requires both arms'
environment fingerprints to match, and exits non-zero when they do not. This is
not pedantry: the committed baseline was captured on macOS and the eventual
backend is Linux-only, so the most natural mistake available — reusing this
baseline as the control for a Linux confined run — is the one the harness
refuses. `--allow-cross-env` overrides it but stamps the output
`INVALID_CONTROL` and forces the verdict to null.

**A noisy family is unmeasured, not slow.** A family is admissible only with 10+
clean repetitions and a relative IQR at or under 0.15. An inadmissible family
blocks the verdict instead of being rounded into it. The fix is a quieter host
and a re-run, never a softer threshold.

## Committed results

| File | What it is |
| --- | --- |
| `results/baseline-unconfined-darwin.json` | Unconfined baseline, macOS. **Not a control for any Linux run** — see METHODOLOGY.md |
| `results/confined-run-baseline-unconfined-linux.json` | Unconfined baseline, Linux — the real control for the confined run below |
| `results/confined-run-sandlock-linux.json` | The confined arm: sandlock 0.8.6, same host and session as the baseline above |
| `results/confined-run-comparison-linux.json` | `aabench.py compare`'s output for the two above |
| `results/selftest-evidence.json` | Negative-control evidence, with both comparisons |
| `results/selftest-arm-*.json` | The three synthetic control arms behind that evidence |

The `selftest-arm-*` files are **synthetic control arms**, not backend
measurements. They carry `"control_experiment": true` and no product decision
may be drawn from them.

## aasm-macos-vm: informational only, not a fourth arm (AAASM-5814)

`results/startup-nop-*-macos-arm64.json` measure `launchers/macos-vm.sh`
against `launchers/unconfined.sh`, same host and session, `startup_nop`
family only (real `aabench.py compare` output,
`control_validity: VALID`, `P1: RED +706.7ms`). This is deliberately **not**
folded into the three-arm comparison above, the `METHODOLOGY.md`
decision rule, or `harness/thresholds.py` — three structural reasons, not an
oversight:

1. **Only one family has a guest-side equivalent.** The guest carries no
   general toolchain (AAASM-5849) — no python3, git, cc, or `rg` — so
   `many_small_files`, `rust_cargo_check`, `python_pkg_test`, etc. cannot run
   in the guest at all. `launchers/macos-vm.sh` refuses every other family
   loudly rather than attempting something broken.
2. **The comparison host is macOS**, and every other arm's data is Linux
   (the `compare` guard above refuses a cross-environment comparison for
   exactly this reason). `startup-nop-baseline-unconfined-macos-arm64.json`
   is this measurement's own same-host baseline, not
   `results/baseline-unconfined-darwin.json` (a different, older capture).
3. **Real cost is boot-dominated, not process-fork-dominated.** This backend
   boots a real Linux guest via Virtualization.framework per launch
   (`docs/src/security/execution-isolation.md`'s "One guest boot per
   launch") — a categorically different mechanism from every other arm's
   host-process confinement, so a same-scale RED/GREEN grade against them
   would compare unlike things under one threshold designed for the other
   three.

Real evidence of the confined boundary itself — not just startup cost —
comes from `dogfood/run-scenarios-macos-vm.sh`
(`docs/src/security/execution-isolation.md`, AAASM-5814), which exercises 12
real scenarios against real guest hardware (inspect-share, edit/create/delete
a permitted file, spawn a child, prohibited-fs-write with a negative control,
descendant confinement with a negative control, capability denial with a
negative control, explicit pinning, exit-code propagation) plus three
recorded `no-counterpart` declines for the toolchain-dependent scenarios this
guest cannot run.

## Gates

```sh
shellcheck workloads/*.sh launchers/*.sh policy/*.sh
uvx ruff check harness/          # config in ./ruff.toml
uvx mypy --strict harness/
python3 harness/aabench.py self-test
```

No CI job currently covers `benchmarks/**` — `ci.yml`'s path triggers do not
match this directory, so these gates are local-only. Wiring them up means
editing `.github/workflows/ci.yml`, which AAASM-5713 does not own.
