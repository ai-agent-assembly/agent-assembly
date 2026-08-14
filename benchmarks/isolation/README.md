# Execution-isolation benchmark harness

Measures representative coding-agent workloads under a pluggable *launcher*, so
the cost of AASM's execution-isolation boundary can be compared against an
unconfined baseline on the same host.

Read [METHODOLOGY.md](METHODOLOGY.md) before running anything or quoting any
number from it. It carries the pre-registered thresholds, the admissibility
rules and the reason a cross-platform comparison is invalid.

## Status

The backend this exists to measure — Sandlock, AAASM-5708 — is merged, and
`aasm run --isolation process` (AAASM-5711) is activated on `main`. What is
**not** yet committed is a confined-arm measurement: producing one requires a
Linux host with the sandlock mechanism actually installed, and no session
that has worked on this directory so far has had one. `launchers/sandlock.sh` and `policy/confined-arm.yaml.tmpl` are built and
confirmed against a real local build of `aa-cli` — both the CLI grammar (see
the launcher's own header comment) and, separately, that the policy's
`filesystem`/`network` grants actually lower to real requirements rather than
`not_stated` (see `policy/README.md`'s dry-run evidence). Running the
confined arm on a Linux host should not require further plumbing work.
**No verdict is drawn and none can be**: `compare` always reports the
compatibility and security dimensions as blocked, so the decision rule can only
return "no verdict" from timing data alone until that run exists.

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
| `launchers/` | `unconfined.sh` (baseline), `throttled.sh` (control only), `sandlock.sh` (confined arm, Linux only) |
| `policy/` | `confined-arm.yaml.tmpl` + `render.sh` (the confined arm's real policy), `allow-all.yaml` (smoke-test only, not a data arm) |
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
| `results/selftest-evidence.json` | Negative-control evidence, with both comparisons |
| `results/selftest-arm-*.json` | The three synthetic control arms behind that evidence |

The `selftest-arm-*` files are **synthetic control arms**, not backend
measurements. They carry `"control_experiment": true` and no product decision
may be drawn from them.

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
