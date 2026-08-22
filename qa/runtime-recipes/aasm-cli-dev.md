# Runtime recipe: `aasm` CLI — source development build

**Public-artifact vs. source-development**: this is the **source-development**
recipe (labeled distinctly per AAASM-5830) — it builds from the monorepo
checkout. It must **not** be used to satisfy a public golden-journey check
(e.g. AAASM-4522 J04 "Install the aasm CLI") — that journey verifies the
*published* `install.sh`/Homebrew path, which this recipe does not exercise.
Use this recipe for `qa-functional`'s in-repo CLI behavior checks where the
journey under test is explicitly a source/contributor path (e.g. J30).

## Preconditions

- `agent-assembly/` checkout (or worktree) at the SHA under test.
- Rust toolchain per `CONTRIBUTING.md` (stable, `RUSTUP_TOOLCHAIN=stable` if
  this machine's default setup requires it — see repo `.claude/CLAUDE.md`).
- No machine-specific absolute paths required beyond the checkout itself.

## Build

```bash
cd agent-assembly   # or your worktree
export CARGO_TARGET_DIR=$(mktemp -d)   # isolated — never assume a shared/prior build
cargo build -p aa-cli --bin aasm
```

Do not point `CARGO_TARGET_DIR` at the shared cargo target dir this machine
normally uses for interactive development — a QA run must not race a live
development session for the shared-target flock (see the machine's own
`~/.cargo/config.toml` note and the "another Claude session holds the shared
cargo lock" lesson). An isolated temp dir avoids that entirely and is cheap
for one crate.

## Readiness observation

```bash
"$CARGO_TARGET_DIR/debug/aasm" --version
# expect: aasm <version>
```

## Minimal behavior probe

```bash
"$CARGO_TARGET_DIR/debug/aasm" status
# expect: prints a status table; "Health: ✗ unreachable" is CORRECT when no
# gateway is running locally — that is the CLI accurately reporting an
# unreachable dependency, not a failure of this recipe. A crash or non-zero
# unexpected exit IS a finding.
```

## Cleanup

```bash
rm -rf "$CARGO_TARGET_DIR"
```

## Platform constraints

- eBPF-dependent subcommands are Linux-only; `aa-cli`'s own build works on
  macOS/Linux (this recipe was executed and verified on macOS).

## Verified

Executed 2026-08-22 against `remote/main` (`ce4638405`) from a fresh isolated
`CARGO_TARGET_DIR`: build completed in ~1m55s, `--version` printed
`aasm 0.0.1-rc.6`, `status` printed the expected table with `Health: ✗
unreachable` (no local gateway running — correct), cleanup removed the temp
target dir. No dependency on any pre-existing worktree/process/path beyond
the checkout itself.
