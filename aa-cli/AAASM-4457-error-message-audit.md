# AAASM-4457 — Audit of hardcoded / stale CLI and error messages

Follow-up to **AAASM-4450**, which found that `aasm start` printed
`failed to exec aa-gateway` regardless of which binary it actually launched
(local mode spawns `aa-api-server`, not `aa-gateway`). This ticket systematically
sweeps the workspace for other operator-facing messages that hardcode a
**binary name, command, flag, env var, port/URL, path, or entity** that can be
wrong at runtime — i.e. a message that names *X* while the code operates on *Y*.

## Scope of the sweep

User-facing string literals in `eprintln!` / `println!` / `panic!` /
`.expect(...)` / `.context(...)` / tracing `info!`/`warn!`/`error!` / thiserror
`#[error("...")]`, across `aa-cli` (primary) and the operator-facing crates
`aa-gateway`, `aa-api`, `aa-runtime`, `aa-proxy`, `aa-sandbox`, `aa-security`,
and the `aa-devtool-*` adapters. Doc comments (`//` / `///` / `//!`) were noted
where wrong but treated as lower priority than runtime-visible messages.

## Summary

| # | Location | Class | Disposition |
|---|----------|-------|-------------|
| 1 | `aa-cli/src/commands/start.rs:239,248` | Wrong binary name (`aa-gateway` vs `aa-api-server` in local mode) | **Covered by AAASM-4450** — not touched here |
| 2 | `aa-cli/src/commands/run.rs:299` | Wrong binary name (`aa` vs `aasm`) | **Fixed** |
| 3 | `aa-devtool-copilot/src/lib.rs:355-356` | Wrong binary name + stale subcommand | **Partly fixed** (binary) / **deferred** (subcommand) |
| 4 | `aa-gateway/src/budget/pricing.rs:104` | Hardcoded filename vs arbitrary `path` arg | **Fixed** |
| 5 | Doc comments (`aa-gateway/src/main.rs:128`, `aa-devtool-windsurf/src/lib.rs:15`, audit-module inline comments) | Stale command / binary names in comments | **Deferred** (not runtime-visible) |

**3 findings fixed, 2 deferred, 1 covered by AAASM-4450.**

---

## Fixed

### 2. `aa-cli/src/commands/run.rs:299` — `aa audit list` → `aasm audit list`

The `--observe` sandbox banner printed:

```
    Review captured events: aa audit list --dry-run-only
```

The operator binary is `aasm` (`aa-cli/Cargo.toml` `[[bin]] name = "aasm"`,
`#[command(name = "aasm")]`). There is no `aa` binary, so a user copy-pasting the
tip gets "command not found". Every other tip in the CLI correctly says
`aasm …`. The subcommand `audit list --dry-run-only` is otherwise correct
(`ListArgs::dry_run_only` exists). Fix: correct the binary name only. The
surrounding banner lines (matched by log scrapers per the function's doc
comment) are unchanged — no lines added/removed/reordered.

### 4. `aa-gateway/src/budget/pricing.rs:104` — hardcoded `pricing.json`

```rust
pub fn load_from_file(path: &std::path::Path) -> Self {
    ...
    eprintln!("aa-gateway: pricing.json parse error ({e}); using defaults");
```

`load_from_file` accepts an arbitrary `path`, but the parse-error message
hardcodes the filename `pricing.json`. Pointed at a differently-named file, the
error misnames the offending file — exactly the "names X, operates on Y" class.
Fix: interpolate `path.display()`. Low impact (production builds the table via
`default_table()`; `load_from_file` is currently test-only), but the fix is
trivial and removes the misdirection.

### 3 (partial). `aa-devtool-copilot/src/lib.rs:355` — `aa run` → `aasm run`

The Copilot adapter's `build_launch_command` returns:

```
GitHub Copilot is a VS Code extension and cannot be launched by `aa run`;
apply governance settings with `aa tool apply copilot` instead
```

`aa run` is the wrong binary (`aasm run`). Fixed the launch-clause binary name
and strengthened the existing `build_launch_command_returns_error_with_message`
test to assert the message names `aasm run`.

---

## Deferred (recommend follow-up)

### 3 (remainder). `aa tool apply copilot` — nonexistent subcommand

The second clause of the Copilot message directs operators to
`aa tool apply copilot`. Beyond the `aa`→`aasm` binary error, **no such
subcommand exists**: the CLI's tool group is `tools` (plural,
`aa-cli/src/commands/tools.rs`) and its only subcommand is `list` — there is no
`apply`. The *correct* command to apply Copilot governance is undefined at the
CLI today (governance is applied by the adapter writing VS Code `settings.json`,
with no CLI trigger wired up). Because the correct replacement is ambiguous and
requires a product decision, this clause was left unchanged rather than
fabricating a command that looks real but isn't. **Follow-up:** decide the
operator flow for applying Copilot (and other non-launchable adapter)
governance, then correct this message to match.

### 5. Stale names in doc comments (not runtime-visible)

Lower priority — not operator-facing output, so out of scope for a message-fix
PR, but noted for a docs pass:

- `aa-gateway/src/main.rs:128` — doc says invocation contract `aasm-gateway --policy …`; the binary is `aa-gateway`.
- `aa-devtool-windsurf/src/lib.rs:15` — doc says "Builds the `aa run windsurf` launch Command" (should be `aasm run`).
- `aa-cli/src/commands/audit/*.rs` and `run.rs` inline comments use `aa audit list` / `aa run` shorthand (should be `aasm …`).
- `aa-cli/src/commands/start.rs` doc comments describe the start path generically as "spawn `aa-gateway`" even though local mode spawns `aa-api-server` — inside the AAASM-4450 region, left untouched to avoid conflict.

---

## Covered by AAASM-4450 (listed, not touched)

- `aa-cli/src/commands/start.rs:239` — `eprintln!("aasm start: failed to exec aa-gateway: {e}")`
- `aa-cli/src/commands/start.rs:248` — `eprintln!("aasm start: failed to spawn aa-gateway: {e}")`

Local mode (`ProcessSpawner::command`) launches `aa-api-server`, so these name
the wrong binary. Being fixed in the parallel AAASM-4450 PR; excluded here to
avoid a merge conflict.

---

## Verified correct (spot-checked, no defect)

The sweep confirmed these are *not* defects (each interpolates the runtime value
or names the correct entity):

- CLI help/`after_help` examples (`topology team/lineage/overview/stats`,
  `policy show`) — every flag shown (`--status`, `--show-budget`,
  `--show-permissions`, `--output`) exists on the referenced command.
- `aa-cli/src/commands/proxy/start.rs` — messages name `aa-proxy` (the binary it
  actually resolves and spawns) and interpolate `args.listen` / `binary.display()`.
- `aa-cli/src/commands/gateway/*` — `start`/`stop`/`status` deliberately wrap the
  `aa-gateway` daemon; the name is correct there.
- `aa-cli/src/commands/context.rs` — env-var messages use the `AASM_API_KEY`
  constant, not a literal.
- `approvals watch` tip `aasm approvals approve <id> --reason` — `ApproveArgs`
  does expose `--reason`.
- `agent inspect` tip `aasm trace <session-id>` — matches `TraceArgs::session_id`.
- `aa-gateway`: `AA_OPCONTROL_NATS_*` (nats.rs), `AA_MODE`/`--policy` (main.rs),
  TLS-refusal env constants (server.rs) all match the code.
- `aa-api`: `AA_API_ADDR`, `AASM_API_AUTH`, `AASM_API_KEY` match reads; "must be
  32 hex characters" and "must be 300, 900, or 3600" match the code bounds.
- `aa-runtime`: env-var errors name the var actually parsed; "aa-proxy binary not
  found" matches `which::which("aa-proxy")`.
- `aa-devtool-{codex,windsurf,claude-code,saas}` — each adapter's runtime messages
  name its own tool / env var (`WINDSURF_BIN`, `codex`, per-provider signature
  headers) correctly.
