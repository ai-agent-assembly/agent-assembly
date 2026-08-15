# Policy artifact for the confined arm

`confined-arm.yaml.tmpl` + `render.sh` produce the policy
`launchers/sandlock.sh` runs the confined arm under, via
`aasm run exec --isolation process --no-proxy --policy ...`.

## What this states, and why

Read against `aa-policy/src/canonical.rs` (`PolicyDocument::to_canonical`,
which is what actually feeds isolation lowering — **not**
`aa-policy/src/resolve.rs`'s `project_rules`, a different projection that
feeds the dev-tool adapter's settings file and carries only the `tools:`
dimension) and `aa-isolation/src/lowering.rs` (`lower_policy`,
`DomainCoverage`):

- **`filesystem.read.allow: ["/"]`** — deliberately unrestricted. The default
  workload families call out to python3, node, pnpm, cargo, rg and git, whose
  interpreters, standard libraries and dependency caches live wherever the
  host's toolchain installer put them. Naming those paths correctly ahead of
  a live run is a runner-image detail this ticket cannot get right from
  static reading, and a wrong guess would fail every family for a
  policy-authoring reason that has nothing to do with the sandlock backend.
  Filesystem-**read** confinement is consequently not exercised by this
  policy or this run.
- **`filesystem.write.allow: ["<scratch root>"]`** — every default workload
  family (`../workloads/*.sh`) was already written to confine its own writes
  to the scratch directory the harness hands it (`rust_cargo_check.sh` pins
  `CARGO_TARGET_DIR` there for exactly this reason). This is a real, narrow
  grant, not a wildcard: a write outside it failing under confinement is
  either a genuine backend limitation or a workload family that turns out
  not to be as contained as its own comment claims, and either is a real
  compatibility finding.
- **`network.allowlist: ["127.0.0.1"]`** — the only network the default
  families need is the harness's own loopback TLS server
  (`harness/tlsserver.py` binds `127.0.0.1`).
- **No `capabilities:` node** — process creation (`agent_spawn` /
  `terminal_exec`) is deliberately left unstated.

## Confirmed against a real `aasm run --dry-run`, not just read from source

Before trusting the reasoning above, it was checked against
`aasm run exec --isolation process --no-proxy --policy <rendered> --dry-run
-- echo hi` on a fresh local `aa-cli` build. The `--- execution isolation
---` report's per-capability table confirmed exactly what the source
predicts:

| Domain | Requested | What that means |
| --- | --- | --- |
| `filesystem_read` | `stated` | the `/` read grant lowered to a real requirement |
| `filesystem_write` | `stated` | the scratch-root write grant lowered to a real requirement |
| `network_egress` | `stated` | the `127.0.0.1` allowlist lowered to a real requirement |
| `process_creation` | `not_stated` | *"schema default: no capability restriction was declared; the document neither grants nor withholds this domain"* — confirms leaving `capabilities:` unset does not confine process spawning, matching the intent above |
| `syscall` | `not_stated` | same shape, unset, unconfined |

That confirms the policy *lowers* the way this document claims. It does
**not** confirm the sandlock backend actually *enforces* those three stated
requirements correctly end to end — this host is macOS, so the dry-run's
`backend: <none selected>` and every per-capability `state: unmeasured` is as
far as it goes without a Linux + sandlock host. That last mile is what the
Linux CI job (`../../../.github/workflows/ci.yml`) exists to close.

## What this run does not measure

- **Filesystem-read confinement.** Read access is granted everywhere, so no
  compatibility finding from this run says anything about the cost or
  coverage of restricting reads.
- **A real process-creation *security* control.** Leaving `capabilities:`
  unset means the `process_creation` domain is never asked to restrict
  anything (confirmed `not_stated` above), so P4's measured 1.82x is **not**
  the cost of a "prevent further spawning" control — no such control was ever
  requested. It is real measured overhead nonetheless: `process_spawn`
  succeeded and its 200 `execve`+reap cycles were genuinely 1.82x slower
  under confinement, which is the incidental cost of the filesystem-write
  Landlock ruleset's own per-`execve` path-resolution checks, paid on every
  process creation regardless of whether process creation itself is
  restricted. A production AASM policy that also restricts `agent_spawn` /
  `terminal_exec` would need its own run to measure that additional cost,
  which stays out of scope here.
- **Security dimensions S1/S2** (advertised-control coverage, kernel floor) —
  METHODOLOGY.md already scopes these as deferred; nothing here changes that.

## What the confined run found this artifact was missing

**`filesystem.write.allow` needed `/dev/null`.** Five of eight default
families failed under confinement — `rust_cargo_metadata`, `many_small_files`,
`python_pkg_test`, `node_pkg_test`, `repo_traversal` — every one of them at
the exact line that redirects a noisy command's output to `/dev/null`
(`sh -x` traces: `cannot create /dev/null: Permission denied`, exit 2). The
write grant above scopes to the scratch root only, and Sandlock denies
opening `/dev/null` for writing exactly like any other ungranted path. This
is a `policy-change`-classified finding (see METHODOLOGY.md's compatibility
catalogue) with an obvious fix — add `/dev/null` to the write grant — that
was identified but not applied or re-measured in this pass; see
METHODOLOGY.md's Follow-up section.

A second, narrower finding: a bare `git status` (not redirected to
`/dev/null`) also fails, exit 128, most likely from `.git/index`'s refresh
write landing outside the scratch-only grant — recorded as a latent finding,
not a sixth catalogue entry, since it was never the proximate cause of
`repo_traversal`'s actual failure.
