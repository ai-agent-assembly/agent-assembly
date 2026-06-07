# Consuming the Shared Crates

The thin per-language SDK shims live in their own repositories
(`python-sdk`, `node-sdk`) but reuse Rust crates that are developed in this
monorepo. Four crates are consumed from **outside** the workspace:

| Crate           | Role in the SDK shim                                            |
| --------------- | -------------------------------------------------------------- |
| `aa-core`       | wire types and traits                                          |
| `aa-proto`      | generated protobuf / gRPC wire types                          |
| `aa-security`   | advisory, non-authoritative credential preflight              |
| `aa-sdk-client` | UDS transport, IPC codec, `AssemblyClient` lifecycle          |

## Distribution mechanism: git SHA pin

The chosen distribution mechanism is a **git SHA pin**, not a registry
publish. The rationale (crates.io was rejected; a bare branch name does not
resolve once a crate consumes the dependency, so a full SHA is required) is
recorded in [ADR 0002 — SDK Security Boundary](../adr/0002-sdk-security-boundary.md).

A consumer pins each crate to an exact commit:

```toml
[dependencies]
aa-core       = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "<full-40-char-sha>", package = "aa-core", features = ["serde"] }
aa-proto      = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "<full-40-char-sha>", package = "aa-proto" }
aa-security   = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "<full-40-char-sha>", package = "aa-security" }
aa-sdk-client = { git = "https://github.com/ai-agent-assembly/agent-assembly.git", rev = "<full-40-char-sha>", package = "aa-sdk-client" }
```

Notes:

- Use the **full 40-character SHA**, not a branch. `cargo`'s `rev` is a precise
  revspec; a bare branch name fails to resolve once another crate in the graph
  consumes the same dependency.
- A git dependency checks out the whole repository, so workspace inheritance
  (`version.workspace`, `[lints] workspace`, `dep = { workspace = true }`) and
  the `proto/` sources at the workspace root resolve transparently — the
  consumer does not need to reproduce any of it.
- `aa-sdk-client` is `publish = false` on purpose: it is distributed only via
  the git pin, never to crates.io.

## Regression guard

`scripts/standalone-build-smoke.sh` builds each of the four crates as a
git-SHA-pinned consumer from a clean checkout of `HEAD`, outside the workspace.
It runs in CI via the **Crate Pinnability Smoke** workflow on every pull request
and master push that touches a shared crate, so a path-coupling regression —
e.g. a shared crate gaining a dependency that resolves only inside the workspace
checkout — fails CI here before an SDK repo hits it.

Run it locally with:

```bash
make standalone-smoke
# or
bash scripts/standalone-build-smoke.sh
```
