# DI-API thin-client reference implementation

A minimal TypeScript client for the [Developer Integration API](../../docs/src/devtools/developer-integration-api.md),
small enough to be read end to end and copied into a VS Code, JetBrains, Claude
Code, Codex or marketplace package.

Full narrative — what a client may and may not do, the UX vocabulary, the porting
checklist, and why **MCP is optional and independent of this protocol** — is in
[`docs/src/devtools/reference-client.md`](../../docs/src/devtools/reference-client.md).
This file is the operational half.

## Layout

```
src/
  discovery.ts   socket resolution ($AA_DEVINT_SOCKET, else ~/.aa/run/devint.sock)
  project.ts     which project a request is for ($AA_DEVINT_PROJECT_ROOT, else cwd)
  credential.ts  the one credential type a thin client may hold
  framing.ts     [tag][varint length][payload], client side
  client.ts      nine methods, because the verb space has nine members
  render.ts      presentation — a lookup table, never a computation
  errors.ts      every failure, each with its remediation
  cli.ts         the example onboarding / status flow
  generated/     `buf generate` output from ../../proto/devint.proto — do not edit
harness/         Rust binary serving the REAL DI-API server for the contract suite
test/
  unit.test.ts            path resolution, credentials, framing, rendering rules
  guards.test.ts          the excluded responsibilities, proved by reading the source
  contract/lifecycle.ts   the responsibilities, against the real server
  contract/security.ts    what a compromised client still cannot do
```

## Commands

```bash
pnpm install                        # pnpm, not npm (house convention)
pnpm generate                       # regenerate bindings from proto/devint.proto
pnpm generate:check                 # fail if the committed bindings have drifted
pnpm typecheck
pnpm lint
cargo build -p aa-devint-harness    # required by the contract suite
pnpm test                           # unit + guards + contract
pnpm build && node dist/cli.js --help
```

`pnpm test` fails loudly if `target/debug/aa-devint-harness` is missing. It does
**not** fall back to a mock: a test against a mock proves the mock is polite, not
that the boundary holds.

## Trying the demo flow

```bash
# In one terminal — a throwaway DI-API server with fixture enrolments.
mkdir -p /tmp/aasm-demo && cargo run -p aa-devint-harness /tmp/aasm-demo/devint.sock
# It prints a JSON line containing the socket path and several fixture tokens.

# In another terminal:
cd examples/aa-devint-reference-client && pnpm build
export AA_DEVINT_SOCKET=/tmp/aasm-demo/devint.sock
export AA_DEVINT_TOKEN=<the "full" token from the JSON line>

node dist/cli.js tools
node dist/cli.js status claude-code
node dist/cli.js install claude-code recommended user
node dist/cli.js events claude-code

# A project-scoped plan is for the directory you run it from — the runtime is
# shared by every client on this host and will not infer which project you meant.
cd /path/to/some/repo && node dist/cli.js plan claude-code recommended project

# Then swap in the "claudeOnly" token and try a different tool — every verb is
# refused, which is the point.
export AA_DEVINT_TOKEN=<the "claudeOnly" token>
node dist/cli.js status codex
```

The harness serves `aa_runtime::devint::DevIntServer` — the real server, codec,
token store, scope check and negotiation — behind a stand-in lifecycle service.
It is a test fixture: do not ship it, and do not point it at a real `~/.aa/run/`.
