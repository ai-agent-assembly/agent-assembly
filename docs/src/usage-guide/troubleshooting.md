# Troubleshooting

Common local issues and the real diagnostics to resolve them. Every error
message below is reproduced verbatim from the `0.0.1-beta.3` build.

## `aasm start` fails: "failed to spawn aa-gateway"

```console
$ aasm start --mode local --port 7391
aasm start: failed to spawn aa-gateway: No such file or directory (os error 2)
```

**Cause.** `aasm start` shells out to a separate `aa-gateway` binary, which must
be on your `PATH`.

**Fix.** Build it and put `target/debug` on `PATH`:

```console
$ cargo build -p aa-gateway --bin aa-gateway
$ export PATH="$PWD/target/debug:$PATH"
$ aasm start --mode local --port 7391
```

## `aasm start` fails: "--policy is required in legacy-grpc mode"

```console
$ aasm start
Error: "--policy is required in legacy-grpc mode"
aasm start: gateway did not become ready within 5.000335375s
```

**Cause.** The `aa-gateway` binary defaults to its legacy gRPC mode, which
requires a policy file. For a local control plane with the HTTP API and
dashboard, you want **local mode**, which does not.

**Fix.** Run local mode directly:

```console
$ aa-gateway --mode local
Agent Assembly [local mode] v0.0.1-beta.3
  Listening:  http://127.0.0.1:7391
  Dashboard:  http://127.0.0.1:7391/
  Storage:    /Users/you/.aasm/local.db (SQLite)

  Ctrl+C to stop.
```

For the legacy gRPC server, supply a policy:
`aa-gateway --policy policy-examples/low-risk.yaml`.

## CLI commands say the gateway is "unreachable"

```console
$ aasm status
Agent Assembly Status
─────────────────────────────────────
  Gateway:   http://localhost:8080
  Health:    ✗ unreachable
─────────────────────────────────────
...
Error: gateway is not running. Start it with: aasm start
```

```console
$ aasm version
+-----------+---------------+-------------+
| COMPONENT | VERSION       | STATUS      |
+=========================================+
| cli       | 0.0.1-beta.3  | -           |
|-----------+---------------+-------------|
| gateway   | -             | unreachable |
|-----------+---------------+-------------|
| api       | -             | unreachable |
+-----------+---------------+-------------+
```

**Cause.** The CLI defaults to the SaaS control-plane API on
`http://localhost:8080`. The local-mode gateway serves its API on `7391`, not
`8080`, so the default target is unreachable.

**Fix.** Point the CLI at the local API:

```console
$ aasm --api-url http://127.0.0.1:7391 status
Agent Assembly Status
─────────────────────────────────────
  Mode:      local
  Gateway:   http://127.0.0.1:7391
  Storage:   sqlite
  Version:   0.0.1-beta.3
  Uptime:    2m 24s
  Health:    ✓ ok
─────────────────────────────────────
```

To avoid repeating the flag, save a named context with `aasm context` or set the
API URL in `~/.aa/config.yaml`.

## `aasm gateway status` says "not running" even though local mode is up

```console
$ aasm gateway status
Gateway: not running
```

**Cause.** `aasm gateway status` tracks the **legacy gRPC** gateway via its PID
file. A gateway started in **local mode** (`aa-gateway --mode local`) is a
different process and is not reflected here.

**Fix.** Check local-mode liveness with the HTTP status instead:

```console
$ aasm --api-url http://127.0.0.1:7391 status
```

or hit the health endpoint directly: `curl http://127.0.0.1:7391/healthz`.

## A dashboard page loads but its tables stay empty / skeleton

**Cause.** The dashboard SPA served by the local-mode gateway can render its
chrome and page shells, but its data endpoints (`/api/v1/fleet`,
`/api/v1/policies`, …) are served by the **SaaS/cloud control plane on port
8080**, which is not part of the open-source local runtime. With only the local
gateway running, data panels stay empty or in their loading state.

**Fix.** Connect a control plane that serves the `/api/v1/*` data routes (the
hosted backend), or use the CLI (`aasm agent list`, `aasm policy list`,
`aasm cost summary`) against the local API for the same data in the terminal.
See [Observe in the dashboard](observe-in-dashboard.md).

## `policy validate` prints "Unknown key … will be ignored"

```console
$ aasm policy validate policy-examples/medium-risk.yaml
warning: tier — Unknown key 'tier' will be ignored
warning: rules — Unknown key 'rules' will be ignored
warning: notifications — Unknown key 'notifications' will be ignored
Policy is valid: policy-examples/medium-risk.yaml
```

**Cause.** These are *warnings*, not errors — the policy still validates. The
keys `tier`, `rules`, `notifications`, and similar are not part of the schema the
gateway enforces; the supported `spec` sections are `network`, `schedule`,
`budget`, `data`, `tools`, `capabilities`, `approval`, and `scope`.

**Fix.** Move the intended behaviour into a supported section (e.g. express
allow/deny via `capabilities` or `tools`, gating via `approval`), or ignore the
warnings if the extra keys are intentional annotations. The `capability-policy.yaml`
example validates with no warnings and is a good reference shape.

## A wildcard egress host is denied in `policy simulate`

If `aasm policy simulate` denies a host that your `*.example.com` allowlist entry
should permit, this is expected: the simulator's decision path uses an **exact**
host comparison, while the live `aa-proxy` uses the glob-aware matcher. Confirm
the host against the running proxy rather than treating the simulation deny as a
real block — see the caveat in
[Enforce an egress policy](enforce-egress-policy.md).

## Quick reference

| Symptom | First thing to check |
|---|---|
| "failed to spawn aa-gateway" | `aa-gateway` on `PATH`? |
| "--policy is required" | Use `aa-gateway --mode local`, not the default |
| "unreachable" on every CLI call | Pass `--api-url http://127.0.0.1:7391` |
| `gateway status` "not running" | Local mode ≠ legacy gRPC; use `status` / `/healthz` |
| Empty dashboard tables | Data API (port 8080) not running locally |
| `validate` warnings | Unknown keys ignored — move into a supported section |
