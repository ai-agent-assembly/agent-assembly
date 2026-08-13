# Troubleshooting

Common local issues and the real diagnostics to resolve them. Every error
message below is reproduced verbatim from the `0.0.1-beta.4` build.

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
Agent Assembly [local mode] v0.0.1-beta.4
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
| cli       | 0.0.1-beta.4  | -           |
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
  Version:   0.0.1-beta.4
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
chrome and page shells, but `aa-gateway --mode local` wires only two REST routes
— `/api/v1/health` and `/api/v1/admin/status`. It cannot mount the full `aa-api`
router, because that router needs an `aa_api::AppState` local mode deliberately
does not construct (`aa-gateway/src/local_mode.rs:269-277`). Every other
`/api/v1/*` path therefore falls through to the SPA catch-all and comes back as
`text/html`, which reads to a caller as "the endpoint is missing".

**Fix — run `aa-api-server`, which is the binary that serves the REST surface.**
This is not discoverable from the gateway's own output, and assuming the local
REST surface does not exist is the wrong conclusion to draw from it
([AAASM-5694](https://lightning-dust-mite.atlassian.net/browse/AAASM-5694)):

```console
$ cargo build -p aa-api --bin aa-api-server
$ AASM_API_AUTH=off AA_API_ADDR=127.0.0.1:7700 ./target/debug/aa-api-server
$ curl -s http://127.0.0.1:7700/api/v1/health
```

This is the same binary the `dashboard-e2e-real-backend` CI lane boots, so a
page verified this way is verified against what CI checks. Endpoints backed by
the SaaS/cloud control plane remain unavailable locally; a panel still empty
after this is either one of those or genuinely has no rows.

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
| Empty dashboard tables | `--mode local` serves no data routes — run `aa-api-server` |
| `validate` warnings | Unknown keys ignored — move into a supported section |
