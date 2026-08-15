# aasm proxy

Manage the `aa-proxy` sidecar — its lifecycle, the per-host CA trust, and log
tailing. The proxy intercepts outbound HTTPS via MitM and denies traffic that
fails policy, without agent code changes — one of the three enforcement
mechanisms.

## Synopsis

```text
aasm proxy <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`start`](#aasm-proxy-start) | Spawn the proxy sidecar (background or foreground). |
| [`stop`](#aasm-proxy-stop) | Stop the running proxy. |
| [`status`](#aasm-proxy-status) | Show whether the proxy is running. |
| [`install-ca`](#aasm-proxy-install-ca) | Install the proxy CA into the OS trust store. |
| [`uninstall-ca`](#aasm-proxy-uninstall-ca) | Remove the proxy CA from the OS trust store. |
| [`logs`](#aasm-proxy-logs) | Tail the proxy log file. |

---

## aasm proxy start

Spawn `aa-proxy` in the background (or foreground with `--no-detach`). The
binary is resolved from `$PATH`, then `~/.cargo/bin` — trusted, absolute
locations only. A cwd-relative `./target/release` fallback was deliberately
removed as a security fix (AAASM-4020): resolving relative to the current
working directory would let whoever controls where `aasm` runs substitute an
attacker-planted `aa-proxy`.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--listen <LISTEN>` | string | `127.0.0.1:8899` (env `AA_PROXY_ADDR`) | Address the proxy listens on. **Must be loopback with a named port** — see below. |
| `--allow-remote-clients` | flag | off | State that a non-loopback `--listen` is intended. Does not currently permit one — see below. |
| `--gateway <GATEWAY>` | string | env `AA_GATEWAY_URL` | Gateway URL to forward policy decisions to. |
| `--ca-dir <CA_DIR>` | path | env `AA_CA_DIR` | Directory for CA certificate and key storage. |
| `--no-detach` | flag | off | Run in the foreground instead of daemonizing. |
| `--log-file <LOG_FILE>` | path | — | Redirect proxy stdout/stderr to this file (background mode only). |

```bash
aasm proxy start --listen 127.0.0.1:8899 --gateway http://localhost:50051
```

### The listen address must be loopback, and must name its port

`--listen` is checked before anything is spawned and before a state file is
written, so a refused start leaves nothing behind (AAASM-5348). Two addresses
that used to start a proxy no longer do:

* **A non-loopback address** — `0.0.0.0`, a LAN address, `[::]`. The proxy reads
  intercepted traffic under a CA this machine trusts and injects your provider
  credentials into forwarded requests, so anything that can reach the listener
  can do both.
* **Port `0`** — it asks the OS for any free port, but the recorded endpoint
  would still say `0`. The proxy would bind a real port that nothing can name:
  `aasm run` refuses a port-0 endpoint, `aasm proxy stop` could not reach the
  process, and the start would report failure while the proxy kept running.

Both previously succeeded and produced an endpoint `aasm run` would then refuse
to route a governed tool at — a proxy that worked for everything except the one
job it exists to do. `aasm proxy start` and `aasm run` now apply the same test,
so an address one accepts is an address the other trusts.

### `--allow-remote-clients` states intent, and still refuses

Intent is not authorization. A proxy reachable from other hosts also needs TLS
on its listener and client authentication — **`aa-proxy` implements neither**,
so the flag currently changes only which refusal you get:

```console
$ aasm proxy start --listen 0.0.0.0:8899 --allow-remote-clients
error: refusing to listen on 0.0.0.0:8899: --allow-remote-clients was given, but
a proxy reachable from other hosts also requires protection aa-proxy does not
implement: TLS on the proxy listener, client authentication and authorization.
Being reachable is not being trusted — without those, every host that can route
to 0.0.0.0:8899 is an authorized client of an interception endpoint that holds
CA material and provider credentials. Listen on a loopback address instead.
```

The flag exists rather than being omitted because a refusal that names the two
missing protections is more useful than one that says only "not supported", and
because the guard relaxes on its own once either protection is implemented. To
reach another machine's proxy today, forward the loopback port over SSH.

> **`AA_PROXY_ADDR` is not covered by this check.** The guard lives in
> `aasm proxy start`; running the `aa-proxy` binary directly with a non-loopback
> `AA_PROXY_ADDR` — which is what the container image and the self-hosting
> example do — still binds it. Tracked as AAASM-5370.

---

## aasm proxy stop

Stop the running proxy sidecar. Takes no flags.

```bash
aasm proxy stop
```

---

## aasm proxy status

Show whether the proxy sidecar is running (confirmed via a TCP connect probe).

| Flag | Type | Default | Description |
|---|---|---|---|
| `--json` | flag | off | Emit machine-readable JSON output. |

```bash
aasm proxy status --json
```

---

## aasm proxy install-ca

Install the proxy CA certificate into the OS trust store so intercepted TLS
connections validate.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ca-dir <CA_DIR>` | path | env `AA_CA_DIR` | Directory where the CA certificate and key are stored. |
| `--yes` | flag | off | Skip the confirmation prompt. |

```bash
aasm proxy install-ca --yes
```

---

## aasm proxy uninstall-ca

Remove the proxy CA certificate from the OS trust store. Same options as
`install-ca`.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--ca-dir <CA_DIR>` | path | env `AA_CA_DIR` | Directory where the CA certificate and key are stored. |
| `--yes` | flag | off | Skip the confirmation prompt. |

```bash
aasm proxy uninstall-ca --yes
```

---

## aasm proxy logs

Tail the proxy log file, with optional level/time filtering.

| Flag | Type | Default | Description |
|---|---|---|---|
| `-f, --follow` | flag | off | Stream new log entries continuously (like `tail -f`). |
| `--lines <LINES>` | integer | `50` | Number of lines to show from the end of the log. |
| `--level <LEVEL>` | string | — | Filter to lines at or above this level: `error`, `warn`, `info`, `debug`. |
| `--since <DURATION>` | string | — | Show only entries since a relative duration (e.g. `5m`, `1h`, `30s`). |

```bash
aasm proxy logs --follow --level warn --since 10m
```
