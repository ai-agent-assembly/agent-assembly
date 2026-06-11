# aasm proxy

Manage the `aa-proxy` sidecar — its lifecycle, the per-host CA trust, and log
tailing. The proxy intercepts outbound HTTPS via MitM so network-egress policy
can be enforced without code changes (layer 2 of the three-layer model).

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
binary is resolved from `$PATH`, then `~/.cargo/bin`, then `./target/release`.

| Flag | Type | Default | Description |
|---|---|---|---|
| `--listen <LISTEN>` | string | `127.0.0.1:8899` (env `AA_PROXY_ADDR`) | Address the proxy listens on. |
| `--gateway <GATEWAY>` | string | env `AA_GATEWAY_URL` | Gateway URL to forward policy decisions to. |
| `--ca-dir <CA_DIR>` | path | env `AA_CA_DIR` | Directory for CA certificate and key storage. |
| `--no-detach` | flag | off | Run in the foreground instead of daemonizing. |
| `--log-file <LOG_FILE>` | path | — | Redirect proxy stdout/stderr to this file (background mode only). |

```bash
aasm proxy start --listen 127.0.0.1:8899 --gateway http://localhost:50051
```

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
