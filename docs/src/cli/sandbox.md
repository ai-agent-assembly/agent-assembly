# aasm sandbox

Run a WebAssembly tool inside the Agent Assembly tool-execution sandbox, with
filesystem, CPU (instruction fuel), memory, and wall-clock isolation. This
surfaces the `aa-sandbox` runtime to the CLI without going through the cloud
`/dispatch_tool` HTTP route.

## Synopsis

```text
aasm sandbox <SUBCOMMAND> [OPTIONS]
```

| Subcommand | Purpose |
|---|---|
| [`run`](#aasm-sandbox-run) | Run a `.wasm` module inside a fresh sandbox. |
| [`info`](#aasm-sandbox-info) | Show the default sandbox runtime limits. |

---

## aasm sandbox run

Run a WebAssembly module under WASI preview 1 inside a fresh sandbox and report
the outcome. Unset limits fall back to the safe-by-default values.

| Name | Type | Default | Description |
|---|---|---|---|
| `<WASM>` | path (arg) | — | Path to a `.wasm` module to execute under WASI preview 1. |
| `--fuel <FUEL>` | integer | `10000000` (10M) | Wasmtime instruction-fuel budget. Raise for long-running tools. |
| `--memory-pages <MEMORY_PAGES>` | integer | `16` (1 MiB) | Maximum linear-memory pages (1 page = 64 KiB). |
| `--wall-clock-ms <WALL_CLOCK_MS>` | integer | `5000` (5s) | Wall-clock deadline in milliseconds. |

```bash
aasm sandbox run ./tool.wasm --fuel 50000000 --wall-clock-ms 10000
```

```text
sandbox exited cleanly (exit_code=0)
```

On success the command prints a single line with the module's exit code. If the
sandbox refuses or traps the module (fuel exhaustion, memory-cap or wall-clock
overrun, or a WASI trap), it instead writes `sandbox refused or trapped the
module: <reason>` to stderr and exits non-zero. Fuel and wall-time usage are not
tracked or reported.

---

## aasm sandbox info

Show the default sandbox runtime limits. Takes no arguments.

```bash
aasm sandbox info
```

```text
aasm sandbox — WASI preview 1 tool-execution sandbox
  fuel (instructions):      10000000
  memory ceiling:           16 pages (1024 KiB)
  wall-clock deadline (ms): 5000
  preopened dirs:           (none — fully sealed FS)
```
