# aasm version

Show CLI and gateway version information. Prints the `aasm` CLI version, then
probes the gateway health endpoint (`GET /api/v1/health`) for the gateway and
API versions. When the gateway is unreachable, the gateway/api rows show an
unreachable marker.

## Synopsis

```text
aasm version
```

This command has no subcommands or flags of its own. It honors the global
`--output` and the resolved API context (`--api-url` / `--context`).

> `aasm -V` / `aasm --version` prints only the CLI version (the standard clap
> flag). `aasm version` additionally reports the gateway and API versions.

## Example

```bash
aasm version
```

```text
COMPONENT   VERSION
cli         0.0.1
gateway     0.0.1
api         0.0.1
```

JSON form:

```bash
aasm version --output json
```
