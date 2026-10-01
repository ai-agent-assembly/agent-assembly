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
cli         <your installed aasm version>
gateway     <reachable gateway's version, or "unreachable">
api         <reachable API's version, or "unreachable">
```

(illustrative shape only — run `aasm version` to see your actual installed
and reachable versions; see `aasm --version` for the bare CLI version)

JSON form:

```bash
aasm version --output json
```
