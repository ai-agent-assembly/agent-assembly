# Installation

This page covers every supported way to get the `aasm` CLI onto your machine,
then how to verify it works. Pick **one** method:

| Method | Best for | Needs a published release? |
|---|---|---|
| [Quick-install script](#quick-install-script) | Fast, reproducible install on macOS / Linux | Yes |
| [Homebrew tap](#homebrew-macos--linux) | macOS / Linux users who already use Homebrew | Yes |
| [Pre-built binaries](#pre-built-binaries-manual) | Air-gapped or scripted installs, custom verification | Yes |
| [`cargo install` / from source](#build-from-source) | Contributors and bleeding-edge builds | No |

> **Alpha note.** Agent Assembly is in the `v0.0.1` pre-release series; published
> releases are GitHub **pre-releases**. The public API and wire protocol are not
> yet stable — do not use in production.

## Quick-install script

The one-line installer downloads the matching pre-built tarball plus its
`SHA256SUMS` file from the GitHub Release, verifies the checksum, and installs
the `aasm` binary:

```sh
curl -sSf https://agent-assembly.com/install.sh | sh
```

By default the binary is installed to `/usr/local/bin` if that directory is
writable, otherwise to `~/.local/bin` (always user-writable, no `sudo` needed).
The installer script lives in the repo at
[`scripts/install-cli.sh`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/scripts/install-cli.sh).

> **Hosted installer endpoint.** The one-liner above fetches from the canonical
> `https://agent-assembly.com/install.sh` (served by the official website — see
> [ADR 0007](../adr/0007-public-domain-and-url-contract.md)); `https://tool.agent-assembly.dev`
> is a kept alternate that serves the same script. Prefer to fetch the installer
> straight from GitHub? The
> [`raw.githubusercontent.com`](https://raw.githubusercontent.com/ai-agent-assembly/agent-assembly/master/scripts/install-cli.sh)
> URL serves the identical script.

If the install directory is not on your `PATH`, the script prints the line to add
to your shell profile, for example:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

### Pin a version or change the install directory

The installer honors these environment variables:

```sh
# Install a specific release tag (default: latest)
AASM_VERSION=v0.0.1-beta.4 curl -sSf https://agent-assembly.com/install.sh | sh

# Install to a custom directory
AASM_INSTALL_DIR=/usr/local/bin curl -sSf https://agent-assembly.com/install.sh | sh
```

| Variable | Default | Purpose |
|---|---|---|
| `AASM_INSTALL_DIR` | `/usr/local/bin` or `~/.local/bin` | Installation directory |
| `AASM_VERSION` | latest | Specific release tag to install |
| `AASM_REQUIRE_SIGNATURE` | `0` | When `1`, a missing cosign signature aborts the install (see below) |
| `AASM_NO_MODIFY_PATH` | `0` | When `1`, suppress the `PATH` hint |

### Supply-chain verification (checksum + cosign)

The installer **always** enforces a SHA-256 checksum: it downloads `SHA256SUMS`
and aborts if the tarball's hash does not match. The checksum file itself is
additionally signed with [cosign](https://docs.sigstore.dev/) (keyless, via
GitHub OIDC — Fulcio cert + Rekor log). If `cosign` is installed locally, the
installer verifies that signature against the release workflow's identity before
trusting the checksums. To make a missing/unverifiable signature fatal:

```sh
AASM_REQUIRE_SIGNATURE=1 curl -sSf https://agent-assembly.com/install.sh | sh
```

> Releases published before signing was added carry no cosign bundle; with the
> default `AASM_REQUIRE_SIGNATURE=0` the installer warns and falls back to
> checksum-only (the SHA-256 check is never skipped).

## Homebrew (macOS / Linux)

Install the latest tagged `aasm` release from the
[Homebrew tap](https://github.com/ai-agent-assembly/homebrew-agent-assembly):

```sh
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
```

## Pre-built binaries (manual)

Each [GitHub Release](https://github.com/ai-agent-assembly/agent-assembly/releases)
publishes per-platform tarballs plus a `SHA256SUMS` file and a
`SHA256SUMS.cosign.bundle` signature. Tarballs are named
`aasm-<arch>-<os>.tar.gz`, where `<arch>` is `x86_64` or `aarch64` and `<os>` is
`apple-darwin` (macOS) or `unknown-linux-gnu` (Linux).

To install and verify by hand:

```sh
VERSION=v0.0.1-beta.4
ASSET=aasm-aarch64-apple-darwin.tar.gz   # adjust for your platform
BASE="https://github.com/ai-agent-assembly/agent-assembly/releases/download/${VERSION}"

curl -sSfL "${BASE}/${ASSET}"        -o "${ASSET}"
curl -sSfL "${BASE}/SHA256SUMS"      -o SHA256SUMS

# Verify the checksum (use sha256sum on Linux, shasum -a 256 on macOS)
shasum -a 256 -c <(grep "${ASSET}" SHA256SUMS)

# (Optional) Verify the cosign signature on the checksum file
curl -sSfL "${BASE}/SHA256SUMS.cosign.bundle" -o SHA256SUMS.cosign.bundle
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github\.com/ai-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  SHA256SUMS

tar -xzf "${ASSET}" aasm
install -m755 aasm ~/.local/bin/aasm
```

## Build from source

Contributors and anyone who wants the bleeding edge can build from the Cargo
workspace. This needs the [build prerequisites](requirements.md#building-from-source)
(Rust ≥ 1.75 and `protoc`).

```sh
git clone https://github.com/ai-agent-assembly/agent-assembly.git
cd agent-assembly
cargo build -p aa-cli            # produces ./target/debug/aasm
```

The compiled binary is at `./target/debug/aasm`. Add it to your `PATH` or run it
by path. You can also install it onto your `PATH` with Cargo:

```sh
cargo install --path aa-cli      # installs `aasm` into ~/.cargo/bin
```

> The eBPF-target crates (`aa-ebpf-probes`, `aa-ebpf-programs`) are intentionally
> outside the workspace and are **not** built by `cargo build -p aa-cli`. See
> [Requirements](requirements.md#requirements-per-interception-layer).

## Verify the install

Confirm the binary is on your `PATH` and runs:

```console
$ aasm --version
aasm 0.0.1-beta.4
```

A fuller report — the CLI version plus whether a gateway and API are reachable —
comes from `aasm version`. With no control plane running yet, both report
`unreachable`, which is expected at this point:

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

List the available commands with `aasm --help`:

```console
$ aasm --help
aasm — command-line tool for Agent Assembly

Usage: aasm [OPTIONS] <COMMAND>

Commands:
  admin       Gateway administrative operations
  agent       Manage monitored agent processes
  alerts      Manage governance alerts
  audit       Query audit log entries and export compliance reports
  ...
  status      Show fleet health, agents, approvals, and budget at a glance
  topology    Visualize agent topology, trees, lineage, and statistics
  gateway     Manage the aa-gateway governance daemon — agent registry, policy engine, audit log
  start       Start the locally-managed Agent Assembly gateway process
  version     Show CLI and gateway version information
  ...
```

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `aasm: command not found` | Install dir not on `PATH` | Add the install dir to `PATH` (the installer prints the exact line) |
| `could not determine latest release` | The repo has no published release yet, or a network/API issue | Pin a tag with `AASM_VERSION=...`, or check the [releases page](https://github.com/ai-agent-assembly/agent-assembly/releases) |
| `SHA256 mismatch` | Corrupted or tampered download | Re-download; do not install. Report it if it persists |
| `cosign signature verification FAILED` | Bad or wrong-identity signature | Do not install; report it |

## Next

Now configure the CLI to talk to your gateway — see [Configuration](configuration.md).
