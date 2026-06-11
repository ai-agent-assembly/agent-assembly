# Installation

This page installs the `aasm` command-line tool — the operator front-end for an Agent Assembly deployment. Pick a channel below; the quick-install script is the recommended path on Linux and macOS.

## Quick install (Linux / macOS)

```sh
curl -fsSL https://tool.agent-assembly.dev | sh
```

This downloads the prebuilt `aasm` binary for your OS/architecture from the
GitHub Release, **verifies its SHA-256 checksum and cosign signature**, and
installs it to `~/.local/bin` (or `/usr/local/bin` if writable).

Confirm the install:

```sh
aasm version
```

> **Tip:** if `aasm` is not found, `~/.local/bin` is probably not on your
> `PATH`. Add it (`export PATH="$HOME/.local/bin:$PATH"`) or re-run with
> `AASM_INSTALL_DIR=/usr/local/bin`.

Useful environment overrides:

| Variable | Effect |
|---|---|
| `AASM_VERSION` | Install a specific release tag (default: latest) |
| `AASM_INSTALL_DIR` | Install directory (default: `~/.local/bin`) |
| `AASM_REQUIRE_SIGNATURE=1` | **Fail** the install unless the cosign signature is verified (requires `cosign` on PATH) |

### Other channels

```sh
brew install ai-agent-assembly/tap/aasm     # Homebrew
cargo install aa-cli                          # from crates.io
```

## Verifying the download (trust model)

Every release publishes, alongside the binaries:

- `SHA256SUMS` — checksums of every `aasm-*.tar.gz`.
- `SHA256SUMS.cosign.bundle` / `.sig` / `.pem` — a **keyless cosign signature** of
  `SHA256SUMS`, produced by the release workflow using GitHub OIDC (Sigstore
  Fulcio certificate + Rekor transparency log — no long-lived signing key).

The installer enforces **both**: it verifies the cosign signature on
`SHA256SUMS` (when `cosign` is available, or always under
`AASM_REQUIRE_SIGNATURE=1`), then verifies each tarball's SHA-256 against the
now-trusted `SHA256SUMS`. Without `cosign` it warns and falls back to
checksum-only (the checksum is always enforced).

To verify manually:

```sh
cosign verify-blob \
  --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/ai-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A valid result means `SHA256SUMS` was signed by the agent-assembly release
workflow at a tagged release — not by an attacker who swapped the file.

> **Warning:** for a supply-chain-sensitive install, set
> `AASM_REQUIRE_SIGNATURE=1` so the install *fails closed* if the cosign
> signature cannot be verified, instead of falling back to checksum-only.

On macOS, release binaries are Developer-ID-signed and notarized once the
project's Apple credentials are provisioned, so Gatekeeper accepts them without
a manual override.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `aasm: command not found` after install | Install dir not on `PATH` | Add `~/.local/bin` to `PATH`, or set `AASM_INSTALL_DIR` to a directory already on it |
| Install warns "cosign not found" | `cosign` is not on `PATH` | Install [cosign](https://docs.sigstore.dev/cosign/installation/); the script then verifies the signature instead of falling back to checksum-only |
| `AASM_REQUIRE_SIGNATURE=1` aborts the install | Signature could not be verified | Confirm `cosign` is installed and the release is a genuine tagged release; do **not** unset the flag to work around a failure |
| macOS Gatekeeper blocks the binary | Notarized credentials not yet provisioned for that release | Right-click → Open once, or remove the quarantine attribute with `xattr -d com.apple.quarantine $(command -v aasm)` |
| Need a specific version | — | Set `AASM_VERSION=<tag>` before running the install script |
