# Installation

## Quick install (Linux / macOS)

```sh
curl -fsSL https://tool.agent-assembly.dev | sh
```

This downloads the prebuilt `aasm` binary for your OS/architecture from the
GitHub Release, **verifies its SHA-256 checksum and cosign signature**, and
installs it to `~/.local/bin` (or `/usr/local/bin` if writable).

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
  --certificate-identity-regexp '^https://github.com/AI-agent-assembly/agent-assembly/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```

A valid result means `SHA256SUMS` was signed by the agent-assembly release
workflow at a tagged release — not by an attacker who swapped the file.

On macOS, release binaries are Developer-ID-signed and notarized once the
project's Apple credentials are provisioned, so Gatekeeper accepts them without
a manual override.
