# Releasing `aasm`

This document describes how to cut a release of the `aasm` binary.
Releases are tagged from `master`; the release workflow handles binary
compilation, packaging, and GitHub Release publication automatically.

## Prerequisites

Ensure all of the following are installed locally before tagging:

| Tool | Version | Install |
|---|---|---|
| Rust (stable) | ≥ 1.75 | `rustup update stable` |
| pnpm | 10.9.0 | `corepack enable && corepack prepare pnpm@10.9.0 --activate` |
| Node.js | 20 | `nvm use 20` or via your system package manager |
| protobuf compiler | any recent | `apt install protobuf-compiler` / `brew install protobuf` |

## Pre-release checklist

Run these steps locally before pushing the release tag. All checks must
pass with a clean exit code.

```bash
# 1. Ensure local master is up to date
git fetch remote && git checkout master && git merge remote/master --ff-only

# 2. Build the dashboard — REQUIRED; aa-cli embeds dashboard/dist/
cd dashboard
pnpm install --frozen-lockfile
pnpm type-check
pnpm lint
pnpm build           # produces dashboard/dist/; must exit 0
cd ..

# 3. Run the full Rust test suite
cargo nextest run --workspace --exclude aa-ebpf

# 4. Clippy clean
cargo clippy --workspace --all-targets --all-features --exclude aa-ebpf -- -D warnings

# 5. Dependency audit
cargo deny check

# 6. Verify aasm binary builds and embeds the dashboard
cargo build --release -p aa-cli
./target/release/aasm --version
```

## Tagging and triggering the release workflow

Once the checklist passes, push a semver tag. The release workflow
(`.github/workflows/release.yml`) triggers automatically:

```bash
git tag v0.1.0        # replace with the actual version
git push remote v0.1.0
```

The workflow will:

1. Build the dashboard (`pnpm build` inside `dashboard/`) for each target.
2. Compile `aasm` for all four release targets in parallel:
   - `x86_64-unknown-linux-gnu`
   - `aarch64-unknown-linux-gnu`
   - `aarch64-apple-darwin`
   - `x86_64-apple-darwin`
3. Package each binary as `aasm-<target>.tar.gz`.
4. Generate `SHA256SUMS`.
5. Publish the GitHub Release with generated release notes.
6. Publish `aa-cli` to crates.io.

> **Note — release smoke test (pending AAASM-1292):** Once `aasm dashboard start`
> is implemented, the release workflow will also verify the embedded assets by
> starting the server and asserting HTTP 200 before publishing. Until then,
> the binary smoke test is performed manually in step 6 of the checklist above.

## Post-release verification

After the workflow completes:

1. Check the GitHub Release page for all four `.tar.gz` files and `SHA256SUMS`.
2. Download and test one binary on the target platform:

```bash
tar -xzf aasm-x86_64-unknown-linux-gnu.tar.gz
./aasm --version
./aasm topology list   # basic sanity check
```

3. Verify the crates.io publish succeeded at `https://crates.io/crates/aa-cli`.

## Versioning

The dashboard has no independent version. It ships as part of `aasm` and
inherits the release tag. Do not publish the dashboard to npm.

All crate versions are unified under `[workspace.package] version` in
`Cargo.toml`. Bump only that single field before tagging.
