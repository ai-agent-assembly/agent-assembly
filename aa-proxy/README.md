# aa-proxy

Sidecar traffic interception proxy for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-proxy?logo=rust&label=crates.io)](https://crates.io/crates/aa-proxy)
[![docs.rs](https://img.shields.io/docsrs/aa-proxy?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-proxy)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Implements **E3, Protocol / Transport Mediation** (ADR 0033 §1): a sidecar proxy
that sits alongside an AI agent process, intercepting outbound HTTPS traffic and
refusing or redacting a request before it leaves the machine. The *agent's* own
code does not change, but the proxy does have to be installed, started, routed to
(`HTTPS_PROXY`, honoured by the client) and have its CA trusted; `llm_only`
defaults to `true`, so only the built-in LLM hosts are decrypted. Linux and
macOS, with Windows unsupported. The release pipeline builds this crate on Linux
only, so on macOS no prebuilt binary exists on any channel: the GitHub Release
assets carry `aasm-proxy` for `linux-amd64` and `linux-arm64` alone, the Homebrew
formula is `depends_on :linux`, the `install.sh` component installer resolves to
a darwin release asset that is never published, and no GHCR image carries it. A
source build of this crate from crates.io (`cargo install aa-proxy`) is the only
route. Runs as a standalone binary or embedded in-process via `aa_proxy::run()`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
