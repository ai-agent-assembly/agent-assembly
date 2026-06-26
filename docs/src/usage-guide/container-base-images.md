# Governed container base images

Agent Assembly publishes a set of **governed language base images** to GitHub
Container Registry (GHCR). Each one bundles the **`aasm` operator binary** and the
**Agent Assembly SDK** for its language, so a containerized agent is governed on its
first run with no extra install step — you just build your agent `FROM` one of them.

> These images are the **convenience on-ramp** for the in-process (SDK) interception
> layer. They are optional: you can always install the SDK and `aasm` yourself. See
> [Choosing interception layers](interception-layers.md) for the bigger picture.

## The images

Three languages × three runtime versions = **9 images**, under
`ghcr.io/ai-agent-assembly/`:

| Language | Image | Runtime variants |
|---|---|---|
| Python | `ghcr.io/ai-agent-assembly/python` | `3.14-slim`, `3.13-slim`, `3.12-slim` |
| Node.js | `ghcr.io/ai-agent-assembly/node` | `24-slim`, `22-slim`, `20-slim` |
| Go | `ghcr.io/ai-agent-assembly/go` | `1.26-alpine`, `1.25-alpine`, `1.24-alpine` |

Each is a small two-stage build (the `aasm` CLI is compiled and copied into an
official `python` / `node` / `golang` slim base) and is published for
`linux/amd64` and `linux/arm64`. The enforcement sidecar image
`ghcr.io/ai-agent-assembly/aa-runtime` is documented separately under
[Self-hosting](self-hosting.md).

## Tags: how to choose one

Every image is published under three kinds of tag. **Which you use is the single most
important choice** for reproducibility:

| Tag form | Example | Mutability | Use it for |
|---|---|---|---|
| `<lang>:<runtime>-<core-version>` | `python:3.14-slim-v0.0.1-rc.1` | **Immutable** — never overwritten | **Pin this in CI and production.** Reproducible: the same tag always resolves to the same image. |
| `<lang>:<runtime>` | `python:3.14-slim` | Moving — re-published each release | Local development / "track the newest release for this runtime". |
| `<lang>:latest` | `python:latest` | Moving | Quick experiments only — newest runtime + newest release. |

The `<core-version>` coordinate is the **Agent Assembly core release** (the same
version as the `aasm` CLI baked into the image and the `aa-runtime` sidecar). So all
of `python:3.14-slim-vX.Y.Z`, `node:24-slim-vX.Y.Z`, … and `aa-runtime:vX.Y.Z`
line up on one version.

## Quick start

Build your agent on top of an image:

```dockerfile
# Pin the immutable tag for a reproducible build (recommended).
FROM ghcr.io/ai-agent-assembly/python:3.14-slim-v0.0.1-rc.1

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt   # your agent's deps

CMD ["python", "agent.py"]
```

What you get inside the image:

- `aasm --version` works — the operator CLI is on `PATH`.
- The SDK is importable with no extra install — `from agent_assembly import init_assembly`
  (Python), `require('@agent-assembly/sdk')` (Node), the `go-sdk` module (Go).

To actually **enforce** policy, run your agent alongside the `aa-runtime` sidecar (the
authoritative chokepoint). The `docker compose` example in the repo
(`examples/docker-compose/`) wires this up; see [Self-hosting](self-hosting.md).

## Choosing the SDK version — the `SDK_VERSION` build-arg

The SDK that ships in the image is controlled by an **optional** `SDK_VERSION`
build argument:

```sh
# Default — no build-arg: installs the latest STABLE SDK release, or the latest
# pre-release when no stable exists yet.
docker build -f docker/Dockerfile.python-3.14-slim .

# Explicit pin — exactly this released SDK (reproducible).
docker build -f docker/Dockerfile.python-3.14-slim \
  --build-arg SDK_VERSION=0.0.1b5 .
```

The default resolution is **uniform across all three SDKs** — *latest stable release,
falling back to the latest pre-release* — and matches how the
[`install-cli.sh`](../quick-start/installation.md) one-liner resolves the CLI, so the
whole product behaves consistently.

> The pre-built images that Agent Assembly publishes always pin `SDK_VERSION`
> explicitly (to the release that is compatible with that core version), so a
> published immutable tag is fully reproducible. The default only applies when you
> build an image yourself without passing the arg.

## Why it's designed this way

The image carries **two** versioned things, and the design makes the relationship
explicit:

- **The core version is the axis _you_ choose.** It is the image-tag coordinate
  (`…-vX.Y.Z`) **and** the `aasm` CLI compiled into the image. Picking an immutable
  tag picks a core release.
- **The SDK version is a _dependent_ value.** Each core release ships with the SDK
  release that is compatible with it; the SDK versions independently of the core (the
  Python/Node/Go SDKs do not share a version number with the core), so the image
  resolves the SDK explicitly rather than assuming "SDK version = core version".

That is why the tag is keyed on the core version while the SDK is pinned through a
separate manifest. The full rationale — including the move away from the old
divergent per-language install defaults — is recorded in
**[ADR 0009](../adr/0009-versioned-base-image-tags-and-sdk-pinning.md)**.

## Recommended best practices

What the Agent Assembly team recommends:

1. **Pin the immutable tag in CI and production.** Use
   `…/<lang>:<runtime>-<core-version>`, never `:latest`, for anything you ship or
   build repeatedly. It guarantees the same `aasm` + SDK every time.
2. **Use the moving `<lang>:<runtime>` tag for local development**, where "the newest
   release for this runtime" is convenient and reproducibility matters less.
3. **Pin `SDK_VERSION` when you need an exact SDK** for compliance, audits, or to
   match a specific gateway/runtime — don't rely on the floating default for shipped
   images.
4. **Keep the image's core version and your `aa-runtime` sidecar on the same
   release.** They are designed and tested as a set; consult the
   [compatibility matrix](../compatibility.md) before mixing versions.
5. **Pair the image with the `aa-runtime` sidecar (and, where needed, the proxy or
   eBPF layers) for authoritative enforcement.** The in-process SDK layer is the
   fastest path but is not, by itself, a security boundary — see
   [Choosing interception layers](interception-layers.md).
6. **Rebuild on each core release** to pick up SDK and CLI fixes; bump the pinned
   `-<core-version>` tag deliberately rather than tracking a moving tag silently.

## Current status

The bundled SDK runs in its **offline / observe** path today — the native
socket-dialing runtime client is not yet shipped inside these images, so live
in-process `SDK → aa-runtime` transport from within the image is a tracked
follow-up. Authoritative enforcement is still fully available via the `aa-runtime`
sidecar (and the proxy / eBPF layers); the images simply give your agent the SDK and
CLI pre-installed. Watch the release notes for when the native client lands.

## Reference

- Source Dockerfiles: `docker/Dockerfile.<lang>-<runtime>` in the
  [`agent-assembly`](https://github.com/ai-agent-assembly/agent-assembly) repo.
- Design: [ADR 0009 — Versioned Base-Image Tags & SDK Pinning](../adr/0009-versioned-base-image-tags-and-sdk-pinning.md).
- Running the sidecar: [Self-hosting (open source)](self-hosting.md).
- Installing the CLI directly: [Installation](../quick-start/installation.md).
- Version compatibility: [Compatibility matrix](../compatibility.md).
