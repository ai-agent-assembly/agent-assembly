#!/usr/bin/env python3
"""J53 (AAASM-4751) pre-publication candidate harness: the aa-gateway container image.

What this can and cannot prove (AAASM-6419, founder decision B1)
----------------------------------------------------------------
The journey is "pull, configure and operate the published `aa-gateway` image". The
image does not exist before the tag, so nothing here pulls or builds one. A real
`docker build` of `aa-gateway/Dockerfile` is deliberately NOT in this harness: it
fetches base images over the network and writes to the Docker daemon, so it is not
hermetic. The checks below are therefore about the *inputs* to the image and the
gateway binary the image ships, labelled with the fidelity they actually have:

  * the Dockerfile and the publish workflow, read statically at the candidate SHA;
  * the host-built candidate `aa-gateway` binary run as a real local process.
    The image carries a musl Linux build, so this proves the gateway behaves, not
    that the image does. Nothing here is fidelity `container`.

Everything that needs the published image (pull by tag and digest, multi-arch
index, SBOM attestation, running the pulled image) is emitted as PENDING with the
read-only command that `scripts/qa/post-publish-verify.py` will run. This script
has no code path that reports one of those as PASS.

Usage:
  python3 -I scripts/qa/j53-candidate-harness.py --candidate-sha <40hex> \
      --expected-version 0.0.1-rc.8 --repo <checkout> --gateway-bin <path> \
      [--expected-digests digests.json] [--docs-dir <docs checkout>] [--out report.json]
"""
from __future__ import annotations

import re
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import b1_candidate_common as c  # noqa: E402

SCRIPT = "scripts/qa/j53-candidate-harness.py"
TEST = "scripts/tests/test_j53_candidate_harness.py"
DOCKERFILE_REL = "aa-gateway/Dockerfile"
WORKFLOW_REL = ".github/workflows/docker.yml"
POLICY_REL = "policy-examples/balanced.yaml"

PENDING = [
    c.PendingCheck(
        "j53-ghcr-tag-resolves", "ghcr",
        "the image tag exists in GHCR only after release.yml/docker.yml publish-gateway runs on the tag",
        "python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only j53-ghcr-tag-resolves",
        "anonymous GET of ghcr.io/ai-agent-assembly/aa-gateway:<tag> returns a manifest whose body hashes to Docker-Content-Digest",
    ),
    c.PendingCheck(
        "j53-ghcr-digest-immutable", "ghcr",
        "pull-by-digest needs the published manifest digest",
        "python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only j53-ghcr-digest-immutable",
        "fetching the manifest by the digest the tag resolved to returns byte-identical content",
    ),
    c.PendingCheck(
        "j53-ghcr-multiarch", "ghcr",
        "the multi-arch index is created by the publish job",
        "python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only j53-ghcr-multiarch",
        "the tag resolves to an index that lists linux/amd64 and linux/arm64",
    ),
    c.PendingCheck(
        "j53-ghcr-sbom-attestation", "ghcr",
        "the SBOM attestation is pushed alongside the image by build-push-action (sbom: true)",
        "python3 -I scripts/qa/post-publish-verify.py --tag <tag> --obligations <file> --only j53-ghcr-sbom-attestation",
        "the index carries at least one attestation-manifest entry per platform image",
    ),
    c.PendingCheck(
        "j53-published-image-runs-healthy", "ghcr",
        "running the pulled image needs the published image and a container runtime; it writes local Docker state, "
        "so it is a post-publication operator step and is not a read-only probe",
        "docker run --rm -p 50051:50051 ghcr.io/ai-agent-assembly/aa-gateway@<digest> --listen 0.0.0.0:50051 --policy /policy/balanced.yaml  # then grpc.health.v1 Check",
        "container stays up, grpc.health.v1.Health/Check answers SERVING, SIGTERM stops it with exit 0",
    ),
]

FAILURE_RESPONSE = {
    "proposed_actions": [
        "do not announce the release; mark the GHCR aa-gateway tag as not verified",
        "if the tag is missing or the digest or index is wrong, re-run docker.yml publish-gateway on the same tag "
        "(the tag already exists, so this repairs the publication, it does not change the candidate)",
        "if the pulled image does not run healthy, file a Bug against AAASM-4751 and decide yank/hold with the release owner",
    ],
    "notify": ["release-owner"],
    "deadline_hours": 24,
}
DEPENDS_ON = [{"repo": "agent-assembly", "event": "docker.yml publish-gateway on the release tag"}]

# --- minimal gRPC health client -------------------------------------------------
# aa-gateway serves grpc.health.v1.Health unauthenticated (aa-gateway/src/server.rs,
# serving_health_service). No gRPC library is available to a `python3 -I` script, so
# this speaks the few HTTP/2 frames a unary Check needs. It reads the response DATA
# frame only: a HealthCheckResponse of `08 01` is SERVING.


def _frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", stream) + payload


def _lit(prefix: int, name_idx: int | None, name: bytes | None, value: bytes) -> bytes:
    out = bytearray()
    if name_idx is not None:
        out.append(prefix | name_idx)
    else:
        out.append(0x00)
        out += bytes([len(name or b"")]) + (name or b"")
    out += bytes([len(value)]) + value
    return bytes(out)


def grpc_health_status(host: str, port: int, timeout: float = 5.0) -> str:
    """Returns SERVING, NOT_SERVING, UNKNOWN, or raises OSError/ValueError."""
    headers = (
        b"\x83" + b"\x86"                                        # :method POST, :scheme http
        + _lit(0x40, 4, None, b"/grpc.health.v1.Health/Check")   # :path
        + _lit(0x40, 1, None, f"{host}:{port}".encode())         # :authority
        + _lit(0x40, 31, None, b"application/grpc")              # content-type
        + _lit(0x00, None, b"te", b"trailers")
    )
    body = b"\x00\x00\x00\x00\x00"  # empty HealthCheckRequest (service ""), uncompressed
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + _frame(4, 0, 0, b"")
                  + _frame(1, 4, 1, headers) + _frame(0, 1, 1, body))
        buf = b""
        end = time.monotonic() + timeout
        data = b""
        while time.monotonic() < end:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 9:
                n = int.from_bytes(buf[:3], "big")
                if len(buf) < 9 + n:
                    break
                ftype, flags = buf[3], buf[4]
                payload = buf[9:9 + n]
                buf = buf[9 + n:]
                if ftype == 0:
                    data += payload
                if ftype == 7:  # GOAWAY
                    raise ValueError("server sent GOAWAY")
                if ftype in (0, 1) and flags & 1:  # END_STREAM
                    return _decode_health(data)
        raise ValueError("no complete gRPC response before the deadline")


def _decode_health(data: bytes) -> str:
    if len(data) < 5:
        raise ValueError("empty gRPC response body")
    msg = data[5:5 + int.from_bytes(data[1:5], "big")]
    if msg == b"":
        return "UNKNOWN"
    if msg == b"\x08\x01":
        return "SERVING"
    if msg == b"\x08\x02":
        return "NOT_SERVING"
    return f"UNKNOWN(0x{msg.hex()})"


# --- checks ---------------------------------------------------------------------


def check_dockerfile(ctx: c.Context, text: str) -> None:
    problems = []
    stages = re.findall(r"^FROM\s+(\S+)(?:\s+AS\s+(\S+))?", text, re.M | re.I)
    if not stages or "distroless/static" not in stages[-1][0] or ":nonroot" not in stages[-1][0]:
        problems.append(f"final stage is {stages[-1][0] if stages else 'missing'}, want distroless/static:nonroot")
    ep = re.findall(r'^ENTRYPOINT\s+(\[.*\])\s*$', text, re.M)
    if ep != ['["/aa-gateway"]']:
        problems.append(f"ENTRYPOINT is {ep or 'missing'}, want [\"/aa-gateway\"]")
    if re.search(r"^USER\s+(root|0)\b", text, re.M | re.I):
        problems.append("explicit USER root")
    if "COPY --from=builder /aa-gateway-bin /aa-gateway" not in text:
        problems.append("runtime stage does not copy the builder's /aa-gateway-bin to /aa-gateway")
    for arch in ("amd64", "arm64"):
        if not re.search(rf"^\s*{arch}\)\s*TARGET=\S+-unknown-linux-musl", text, re.M):
            problems.append(f"no musl target mapping for TARGETARCH={arch}")
    for label in ("org.opencontainers.image.source", "org.opencontainers.image.licenses"):
        if label not in text:
            problems.append(f"missing OCI label {label}")
    ctx.add("j53-dockerfile-contract", c.FAIL if problems else c.PASS, "mock",
            "; ".join(problems) or "distroless nonroot runtime, ENTRYPOINT /aa-gateway, amd64+arm64 musl mapping, OCI labels",
            [DOCKERFILE_REL], f"{TEST}::test_dockerfile_without_entrypoint_fails")


def _job_block(text: str, job: str) -> str | None:
    m = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S)
    return m.group(1) if m else None


def check_publish_workflow(ctx: c.Context, text: str) -> None:
    job = _job_block(text, "publish-gateway")
    problems = []
    if job is None:
        problems.append("no publish-gateway job")
    else:
        if "startsWith(github.ref, 'refs/tags/v')" not in job:
            problems.append("publish-gateway is not tag-gated")
        if "linux/amd64,linux/arm64" not in job:
            problems.append("platforms is not linux/amd64,linux/arm64")
        if not re.search(r"^\s*sbom:\s*true\s*$", job, re.M):
            problems.append("sbom: true is absent")
        if "aa-gateway:${{ github.ref_name }}" not in job:
            problems.append("the tag is not published as aa-gateway:<ref_name>")
        if "file: aa-gateway/Dockerfile" not in job:
            problems.append("publish-gateway does not build aa-gateway/Dockerfile")
    ctx.add("j53-publish-workflow-contract", c.FAIL if problems else c.PASS, "mock",
            "; ".join(problems) or "publish-gateway: tag-only, multi-arch, sbom, tag = ref_name, builds aa-gateway/Dockerfile",
            [WORKFLOW_REL], f"{TEST}::test_workflow_without_sbom_fails")


def check_binary_identity(ctx: c.Context, gateway: Path, env: dict[str, str]) -> None:
    rc, out = c.run([str(gateway), "--version"], env, ctx.tmp)
    lines = out.splitlines()
    problems = []
    if rc != 0 or not lines:
        problems.append(f"--version exited {rc}")
    else:
        if lines[0].strip() != f"aa-gateway {ctx.expected_version}":
            problems.append(f"version line {lines[0].strip()!r}, want 'aa-gateway {ctx.expected_version}'")
        sha = next((l.split(":", 1)[1].strip() for l in lines if l.startswith("build-sha:")), None)
        if sha != ctx.candidate_sha:
            problems.append(f"build-sha {sha!r} is not the candidate {ctx.candidate_sha}")
    ctx.add("j53-gateway-binary-identity", c.FAIL if problems else c.PASS, "real_local_process",
            "; ".join(problems) or f"aa-gateway {ctx.expected_version} built from {ctx.candidate_sha[:12]}",
            ["aa-gateway"], f"{TEST}::test_wrong_version_fails")


def check_start_health_stop(ctx: c.Context, gateway: Path, policy: Path, env: dict[str, str]) -> None:
    port = c.free_port()
    audit, db = ctx.tmp / "audit", ctx.tmp / "gw.db"
    audit.mkdir()
    argv = [str(gateway), "--policy", str(policy), "--listen", f"127.0.0.1:{port}",
            "--audit-dir", str(audit), "--db-path", str(db)]
    proc = ctx.spawn(argv, env, ctx.tmp)
    problems, health = [], "n/a"
    if not c.wait_port(port, 20):
        problems.append(f"nothing listening on 127.0.0.1:{port} within 20s (exit={proc.poll()})")
    else:
        try:
            health = grpc_health_status("127.0.0.1", port)
            if health != "SERVING":
                problems.append(f"grpc.health.v1 Check returned {health}")
        except (OSError, ValueError) as e:
            problems.append(f"grpc health probe failed: {e}")
    code = c.terminate_group(proc)
    if code is None:
        problems.append("did not stop on SIGTERM within 10s and had to be killed")
    elif code != 0:
        problems.append(f"SIGTERM stop exited {code}, want 0")
    ctx.add("j53-gateway-start-health-stop", c.FAIL if problems else c.PASS, "real_local_process",
            "; ".join(problems) or f"started with {POLICY_REL} on an ephemeral loopback port, Health/Check {health}, SIGTERM exit 0",
            ["aa-gateway", "policy-sample"], f"{TEST}::test_gateway_that_never_listens_fails")


def check_docs(ctx: c.Context, docs_dir: Path | None) -> None:
    if docs_dir is None:
        ctx.add("j53-docs-container-operation", c.NOT_COVERED, "mock",
                "no --docs-dir given; the container operation docs live in the public docs repo, not in this "
                "checkout (only ADR 0010 here mentions the image)", [])
        return
    blob = "\n".join(p.read_text(errors="replace") for p in docs_dir.rglob("*.md") if p.is_file())
    needles = {
        "pull by tag": r"docker pull ghcr\.io/ai-agent-assembly/aa-gateway:\S+",
        "pull by digest": r"ghcr\.io/ai-agent-assembly/aa-gateway@sha256:",
        "policy mount": r"-v\s+\S+:\S*policy",
        "AA_* env": r"AA_[A-Z_]+",
        "health": r"grpc\.health|health",
        "compose snippet": r"image:\s*ghcr\.io/ai-agent-assembly/aa-gateway",
    }
    missing = [k for k, rx in needles.items() if not re.search(rx, blob)]
    ctx.add("j53-docs-container-operation", c.FAIL if missing else c.PASS, "mock",
            ("docs do not show: " + ", ".join(missing)) if missing else "tag pull, digest pull, policy mount, AA_* env, health and compose are documented",
            [], f"{TEST}::test_docs_missing_digest_pull_fails")


def run_harness(argv: list[str]) -> int:
    def extra(ap):
        ap.add_argument("--gateway-bin", required=True)
        ap.add_argument("--docs-dir")
    a = c.parse_common_args(argv, extra)
    repo = Path(a.repo).resolve()
    ctx = c.Context("J53", a.candidate_sha, a.expected_version)
    try:
        gateway = Path(a.gateway_bin).resolve()
        for name, p in (("aa-gateway", gateway), ("aa-gateway/Dockerfile", repo / DOCKERFILE_REL),
                        ("docker.yml", repo / WORKFLOW_REL), ("policy-sample", repo / POLICY_REL)):
            if not p.is_file():
                print(f"missing artifact {name}: {p}", file=sys.stderr)
                return c.EXIT_USAGE
            ctx.register(name, p)
        c.check_artifact_binding(
            ctx, "j53-artifacts-bound-to-candidate", {"aa-gateway": gateway},
            {"aa-gateway/Dockerfile": DOCKERFILE_REL, "docker.yml": WORKFLOW_REL, "policy-sample": POLICY_REL},
            repo, c.load_expected(a.expected_digests), f"{TEST}::test_tampered_binary_fails")
        home = ctx.tmp / "home"
        home.mkdir()
        env = c.clean_env(home)
        check_dockerfile(ctx, (repo / DOCKERFILE_REL).read_text())
        check_publish_workflow(ctx, (repo / WORKFLOW_REL).read_text())
        check_binary_identity(ctx, gateway, env)
        check_start_health_stop(ctx, gateway, repo / POLICY_REL, env)
        check_docs(ctx, Path(a.docs_dir).resolve() if a.docs_dir else None)
        report = c.build_report(ctx, SCRIPT, PENDING, FAILURE_RESPONSE, DEPENDS_ON)
        report["observations"] = [
            "Dockerfile base images (rust:alpine, gcr.io/distroless/static:nonroot) are floating tags, not digest-pinned; "
            "reported as a finding, not a check, because pinning is not a stated J53 acceptance criterion.",
            "docker.yml states cosign image signing is not committed scope (AAASM-5887), so no signature check is owed.",
        ]
        return c.finish(ctx, report, a.out, a.obligation_fragment)
    finally:
        ctx.cleanup()


if __name__ == "__main__":
    c.main_guard(run_harness)
