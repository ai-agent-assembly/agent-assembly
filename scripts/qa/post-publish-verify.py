#!/usr/bin/env python3
"""Read-only post-publication verifier for `pending_checks` (AAASM-6419, Core ADR 0042).

A release recorded CANDIDATE_VERIFIED owes the checks listed in its
`publication-obligations.json`. After the tag is published, run:

  python3 -I scripts/qa/post-publish-verify.py --tag v0.0.1-rc.8 \
      --obligations docs/release/qa-signoff/v0.0.1-rc.8.publication-obligations.json

Safety properties (each has a test in scripts/tests/test_post_publish_verify.py)
------------------------------------------------------------------------------
* The `command` field of a pending check is documentation for a human. It is never
  executed, never passed to a shell, never parsed: the runner is chosen by the check
  `id` from the allowlist `RUNNERS` below, and a check id with no runner is
  INCONCLUSIVE ("no allowlisted runner"), never PASS.
* Every probe is an HTTPS GET to an allowlisted host (ghcr.io, api.github.com,
  raw.githubusercontent.com, crates.io, pypi.org; downloads may also follow a redirect to files.pythonhosted.org)
  with a per-request timeout. Nothing is published,
  yanked, tagged, pushed or written to a registry. Local programs run only through the
  `Tools` seam, as argv lists (no shell): `cosign verify-blob` (INCONCLUSIVE when cosign is
  absent or cannot reach sigstore; cosign itself contacts sigstore's TUF and Rekor hosts,
  which are NOT in ALLOWED_HOSTS and are not vetted by Probe), the j59 harness on binaries verified against SHA256SUMS, and, for
  j53-published-image-runs-healthy only, `docker run` of the digest-pinned aa-gateway image
  (INCONCLUSIVE when docker is absent; the container is always removed), and, for the two
  published-Python-SDK checks (J08, J56), `pip download --only-binary=:all:` of the SDK's dependency wheels (pip contacts
  PyPI itself, outside Probe's vetting, without hash pinning, and runs no package code at download time; the harness
  then installs and imports those wheels) followed by the j08/j56 harness on the PyPI wheel and
  the release binaries (signature-gated like the j59 harness). The installer
  script is fetched and hashed but never executed.
* FAIL means positive evidence the publication is wrong (a 404 for the tag, a body that
  does not hash to its digest, a missing platform). A timeout, a 5xx, a rate limit or
  an auth refusal is INCONCLUSIVE: "could not tell" is not "wrong" and not "right".
* The release-assets probe checks that the release is published, not a draft, and that
  SHA256SUMS names every required tarball for every platform. It does not download or
  hash the tarballs, so it proves presence, not contents.
* Exit 0 only when at least one check ran, every check is PASS, and every pending check in
  the obligations file was run. 1 if any FAIL, 3 if some are INCONCLUSIVE and none FAIL,
  4 if every selected check PASSED but `--only` left other pending checks NOT run (a
  PARTIAL run: it proves nothing about the unrun checks, so it must not read as success),
  2 for a usage or malformed-record error, including an `--only` id that names no pending
  check in the obligations file (a typo must not read as a partial run).
  Consequently a single-check `--only <id>` run exits 4 even when that check passes: its
  PASS is in the JSON `results`, and only a full run with every check PASS exits 0. The
  `PARTIAL: N of M pending checks run; not run: ...` line goes to stderr whenever at least
  one result exists and some pending checks were not run (exit 1, 3 and 4 alike).

Check-id convention (so other journeys can add runners): `<journey>-<channel>-<what>`,
e.g. `j53-ghcr-multiarch`. A journey that owes a check names its id in its obligation
and a runner is added here; until then the check stays INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform as _platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import zipfile
import http.client
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
# raw.githubusercontent.com serves scripts/install-cli.sh at the tag; crates.io serves the
# read-only /api/v1/crates/<name>/<version> JSON. Membership is exact hostname equality, so
# `crates.io.evil.example` and `evilcrates.io` are refused.
ALLOWED_HOSTS = {"ghcr.io", "api.github.com", "raw.githubusercontent.com", "crates.io", "pypi.org"}
# Hosts a GitHub release-asset download legitimately redirects to. Only `Probe.download`
# may follow a redirect, and only to these; no probe ever forwards Authorization on one.
DOWNLOAD_HOSTS = {"objects.githubusercontent.com", "release-assets.githubusercontent.com", "files.pythonhosted.org"}
MAX_REDIRECTS = 3
MAX_BODY = 256 << 20
USER_AGENT = "aa-post-publish-verify"
TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?", re.ASCII)
GHCR_NAMESPACE = "ai-agent-assembly"
GH_REPO = "ai-agent-assembly/agent-assembly"
INDEX_ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
# Names produced by release.yml (`tar -czf` in the package step): the legacy per-target CLI
# tarball and the component-aware cli/api tarballs. runtime and proxy tarballs are conditional
# in release.yml, so they are required only when SHA256SUMS names them.
RELEASE_TARBALLS = [
    "aasm-x86_64-unknown-linux-gnu.tar.gz", "aasm-aarch64-unknown-linux-gnu.tar.gz",
    "aasm-aarch64-apple-darwin.tar.gz", "aasm-x86_64-apple-darwin.tar.gz",
]
OSARCHES = ["linux-amd64", "linux-arm64", "darwin-arm64", "darwin-amd64"]


def required_assets(tag: str) -> list[str]:
    comp = [f"aasm-{c}-{tag}-{oa}.tar.gz" for c in ("cli", "api") for oa in OSARCHES]
    return ["SHA256SUMS", *RELEASE_TARBALLS, *comp]


class FetchError(Exception):
    """Transport failure: no HTTP answer was obtained."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


Fetcher = Callable[[str, dict[str, str], float], Response]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib's default handler follows a 3xx and copies Authorization to the new host.
    Returning None here makes the 3xx surface as an HTTPError, i.e. a Response the caller
    decides about after re-vetting the Location host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


# No env proxies either: a probe talks to the vetted host directly.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


def _read_capped(r: Any, cap: int, deadline_s: float, clock: Callable[[], float] = time.monotonic) -> bytes:
    """Read a body in chunks under an overall deadline (a trickling server cannot hold the run)
    and a size cap (a silently truncated tarball would read as a digest mismatch)."""
    end, chunks, n = clock() + deadline_s, [], 0
    while True:
        if clock() > end:
            raise FetchError("response deadline exceeded")
        c = r.read(65536)
        if not c:
            return b"".join(chunks)
        n += len(c)
        if n > cap:
            raise FetchError("response body exceeds the size cap")
        chunks.append(c)


def urllib_fetcher(url: str, headers: dict[str, str], timeout: float) -> Response:
    """The only network code in this file: one GET, never following a redirect."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # noqa: S310 - scheme and host vetted by Probe
            body = _read_capped(r, MAX_BODY, max(timeout * 10, 60.0))
            declared = r.headers.get("Content-Length")
            if declared is not None and declared.strip().isdigit() and int(declared) != len(body):
                raise FetchError(f"body is {len(body)} bytes but Content-Length said {declared}")
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, body)
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1 << 20))
    except (urllib.error.URLError, OSError, TimeoutError, http.client.HTTPException) as e:
        raise FetchError(type(e).__name__) from e


class Probe:
    """Vets every URL, owns the per-probe timeout and the anonymous GHCR token."""

    def __init__(self, fetch: Fetcher, timeout: float, tools: "Tools | None" = None,
                 binding: "Binding | None" = None):
        self._fetch, self.timeout = fetch, timeout
        self.tools = tools or Tools()
        self.binding = binding or Binding()
        self.cache: dict[tuple, Any] = {}  # one release/SHA256SUMS/signature lookup per invocation
        self._tokens: dict[str, str] = {}

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise FetchError(f"refused non-allowlisted url {u.scheme}://{u.hostname}")
        hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
        token = os.environ.get("GITHUB_TOKEN")
        if token and u.hostname == "api.github.com" and not any(k.lower() == "authorization" for k in hdrs):
            hdrs["Authorization"] = f"Bearer {token}"  # only ever to api.github.com, never on a download hop
        return self._fetch(url, hdrs, self.timeout)

    def download(self, url: str, headers: dict[str, str] | None = None) -> Response:
        """GET that follows at most MAX_REDIRECTS redirects, re-vetting every hop against
        ALLOWED_HOSTS plus DOWNLOAD_HOSTS. Authorization is never forwarded on any hop."""
        hdrs = {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"}
        for _ in range(MAX_REDIRECTS + 1):
            u = urllib.parse.urlsplit(url)
            if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS | DOWNLOAD_HOSTS:
                raise FetchError(f"refused redirect to non-allowlisted host {u.hostname}")
            r = self._fetch(url, dict(hdrs), self.timeout)
            if r.status not in (301, 302, 303, 307, 308):
                return r
            loc = r.headers.get("location")
            if not loc:
                raise FetchError(f"redirect {r.status} without Location")
            url = urllib.parse.urljoin(url, loc)
        raise FetchError("too many redirects")

    def ghcr_token(self, repo: str) -> str:
        if repo not in self._tokens:
            q = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repo}:pull"})
            r = self.get(f"https://ghcr.io/token?{q}")
            if r.status != 200:
                raise FetchError(f"ghcr token endpoint answered {r.status}")
            try:
                self._tokens[repo] = json.loads(r.body)["token"]
            except (ValueError, KeyError, TypeError) as e:
                raise FetchError("ghcr token endpoint returned no token") from e
        return self._tokens[repo]

    def manifest(self, image: str, ref: str) -> Response:
        repo = f"{GHCR_NAMESPACE}/{image}"
        tok = self.ghcr_token(repo)
        return self.get(f"https://ghcr.io/v2/{repo}/manifests/{urllib.parse.quote(ref, safe=':')}",
                        {"Accept": INDEX_ACCEPT, "Authorization": f"Bearer {tok}"})


def _digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


Result = tuple[str, str]  # (status, detail)


def _http_gate(r: Response, what: str) -> Result | None:
    """Map a non-200 answer to FAIL (definitively absent) or INCONCLUSIVE (cannot tell)."""
    if r.status == 200:
        return None
    if r.status == 404:
        return FAIL, f"{what} not found (404)"
    if 300 <= r.status < 400:
        host = urllib.parse.urlsplit(r.headers.get("location", "")).hostname
        return INCONCLUSIVE, f"{what} answered a redirect ({r.status}) to host {host!r}; not followed, cannot tell"
    return INCONCLUSIVE, f"{what} answered {r.status}; cannot tell"


def resolve_tag(p: Probe, image: str, tag: str) -> tuple[Result | None, Response | None, str | None]:
    r = p.manifest(image, tag)
    gate = _http_gate(r, f"{image}:{tag}")
    if gate:
        return gate, None, None
    computed = _digest(r.body)
    claimed = r.headers.get("docker-content-digest")
    want = p.binding.image_digests.get(image)
    if want is not None and want != computed:
        return (FAIL, f"{image}:{tag} resolves to {computed}, the obligations record {want}"), None, None
    if claimed != computed:
        return (FAIL, f"{image}:{tag} body hashes to {computed} but Docker-Content-Digest is {claimed!r}"), None, None
    return None, r, computed


def run_tag_resolves(p: Probe, image: str, tag: str) -> Result:
    err, _, digest = resolve_tag(p, image, tag)
    return err or (PASS, f"{image}:{tag} resolves to {digest} and the body hashes to it")


def run_digest_immutable(p: Probe, image: str, tag: str) -> Result:
    """Consistency only: the registry returns the same bytes for the digest it computed from
    the tag. That does not show the digest is the qualified one; resolve_tag compares it to the
    obligations' `image_digests` entry when the record carries one."""
    err, first, digest = resolve_tag(p, image, tag)
    if err:
        return err
    r = p.manifest(image, digest)
    gate = _http_gate(r, f"{image}@{digest}")
    if gate:
        return gate
    if r.body != first.body:
        return FAIL, f"{image}@{digest} returns different bytes from {image}:{tag}"
    return PASS, f"{image}@{digest} is byte-identical to {image}:{tag}"


def _index(first: Response) -> dict[str, Any] | None:
    try:
        doc = json.loads(first.body)
    except ValueError:
        return None
    return doc if isinstance(doc.get("manifests"), list) else None


def _platforms(doc: dict[str, Any]) -> dict[str, str]:
    out = {}
    for m in doc["manifests"]:
        plat = m.get("platform") or {}
        if plat.get("os") and plat.get("os") != "unknown":
            out[f"{plat['os']}/{plat.get('architecture')}"] = m.get("digest", "")
    return out


def run_multiarch(p: Probe, image: str, tag: str) -> Result:
    err, first, _ = resolve_tag(p, image, tag)
    if err:
        return err
    doc = _index(first)
    if doc is None:
        return FAIL, f"{image}:{tag} is a single manifest, not a multi-arch index"
    have = _platforms(doc)
    missing = [x for x in ("linux/amd64", "linux/arm64") if x not in have]
    return (FAIL, f"index lacks {missing}; has {sorted(have)}") if missing else (PASS, f"index lists {sorted(have)}")


def run_sbom(p: Probe, image: str, tag: str) -> Result:
    err, first, _ = resolve_tag(p, image, tag)
    if err:
        return err
    doc = _index(first)
    if doc is None:
        return FAIL, f"{image}:{tag} is not an index, so it carries no attestation manifests"
    have = _platforms(doc)
    attested = {
        (m.get("annotations") or {}).get("vnd.docker.reference.digest")
        for m in doc["manifests"]
        if (m.get("annotations") or {}).get("vnd.docker.reference.type") == "attestation-manifest"
    }
    missing = [plat for plat in ("linux/amd64", "linux/arm64") if have.get(plat) not in attested]
    return (FAIL, f"no attestation-manifest for {missing}") if missing else (PASS, "an attestation manifest exists for linux/amd64 and linux/arm64")


def run_image_bundle(p: Probe, image: str, tag: str) -> Result:
    for fn in (run_tag_resolves, run_digest_immutable, run_multiarch):
        res = fn(p, image, tag)
        if res[0] != PASS:
            return res
    return PASS, f"{image}:{tag} resolves, is digest-consistent and multi-arch"


SUMS_LINE = re.compile(r"([0-9a-f]{64})\s+\*?(\S+)")


def run_release_assets(p: Probe, tag: str) -> Result:
    err, assets = _release(p, tag)
    if err:
        return err
    err, _, named, _ = _release_sums(p, tag)
    if err:
        return err
    problems: list[str] = []
    for name in required_assets(tag):
        if name != "SHA256SUMS" and name not in named:
            problems.append(f"SHA256SUMS does not name required {name}")
    for name in sorted(named):
        if name not in assets:
            problems.append(f"SHA256SUMS names {name} but it is not a release asset")
    for name in sorted(set(named) | {n for n in required_assets(tag)}):
        a = assets.get(name)
        if a is not None and (a.get("state") != "uploaded" or not a.get("size")):
            problems.append(f"asset {name} state={a.get('state')!r} size={a.get('size')!r}")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, (f"SHA256SUMS names {len(named)} files, every one is an uploaded release asset, and the "
                  f"required legacy, cli and api tarballs for {len(OSARCHES)} platforms are all named "
                  "(tarball contents are not downloaded or hashed here)")


# --- local-tool seam (AAASM-6424) --------------------------------------------------------
# Runners that need a local program (cosign, docker, the j59 harness) go through `Tools`, the
# second injectable seam beside `Fetcher`. Tests pass a fake, so no test ever runs a real
# binary, opens a socket to a container or touches a Docker daemon.

def grpc_health_check(host: str, port: int, timeout: float) -> str:
    """One unary grpc.health.v1.Health/Check over cleartext HTTP/2, stdlib only (the standard
    library has no HTTP/2 client). `timeout` is an overall deadline, not per read. The call
    must end with a trailers HEADERS frame carrying END_STREAM after the response message;
    when the trailers spell `grpc-status` as a plain literal its value must be 0. Huffman-coded
    trailers are not decoded (no HPACK decoder in the stdlib), so a non-zero status hidden that
    way is not seen, but a gRPC server only sends a response message with status OK.
    Returns "SERVING" or "STATUS_<n>"; raises FetchError otherwise."""
    deadline = time.monotonic() + timeout

    def frame(kind: int, flags: int, sid: int, payload: bytes) -> bytes:
        return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + sid.to_bytes(4, "big") + payload

    def lit(name: bytes, value: bytes) -> bytes:  # HPACK literal without indexing, no Huffman
        return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value

    headers = (b"\x83\x86"  # static table: :method POST, :scheme http
               + lit(b":path", b"/grpc.health.v1.Health/Check")
               + lit(b":authority", f"{host}:{port}".encode())
               + lit(b"content-type", b"application/grpc") + lit(b"te", b"trailers"))
    request = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"") + frame(1, 0x4, 1, headers)
               + frame(0, 0x1, 1, b"\x00\x00\x00\x00\x00"))  # empty HealthCheckRequest, END_STREAM
    data = b""
    with socket.create_connection((host, port), timeout) as s:
        def recv() -> bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise FetchError("health probe deadline exceeded")
            s.settimeout(remaining)
            chunk = s.recv(4096)
            if not chunk:
                raise FetchError("connection closed before the gRPC call completed")
            return chunk

        s.settimeout(timeout)
        s.sendall(request)
        buf = b""
        while True:
            while len(buf) < 9:
                buf += recv()
            length, kind, flags = int.from_bytes(buf[:3], "big"), buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            while len(buf) < 9 + length:
                buf += recv()
            payload, buf = buf[9:9 + length], buf[9 + length:]
            if kind == 4 and not flags & 1:
                s.sendall(frame(4, 1, 0, b""))
            elif kind == 6 and not flags & 1:
                s.sendall(frame(6, 1, 0, payload))  # PING must be ACKed with the same payload
            elif kind in (3, 7):
                raise FetchError("server reset the stream or sent GOAWAY")
            elif kind == 0 and sid == 1:
                data += payload
                if flags & 1:
                    raise FetchError("response ended without gRPC trailers")
            elif kind == 1 and sid == 1 and flags & 1:
                m = re.search(rb"grpc-status\x01(.)", payload)
                if m and m.group(1) != b"0":
                    raise FetchError(f"grpc-status {m.group(1)!r} in trailers")
                return parse_health_response(data)


def parse_health_response(data: bytes) -> str:
    if len(data) < 5 or data[0] != 0:
        raise FetchError("no gRPC message in the health response")
    n = int.from_bytes(data[1:5], "big")
    msg = data[5:5 + n]
    if len(msg) != n or n < 2 or msg[0] != 0x08:
        raise FetchError("malformed HealthCheckResponse")
    return "SERVING" if msg[1] == 1 else f"STATUS_{msg[1]}"


_SECRET_ENV = re.compile(r"TOKEN|SECRET|PASSW|CREDENTIAL|API_?KEY|PRIVATE|AUTH", re.I)


def _scrubbed_env() -> dict[str, str]:
    """The default environment for a local program: the caller's, minus anything that looks
    like a credential (the process may be a downloaded binary or a container client)."""
    return {k: v for k, v in os.environ.items() if not _SECRET_ENV.search(k)}


class Tools:
    """Real local-program access. Every method is overridden by a fake in tests."""

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, argv: list[str], timeout: float, cwd: str | None = None,
            env: dict[str, str] | None = None) -> tuple[int, str, str]:
        """argv list only, never a shell. The program gets its own session so a timeout kills
        the whole process group (a hung harness cannot leave a server behind). A timeout is a
        FetchError (could not tell). `env` is used as given; None means the credential-scrubbed
        caller environment."""
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd,
                                    env=_scrubbed_env() if env is None else env, stdin=subprocess.DEVNULL,
                                    start_new_session=True)
        except OSError as e:
            raise FetchError(f"cannot execute {Path(argv[0]).name}: {type(e).__name__}") from e
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()
            proc.communicate()
            raise FetchError(f"{Path(argv[0]).name} timed out after {timeout:.0f}s") from e
        return proc.returncode, out, err

    def grpc_health(self, host: str, port: int, timeout: float) -> str:
        try:
            return grpc_health_check(host, port, timeout)
        except OSError as e:
            raise FetchError(type(e).__name__) from e

    def platform(self) -> tuple[str, str]:
        return _platform.system(), _platform.machine()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


# --- binding to the qualified candidate (H1) ---------------------------------------------
@dataclass
class Binding:
    """What the obligations file says the candidate was. `candidate_shas` has more than one
    member only when the record contradicts itself; runners then refuse to bind.
    `registry_digests` is the digest of the golden-journey registry, not of any image or
    asset, so no runner can compare it to published state; it is carried for the record."""
    candidate_shas: frozenset[str] = frozenset()
    installer_sha256: str | None = None
    image_digests: dict[str, str] = field(default_factory=dict)
    registry_digests: frozenset[str] = frozenset()


SHA40_RE = re.compile(r"[0-9a-f]{40}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def binding_from(doc: Any) -> Binding:
    """Read candidate_sha, installer_sha256 (or the installer artifact digest), registry_digest
    and optional image_digests ({image: sha256:<hex>}) from the obligations file. Absent or
    malformed values are simply absent; a runner that needs one reports INCONCLUSIVE."""
    shas: set[str] = set()
    installers: set[str] = set()
    regs: set[str] = set()
    images: dict[str, str] = {}

    def take(node: Any) -> None:
        if not isinstance(node, dict):
            return
        v = node.get("candidate_sha")
        if isinstance(v, str) and SHA40_RE.fullmatch(v):
            shas.add(v)
        v = node.get("installer_sha256")
        if isinstance(v, str) and SHA256_RE.fullmatch(v):
            installers.add(v)
        ad = node.get("artifact_digests")
        v = ad.get("installer:install-cli.sh") if isinstance(ad, dict) else None
        if isinstance(v, str) and DIGEST_RE.fullmatch(v):
            installers.add(v[len("sha256:"):])
        v = node.get("registry_digest")
        if isinstance(v, str) and DIGEST_RE.fullmatch(v):
            regs.add(v)
        v = node.get("image_digests")
        if isinstance(v, dict):
            images.update({k: d for k, d in v.items()
                           if isinstance(k, str) and isinstance(d, str) and DIGEST_RE.fullmatch(d)})

    if isinstance(doc, dict):
        take(doc)
        for j in doc.get("journeys") or []:
            take(j)
            for c in (j.get("candidate_checks") or []) if isinstance(j, dict) else []:
                take(c)
    return Binding(frozenset(shas), next(iter(installers)) if len(installers) == 1 else None, images,
                   frozenset(regs))


# --- published-state runners (AAASM-6424) ------------------------------------------------
RELEASE_API = f"https://api.github.com/repos/{GH_REPO}"
TAP_API = "https://api.github.com/repos/ai-agent-assembly/homebrew-tap"
INSTALLER_PATH = "scripts/install-cli.sh"
SIGNING_ISSUER = "https://token.actions.githubusercontent.com"
RAW_ACCEPT = "application/vnd.github.raw+json"
REPO_ROOT = Path(__file__).resolve().parents[2]
HEALTH_ATTEMPTS, HEALTH_INTERVAL = 30, 2.0
MAX_TAR_MEMBERS, MAX_TAR_BYTES = 10_000, 1 << 30
# cosign failures that are about reaching or parsing sigstore state, not about this signature
COSIGN_TRANSIENT = re.compile(
    r"TUF|rekor|dial |timeout|timed out|no such host|connection|tls|EOF|unmarshal|unexpected|"
    r"network|temporar|\b50\d\b|\b429\b|proxy|lookup|parse|decod|malformed|invalid bundle|cache", re.I)


def _cached(p: Probe, key: tuple, make: Callable[[], Any]) -> Any:
    if key not in p.cache:
        p.cache[key] = make()
    return p.cache[key]


def _bound(fn: Callable[[Probe, str], Result]) -> Callable[[Probe, str], Result]:
    """A runner that proves a property of the published tag only means something for the
    candidate that was qualified, so it first binds the tag to the record."""
    def run(p: Probe, tag: str) -> Result:
        return _bind(p, tag) or fn(p, tag)
    return run


def _bind(p: Probe, tag: str) -> Result | None:
    """None when the tag's commit has the record's candidate_sha as an ancestor (or equals it).
    Which files may differ between the two is the gate's rule (docs-only delta), enforced by
    the checker and not re-implemented here."""
    shas = p.binding.candidate_shas
    if len(shas) != 1:
        return INCONCLUSIVE, ("obligations record no candidate_sha" if not shas else
                              f"obligations name {len(shas)} different candidate_sha values")
    cand = next(iter(shas))

    def make() -> Result | None:
        hdr = {"Accept": "application/vnd.github+json"}
        r = p.get(f"{RELEASE_API}/commits/{urllib.parse.quote(tag)}", hdr)
        gate = _http_gate(r, f"commit of {tag}")
        if gate:
            return gate
        try:
            tag_sha = json.loads(r.body)["sha"]
        except (ValueError, KeyError, TypeError):
            return INCONCLUSIVE, "commit JSON was not parseable"
        r = p.get(f"{RELEASE_API}/compare/{cand}...{tag_sha}", hdr)
        gate = _http_gate(r, f"compare {cand[:12]}...{str(tag_sha)[:12]}")
        if gate:
            return gate
        try:
            status = json.loads(r.body)["status"]
        except (ValueError, KeyError, TypeError):
            return INCONCLUSIVE, "compare JSON was not parseable"
        if status not in ("ahead", "identical"):
            return FAIL, (f"tag {tag} ({str(tag_sha)[:12]}) does not descend from candidate {cand[:12]} "
                          f"(compare status {status!r})")
        return None
    return _cached(p, ("bind", tag, cand), make)


def _release(p: Probe, tag: str) -> tuple[Result | None, dict[str, dict[str, Any]]]:
    def make() -> tuple[Result | None, dict[str, dict[str, Any]]]:
        r = p.get(f"{RELEASE_API}/releases/tags/{urllib.parse.quote(tag)}", {"Accept": "application/vnd.github+json"})
        gate = _http_gate(r, f"GitHub Release {tag}")
        if gate:
            return gate, {}
        try:
            rel = json.loads(r.body)
            assets = {a["name"]: a for a in rel["assets"]}
        except (ValueError, KeyError, TypeError):
            return (INCONCLUSIVE, "release JSON was not parseable"), {}
        if rel.get("draft"):
            return (FAIL, f"release {tag} is still a draft"), {}
        return None, assets
    return _cached(p, ("release", tag), make)


def _asset(p: Probe, assets: dict[str, dict[str, Any]], name: str) -> tuple[Result | None, bytes]:
    """Download one release asset. Missing or empty is FAIL, never an empty PASS."""
    a = assets.get(name)
    if a is None:
        return (FAIL, f"release asset {name} missing"), b""
    if a.get("state") != "uploaded" or not a.get("size"):
        return (FAIL, f"asset {name} state={a.get('state')!r} size={a.get('size')!r}"), b""
    url = a.get("url")
    if not isinstance(url, str):
        return (INCONCLUSIVE, f"asset {name} has no API url"), b""
    r = p.download(url, {"Accept": "application/octet-stream"})
    gate = _http_gate(r, f"{name} download")
    if gate:
        return gate, b""
    if not r.body:
        return (FAIL, f"{name} downloaded empty"), b""
    claimed = a.get("digest")  # GitHub reports sha256:<hex> for uploaded assets
    if isinstance(claimed, str) and claimed != _digest(r.body):
        return (FAIL, f"{name} bytes hash to {_digest(r.body)} but the release API reports {claimed}"), b""
    return None, r.body


def _parse_sums(body: bytes) -> tuple[dict[str, str], list[str]]:
    named: dict[str, str] = {}
    bad: list[str] = []
    for line in body.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        m = SUMS_LINE.fullmatch(line.strip())
        if not m:
            bad.append(f"malformed SHA256SUMS line {line.strip()[:60]!r}")
        elif named.get(m.group(2), m.group(1)) != m.group(1):
            bad.append(f"SHA256SUMS lists {m.group(2)} twice with different digests")
        else:
            named[m.group(2)] = m.group(1)
    return named, bad


def _release_sums(p: Probe, tag: str) -> tuple[Result | None, dict[str, dict[str, Any]], dict[str, str], bytes]:
    def make() -> tuple[Result | None, dict[str, dict[str, Any]], dict[str, str], bytes]:
        err, assets = _release(p, tag)
        if err:
            return err, {}, {}, b""
        err, body = _asset(p, assets, "SHA256SUMS")
        if err:
            return err, assets, {}, b""
        named, bad = _parse_sums(body)
        if bad or not named:
            return (FAIL, "; ".join(bad or ["SHA256SUMS names no files"])), assets, {}, body
        return None, assets, named, body
    return _cached(p, ("sums", tag), make)


def _signature(p: Probe, tag: str) -> Result:
    """cosign verify-blob of SHA256SUMS against this tag's release workflow identity.
    INCONCLUSIVE when cosign is absent or cannot reach sigstore (TUF/Rekor); never PASS then.
    cosign contacts sigstore hosts of its own, outside ALLOWED_HOSTS: that is the one
    network path here that is not a vetted GET."""
    def make() -> Result:
        err, assets, _, sums = _release_sums(p, tag)
        if err:
            return err
        err, bundle = _asset(p, assets, "SHA256SUMS.cosign.bundle")
        if err:
            return err
        try:
            if not isinstance(json.loads(bundle), dict):
                raise ValueError
        except ValueError:
            return FAIL, "SHA256SUMS.cosign.bundle is not a JSON object"
        cosign = p.tools.which("cosign")
        if cosign is None:
            return INCONCLUSIVE, "the cosign binary is not on PATH so the signature was NOT verified"
        with tempfile.TemporaryDirectory(prefix="ppv-cosign-") as d:
            (Path(d) / "SHA256SUMS").write_bytes(sums)
            (Path(d) / "SHA256SUMS.cosign.bundle").write_bytes(bundle)
            env = {**_scrubbed_env(), "HOME": d}
            rc, _, err_txt = p.tools.run(
                [cosign, "verify-blob", "--bundle", "SHA256SUMS.cosign.bundle", "--certificate-identity-regexp",
                 f"^https://github.com/{GH_REPO}/\\.github/workflows/release\\.yml@refs/tags/{re.escape(tag)}$",
                 "--certificate-oidc-issuer", SIGNING_ISSUER, "SHA256SUMS"], 120, cwd=d, env=env)
        if rc != 0:
            msg = err_txt.strip()[:200]
            if COSIGN_TRANSIENT.search(err_txt):
                return INCONCLUSIVE, f"cosign could not complete verification (exit {rc}): {msg}"
            return FAIL, f"cosign verify-blob rejected SHA256SUMS (exit {rc}): {msg}"
        return PASS, f"cosign verify-blob accepted SHA256SUMS for release.yml at {tag}"
    return _cached(p, ("signature", tag), make)


def run_checksums_and_signature(p: Probe, tag: str) -> Result:
    err, assets, named, _ = _release_sums(p, tag)
    if err:
        return err
    problems = [f"SHA256SUMS names {n} but it is not an uploaded release asset"
                for n in sorted(named) if n not in assets or assets[n].get("state") != "uploaded"]
    compared = 0
    for n, want in named.items():
        d = assets.get(n, {}).get("digest")
        if isinstance(d, str):
            compared += 1
            if d != f"sha256:{want}":
                problems.append(f"{n}: release API digest {d} != SHA256SUMS sha256:{want}")
    if problems:
        return FAIL, "; ".join(problems)
    sig = _signature(p, tag)
    if sig[0] != PASS:
        return sig
    if compared < len(named):
        return INCONCLUSIVE, (f"signature verified, but only {compared} of {len(named)} SHA256SUMS entries have a "
                              "release-API digest to compare; the rest were not hashed")
    return PASS, (f"{sig[1]}; all {len(named)} listed files are uploaded assets whose release-API digest "
                  "equals its SHA256SUMS entry")


def run_installer(p: Probe, tag: str) -> Result:
    """The installer served at the tag equals the digest the candidate recorded, and the
    release it installs from is complete. The script is NOT executed here (it writes outside
    a temp tree if it misbehaves), so its behaviour is not exercised."""
    expected = p.binding.installer_sha256
    if expected is None:
        return INCONCLUSIVE, "obligations record no installer digest (installer_sha256 or the installer artifact digest)"
    r = p.get(f"https://raw.githubusercontent.com/{GH_REPO}/{urllib.parse.quote(tag)}/{INSTALLER_PATH}")
    gate = _http_gate(r, f"{INSTALLER_PATH} at {tag}")
    if gate:
        return gate
    if not r.body:
        return FAIL, f"{INSTALLER_PATH} at {tag} is empty"
    got = hashlib.sha256(r.body).hexdigest()
    if got != expected:
        return FAIL, f"{INSTALLER_PATH} at {tag} hashes to {got}, the candidate recorded {expected}"
    res = run_release_assets(p, tag)
    if res[0] != PASS:
        return res
    return PASS, (f"{INSTALLER_PATH} at {tag} equals the recorded candidate digest; release assets complete; "
                  "the installer was not executed")


def _tag_name(r: Response, what: str) -> tuple[Result | None, str]:
    gate = _http_gate(r, what)
    if gate:
        return gate, ""
    try:
        doc = json.loads(r.body)
        doc = doc[0] if isinstance(doc, list) else doc
        name = doc["tag_name"]
    except (ValueError, KeyError, IndexError, TypeError):
        return (INCONCLUSIVE, f"{what} JSON was not parseable"), ""
    return None, name if isinstance(name, str) else ""


def run_latest_resolves(p: Probe, tag: str) -> Result:
    """/releases/latest skips pre-releases, so for an rc it is normally 404 (the installer then
    takes the newest release overall). PASS when it is 404 or names this tag; FAIL when an
    unpinned install would land on a different stable release. The newest-overall fallback
    target is reported but not required to be this tag: a later rc must not fail an earlier one."""
    hdr = {"Accept": "application/vnd.github+json"}
    r = p.get(f"{RELEASE_API}/releases/latest", hdr)
    if r.status == 404:
        err, top = _tag_name(p.get(f"{RELEASE_API}/releases?per_page=1", hdr), "newest release")
        if err:
            return err
        return PASS, f"/releases/latest is 404 (no stable release); the installer falls back to the newest release, {top!r}"
    err, latest = _tag_name(r, "/releases/latest")
    if err:
        return err
    if latest != tag:
        return FAIL, f"an unpinned install resolves to {latest!r}, not {tag}"
    return PASS, f"/releases/latest is {tag}"


def _tap_text(p: Probe, path: str) -> tuple[Result | None, str]:
    r = p.get(f"{TAP_API}/contents/{path}", {"Accept": RAW_ACCEPT})
    gate = _http_gate(r, f"homebrew-tap {path}")
    if gate:
        return gate, ""
    if not r.body:
        return (FAIL, f"homebrew-tap {path} is empty"), ""
    return None, r.body.decode("utf-8", "replace")


URL_LINE = re.compile(r'^\s*url\s+"([^"]+)"')
SHA_LINE = re.compile(r'^\s*sha256\s+"([^"]*)"')


def run_homebrew(p: Probe, tag: str, formula: str, binary: str) -> Result:
    version = tag[1:]
    err, _, named, _ = _release_sums(p, tag)
    if err:
        return err
    err, versions = _tap_text(p, "metadata/versions.rb")
    if err:
        return err
    m = re.search(r'VERSION\s*=\s*"([^"]*)"', versions)
    if not m or m.group(1) != version:
        return FAIL, f"tap metadata/versions.rb VERSION is {m.group(1) if m else None!r}, expected {version!r}"
    err, text = _tap_text(p, f"Formula/{formula}.rb")
    if err:
        return err
    if binary not in text:
        return FAIL, f"Formula/{formula}.rb does not mention {binary}"
    problems: list[str] = []
    entries: list[tuple[str, str]] = []
    pending: str | None = None
    for line in text.splitlines():
        if um := URL_LINE.match(line):
            if pending is not None:
                problems.append(f"formula url {pending.rsplit('/', 1)[-1]} has no sha256")
            pending = um.group(1)
        elif (sm := SHA_LINE.match(line)) and pending is not None:
            entries.append((pending, sm.group(1)))
            pending = None
    if pending is not None:
        problems.append(f"formula url {pending.rsplit('/', 1)[-1]} has no sha256")
    if not entries:
        return FAIL, "; ".join(problems + [f"Formula/{formula}.rb has no url/sha256 pair"])
    prefix = f"https://github.com/{GH_REPO}/releases/download/{tag}/"
    for raw_url, sha in entries:
        url = raw_url.replace("#{version}", version).replace("#{VERSION}", version)
        if "#{" in url:
            problems.append(f"formula url {raw_url!r} has an interpolation this check cannot resolve")
            continue
        if not url.startswith(prefix) or "/" in url[len(prefix):]:
            problems.append(f"formula url {url!r} is not a direct asset under {prefix}")
            continue
        base = url[len(prefix):]
        if base not in named:
            problems.append(f"formula url {base} is not named in SHA256SUMS")
        elif not SHA256_RE.fullmatch(sha) or named[base] != sha:
            problems.append(f"{base}: formula sha256 {sha!r} != SHA256SUMS {named[base]}")
    if problems:
        return FAIL, "; ".join(problems)
    return PASS, (f"tap VERSION is {version} and all {len(entries)} Formula/{formula}.rb urls point at {tag} "
                  "with sha256 equal to SHA256SUMS")


def run_crates_io(p: Probe, tag: str, crate: str) -> Result:
    version = tag[1:]
    r = p.get(f"https://crates.io/api/v1/crates/{crate}/{urllib.parse.quote(version)}", {"Accept": "application/json"})
    gate = _http_gate(r, f"crates.io {crate} {version}")
    if gate:
        return gate
    try:
        v = json.loads(r.body)["version"]
        num, yanked = v["num"], v["yanked"]
    except (ValueError, KeyError, TypeError):
        return INCONCLUSIVE, "crates.io JSON was not parseable"
    if num != version:
        return FAIL, f"crates.io answered version {num!r}, expected {version!r}"
    if yanked is not False:
        return FAIL, f"{crate} {version} is yanked (yanked={yanked!r})"
    return PASS, f"{crate} {version} is published and not yanked"


def run_images(p: Probe, tag: str) -> Result:
    for image in ("aa-runtime", "aa-gateway"):
        res = run_image_bundle(p, image, tag)
        if res[0] != PASS:
            return res
    return PASS, f"aa-runtime and aa-gateway {tag} resolve, are digest-consistent and multi-arch"


def run_image_runs_healthy(p: Probe, tag: str) -> Result:
    """Runs the digest-pinned aa-gateway image. Never PASSes unless the container really ran,
    answered SERVING and stopped with exit 0 on SIGTERM; the container is always removed.
    It runs with no capabilities, no-new-privileges, a pid and memory limit."""
    docker = p.tools.which("docker")
    if docker is None:
        return INCONCLUSIVE, "docker is not on PATH; the published image was not run"
    err, _, digest = resolve_tag(p, "aa-gateway", tag)
    if err:
        return err
    ref = f"ghcr.io/{GHCR_NAMESPACE}/aa-gateway@{digest}"
    name = f"aa-ppv-{uuid.uuid4().hex[:16]}"
    t = p.tools

    def dk(*a: str, timeout: float = 120) -> tuple[int, str, str]:
        return t.run([docker, *a], timeout)

    try:
        rc, _, e = dk("run", "-d", "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                      "--pids-limit", "256", "--memory", "512m", "-p", "127.0.0.1::50051", ref,
                      "--listen", "0.0.0.0:50051", "--policy", "/policy/balanced.yaml", timeout=600)
        if rc != 0:
            return INCONCLUSIVE, f"docker run failed (exit {rc}): {e.strip()[:200]}"
        rc, out, _ = dk("port", name, "50051/tcp")
        m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)\s*$", out.strip().splitlines()[0]) if rc == 0 and out.strip() else None
        if not m:
            return INCONCLUSIVE, "could not resolve the published container port"
        host, port = m.group(1), int(m.group(2))
        status = "no answer"
        for _ in range(HEALTH_ATTEMPTS):
            rc, running, _ = dk("inspect", "-f", "{{.State.Running}}", name)
            if rc != 0 or running.strip() != "true":
                _, logs, lerr = dk("logs", "--tail", "10", name)
                return FAIL, f"container exited before answering health: {(logs + lerr).strip()[-200:]}"
            try:
                status = t.grpc_health(host, port, 3.0)
            except FetchError as ex:
                status = f"error {ex}"
            if status == "SERVING":
                break
            t.sleep(HEALTH_INTERVAL)
        if status != "SERVING":
            return FAIL, f"grpc.health.v1 never answered SERVING (last: {status})"
        rc, _, e = dk("stop", "-t", "20", name, timeout=60)
        rc2, code, _ = dk("inspect", "-f", "{{.State.ExitCode}}", name)
        if rc != 0 or rc2 != 0 or code.strip() != "0":
            return FAIL, f"container did not stop with exit 0 on SIGTERM (exit code {code.strip()!r})"
        return PASS, f"{ref} answered SERVING and stopped with exit 0"
    finally:
        try:
            dk("rm", "-f", name, timeout=60)
        except FetchError:
            pass


def _safe_extract(archive: Path, dest: Path) -> None:
    """Regular files and directories only, all under dest, bounded in count and size.
    Violations raise TarError (a defective published archive: FAIL)."""
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > MAX_TAR_MEMBERS or sum(m.size for m in members) > MAX_TAR_BYTES:
            raise tarfile.TarError("archive exceeds the member or size cap")
        for m in members:
            target = (dest / m.name).resolve()
            if not (m.isreg() or m.isdir()) or dest.resolve() not in (target, *target.parents):
                raise tarfile.TarError(f"unsafe tar member {m.name!r}")
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")
        else:  # pragma: no cover - interpreters older than 3.12 without the backport
            tf.extractall(dest)  # noqa: S202 - members vetted above


def _find_one(root: Path, name: str) -> Path | None:
    hits = [x for x in root.rglob(name) if x.is_file()]
    return hits[0] if len(hits) == 1 else None


def _published_platform(p: Probe) -> str | None:
    """The release-asset os-arch suffix for the machine running the verifier, or None."""
    return {("Linux", "x86_64"): "linux-amd64", ("Linux", "aarch64"): "linux-arm64", ("Linux", "arm64"): "linux-arm64",
            ("Darwin", "arm64"): "darwin-arm64", ("Darwin", "x86_64"): "darwin-amd64"}.get(p.tools.platform())


def _extract_published(p: Probe, tag: str, assets: dict[str, dict[str, Any]], named: dict[str, str], tmp: Path,
                       oa: str, wanted: tuple[tuple[str, tuple[str, ...]], ...]) -> tuple[Result | None, dict[str, Path]]:
    """Download `aasm-<comp>-<tag>-<oa>.tar.gz` for each (comp, binaries) in `wanted`, require its
    digest in SHA256SUMS, extract it safely under `tmp` and return each binary's path. A defect in
    the published archive is FAIL; the caller has already verified the signature of SHA256SUMS."""
    found: dict[str, Path] = {}
    for comp, binaries in wanted:
        name = f"aasm-{comp}-{tag}-{oa}.tar.gz"
        err, body = _asset(p, assets, name)
        if err:
            return err, {}
        if name not in named:
            return (FAIL, f"SHA256SUMS does not name {name}"), {}
        if hashlib.sha256(body).hexdigest() != named[name]:
            return (FAIL, f"{name} does not match SHA256SUMS"), {}
        arc, dest = tmp / name, tmp / comp
        arc.write_bytes(body)
        dest.mkdir()
        try:
            _safe_extract(arc, dest)
        except (tarfile.TarError, OSError) as e:
            return (FAIL, f"{name} is not a safe readable tarball: {e}"), {}
        for binary in binaries:
            exe = _find_one(dest, binary)
            if exe is None:
                return (FAIL, f"{name} does not contain exactly one {binary}"), {}
            exe.chmod(0o755)
            found[binary] = exe
    return None, found


def run_golden_path(p: Probe, tag: str) -> Result:
    """Downloads the published tarballs, verifies them against SHA256SUMS and re-runs the j59
    harness on the extracted binaries. Executes downloaded code, so it first requires that the
    signature check of this same release passed in this invocation, and then runs the harness
    with a minimal environment (PATH and a temp HOME only: no tokens) in its own process group.
    The candidate sha handed to the harness is the obligations', never one read from the remote."""
    shas = p.binding.candidate_shas
    if len(shas) != 1:
        return INCONCLUSIVE, "obligations record no single candidate_sha to hand the harness"
    sig = _signature(p, tag)
    if sig[0] != PASS:
        return (FAIL if sig[0] == FAIL else INCONCLUSIVE), f"not running downloaded binaries: signature not verified ({sig[1]})"
    oa = _published_platform(p)
    if oa is None:
        system, machine = p.tools.platform()
        return INCONCLUSIVE, f"no published binaries for runner platform {system}/{machine}"
    err, assets, named, _ = _release_sums(p, tag)
    if err:
        return err
    harness = REPO_ROOT / "scripts/qa/j59-candidate-harness.py"
    with tempfile.TemporaryDirectory(prefix="ppv-j59-") as tmp:
        err, found = _extract_published(p, tag, assets, named, Path(tmp), oa,
                                        (("cli", ("aasm",)), ("api", ("aa-api-server",))))
        if err:
            return err
        digests = Path(tmp) / "expected.json"
        digests.write_text(json.dumps({b: "sha256:" + hashlib.sha256(x.read_bytes()).hexdigest()
                                       for b, x in found.items()}))
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": tmp, "TMPDIR": tmp}
        rc, out, err_txt = p.tools.run(
            [sys.executable, "-I", str(harness), "--candidate-sha", next(iter(shas)), "--expected-version", tag[1:],
             "--repo", str(REPO_ROOT), "--aasm-bin", str(found["aasm"]), "--api-server-bin", str(found["aa-api-server"]),
             "--expected-digests", str(digests)], 900, cwd=tmp, env=env)
    try:
        report = json.loads(out)
        checks = report["candidate_checks"]
        verdict = report["verdict"]
    except (ValueError, KeyError, TypeError):
        return INCONCLUSIVE, f"j59 harness produced no parseable report (exit {rc}): {err_txt.strip()[:160]}"
    bad = [c["id"] for c in checks if c.get("status") == FAIL]
    if verdict == "BLOCK" or bad:
        return FAIL, f"j59 harness against the published binaries: FAIL {bad}"
    notcov = [c["id"] for c in checks if c.get("status") != PASS]
    if rc == 0 and verdict == "CANDIDATE_VERIFIED" and checks and not notcov:
        return PASS, f"every one of {len(checks)} j59 candidate checks passed against the published {oa} binaries"
    return INCONCLUSIVE, f"j59 harness exit {rc}, verdict {verdict}; not PASS: {notcov}"


# --- published Python SDK (J08, J56) ----------------------------------------------------
SDK_DIST = "agent-assembly"
PYPI_JSON = f"https://pypi.org/pypi/{SDK_DIST}"
RC_TAG_RE = re.compile(r"v([0-9]+\.[0-9]+\.[0-9]+)-rc\.([0-9]+)", re.ASCII)
WHEEL_NAME_RE = re.compile(r"[A-Za-z0-9_.+]+-[A-Za-z0-9_.+]+(?:-[0-9][A-Za-z0-9_.]*)?-([a-z0-9_.]+)-([a-z0-9_.]+)-([A-Za-z0-9_.]+)\.whl")
# Mirrors LANGCHAIN_REQUIREMENT in j08-j56-candidate-harness.py: the dependencies its clean venv installs beside the SDK.
SDK_HARNESS_DEPS = ("langchain", "langchain-core>=1.4.9,<1.7.0")
# The harness records --sdk-sha but never uses it to select or verify anything. A wheel downloaded from PyPI has no
# known source commit, so an all-zero value says "unknown" rather than naming a commit it was not built from.
UNKNOWN_SDK_SHA = "0" * 40
PYPI_INDEX = "https://pypi.org/simple"
MAX_METADATA_BYTES = 1 << 20
# The check ids each harness must emit for a PASS. A harness edit that drops a check must not PASS, so the runner
# asks for these by name instead of trusting "every check the report happens to contain passed".
SDK_EXPECTED_CHECKS: dict[str, frozenset[str]] = {
    "J08": frozenset(f"j08-c-{n}" for n in (
        "artifacts-bound-to-candidate", "binary-identity", "readme-snippet-matches-wiring",
        "install-clean-venv-native-core", "register-governed-agent", "allow-deny")),
    "J56": frozenset(f"j56-c-{n}" for n in (
        "artifacts-bound-to-candidate", "binary-identity", "install-clean-venv-native-core", "register-authenticated",
        "allow-read-file", "deny-delete-file-typed-no-sideeffect", "applied-policy-stays-enforced",
        "send-email-approval-or-gap", "audit-correlation", "policy-flip-changes-behavior",
        "unwired-callbacks-control")),
}


def sdk_version_for_tag(tag: str) -> str | None:
    """PEP 440 version of the Python SDK expected to ship in lockstep with an `-rc.N` core tag
    (`v0.0.1-rc.8` -> `0.0.1rc8`). None for any other tag shape: only the rc series has a rule."""
    m = RC_TAG_RE.fullmatch(tag)
    return f"{m.group(1)}rc{m.group(2)}" if m else None


def _wheel_matches_runner(name: str, system: str, machine: str) -> bool:
    m = WHEEL_NAME_RE.fullmatch(name)
    if not m:
        return False
    pytag, abi, plat = m.groups()
    cp = f"cp{sys.version_info.major}{sys.version_info.minor}"
    if not (plat == "any" or pytag == cp or (abi == "abi3" and pytag.startswith("cp"))):
        return False
    if plat == "any":
        return True
    arch = {"x86_64": ("x86_64", "amd64"), "arm64": ("arm64", "aarch64"), "aarch64": ("aarch64", "arm64")}.get(machine, (machine,))
    if system == "Darwin":
        return "macosx" in plat and any(a in plat for a in arch + ("universal2",))
    if system == "Linux":
        return "linux" in plat and any(a in plat for a in arch)
    return False


def _pypi_wheel(p: Probe, tag: str, dest: Path) -> tuple[Result | None, Path | None]:
    """Fetch the published SDK wheel for this runner from PyPI into `dest`. Absent is FAIL, a
    wheel whose bytes do not hash to the digest PyPI itself reports is FAIL, and nothing is
    executed or installed here."""
    ver = sdk_version_for_tag(tag)
    if ver is None:
        return (INCONCLUSIVE, f"no Python SDK version rule for tag {tag!r} (only -rc.N)"), None
    what = f"PyPI {SDK_DIST} {ver}"
    r = p.get(f"{PYPI_JSON}/{ver}/json", {"Accept": "application/json"})
    gate = _http_gate(r, what)
    if gate:
        return gate, None
    try:
        doc = json.loads(r.body)
        got_ver, files = doc["info"]["version"], doc["urls"]
        if not isinstance(files, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        return (INCONCLUSIVE, f"{what} JSON was not parseable"), None
    if got_ver != ver:
        return (FAIL, f"PyPI answered version {got_ver!r}, expected {ver!r}"), None
    files = [f for f in files if isinstance(f, dict)]
    yanked = [f.get("filename") for f in files if f.get("yanked")]
    if yanked:
        return (FAIL, f"{what} has yanked file(s): {yanked}"), None
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel" and isinstance(f.get("filename"), str)]
    if not wheels:
        return (FAIL, f"{what} publishes no wheel"), None
    system, machine = p.tools.platform()
    fit = sorted((f for f in wheels if _wheel_matches_runner(f["filename"], system, machine)), key=lambda f: f["filename"])
    if not fit:
        return (INCONCLUSIVE, f"{what} has no wheel for {system}/{machine} on Python "
                              f"{sys.version_info.major}.{sys.version_info.minor}: {sorted(f['filename'] for f in wheels)}"), None
    pick = fit[0]
    want = (pick.get("digests") or {}).get("sha256")
    if not (isinstance(want, str) and SHA256_RE.fullmatch(want) and isinstance(pick.get("url"), str)):
        return (INCONCLUSIVE, f"{what} file {pick['filename']} lacks a usable sha256 or url"), None
    dl = p.download(pick["url"])
    gate = _http_gate(dl, f"{pick['filename']} download")
    if gate:
        return gate, None
    if hashlib.sha256(dl.body).hexdigest() != want:
        return (FAIL, f"{pick['filename']} bytes hash to {_digest(dl.body)} but PyPI reports sha256:{want}"), None
    try:
        with zipfile.ZipFile(io.BytesIO(dl.body)) as zf:
            metas = [n for n in zf.namelist() if n.count("/") == 1 and n.endswith(".dist-info/METADATA")]
            if len(metas) != 1:
                return (FAIL, f"{pick['filename']} has {len(metas)} dist-info/METADATA files"), None
            if zf.getinfo(metas[0]).file_size > MAX_METADATA_BYTES:
                return (FAIL, f"{pick['filename']} METADATA exceeds {MAX_METADATA_BYTES} bytes"), None
            meta = zf.read(metas[0]).decode("utf-8", "replace")
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        return (FAIL, f"{pick['filename']} is not a readable wheel: {type(e).__name__}"), None
    fields = dict(re.findall(r"^(Name|Version): (.+)$", meta.split("\n\n", 1)[0], re.M))
    if re.sub(r"[-_.]+", "-", fields.get("Name", "")).lower() != SDK_DIST or fields.get("Version", "").strip() != ver:
        return (FAIL, f"{pick['filename']} METADATA says {fields.get('Name')!r} {fields.get('Version')!r}, "
                      f"expected {SDK_DIST!r} {ver!r}"), None
    path = dest / pick["filename"]
    path.write_bytes(dl.body)
    return None, path


def run_sdk_governed_agent(p: Probe, tag: str, journey: str) -> Result:
    """Runs the j08/j56 candidate harness with the wheel published on PyPI and the binaries published
    in the GitHub Release. Executes downloaded code, so it requires the SHA256SUMS signature first and
    runs the harness with a minimal environment in its own process group. The dependency wheels the
    harness's offline venv needs are fetched by `pip download --only-binary=:all:`, which contacts PyPI
    itself (not through Probe, like cosign contacting sigstore) and runs no package code.
    What a PASS covers: every check the harness emits for `journey` passed against the published wheel and
    release binaries. It does NOT cover public-docs discoverability, which no probe here reads.
    Disclosed limitation: the dependency wheels are resolved from pypi.org at run time WITHOUT hash pinning (no
    pinned constraints file exists for them), then installed and imported by the harness. pip runs with no config file,
    no prompts, an explicit pypi.org index, no extra index and binary wheels only (no build scripts run)."""
    shas = p.binding.candidate_shas
    if len(shas) != 1:
        return INCONCLUSIVE, "obligations record no single candidate_sha to hand the harness"
    with tempfile.TemporaryDirectory(prefix=f"ppv-{journey.lower()}-") as tmp:
        house = Path(tmp) / "house"
        house.mkdir()
        err, wheel = _pypi_wheel(p, tag, house)
        if err or wheel is None:
            return err or (INCONCLUSIVE, "no wheel")
        sig = _signature(p, tag)
        if sig[0] != PASS:
            return (FAIL if sig[0] == FAIL else INCONCLUSIVE), f"not running downloaded binaries: signature not verified ({sig[1]})"
        oa = _published_platform(p)
        if oa is None:
            system, machine = p.tools.platform()
            return INCONCLUSIVE, f"no published binaries for runner platform {system}/{machine}"
        err, assets, named, _ = _release_sums(p, tag)
        if err:
            return err
        err, found = _extract_published(p, tag, assets, named, Path(tmp), oa, (
            ("cli", ("aasm", "aa-gateway")), ("api", ("aa-api-server",)), ("runtime", ("aa-runtime",))))
        if err:
            return err
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": tmp, "TMPDIR": tmp,
               "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1", "PIP_CONFIG_FILE": os.devnull}
        rc, _, e = p.tools.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--index-url", PYPI_INDEX,
                                "--dest", str(house), "--find-links", str(house), str(wheel), *SDK_HARNESS_DEPS],
                               600, cwd=tmp, env=env)
        if rc != 0:
            return INCONCLUSIVE, f"could not fetch the SDK's dependency wheels (pip exit {rc}): {e.strip()[-200:]}"
        digests = Path(tmp) / "expected.json"
        expected = {b: "sha256:" + hashlib.sha256(x.read_bytes()).hexdigest() for b, x in found.items()}
        expected["python-sdk-wheel"] = "sha256:" + hashlib.sha256(wheel.read_bytes()).hexdigest()
        digests.write_text(json.dumps(expected))
        harness = REPO_ROOT / "scripts/qa/j08-j56-candidate-harness.py"
        rc, out, err_txt = p.tools.run(
            [sys.executable, "-I", str(harness), "--journey", journey, "--candidate-sha", next(iter(shas)),
             "--version", tag[1:], "--repo", str(REPO_ROOT), "--aasm", str(found["aasm"]),
             "--gateway", str(found["aa-gateway"]), "--runtime", str(found["aa-runtime"]),
             "--api-server", str(found["aa-api-server"]), "--sdk-wheel", str(wheel), "--sdk-sha", UNKNOWN_SDK_SHA,
             "--expected-digests", str(digests)], 1800, cwd=tmp, env=env)
    try:
        report = json.loads(out)
        checks = report["candidate_checks"]
        verdict = report["verdict"]
    except (ValueError, KeyError, TypeError):
        return INCONCLUSIVE, f"{journey} harness produced no parseable report (exit {rc}): {err_txt.strip()[:160]}"
    bad = [c["id"] for c in checks if c.get("status") == FAIL]
    if verdict == "BLOCK" or bad:
        return FAIL, f"{journey} harness against the published SDK wheel and binaries: FAIL {bad}"
    notcov = [c["id"] for c in checks if c.get("status") != PASS]
    missing = sorted(SDK_EXPECTED_CHECKS[journey] - {c.get("id") for c in checks if c.get("status") == PASS})
    if rc == 0 and verdict == "CANDIDATE_VERIFIED" and checks and not notcov and not missing:
        return PASS, (f"every one of {len(checks)} {journey} checks passed (all {len(SDK_EXPECTED_CHECKS[journey])} expected ids "
                      f"present) with the published {wheel.name} and the published {oa} binaries; the SDK's dependency "
                      "wheels were fetched from PyPI without hash pinning and then executed; public-docs discoverability "
                      "was not probed")
    return INCONCLUSIVE, f"{journey} harness exit {rc}, verdict {verdict}; not PASS: {notcov}; expected ids missing: {missing}"


def manual(why: str) -> Callable[[Probe, str], Result]:
    runner: Callable[[Probe, str], Result] = lambda p, tag: (INCONCLUSIVE, f"operator step, no automated probe: {why}")
    # Marked so the rc release gate can tell a probe that can PASS from a stub
    # that always reports INCONCLUSIVE, without re-reading this table by hand.
    runner.is_manual = True  # type: ignore[attr-defined]
    return runner


# The allowlist. Key = pending-check id; the record's `command` text plays no part.
RUNNERS: dict[str, Callable[[Probe, str], Result]] = {
    "j53-ghcr-tag-resolves": lambda p, t: run_tag_resolves(p, "aa-gateway", t),
    "j53-ghcr-digest-immutable": lambda p, t: run_digest_immutable(p, "aa-gateway", t),
    "j53-ghcr-multiarch": lambda p, t: run_multiarch(p, "aa-gateway", t),
    "j53-ghcr-sbom-attestation": lambda p, t: run_sbom(p, "aa-gateway", t),
    "j53-published-image-runs-healthy": _bound(run_image_runs_healthy),
    "j59-ghcr-gateway-image": lambda p, t: run_image_bundle(p, "aa-gateway", t),
    "j59-ghcr-runtime-image": lambda p, t: run_image_bundle(p, "aa-runtime", t),
    "j59-install-release-assets": run_release_assets,
    "j59-published-binaries-golden-path": _bound(run_golden_path),
    "j04.published_release_checksums_and_signature": _bound(run_checksums_and_signature),
    "j04.published_install_sh_default": _bound(run_installer),
    "j17.published_installer_profile_full_gateway": _bound(run_installer),
    "j04.published_latest_resolves_to_candidate": _bound(run_latest_resolves),
    "j04.published_homebrew_tap_install": _bound(lambda p, t: run_homebrew(p, t, "aasm", "aa-gateway")),
    "j04.published_homebrew_runtime": _bound(lambda p, t: run_homebrew(p, t, "aasm-runtime", "aa-runtime")),
    "j17.published_homebrew_gateway": _bound(lambda p, t: run_homebrew(p, t, "aasm", "aa-gateway")),
    "j04.published_crates_io_aa_cli": _bound(lambda p, t: run_crates_io(p, t, "aa-cli")),
    "j17.published_container_image_manifest": _bound(run_images),
    "j08-published-python-sdk-governed-agent": _bound(lambda p, t: run_sdk_governed_agent(p, t, "J08")),
    "j56-published-python-sdk-canonical-11-step": _bound(lambda p, t: run_sdk_governed_agent(p, t, "J56")),
}


def automated_runner_ids() -> frozenset[str]:
    """Ids whose runner can reach PASS, i.e. every RUNNERS key except manual stubs."""
    return frozenset(i for i, r in RUNNERS.items() if not getattr(r, "is_manual", False))


def load_pending(doc: Any) -> list[dict[str, Any]]:
    if not isinstance(doc, dict) or not isinstance(doc.get("journeys"), list):
        raise ValueError("obligations file must be an object with a 'journeys' list")
    out = []
    for j in doc["journeys"]:
        if not isinstance(j, dict) or not isinstance(j.get("journey"), str):
            raise ValueError("obligation entry without a 'journey' id")
        for pc in j.get("pending_checks") or []:
            if not isinstance(pc, dict) or not isinstance(pc.get("id"), str):
                raise ValueError(f"journey {j['journey']} has a pending check without an id")
            out.append({"journey": j["journey"], "id": pc["id"], "failure_response": j.get("failure_response")})
    return out


def verify(pending: list[dict[str, Any]], tag: str, fetch: Fetcher, timeout: float,
           only: set[str] | None = None, tools: Tools | None = None,
           binding: Binding | None = None) -> list[dict[str, Any]]:
    probe = Probe(fetch, timeout, tools, binding)
    results = []
    for pc in pending:
        if only and pc["id"] not in only:
            continue
        runner = RUNNERS.get(pc["id"])
        if runner is None:
            status, detail = INCONCLUSIVE, f"no allowlisted runner for check id {pc['id']!r}"
        else:
            try:
                status, detail = runner(probe, tag)
            except FetchError as e:
                status, detail = INCONCLUSIVE, f"probe could not complete: {e}"
            except Exception as e:  # a runner bug must not read as PASS or abort the rest
                status, detail = INCONCLUSIVE, f"runner error {type(e).__name__}"
        row: dict[str, Any] = {"journey": pc["journey"], "id": pc["id"], "status": status, "detail": detail}
        if status != PASS:
            fr = pc.get("failure_response") or {}
            row["failure_response"] = {
                "pointer": f"{pc['journey']} failure_response in the obligations file",
                "proposed_actions": fr.get("proposed_actions"), "notify": fr.get("notify"),
                "deadline_hours": fr.get("deadline_hours"),
            }
        results.append(row)
    return results


PARTIAL_EXIT = 4

# Only "not there yet" is worth retrying while an asynchronous publish finishes. A body
# that hashes wrong or a missing platform is definitive and must not be retried away.
_NOT_YET_RE = re.compile(r"not found \(404\)|asset .* missing|still a draft")


def retryable(results: list[dict[str, Any]]) -> bool:
    """True when nothing definitive failed: every non-PASS is INCONCLUSIVE or a FAIL that
    only says the artifact is not published yet. All-PASS is not retryable (nothing to retry)."""
    bad = [r for r in results if r["status"] != PASS]
    return bool(bad) and all(
        r["status"] == INCONCLUSIVE or _NOT_YET_RE.search(r["detail"]) for r in bad
    )


def exit_code(results: list[dict[str, Any]], pending_total: int | None = None) -> int:
    """`pending_total` is the number of pending checks in the obligations file; when given and
    larger than the number run, an all-PASS result is a partial run (PARTIAL_EXIT), not 0."""
    if not results:
        return 2
    statuses = {r["status"] for r in results}
    if FAIL in statuses:
        return 1
    if statuses == {PASS}:
        return PARTIAL_EXIT if pending_total is not None and len(results) < pending_total else 0
    return 3


def main(argv: list[str], fetch: Fetcher = urllib_fetcher, tools: Tools | None = None) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--obligations", required=True)
    ap.add_argument("--only", action="append",
                    help="restrict to this pending-check id (repeatable); if the selected checks pass but "
                         "other pending checks were not run, the run is PARTIAL and exits 4, not 0 (so a "
                         "single-check run exits 4 even when it passes; its PASS is in the JSON "
                         "results). An id naming no pending check is an error (exit 2)")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds per probe request")
    args = ap.parse_args(argv)
    if not TAG_RE.fullmatch(args.tag):
        print(f"invalid --tag {args.tag!r}", file=sys.stderr)
        return 2
    try:
        raw = Path(args.obligations).read_bytes()
        doc = json.loads(raw)
        pending = load_pending(doc)
    except (OSError, ValueError) as e:
        print(f"cannot read obligations: {e}", file=sys.stderr)
        return 2
    only = set(args.only) if args.only else None
    unknown = sorted(only - {pc["id"] for pc in pending}) if only else []
    if unknown:
        print(f"unknown --only check id(s) not in the obligations file: {', '.join(unknown)}", file=sys.stderr)
        return 2
    results = verify(pending, args.tag, fetch, args.timeout, only, tools, binding_from(doc))
    code = exit_code(results, len(pending))
    ran = {r["id"] for r in results}
    not_run = [pc["id"] for pc in pending if pc["id"] not in ran]
    if not_run and results:
        print(f"PARTIAL: {len(results)} of {len(pending)} pending checks run; "
              f"not run: {', '.join(not_run)}", file=sys.stderr)
    print(json.dumps({
        "schema": "post-publish-verify/1", "tag": args.tag,
        "obligations_sha256": _digest(raw), "exit_code": code,
        "partial": {"run": len(results), "pending": len(pending), "not_run": not_run} if not_run else None,
        "summary": {s: sum(1 for r in results if r["status"] == s) for s in (PASS, FAIL, INCONCLUSIVE)},
        "retryable": retryable(results),
        "results": results,
    }, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
