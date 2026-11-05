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
  raw.githubusercontent.com, crates.io) with a per-request timeout. Nothing is published,
  yanked, tagged, pushed or written to a registry. Local programs run only through the
  `Tools` seam, as argv lists (no shell): `cosign verify-blob` (INCONCLUSIVE when cosign is
  absent), the j59 harness on binaries verified against SHA256SUMS, and, for
  j53-published-image-runs-healthy only, `docker run` of the digest-pinned aa-gateway image
  (INCONCLUSIVE when docker is absent; the container is always removed). The installer
  script is fetched and hashed but never executed.
* FAIL means positive evidence the publication is wrong (a 404 for the tag, a body that
  does not hash to its digest, a missing platform). A timeout, a 5xx, a rate limit or
  an auth refusal is INCONCLUSIVE: "could not tell" is not "wrong" and not "right".
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
import json
import os
import platform as _platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
# raw.githubusercontent.com serves scripts/install-cli.sh at the tag; crates.io serves the
# read-only /api/v1/crates/<name>/<version> JSON. Membership is exact hostname equality, so
# `crates.io.evil.example` and `evilcrates.io` are refused.
ALLOWED_HOSTS = {"ghcr.io", "api.github.com", "raw.githubusercontent.com", "crates.io"}
# Hosts a GitHub release-asset download legitimately redirects to. Only `Probe.download`
# may follow a redirect, and only to these; no probe ever forwards Authorization on one.
DOWNLOAD_HOSTS = {"objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_REDIRECTS = 3
MAX_BODY = 256 << 20
USER_AGENT = "aa-post-publish-verify"
TAG_RE = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?")
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


def urllib_fetcher(url: str, headers: dict[str, str], timeout: float) -> Response:
    """The only network code in this file: one GET, never following a redirect."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _OPENER.open(req, timeout=timeout) as r:  # noqa: S310 - scheme and host vetted by Probe
            body = r.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:  # a silently truncated tarball would read as a digest mismatch
                raise FetchError("response body exceeds the size cap")
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, body)
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1 << 20))
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise FetchError(type(e).__name__) from e


class Probe:
    """Vets every URL, owns the per-probe timeout and the anonymous GHCR token."""

    def __init__(self, fetch: Fetcher, timeout: float, tools: "Tools | None" = None,
                 installer_sha256: str | None = None):
        self._fetch, self.timeout = fetch, timeout
        self.tools = tools or Tools()
        self.installer_sha256 = installer_sha256
        self._tokens: dict[str, str] = {}

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise FetchError(f"refused non-allowlisted url {u.scheme}://{u.hostname}")
        return self._fetch(url, {"User-Agent": USER_AGENT, **(headers or {})}, self.timeout)

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
    if claimed != computed:
        return (FAIL, f"{image}:{tag} body hashes to {computed} but Docker-Content-Digest is {claimed!r}"), None, None
    return None, r, computed


def run_tag_resolves(p: Probe, image: str, tag: str) -> Result:
    err, _, digest = resolve_tag(p, image, tag)
    return err or (PASS, f"{image}:{tag} resolves to {digest} and the body hashes to it")


def run_digest_immutable(p: Probe, image: str, tag: str) -> Result:
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
    return PASS, f"{image}:{tag} resolves, is digest-immutable and multi-arch"


SUMS_LINE = re.compile(r"([0-9a-f]{64})\s+\*?(\S+)")


def run_release_assets(p: Probe, tag: str) -> Result:
    r = p.get(f"https://api.github.com/repos/{GH_REPO}/releases/tags/{urllib.parse.quote(tag)}",
              {"Accept": "application/vnd.github+json"})
    gate = _http_gate(r, f"GitHub Release {tag}")
    if gate:
        return gate
    try:
        rel = json.loads(r.body)
        assets = {a["name"]: a for a in rel.get("assets", [])}
    except (ValueError, KeyError, TypeError):
        return INCONCLUSIVE, "release JSON was not parseable"
    problems = []
    if rel.get("draft"):
        problems.append("release is still a draft")
    if "SHA256SUMS" not in assets:
        return FAIL, "; ".join(problems + ["asset SHA256SUMS missing"])
    sums_url = assets["SHA256SUMS"].get("url")
    if not isinstance(sums_url, str):
        return INCONCLUSIVE, "SHA256SUMS asset has no API url"
    dl = p.download(sums_url, {"Accept": "application/octet-stream"})
    gate = _http_gate(dl, "SHA256SUMS download")
    if gate:
        return gate
    named: dict[str, str] = {}
    for line in dl.body.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        m = SUMS_LINE.fullmatch(line.strip())
        if not m:
            problems.append(f"malformed SHA256SUMS line {line.strip()[:60]!r}")
        else:
            named[m.group(2)] = m.group(1)
    if not named:
        problems.append("SHA256SUMS names no files")
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
    library has no HTTP/2 client). Returns "SERVING" or "STATUS_<n>"; raises FetchError when no
    gRPC message came back."""
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
        s.settimeout(timeout)
        s.sendall(request)
        buf = b""
        while True:
            while len(buf) < 9:
                chunk = s.recv(4096)
                if not chunk:
                    return parse_health_response(data)
                buf += chunk
            length, kind, flags = int.from_bytes(buf[:3], "big"), buf[3], buf[4]
            sid = int.from_bytes(buf[5:9], "big") & 0x7FFFFFFF
            while len(buf) < 9 + length:
                chunk = s.recv(4096)
                if not chunk:
                    return parse_health_response(data)
                buf += chunk
            payload, buf = buf[9:9 + length], buf[9 + length:]
            if kind == 4 and not flags & 1:
                s.sendall(frame(4, 1, 0, b""))
            elif kind == 0 and sid == 1:
                data += payload
            if kind in (7, 3) or (sid == 1 and flags & 1 and kind in (0, 1)):
                return parse_health_response(data)


def parse_health_response(data: bytes) -> str:
    if len(data) < 5 or data[0] != 0:
        raise FetchError("no gRPC message in the health response")
    n = int.from_bytes(data[1:5], "big")
    msg = data[5:5 + n]
    if len(msg) != n or n < 2 or msg[0] != 0x08:
        raise FetchError("malformed HealthCheckResponse")
    return "SERVING" if msg[1] == 1 else f"STATUS_{msg[1]}"


class Tools:
    """Real local-program access. Every method is overridden by a fake in tests."""

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, argv: list[str], timeout: float, cwd: str | None = None,
            env: dict[str, str] | None = None) -> tuple[int, str, str]:
        """argv list only, never a shell. A timeout is a FetchError (could not tell)."""
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env,
                               check=False, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired as e:
            raise FetchError(f"{Path(argv[0]).name} timed out after {timeout:.0f}s") from e
        except OSError as e:
            raise FetchError(f"cannot execute {Path(argv[0]).name}: {type(e).__name__}") from e
        return r.returncode, r.stdout, r.stderr

    def grpc_health(self, host: str, port: int, timeout: float) -> str:
        try:
            return grpc_health_check(host, port, timeout)
        except OSError as e:
            raise FetchError(type(e).__name__) from e

    def platform(self) -> tuple[str, str]:
        return _platform.system(), _platform.machine()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


# --- published-state runners (AAASM-6424) ------------------------------------------------
RELEASE_API = f"https://api.github.com/repos/{GH_REPO}"
TAP_API = "https://api.github.com/repos/ai-agent-assembly/homebrew-tap"
INSTALLER_PATH = "scripts/install-cli.sh"
SIGNING_ISSUER = "https://token.actions.githubusercontent.com"
RAW_ACCEPT = "application/vnd.github.raw+json"
REPO_ROOT = Path(__file__).resolve().parents[2]
HEALTH_ATTEMPTS, HEALTH_INTERVAL = 30, 2.0


def _release(p: Probe, tag: str) -> tuple[Result | None, dict[str, dict[str, Any]]]:
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
        if line.strip():
            m = SUMS_LINE.fullmatch(line.strip())
            if m:
                named[m.group(2)] = m.group(1)
            else:
                bad.append(f"malformed SHA256SUMS line {line.strip()[:60]!r}")
    return named, bad


def _release_sums(p: Probe, tag: str) -> tuple[Result | None, dict[str, dict[str, Any]], dict[str, str], bytes]:
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


def run_checksums_and_signature(p: Probe, tag: str) -> Result:
    err, assets, named, sums = _release_sums(p, tag)
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
    err, bundle = _asset(p, assets, "SHA256SUMS.cosign.bundle")
    if err:
        problems.append(err[1])
    else:
        try:
            if not isinstance(json.loads(bundle), dict):
                raise ValueError
        except ValueError:
            problems.append("SHA256SUMS.cosign.bundle is not a JSON object")
    if problems:
        return FAIL, "; ".join(problems)
    cosign = p.tools.which("cosign")
    if cosign is None:
        return INCONCLUSIVE, ("checksums consistent and the cosign bundle is present, but the cosign binary is not "
                              "on PATH so the signature was NOT verified")
    with tempfile.TemporaryDirectory(prefix="ppv-cosign-") as d:
        (Path(d) / "SHA256SUMS").write_bytes(sums)
        (Path(d) / "SHA256SUMS.cosign.bundle").write_bytes(bundle)
        rc, _, err_txt = p.tools.run(
            [cosign, "verify-blob", "--bundle", "SHA256SUMS.cosign.bundle", "--certificate-identity-regexp",
             f"^https://github.com/{GH_REPO}/\\.github/workflows/release\\.yml@refs/tags/{re.escape(tag)}$",
             "--certificate-oidc-issuer", SIGNING_ISSUER, "SHA256SUMS"], 120, cwd=d)
    if rc != 0:
        return FAIL, f"cosign verify-blob failed (exit {rc}): {err_txt.strip()[:200]}"
    return PASS, (f"cosign verify-blob accepted SHA256SUMS for release.yml at {tag}; {len(named)} listed files are "
                  f"uploaded assets; {compared} release-API digests equal SHA256SUMS")


def _expected_installer_sha(p: Probe) -> str | None:
    if p.installer_sha256:
        return p.installer_sha256
    local = REPO_ROOT / INSTALLER_PATH
    return hashlib.sha256(local.read_bytes()).hexdigest() if local.is_file() else None


def _installer(p: Probe, tag: str) -> tuple[Result | None, str]:
    expected = _expected_installer_sha(p)
    if expected is None:
        return (INCONCLUSIVE, "no committed installer digest to compare with"), ""
    r = p.get(f"https://raw.githubusercontent.com/{GH_REPO}/{urllib.parse.quote(tag)}/{INSTALLER_PATH}")
    gate = _http_gate(r, f"{INSTALLER_PATH} at {tag}")
    if gate:
        return gate, ""
    if not r.body:
        return (FAIL, f"{INSTALLER_PATH} at {tag} is empty"), ""
    got = hashlib.sha256(r.body).hexdigest()
    if got != expected:
        return (FAIL, f"{INSTALLER_PATH} at {tag} hashes to {got}, committed digest is {expected}"), ""
    return None, r.body.decode("utf-8", "replace")


def run_installer(p: Probe, tag: str, needs: tuple[str, ...]) -> Result:
    """Installer content and the release it installs from. It is NOT executed here: the script
    would write outside the temp tree if it misbehaved, so execution stays an operator step."""
    err, text = _installer(p, tag)
    if err:
        return err
    missing = [n for n in needs if n not in text]
    if missing:
        return FAIL, f"installer at {tag} does not mention {missing}"
    res = run_release_assets(p, tag)
    if res[0] != PASS:
        return res
    return PASS, (f"{INSTALLER_PATH} at {tag} equals the committed digest and mentions {list(needs)}; "
                  f"release assets complete; the installer was not executed")


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
    hdr = {"Accept": "application/vnd.github+json"}
    err, top = _tag_name(p.get(f"{RELEASE_API}/releases?per_page=1", hdr), "newest release")
    if err:
        return err
    if top != tag:
        return FAIL, f"newest release is {top!r}, not {tag}"
    r = p.get(f"{RELEASE_API}/releases/latest", hdr)
    if r.status == 404:  # every release is a pre-release: the installer falls back to per_page=1
        return PASS, f"newest release is {tag}; /releases/latest is 404 so the installer falls back to it"
    err, latest = _tag_name(r, "/releases/latest")
    if err:
        return err
    if latest != tag:
        return FAIL, f"an unpinned install resolves to {latest!r}, not {tag}"
    return PASS, f"newest release and /releases/latest are both {tag}"


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
    pairs, pending_url = [], None
    for line in text.splitlines():
        if um := URL_LINE.match(line):
            pending_url = um.group(1)
        elif (sm := SHA_LINE.match(line)) and pending_url is not None:
            pairs.append((pending_url, sm.group(1)))
            pending_url = None
    if not pairs:
        return FAIL, f"Formula/{formula}.rb has no url/sha256 pair"
    problems = []
    for url, sha in pairs:
        base = url.rsplit("/", 1)[-1]
        if base not in named:
            problems.append(f"formula url {base} is not named in SHA256SUMS")
        elif named[base] != sha:
            problems.append(f"{base}: formula sha256 {sha} != SHA256SUMS {named[base]}")
        if "#{" not in url and tag not in url and version not in url:
            problems.append(f"{base}: url does not name {tag}")
    return (FAIL, "; ".join(problems)) if problems else (
        PASS, f"tap VERSION is {version} and all {len(pairs)} Formula/{formula}.rb sha256 values equal SHA256SUMS")


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
    return PASS, f"aa-runtime and aa-gateway {tag} resolve, are digest-immutable and multi-arch"


def run_image_runs_healthy(p: Probe, tag: str) -> Result:
    """Runs the digest-pinned aa-gateway image. Never PASSes unless the container really ran,
    answered SERVING and stopped with exit 0 on SIGTERM; the container is always removed."""
    docker = p.tools.which("docker")
    if docker is None:
        return INCONCLUSIVE, "docker is not on PATH; the published image was not run"
    err, _, digest = resolve_tag(p, "aa-gateway", tag)
    if err:
        return err
    ref = f"ghcr.io/{GHCR_NAMESPACE}/aa-gateway@{digest}"
    name = f"aa-ppv-{os.getpid()}-{int(time.time())}"
    t = p.tools

    def dk(*a: str, timeout: float = 120) -> tuple[int, str, str]:
        return t.run([docker, *a], timeout)

    try:
        rc, _, e = dk("run", "-d", "--name", name, "-p", "127.0.0.1::50051", ref,
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
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            if not (m.isreg() or m.isdir()) or dest.resolve() not in (target, *target.parents):
                raise tarfile.TarError(f"unsafe tar member {m.name!r}")
        tf.extractall(dest)  # noqa: S202 - members vetted above (regular files and dirs under dest only)


def _find_one(root: Path, name: str) -> Path | None:
    hits = [x for x in root.rglob(name) if x.is_file()]
    return hits[0] if len(hits) == 1 else None


def run_golden_path(p: Probe, tag: str) -> Result:
    system, machine = p.tools.platform()
    oa = {("Linux", "x86_64"): "linux-amd64", ("Linux", "aarch64"): "linux-arm64", ("Linux", "arm64"): "linux-arm64",
          ("Darwin", "arm64"): "darwin-arm64", ("Darwin", "x86_64"): "darwin-amd64"}.get((system, machine))
    if oa is None:
        return INCONCLUSIVE, f"no published binaries for runner platform {system}/{machine}"
    err, assets, named, _ = _release_sums(p, tag)
    if err:
        return err
    r = p.get(f"{RELEASE_API}/commits/{urllib.parse.quote(tag)}", {"Accept": "application/vnd.github+json"})
    gate = _http_gate(r, f"commit of {tag}")
    if gate:
        return gate
    try:
        sha = json.loads(r.body)["sha"]
    except (ValueError, KeyError, TypeError):
        return INCONCLUSIVE, "commit JSON was not parseable"
    harness = REPO_ROOT / "scripts/qa/j59-candidate-harness.py"
    with tempfile.TemporaryDirectory(prefix="ppv-j59-") as tmp:
        found: dict[str, Path] = {}
        for comp, binary in (("cli", "aasm"), ("api", "aa-api-server")):
            name = f"aasm-{comp}-{tag}-{oa}.tar.gz"
            err, body = _asset(p, assets, name)
            if err:
                return err
            if name not in named:
                return FAIL, f"SHA256SUMS does not name {name}"
            if hashlib.sha256(body).hexdigest() != named[name]:
                return FAIL, f"{name} does not match SHA256SUMS"
            arc, dest = Path(tmp) / name, Path(tmp) / comp
            arc.write_bytes(body)
            dest.mkdir()
            try:
                _safe_extract(arc, dest)
            except (tarfile.TarError, OSError) as e:
                return FAIL, f"{name} is not a readable tarball: {type(e).__name__}"
            exe = _find_one(dest, binary)
            if exe is None:
                return FAIL, f"{name} does not contain exactly one {binary}"
            exe.chmod(0o755)
            found[binary] = exe
        digests = Path(tmp) / "expected.json"
        digests.write_text(json.dumps({b: "sha256:" + hashlib.sha256(x.read_bytes()).hexdigest() for b, x in found.items()}))
        rc, out, err_txt = p.tools.run(
            [sys.executable, "-I", str(harness), "--candidate-sha", sha, "--expected-version", tag[1:],
             "--repo", str(REPO_ROOT), "--aasm-bin", str(found["aasm"]), "--api-server-bin", str(found["aa-api-server"]),
             "--expected-digests", str(digests)], 900, cwd=tmp)
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
    "j53-published-image-runs-healthy": run_image_runs_healthy,
    "j59-ghcr-gateway-image": lambda p, t: run_image_bundle(p, "aa-gateway", t),
    "j59-ghcr-runtime-image": lambda p, t: run_image_bundle(p, "aa-runtime", t),
    "j59-install-release-assets": run_release_assets,
    "j59-published-binaries-golden-path": run_golden_path,
    "j04.published_release_checksums_and_signature": run_checksums_and_signature,
    "j04.published_install_sh_default": lambda p, t: run_installer(p, t, ("--version",)),
    "j17.published_installer_profile_full_gateway": lambda p, t: run_installer(p, t, ("--profile", "full")),
    "j04.published_latest_resolves_to_candidate": run_latest_resolves,
    "j04.published_homebrew_tap_install": lambda p, t: run_homebrew(p, t, "aasm", "aa-gateway"),
    "j04.published_homebrew_runtime": lambda p, t: run_homebrew(p, t, "aasm-runtime", "aa-runtime"),
    "j17.published_homebrew_gateway": lambda p, t: run_homebrew(p, t, "aasm", "aa-gateway"),
    "j04.published_crates_io_aa_cli": lambda p, t: run_crates_io(p, t, "aa-cli"),
    "j17.published_container_image_manifest": run_images,
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
           installer_sha256: str | None = None) -> list[dict[str, Any]]:
    probe = Probe(fetch, timeout, tools, installer_sha256)
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


INSTALLER_SHA_RE = re.compile(r"[0-9a-f]{64}")


def installer_sha_from(doc: Any) -> str | None:
    """Optional `installer_sha256` on a journey entry: the digest the candidate recorded for
    scripts/install-cli.sh. Absent, the runner falls back to the checkout's own copy."""
    for j in doc.get("journeys", []):
        v = j.get("installer_sha256") if isinstance(j, dict) else None
        if isinstance(v, str) and INSTALLER_SHA_RE.fullmatch(v):
            return v
    return None


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
    results = verify(pending, args.tag, fetch, args.timeout, only, tools, installer_sha_from(doc))
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
        "results": results,
    }, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
