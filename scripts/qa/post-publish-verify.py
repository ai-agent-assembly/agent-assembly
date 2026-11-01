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
* Every probe is an HTTPS GET to an allowlisted host (ghcr.io, api.github.com) with a
  per-request timeout. Nothing is published, yanked, tagged, pushed or written to a
  registry, and nothing is pulled into a local Docker store.
* FAIL means positive evidence the publication is wrong (a 404 for the tag, a body that
  does not hash to its digest, a missing platform). A timeout, a 5xx, a rate limit or
  an auth refusal is INCONCLUSIVE: "could not tell" is not "wrong" and not "right".
* Exit 0 only when at least one check ran and every check is PASS. 1 if any FAIL,
  3 if some are INCONCLUSIVE and none FAIL, 2 for a usage or malformed-record error.

Check-id convention (so other journeys can add runners): `<journey>-<channel>-<what>`,
e.g. `j53-ghcr-multiarch`. A journey that owes a check names its id in its obligation
and a runner is added here; until then the check stays INCONCLUSIVE.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"
ALLOWED_HOSTS = {"ghcr.io", "api.github.com"}
# Hosts a GitHub release-asset download legitimately redirects to. Only `Probe.download`
# may follow a redirect, and only to these; no probe ever forwards Authorization on one.
DOWNLOAD_HOSTS = {"objects.githubusercontent.com", "release-assets.githubusercontent.com"}
MAX_REDIRECTS = 3
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
            return Response(r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(32 << 20))
    except urllib.error.HTTPError as e:
        return Response(e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(1 << 20))
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise FetchError(type(e).__name__) from e


class Probe:
    """Vets every URL, owns the per-probe timeout and the anonymous GHCR token."""

    def __init__(self, fetch: Fetcher, timeout: float):
        self._fetch, self.timeout = fetch, timeout
        self._tokens: dict[str, str] = {}

    def get(self, url: str, headers: dict[str, str] | None = None) -> Response:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
            raise FetchError(f"refused non-allowlisted url {u.scheme}://{u.hostname}")
        return self._fetch(url, dict(headers or {}), self.timeout)

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


def manual(why: str) -> Callable[[Probe, str], Result]:
    return lambda p, tag: (INCONCLUSIVE, f"operator step, no automated probe: {why}")


# The allowlist. Key = pending-check id; the record's `command` text plays no part.
RUNNERS: dict[str, Callable[[Probe, str], Result]] = {
    "j53-ghcr-tag-resolves": lambda p, t: run_tag_resolves(p, "aa-gateway", t),
    "j53-ghcr-digest-immutable": lambda p, t: run_digest_immutable(p, "aa-gateway", t),
    "j53-ghcr-multiarch": lambda p, t: run_multiarch(p, "aa-gateway", t),
    "j53-ghcr-sbom-attestation": lambda p, t: run_sbom(p, "aa-gateway", t),
    "j53-published-image-runs-healthy": manual("run the pulled image and probe grpc.health.v1; it writes local Docker state"),
    "j59-ghcr-gateway-image": lambda p, t: run_image_bundle(p, "aa-gateway", t),
    "j59-ghcr-runtime-image": lambda p, t: run_image_bundle(p, "aa-runtime", t),
    "j59-install-release-assets": run_release_assets,
    "j59-published-binaries-golden-path": manual("download, verify against SHA256SUMS and re-run scripts/qa/j59-candidate-harness.py on the extracted binaries"),
}


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
           only: set[str] | None = None) -> list[dict[str, Any]]:
    probe = Probe(fetch, timeout)
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


def exit_code(results: list[dict[str, Any]]) -> int:
    if not results:
        return 2
    statuses = {r["status"] for r in results}
    if FAIL in statuses:
        return 1
    if statuses == {PASS}:
        return 0
    return 3


def main(argv: list[str], fetch: Fetcher = urllib_fetcher) -> int:
    ap = argparse.ArgumentParser(allow_abbrev=False, description=__doc__.split("\n")[0])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--obligations", required=True)
    ap.add_argument("--only", action="append", help="restrict to this pending-check id (repeatable)")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds per probe request")
    args = ap.parse_args(argv)
    if not TAG_RE.fullmatch(args.tag):
        print(f"invalid --tag {args.tag!r}", file=sys.stderr)
        return 2
    try:
        raw = Path(args.obligations).read_bytes()
        pending = load_pending(json.loads(raw))
    except (OSError, ValueError) as e:
        print(f"cannot read obligations: {e}", file=sys.stderr)
        return 2
    results = verify(pending, args.tag, fetch, args.timeout, set(args.only) if args.only else None)
    code = exit_code(results)
    print(json.dumps({
        "schema": "post-publish-verify/1", "tag": args.tag,
        "obligations_sha256": _digest(raw), "exit_code": code,
        "summary": {s: sum(1 for r in results if r["status"] == s) for s in (PASS, FAIL, INCONCLUSIVE)},
        "results": results,
    }, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
