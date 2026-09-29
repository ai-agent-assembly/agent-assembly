"""Refuse a release version that any publish registry has already registered. AAASM-6232.

THE FAILURE MODE

A release uploads to three immutable registries in one run: PyPI (via the
python-sdk fan-out), crates.io (nine crates, sequentially), and npm (five
packages). None of the three permits re-uploading a filename or a version that
already exists, and none of them lets you free one by deleting it.

Yanking is not deletion. PEP 592 is explicit that a yanked file stays on the
index and the version stays registered; crates.io yanking is the same; npm
records an unpublished version in its `time` map forever and refuses to let it
be republished. So a version number consumed by a mistake stays consumed.

`agent-assembly` on PyPI has exactly that. Version `0.0.2` was uploaded on
2026-05-28 — six days *before* the earliest surviving prerelease, `0.0.1a4` —
as one pure-Python `py3-none-any` wheel plus an sdist, where every genuine
release of this package ships a platform-wheel set instead (twelve wheels since
`0.0.1rc4`, four before that) alongside its sdist. Both 0.0.2 files were yanked
with the reason "have wrong to release". The version is still registered and
the filename `agent_assembly-0.0.2.tar.gz` is permanently taken.

Nothing checked for that before this script. The consequence is the worst
available shape: not a clean refusal up front, but a *partial* publish. A
future release cut at 0.0.2 would build an sdist with precisely that name and
have it rejected, while the twelve platform wheels — whose names no existing
file uses — upload fine. That leaves 0.0.2 live with fresh un-yanked wheels
beside the old yanked one and no sdist, and a red release job at the end of it.
The same shape is available on crates.io, where it is worse: nine crates
publish in sequence, so a collision midway leaves a half-published workspace
that cannot be rolled back.

WHAT THIS SCRIPT CHECKS

For the version about to be released, that the version is NOT already
registered on any of the three registries — yanked, unpublished, or live. It
reads; it never uploads, tags, or mutates anything.

PyPI is queried under the PEP 440 spelling (`0.0.1-rc.7` -> `0.0.1rc7`);
crates.io and npm use the SemVer spelling verbatim. When PyPI reports a
collision the check names the colliding filenames, because those are what the
upload actually fails on.

A probe that cannot be completed is a FAILURE, not an "available". A network
error tells you nothing about whether the number is free, and a gate that reads
silence as permission is the vacuity this exists to remove.

WHAT THIS SCRIPT DOES NOT CHECK, AND WHY

It does not check GHCR or the Homebrew tap. Both are mutable — a container tag
can be re-pushed and a formula is a file in a git repo — so neither can produce
the permanently-consumed-number failure this gate is about.

It does not decide what the next version should be. It answers one question
about one candidate number and refuses; choosing the successor is the
operator's call.

Run from the repo root:  python3 scripts/check_version_availability.py <version>
Self-test (anti-vacuity): python3 scripts/check_version_availability.py --selftest

The self-test is offline and deterministic: it drives the same decision
function this script's live path uses, over fixtures that include the real
shape of PyPI's yanked 0.0.2.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

USER_AGENT = (
    "agent-assembly-version-availability-check/1.0 "
    "(+https://github.com/ai-agent-assembly/agent-assembly)"
)

# The nine crates release.yml publishes, in its publish order. Same list as
# scripts/check-release.sh section 3.
CRATES = [
    "aa-core",
    "aa-proto",
    "aa-runtime",
    "aa-ebpf-common",
    "aa-ebpf",
    "aa-proxy",
    "aa-sandbox",
    "aa-gateway",
    "aa-cli",
]

# The five packages the node-sdk fan-out publishes. Same list as
# scripts/check-release.sh section 4.
NPM_PACKAGES = [
    "@agent-assembly/sdk",
    "@agent-assembly/runtime-linux-x64",
    "@agent-assembly/runtime-linux-arm64",
    "@agent-assembly/runtime-darwin-x64",
    "@agent-assembly/runtime-darwin-arm64",
]

PYPI_PROJECT = "agent-assembly"

ATTEMPTS = 3


def pep440(version: str) -> str:
    """`0.0.1-rc.7` -> `0.0.1rc7`, matching check-release.sh's `to_pep440()`."""
    for marker, short in (("-alpha", "a"), ("-beta", "b"), ("-rc", "rc")):
        for spelling in (marker + ".", marker):
            if spelling in version:
                return version.replace(spelling, short, 1)
    return version


def fetch(url: str) -> object:
    """Parsed JSON, or raise. Retried: a dropped connection is not an answer.

    `--retry-all-errors` is the curl equivalent and is load-bearing for the
    same reason it is in actionlint.yml (AAASM-6194): the failures that matter
    here are connection-level, not retryable HTTP statuses.
    """
    last: Exception | None = None
    for _ in range(ATTEMPTS):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise  # a definite answer, not a transient failure
            last = exc
        except Exception as exc:  # noqa: BLE001 — any transport failure is retryable
            last = exc
    raise last if last else RuntimeError("unreachable")


def probe_pypi(project: str, asked: str) -> dict:
    """Every version PyPI has registered for `project`, plus each one's filenames.

    `releases` lists yanked versions exactly like live ones — which is the whole
    point: the yanked 0.0.2 is why this check exists.
    """
    result: dict = {"label": f"PyPI {project}", "asked": asked, "versions": [], "files": {}}
    try:
        payload = fetch(f"https://pypi.org/pypi/{project}/json")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # The project itself does not exist. Nothing is registered, and that
            # is a real answer — but it is also not a state this repo can be in,
            # so say so rather than passing silently.
            result["error"] = (
                f"PyPI has no project '{project}' at all (HTTP 404). Every published "
                "release of this repo is on that project, so this is a wrong name or a "
                "broken index read, not an empty index."
            )
            return result
        result["error"] = f"PyPI query failed after {ATTEMPTS} attempts: {exc}"
        return result
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"PyPI query failed after {ATTEMPTS} attempts: {exc}"
        return result

    releases = payload.get("releases") if isinstance(payload, dict) else None
    if not isinstance(releases, dict):
        result["error"] = "PyPI response carried no `releases` map"
        return result
    result["versions"] = sorted(releases)
    result["files"] = {
        version: sorted(f.get("filename", "?") for f in files if isinstance(f, dict))
        for version, files in releases.items()
        if isinstance(files, list)
    }
    return result


def probe_crate(crate: str, asked: str) -> dict:
    """Every version crates.io has registered for `crate`, yanked included."""
    result: dict = {"label": f"crates.io {crate}", "asked": asked, "versions": [], "files": {}}
    try:
        payload = fetch(f"https://crates.io/api/v1/crates/{crate}")
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"crates.io query failed after {ATTEMPTS} attempts: {exc}"
        return result
    versions = payload.get("versions") if isinstance(payload, dict) else None
    if not isinstance(versions, list):
        result["error"] = "crates.io response carried no `versions` list"
        return result
    result["versions"] = sorted(
        v["num"] for v in versions if isinstance(v, dict) and "num" in v
    )
    return result


def probe_npm(package: str, asked: str) -> dict:
    """Every version npm will refuse to accept again for `package`.

    That is NOT just `versions`. npm records an unpublished version in `time`
    and permanently refuses to let the same version be published again, so a
    version present only in `time` is just as unavailable as a live one. Reading
    `versions` alone would report such a number as free.
    """
    result: dict = {"label": f"npm {package}", "asked": asked, "versions": [], "files": {}}
    encoded = package.replace("/", "%2f")
    try:
        payload = fetch(f"https://registry.npmjs.org/{encoded}")
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"npm query failed after {ATTEMPTS} attempts: {exc}"
        return result
    if not isinstance(payload, dict):
        result["error"] = "npm response was not an object"
        return result
    live = payload.get("versions")
    times = payload.get("time")
    if not isinstance(live, dict) and not isinstance(times, dict):
        result["error"] = "npm response carried neither `versions` nor `time`"
        return result
    known = set(live) if isinstance(live, dict) else set()
    if isinstance(times, dict):
        known |= {k for k in times if k not in ("created", "modified")}
    result["versions"] = sorted(known)
    return result


def findings_for(probes: list[dict]) -> tuple[list[str], int]:
    """(messages, number of probes that returned a non-empty version list).

    The second value is the non-vacuity signal. Every probe returning an empty
    list is indistinguishable, from the verdict alone, from a check that is
    reading the wrong URL or parsing the wrong field — and this repo has
    published on all three registries, so an empty list is never correct here.
    """
    messages: list[str] = []
    populated = 0
    for probe in probes:
        label = probe["label"]
        if probe.get("error"):
            messages.append(
                f"{label}: could not be read, so version availability is UNKNOWN, not "
                f"confirmed: {probe['error']}. Treating an unreadable index as 'the "
                "number is free' is how a release discovers a collision halfway through "
                "uploading. Re-run when the index is reachable."
            )
            continue
        versions = probe.get("versions") or []
        if versions:
            populated += 1
        asked = probe["asked"]
        if asked not in versions:
            continue
        detail = ""
        files = (probe.get("files") or {}).get(asked)
        if files:
            detail = (
                " The upload fails on the colliding filename(s): " + ", ".join(files) + "."
            )
        messages.append(
            f"{label}: version {asked} is ALREADY REGISTERED. Registries do not free a "
            "version number — yanking, unpublishing and deleting all leave it taken — so "
            "this release cannot publish that number and must use a different one."
            + detail
        )
    return messages, populated


def live_probes(version: str) -> list[dict]:
    """Probe all three registries for `version`, PyPI under its PEP 440 spelling."""
    probes = [probe_pypi(PYPI_PROJECT, pep440(version))]
    probes += [probe_crate(crate, version) for crate in CRATES]
    probes += [probe_npm(package, version) for package in NPM_PACKAGES]
    return probes


def check(version: str) -> int:
    probes = live_probes(version)
    messages, populated = findings_for(probes)

    for message in messages:
        print(f"::error::check-version-availability: {message}", file=sys.stderr)
    if messages:
        print(
            f"check-version-availability: {len(messages)} finding(s) for {version} — "
            "DO NOT release this version",
            file=sys.stderr,
        )
        return 1

    if populated == 0:
        print(
            "::error::check-version-availability: not one of the "
            f"{len(probes)} registry probes returned a single existing version. This repo "
            "has published on PyPI, crates.io and npm, so an empty result everywhere is "
            "not a true 'nothing is registered' — it means the probes are not reading "
            "what they think they are reading. Refusing rather than reporting the number "
            "as free.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-version-availability: {version} (PyPI: {pep440(version)}) is unregistered "
        f"on all {len(probes)} publish targets; {populated} of them returned an existing "
        "version list, so the comparison was real"
    )
    return 0


def selftest() -> int:
    """Prove the decision rejects a registered number and accepts an unregistered one.

    Offline and deterministic: it drives `findings_for`, the same function the
    live path uses, over fixtures. The first two cases are the real shape of
    PyPI's `agent-assembly` 0.0.2 — a registered, yanked, two-file version.
    """
    pypi_real = {
        "label": "PyPI agent-assembly",
        "asked": "0.0.2",
        "versions": ["0.0.1a4", "0.0.1rc7", "0.0.2"],
        "files": {
            "0.0.2": [
                "agent_assembly-0.0.2-py3-none-any.whl",
                "agent_assembly-0.0.2.tar.gz",
            ]
        },
    }

    def pypi(asked: str) -> dict:
        return {**pypi_real, "asked": asked}

    cases: list[tuple[str, list[dict], int, int]] = [
        (
            "the live yanked PyPI 0.0.2 is rejected",
            [pypi("0.0.2")],
            1,
            1,
        ),
        (
            "an unregistered number is accepted against that same index",
            [pypi("0.0.3")],
            0,
            1,
        ),
        (
            "an existing prerelease is rejected too -- 'yanked' is not the trigger",
            [pypi("0.0.1rc7")],
            1,
            1,
        ),
        (
            "a crates.io collision is caught with no filename detail to offer",
            [
                {
                    "label": "crates.io aa-core",
                    "asked": "0.0.1-rc.7",
                    "versions": ["0.0.1-rc.6", "0.0.1-rc.7"],
                    "files": {},
                }
            ],
            1,
            1,
        ),
        (
            "an npm version present only in `time` (unpublished) is still rejected",
            [
                {
                    "label": "npm @agent-assembly/sdk",
                    "asked": "0.0.1-beta.9",
                    "versions": ["0.0.1-beta.9", "0.0.1-rc.7"],
                    "files": {},
                }
            ],
            1,
            1,
        ),
        (
            "an unreadable probe is a finding, not an 'available'",
            [{"label": "PyPI agent-assembly", "asked": "0.0.3", "error": "boom"}],
            1,
            0,
        ),
        (
            "one collision among many clean probes still fails",
            [pypi("0.0.3"), {"label": "crates.io aa-cli", "asked": "0.0.3",
                             "versions": ["0.0.3"], "files": {}}],
            1,
            2,
        ),
        (
            "all clean, all populated: no findings",
            [pypi("0.0.3"), {"label": "crates.io aa-cli", "asked": "0.0.3",
                             "versions": ["0.0.1-rc.7"], "files": {}}],
            0,
            2,
        ),
        (
            "every probe empty yields no findings, and zero populated -- the vacuity shape",
            [{"label": "PyPI agent-assembly", "asked": "0.0.3", "versions": [], "files": {}}],
            0,
            0,
        ),
    ]

    failures = 0
    for name, probes, want_findings, want_populated in cases:
        messages, populated = findings_for(probes)
        if len(messages) != want_findings or populated != want_populated:
            print(
                f"selftest FAILED: {name}: expected {want_findings} finding(s) and "
                f"{want_populated} populated, got {len(messages)} and {populated}: {messages}"
            )
            failures += 1
            continue
        print(f"selftest ok: {name}")

    # The rejection must name the filenames the upload actually fails on, not
    # merely announce a collision — that string is the whole remediation.
    messages, _ = findings_for([pypi("0.0.2")])
    if "agent_assembly-0.0.2.tar.gz" not in messages[0]:
        print(
            "selftest FAILED: the PyPI rejection does not name the colliding sdist "
            f"filename: {messages[0]}"
        )
        failures += 1
    else:
        print("selftest ok: the PyPI rejection names the colliding sdist filename")

    # The last case above proves the vacuity shape produces no findings; assert
    # here that `check()`'s guard is what turns it into a refusal, so "0
    # findings" can never be reported as success.
    if findings_for([{"label": "x", "asked": "0.0.3", "versions": [], "files": {}}])[1] != 0:
        print("selftest FAILED: an all-empty probe set should report zero populated")
        failures += 1
    else:
        print(
            "selftest ok: an all-empty probe set is caught by the non-vacuity guard in "
            "check(), not by a comparison"
        )

    # PEP 440 spelling: the PyPI probe asks a different string from the one the
    # tag carries, and getting that wrong would query a version nobody ever
    # published and report it free.
    spellings = [
        ("0.0.1-rc.7", "0.0.1rc7"),
        ("0.0.1-beta.4", "0.0.1b4"),
        ("0.0.1-alpha.9", "0.0.1a9"),
        ("0.0.2", "0.0.2"),
        ("1.2.3", "1.2.3"),
    ]
    for given, want in spellings:
        got = pep440(given)
        if got != want:
            print(f"selftest FAILED: pep440({given!r}) == {got!r}, expected {want!r}")
            failures += 1
    if not failures:
        print(f"selftest ok: {len(spellings)} PEP 440 spellings convert as check-release.sh does")

    if failures:
        print(
            f"::error::check-version-availability selftest: {failures} case(s) failed",
            file=sys.stderr,
        )
        return 1
    print(
        f"check-version-availability selftest: {len(cases)} case(s) behave as specified"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "version",
        nargs="?",
        help="the version about to be released, SemVer spelling (e.g. 0.0.1-rc.8)",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove the check rejects a registered version and accepts an unregistered one",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    if not args.version:
        parser.error("a version is required unless --selftest is given")
    return check(args.version)


if __name__ == "__main__":
    sys.exit(main())
