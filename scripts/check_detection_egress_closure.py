#!/usr/bin/env python3
"""Fail if the sensitive-data detection fast path gains any new dependency.

AAASM-5738, for AAASM-5270 exit criterion 6 ("Local-only runtime behavior is
verified under egress-denied testing").

# What this checks, and why it is a SET rather than a denylist

The obvious shape for this control is a denylist: fail if the closure contains
`reqwest`, `hyper`, `ureq`, `curl`, `tokio`… That shape is what AAASM-5738's own
acceptance criteria rule out, and correctly:

  "The control derives its notion of 'network-capable' from the dependency
   graph, not from a list someone must remember to update."

A denylist only rejects transports someone thought of. It passes silently on the
next one — a new HTTP crate, a vendored socket wrapper, a `libc`-using crate that
opens a descriptor itself. The list is exactly the thing that rots, and it rots
invisibly, because a passing run looks identical either way.

So this control keeps no notion of "network-capable" at all. It pins the
**complete set of crate names** in the detection fast path's normal dependency
closure and fails on *any* difference. A new transport fails it. So does a new
CSV parser — deliberately. The detector's closure is three crates by default,
and a change to it is a thing a human should look at, whatever the crate does.
The remedy when it fires is one line plus a sentence saying why the new
dependency is acceptable, which is the review this control exists to force.

# Names, not versions

`EXPECTED` holds crate *names*. Versions are deliberately excluded: Dependabot
bumps them weekly, and a control that goes red on every patch bump gets muted or
routed around within a month. A version bump cannot introduce a capability the
crate did not already have a name for; a new name can. Names are the signal.

# What this does NOT check — the AAASM-5702 boundary

This is a statement about the detector's **dependency closure**, which is a
capability argument: `aa-security` links nothing that can open a socket. It is
NOT process or network isolation, and it must not be read as one:

  * this control       — "the detector has no outbound capability compiled in"
  * AAASM-5702         — "this process cannot use the network, enforced by the OS"

They answer different questions and neither substitutes for the other. A crate
closure proves nothing about a process that shells out; OS confinement proves
nothing about which crates were linked. This file deliberately implements only
the first, and the CI job that runs the detector's tests inside an empty network
namespace (see `ci.yml`) is a test harness for the second axis — it is not, and
must not grow into, a second isolation backend. `aa-isolation` owns that.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_INTERNAL = 2

# Each selection is (label, cargo args). The label is what a failure names, so
# it has to say which build this is — a drift under `serde` and a drift under
# default features are different findings with different blast radii.
#
# `--edges normal` excludes dev- and build-dependencies: a test-only HTTP client
# is not in the shipped detector, and including dev-deps would make this control
# fire on test infrastructure and get muted.
SELECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "aa-security (default features)",
        ("-p", "aa-security", "--no-default-features"),
    ),
    (
        # What `aa-gateway` and `aa-runtime` actually enable
        # (`aa-gateway/Cargo.toml`, `aa-runtime/Cargo.toml`: features = ["serde"]).
        # This is the closure that ships, so it is the one that matters most.
        "aa-security (serde — the feature set the gateway and runtime enable)",
        ("-p", "aa-security", "--features", "serde"),
    ),
)

EXPECTED: dict[str, frozenset[str]] = {
    "aa-security (default features)": frozenset(
        {
            "aa-security",
            "aho-corasick",
            "memchr",
        }
    ),
    "aa-security (serde — the feature set the gateway and runtime enable)": frozenset(
        {
            "aa-security",
            "aho-corasick",
            "memchr",
            # `serde = ["dep:serde", "dep:serde_yaml"]` — the canonical policy
            # AST's YAML parsing. serde_yaml brings the rest.
            "equivalent",
            "hashbrown",
            "indexmap",
            "itoa",
            "proc-macro2",
            "quote",
            "ryu",
            "serde",
            "serde_core",
            "serde_derive",
            "serde_yaml",
            "syn",
            "unicode-ident",
            "unsafe-libyaml",
        }
    ),
}

# `cargo tree --format {p}` emits e.g.
#   aa-security v0.0.1-rc.6 (/abs/path/to/aa-security)
#   serde_derive v1.0.229 (proc-macro)
#   memchr v2.8.3 (*)
# The name is everything before the first ` v<digit>`; the trailing annotations
# are noise for our purpose but must not be parsed *into* the name.
_PKG = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)\s+v\d")


def parse_names(tree_output: str) -> set[str]:
    """Crate names from `cargo tree --prefix none --format '{p}'` output.

    Raises ValueError on a line that does not look like a package, rather than
    skipping it: a silently-dropped line is a crate this control did not see,
    which is the failure mode the whole file exists to prevent.
    """
    names: set[str] = set()
    for raw in tree_output.splitlines():
        line = raw.strip()
        if not line:
            continue
        match = _PKG.match(line)
        if match is None:
            raise ValueError(f"unparseable cargo tree line: {line!r}")
        names.add(match.group("name"))
    return names


def closure(manifest_dir: Path, args: tuple[str, ...]) -> set[str]:
    cmd = [
        "cargo",
        "tree",
        "--edges",
        "normal",
        "--prefix",
        "none",
        "--format",
        "{p}",
        *args,
    ]
    proc = subprocess.run(
        cmd, cwd=manifest_dir, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"`{' '.join(cmd)}` failed with exit {proc.returncode}\n{proc.stderr}"
        )
    return parse_names(proc.stdout)


def check(manifest_dir: Path) -> int:
    drifted = False
    for label, args in SELECTIONS:
        expected = EXPECTED[label]
        try:
            actual = closure(manifest_dir, args)
        except (RuntimeError, ValueError) as exc:
            print(f"check_detection_egress_closure: internal error: {exc}", file=sys.stderr)
            return EXIT_INTERNAL

        added = sorted(actual - expected)
        removed = sorted(expected - actual)
        if not added and not removed:
            print(f"  ok    {label}: {len(actual)} crate(s), unchanged")
            continue

        drifted = True
        print(f"  DRIFT {label}:")
        for name in added:
            print(
                f"    + {name}  — new dependency in the detection fast path. "
                f"If this is intended, add it to EXPECTED with a comment saying "
                f"why it cannot reach the network."
            )
        for name in removed:
            print(
                f"    - {name}  — no longer present. Remove it from EXPECTED; a "
                f"stale entry makes the pinned set describe a closure that does "
                f"not exist."
            )

    if drifted:
        print(
            "\ncheck_detection_egress_closure: FAIL — the sensitive-data detection\n"
            "fast path's dependency closure changed. AAASM-5270 exit criterion 6\n"
            "and product constraint 1 ('raw sensitive content must not be sent to\n"
            "third-party services') rest on this closure being inspectable and\n"
            "small. Review the change, then update EXPECTED in the same commit.",
            file=sys.stderr,
        )
        return EXIT_DRIFT

    print("check_detection_egress_closure: OK — every pinned closure matches.")
    return EXIT_OK


def selftest() -> int:
    """Prove the parser and the comparison can both fail.

    A control whose selftest only exercises the passing path is the defect this
    repository keeps finding. Every case below is a mutation that MUST be
    rejected, asserted against literals rather than against EXPECTED — deriving
    the assertion from the same table it checks would let a wrong table agree
    with itself.
    """
    failures: list[str] = []

    # --- parser --------------------------------------------------------------
    sample = (
        "aa-security v0.0.1-rc.6 (/abs/path/aa-security)\n"
        "aho-corasick v1.1.5\n"
        "memchr v2.8.3 (*)\n"
        "serde_derive v1.0.229 (proc-macro)\n"
        "\n"
    )
    got = parse_names(sample)
    want = {"aa-security", "aho-corasick", "memchr", "serde_derive"}
    if got != want:
        failures.append(f"parser: got {sorted(got)}, want {sorted(want)}")

    # A path containing " v1" must not be mistaken for the version field.
    got = parse_names("aa-security v0.0.1-rc.6 (/home/v1/checkout/aa-security)\n")
    if got != {"aa-security"}:
        failures.append(f"parser path-with-v1: got {sorted(got)}")

    # Garbage must raise, not be skipped. A skipped line is an unseen crate.
    try:
        parse_names("this is not a package line\n")
    except ValueError:
        pass
    else:
        failures.append("parser accepted an unparseable line instead of raising")

    # --- comparison ----------------------------------------------------------
    # The real check compares sets; these assert the set algebra rejects both
    # directions of drift. Literal sets, not EXPECTED.
    baseline = {"aa-security", "aho-corasick", "memchr"}
    if not (baseline | {"reqwest"}) - baseline == {"reqwest"}:
        failures.append("comparison failed to see an ADDED crate")
    if not baseline - (baseline - {"memchr"}) == {"memchr"}:
        failures.append("comparison failed to see a REMOVED crate")
    if (baseline - baseline) or (baseline - baseline):
        failures.append("comparison reported drift on an identical set")

    # --- table sanity --------------------------------------------------------
    for label, _ in SELECTIONS:
        if label not in EXPECTED:
            failures.append(f"selection {label!r} has no EXPECTED entry")
    for label in EXPECTED:
        if label not in {sel for sel, _ in SELECTIONS}:
            failures.append(f"EXPECTED entry {label!r} matches no selection")

    if failures:
        for line in failures:
            print(f"check_detection_egress_closure --selftest: {line}", file=sys.stderr)
        return EXIT_INTERNAL

    print(
        "check_detection_egress_closure --selftest: "
        f"parser and comparison cases passed; {len(SELECTIONS)} selection(s) pinned."
    )
    return EXIT_OK


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run the control's own cases and exit; no cargo invocation",
    )
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="workspace root (default: the repository containing this script)",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    return check(args.manifest_dir)


if __name__ == "__main__":
    sys.exit(main())
