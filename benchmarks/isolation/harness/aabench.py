"""Isolation benchmark harness for AAASM-5713.

Parameterised by a *launcher* so the same harness produces the unconfined
baseline today and the AAASM-5708 confined arm later with no code change:

    python3 aabench.py run --launcher 'sh /abs/path/to/launchers/unconfined.sh' --out base.json
    python3 aabench.py run --launcher '/usr/bin/aasm-sandlock-run' --out confined.json
    python3 aabench.py compare --baseline base.json --candidate confined.json

Launcher paths must be absolute: runner.py chdirs the child to REPO_ROOT (the
monorepo root, not this directory) before exec, so a launcher spec written
relative to here resolves against the wrong directory (AAASM-5713 — every
family failed identically on the first confined-arm CI run for exactly this
reason before it was caught).

Read METHODOLOGY.md first. The thresholds this applies were pre-registered
before any backend existed, and nothing here issues a verdict from timing data
alone.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
if HARNESS_DIR not in sys.path:
    sys.path.insert(0, HARNESS_DIR)

import compare as compare_mod  # noqa: E402
import envinfo  # noqa: E402
import runner  # noqa: E402
from tlsserver import LoopbackTlsServer  # noqa: E402

ROOT = os.path.dirname(HARNESS_DIR)
WORKLOADS_DIR = os.path.join(ROOT, "workloads")
LAUNCHERS_DIR = os.path.join(ROOT, "launchers")
MANIFEST = os.path.join(WORKLOADS_DIR, "manifest.json")
REPO_ROOT = os.path.dirname(os.path.dirname(ROOT))

SCHEMA_VERSION = "1.0.0"
HARNESS_VERSION = "0.1.0"

DEFAULT_LAUNCHER = f"sh {os.path.join(LAUNCHERS_DIR, 'unconfined.sh')}"
THROTTLED_LAUNCHER = f"sh {os.path.join(LAUNCHERS_DIR, 'throttled.sh')}"


def select_families(
    families: Sequence[runner.Family], names: str | None, heavy: bool, with_network: bool
) -> list[runner.Family]:
    """Resolve the family set, keeping ``startup_nop`` first.

    Ordering is load-bearing rather than cosmetic: every other family's
    steady-state figure is derived by subtracting this launcher's measured
    startup median, so the startup family has to be measured before them.
    """
    if names:
        wanted = {n.strip() for n in names.split(",") if n.strip()}
        unknown = wanted - {f.name for f in families}
        if unknown:
            raise SystemExit(f"unknown families: {', '.join(sorted(unknown))}")
        chosen = [f for f in families if f.name in wanted]
    else:
        chosen = [f for f in families if f.default]
        if heavy:
            chosen = list(families)
        if not with_network:
            chosen = [f for f in chosen if f.dimension_tag != "network"]
    chosen.sort(key=lambda f: (f.dimension_tag != "startup", f.name))
    return chosen


def cmd_run(args: argparse.Namespace) -> int:
    families = runner.load_families(MANIFEST)
    chosen = select_families(families, args.families, args.heavy, not args.no_network)
    if not chosen:
        raise SystemExit("no workload families selected")

    launcher_argv = runner.parse_launcher(args.launcher)
    scratch_root = args.scratch_root or tempfile.mkdtemp(prefix="aabench-")
    os.makedirs(scratch_root, exist_ok=True)

    required_tools: set[str] = set()
    for family in chosen:
        required_tools.update(family.requires)

    started = datetime.now(timezone.utc)
    environment = envinfo.capture(REPO_ROOT, scratch_root, required_tools)

    tls: LoopbackTlsServer | None = None
    extra_env: dict[str, str] = {}
    wants_network = any(f.dimension_tag == "network" for f in chosen)
    network_note: str | None = None
    if wants_network:
        if shutil.which("openssl") is None:
            network_note = "openssl absent; loopback TLS server not started"
            chosen = [f for f in chosen if f.dimension_tag != "network"]
        else:
            tls = LoopbackTlsServer(scratch_root)
            tls.start()
            extra_env.update(tls.client_env())

    results: list[runner.FamilyResult] = []
    try:
        for family in chosen:
            print(f"  running {family.name} ...", file=sys.stderr, flush=True)
            results.append(
                runner.run_family(
                    family=family,
                    launcher_argv=launcher_argv,
                    workloads_dir=WORKLOADS_DIR,
                    repo_root=REPO_ROOT,
                    scratch_root=scratch_root,
                    repetitions=args.repetitions,
                    warmups=args.warmups,
                    extra_env=extra_env if family.dimension_tag == "network" else None,
                )
            )
    finally:
        if tls is not None:
            tls.stop()
        if not args.keep_scratch:
            shutil.rmtree(scratch_root, ignore_errors=True)

    startup_median: float | None = None
    startup_note = "startup_nop not selected; steady-state correction unavailable"
    for result in results:
        if result.dimension_tag == "startup":
            if result.admissible and result.stats_ms is not None:
                startup_median = result.stats_ms["median"]
            else:
                startup_note = (
                    "startup_nop inadmissible "
                    f"({result.inadmissible_reason}); steady-state correction unavailable"
                )
    runner.apply_startup_correction(results, startup_median, startup_note)

    declared = len(families)
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "harness_version": HARNESS_VERSION,
        "run_id": f"{started.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}",
        "label": args.label,
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "control_experiment": bool(args.control_experiment),
        "launcher": {
            "spec": args.launcher,
            "argv": launcher_argv,
            "throttle_env": {
                key: value
                for key, value in os.environ.items()
                if key.startswith("AABENCH_THROTTLE")
            },
        },
        "config": {
            "repetitions": args.repetitions,
            "warmups": args.warmups,
            "families_requested": args.families,
            "heavy": bool(args.heavy),
            "network": not args.no_network,
            "scratch_root": scratch_root,
        },
        "notes": [note for note in (network_note,) if note],
        "environment": environment,
        "startup_correction_ms": startup_median,
        "results": [result.to_json() for result in results],
        # Denominators, not just the passing count: a run that quietly measured
        # three families is not the same evidence as one that measured nine.
        "denominators": {
            "families_declared_in_manifest": declared,
            "families_selected": len(chosen),
            "families_attempted": len(results),
            "families_ok": sum(1 for r in results if r.status == "ok"),
            "families_skipped": sum(1 for r in results if r.status == "skipped"),
            "families_failed": sum(1 for r in results if r.status == "failed"),
            "families_admissible": sum(1 for r in results if r.admissible),
        },
    }

    _write(args.out, document)
    print(json.dumps(document["denominators"], indent=2))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    baseline = compare_mod.load(args.baseline)
    candidate = compare_mod.load(args.candidate)
    document = compare_mod.build_comparison(
        baseline, candidate, args.baseline, args.candidate, args.allow_cross_env
    )
    _write(args.out, document)
    headline = {k: document[k] for k in ("control_validity", "verdict", "verdict_reason")}
    print(json.dumps(headline, indent=2))
    for key, block in sorted(document["dimensions"].items()):
        if block.get("blocked"):
            print(f"  {key}: BLOCKED - {block.get('reason')}")
        else:
            print(
                f"  {key}: {block['grade']:<5} {block['value']:.4f} "
                f"{block['unit']} ({block['label']})"
            )
    return 0


def cmd_env(args: argparse.Namespace) -> int:
    scratch = args.scratch_root or tempfile.gettempdir()
    print(json.dumps(envinfo.capture(REPO_ROOT, scratch, None), indent=2))
    return 0


def cmd_self_test(args: argparse.Namespace) -> int:
    import selftest

    return selftest.run(
        out_dir=args.out_dir,
        repetitions=args.repetitions,
        warmups=args.warmups,
        delay_ms=args.delay_ms,
        repeat=args.repeat,
    )


def _write(path: str | None, document: dict[str, Any]) -> None:
    if path is None:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print(f"wrote {path}", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aabench", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="measure workload families under one launcher")
    run_parser.add_argument("--launcher", default=DEFAULT_LAUNCHER, help="launcher command")
    run_parser.add_argument("--label", default="unlabelled", help="human label for this arm")
    run_parser.add_argument("--out", default=None, help="result JSON path")
    run_parser.add_argument("--families", default=None, help="comma-separated family names")
    run_parser.add_argument("--repetitions", type=int, default=10, help="kept repetitions")
    run_parser.add_argument("--warmups", type=int, default=2, help="discarded repetitions")
    run_parser.add_argument("--heavy", action="store_true", help="include non-default families")
    run_parser.add_argument("--no-network", action="store_true", help="skip loopback TLS family")
    run_parser.add_argument("--scratch-root", default=None, help="scratch directory root")
    run_parser.add_argument("--keep-scratch", action="store_true", help="do not delete scratch")
    run_parser.add_argument(
        "--control-experiment",
        action="store_true",
        help="mark this run as a synthetic control, not a data arm",
    )
    run_parser.set_defaults(func=cmd_run)

    compare_parser = sub.add_parser("compare", help="score two result files")
    compare_parser.add_argument("--baseline", required=True)
    compare_parser.add_argument("--candidate", required=True)
    compare_parser.add_argument("--out", default=None)
    compare_parser.add_argument(
        "--allow-cross-env",
        action="store_true",
        help="compare mismatched environments; stamps the result INVALID_CONTROL",
    )
    compare_parser.set_defaults(func=cmd_compare)

    env_parser = sub.add_parser("env", help="print the environment block")
    env_parser.add_argument("--scratch-root", default=None)
    env_parser.set_defaults(func=cmd_env)

    st_parser = sub.add_parser(
        "self-test", help="negative control: prove the harness detects a known slowdown"
    )
    st_parser.add_argument("--out-dir", default=None)
    st_parser.add_argument("--repetitions", type=int, default=10)
    st_parser.add_argument("--warmups", type=int, default=2)
    st_parser.add_argument("--delay-ms", type=int, default=500)
    st_parser.add_argument("--repeat", type=int, default=2)
    st_parser.set_defaults(func=cmd_self_test)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
