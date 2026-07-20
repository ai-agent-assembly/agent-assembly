#!/usr/bin/env python3
"""Stamp every hand-maintained version-bearing site in this repo from its SoT.

ADR 0013 ("Version Metadata Source-of-Truth & Drift Gate") decides that every
version-bearing value has exactly one source of truth (SoT) and propagates in
one direction only: **SoT -> generator -> checked-in consumer**. Nothing outside
a SoT (or its generated output) may carry a version literal.

The audit in that ADR (Appendix A) found a cluster of ``agent-assembly``-local
sites that are *hand-maintained* (tag ``[B]``) — they only stay aligned because a
release operator remembers to edit each one. That forgettable manual step is the
drift class behind AAASM-4900/4903/4905 (and the stale ``installation.md`` this
tool was written against, which sat on ``beta.4`` while the anchor was ``rc.6``).

This script is the propagation tool the ADR calls for (AAASM-4910): it stamps
**all** of those hand-maintained consumers from their SoT in a single pass, and
ships a ``--check`` drift-gate mode that reports staleness without writing.

Source-of-truth anchors it reads
--------------------------------
* **Core/runtime version** = ``Cargo.toml [workspace.package].version`` — the
  authoritative core version anchor (ADR 0013 Decision 1). ``release-tag-cut``
  is its only sanctioned writer.
* **mdBook / toolchain pins** = ``metadata/docs.yaml`` keys ``mdbook_version`` /
  ``mdbook_mermaid_version`` — a repo-scoped metadata SoT (the ``metadata/*.yaml``
  pattern the ADR blesses). Before this tool those pins were duplicated by hand
  in both the docs workflow and CONTRIBUTING.md.

Consumers it stamps (all ``agent-assembly``-local, tag ``[B]`` in the audit)
--------------------------------------------------------------------------
Core-version tier (from the ``Cargo.toml`` anchor):
  * ``README.md`` — ``AASM_VERSION=v<tag>`` quick-install snippet + the Project
    Status "latest ``[v<tag>]``" release link.
  * ``docs/src/quick-start/installation.md`` — the four live install examples the
    release verifier asserts (``AASM_VERSION=`` pin, ``VERSION=`` manual download,
    ``aasm <ver>`` sample output, ``| cli | <ver> |`` version-table sample).
Tool-pin tier (from ``metadata/docs.yaml``):
  * ``.github/workflows/docs.yml`` — mdBook / mdbook-mermaid ``--version`` pins +
    the cache-key version segment.
  * ``CONTRIBUTING.md`` — the mdBook / mdbook-mermaid install commands.
Generated-snippet tier (already SoT-wired; refreshed here so one command syncs
everything):
  * ``docs/src/generated/*.md`` — delegated to ``generate_docs_metadata.py``, its
    single sanctioned writer (reused, not reimplemented).

Deliberately NOT stamped (ADR-directed)
---------------------------------------
* ``docs/src/compatibility.md`` matrix rows — per-tag rows stay **literal** (ADR
  0013 "Explicitly forbidden designs": templating historical values). The matrix
  grows by append-on-release; its row-presence gate is upgraded under AAASM-4911.
* ``aa-ebpf-probes/rust-toolchain.toml`` ``channel = "nightly"`` — a channel, not
  a version derived from any anchor; there is nothing to propagate.
* The README Project Status maturity **banner** ("Release candidate — `v0.0.1-rc`
  series" + "status as of <date>") — channel word and date are per-release human
  judgement, not a literal derivable from the anchor; it stays a skill checklist
  item.

Modes
-----
* default (write): rewrite every consumer to match the SoT; exit 0.
* ``--check`` / ``--dry-run``: report drift and exit 1 if any consumer is stale
  (or a consumer's expected anchor line has gone missing); never writes. This is
  the blocking drift-gate contract from ADR 0013 Decision 3 (regenerate-and-diff
  for the snippet tier; anchored value check for the literal tier).

Stdlib only (``tomllib`` on Python 3.11+); no third-party deps so CI needs no
install to run the gate.

Refs: AAASM-4910, ADR docs/src/adr/0013-version-metadata-source-of-truth-and-drift-gate.md.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# generate_docs_metadata.py lives beside this file and is the sanctioned writer
# for docs/src/generated/. We reuse it wholesale (its loaders + main) rather than
# duplicate the snippet-rendering logic; its module-level path globals are
# rebindable, which is how we point it at an injected root (tests) or a temp dir
# (check mode) without a refactor.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_docs_metadata as gen  # noqa: E402

# Default anchor: this script sits at scripts/, so parent.parent is the repo root.
# All public functions take an explicit ``root`` so they are working-directory
# invariant and unit-testable against a throwaway fixture tree.
DEFAULT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Context:
    """Resolved SoT values, in every form the consumers need."""

    core_version: str  # bare, e.g. "0.0.1-rc.6"
    core_tag: str  # tag form, e.g. "v0.0.1-rc.6"
    mdbook_version: str  # e.g. "0.5.2"
    mdbook_mermaid_version: str  # e.g. "0.17.0"


@dataclass
class Rule:
    """One consumer file and the anchored substitutions that keep it in sync.

    Each substitution is ``(compiled_pattern, replacement)``. A pattern that
    matches **zero** times is treated as a hard error in both modes: it means the
    consumer line was renamed or removed, and a silently-skipped consumer is
    exactly the drift this tool exists to prevent.
    """

    path: str
    subs: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = field(
        default_factory=list
    )


def resolve_context(root: Path) -> Context:
    """Read every SoT anchor into a :class:`Context`.

    Reuses ``generate_docs_metadata``'s loaders (pointed at ``root``) so the core
    version and metadata are parsed by exactly one implementation.
    """
    gen.CARGO_TOML = root / "Cargo.toml"
    gen.METADATA_YAML = root / "metadata" / "docs.yaml"
    core_version = gen.load_workspace_version()
    meta = gen.load_docs_metadata()
    missing = [k for k in ("mdbook_version", "mdbook_mermaid_version") if k not in meta]
    if missing:
        raise SystemExit(
            f"{gen.METADATA_YAML}: missing required tool-pin key(s): {', '.join(missing)}"
        )
    return Context(
        core_version=core_version,
        core_tag=f"v{core_version}",
        mdbook_version=meta["mdbook_version"],
        mdbook_mermaid_version=meta["mdbook_mermaid_version"],
    )


def build_rules(ctx: Context) -> list[Rule]:
    """Declarative consumer -> substitution table.

    Adding a consumer is a data edit here plus a doc line in the skill; the write
    and check paths both consume this same table, so they can never disagree.
    """
    ver = ctx.core_version
    tag = ctx.core_tag
    mdbook = ctx.mdbook_version
    mermaid = ctx.mdbook_mermaid_version

    def const(value: str) -> Callable[[re.Match[str]], str]:
        # Replace the version span (group 2) between preserved anchors g1 + g3.
        return lambda m: f"{m.group(1)}{value}{m.group(3)}"

    # --- core-version tier ---------------------------------------------------
    # AASM_VERSION=v<tag> ... (install snippet, shared shape in README + install)
    aasm_pin = (re.compile(r"(AASM_VERSION=)(v\S+)( curl)"), const(tag))

    readme = Rule(
        "README.md",
        [
            aasm_pin,
            # Project Status "latest [`v<tag>`](.../releases/tag/v<tag>)" — update
            # both the backticked label and the tag URL in one shot.
            (
                re.compile(
                    r"(\[`)v[^`]+(`\]\(https://github\.com/ai-agent-assembly/"
                    r"agent-assembly/releases/tag/)v[^)]+(\))"
                ),
                lambda m: f"{m.group(1)}{tag}{m.group(2)}{tag}{m.group(3)}",
            ),
        ],
    )

    installation = Rule(
        "docs/src/quick-start/installation.md",
        [
            aasm_pin,
            # VERSION=v<tag> manual pre-built-binaries snippet (line-anchored so it
            # can't collide with the AASM_VERSION= line).
            (re.compile(r"(?m)^(VERSION=)(v\S+)()$"), const(tag)),
            # `aasm <bare ver>` --version sample output (line-anchored).
            (re.compile(r"(?m)^(aasm )(\d+\.\d+\.\d+\S*)()$"), const(ver)),
            # `| cli       | <bare ver>  |` aasm-version table sample.
            (re.compile(r"(?m)^(\| cli\s+\| )(\d+\.\d+\.\d+\S*)()"), const(ver)),
        ],
    )

    # --- tool-pin tier -------------------------------------------------------
    # `--version <ver> mdbook` — the lookahead stops it matching `mdbook-mermaid`.
    mdbook_install = (
        re.compile(r"(--version )([0-9][0-9.]*)( mdbook)(?![-\w])"),
        const(mdbook),
    )
    mermaid_install = (
        re.compile(r"(--version )([0-9][0-9.]*)( mdbook-mermaid)"),
        const(mermaid),
    )

    docs_yml = Rule(
        ".github/workflows/docs.yml",
        [
            mdbook_install,
            mermaid_install,
            # Cache key: `mdbook-<mdbook>-mermaid-<mermaid>`. A digit right after
            # `mdbook-` distinguishes it from the `mdbook-mermaid` install token.
            (
                re.compile(r"(mdbook-)([0-9][0-9.]*)(-mermaid-)([0-9][0-9.]*)"),
                lambda m: f"{m.group(1)}{mdbook}{m.group(3)}{mermaid}",
            ),
        ],
    )
    contributing = Rule("CONTRIBUTING.md", [mdbook_install, mermaid_install])

    return [readme, installation, docs_yml, contributing]


def _apply_rule(text: str, rule: Rule) -> tuple[str, list[str]]:
    """Return ``(new_text, errors)`` after applying every sub in ``rule``.

    ``errors`` is non-empty when a pattern matched nothing (a moved/renamed
    consumer anchor) — a condition both modes must surface, never swallow.
    """
    errors: list[str] = []
    new_text = text
    for pattern, repl in rule.subs:
        new_text, count = pattern.subn(repl, new_text)
        if count == 0:
            errors.append(
                f"{rule.path}: anchor pattern matched nothing: {pattern.pattern!r} "
                "(the consumer line was renamed/removed — update propagate_versions.py)"
            )
    return new_text, errors


def sync_literals(root: Path, rules: list[Rule], check: bool) -> tuple[list[str], list[str]]:
    """Stamp (or, in check mode, diff) the literal-tier consumers.

    Returns ``(drift, errors)`` — ``drift`` lists stale files, ``errors`` lists
    missing anchors. In write mode, stale files are rewritten in place.
    """
    drift: list[str] = []
    errors: list[str] = []
    for rule in rules:
        path = root / rule.path
        if not path.is_file():
            errors.append(f"{rule.path}: consumer file not found")
            continue
        original = path.read_text()
        new_text, rule_errors = _apply_rule(original, rule)
        errors.extend(rule_errors)
        if new_text != original:
            drift.append(rule.path)
            if not check:
                path.write_text(new_text)
    return drift, errors


def sync_snippets(root: Path, check: bool) -> list[str]:
    """Refresh (or diff) ``docs/src/generated/*.md`` via the sanctioned writer.

    Reuses ``generate_docs_metadata.main`` by rebinding its path globals. In check
    mode it renders into a temp dir and diffs against the checked-in snippets, so
    nothing on disk is touched.
    """
    gen.CARGO_TOML = root / "Cargo.toml"
    gen.METADATA_YAML = root / "metadata" / "docs.yaml"
    real_dir = root / "docs" / "src" / "generated"

    if not check:
        gen.GENERATED_DIR = real_dir
        gen.main()
        return []

    drift: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        gen.GENERATED_DIR = Path(tmp)
        gen.main()
        for produced in sorted(Path(tmp).glob("*.md")):
            checked_in = real_dir / produced.name
            if not checked_in.is_file() or checked_in.read_text() != produced.read_text():
                drift.append(f"docs/src/generated/{produced.name}")
    return drift


def run(root: Path, check: bool) -> int:
    ctx = resolve_context(root)
    rules = build_rules(ctx)
    lit_drift, errors = sync_literals(root, rules, check)
    snip_drift = sync_snippets(root, check)
    drift = lit_drift + snip_drift

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 2

    if check:
        if drift:
            print(
                f"DRIFT: {len(drift)} version-bearing site(s) are stale vs the SoT "
                f"(core {ctx.core_tag}, mdBook {ctx.mdbook_version}, "
                f"mdbook-mermaid {ctx.mdbook_mermaid_version}):",
                file=sys.stderr,
            )
            for site in drift:
                print(f"  - {site}", file=sys.stderr)
            print(
                "Run 'python3 scripts/propagate_versions.py' to stamp them from the SoT.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: all version-bearing sites match the SoT ({ctx.core_tag}).")
        return 0

    if drift:
        print(f"Stamped {len(drift)} site(s) from the SoT ({ctx.core_tag}):")
        for site in drift:
            print(f"  - {site}")
    else:
        print(f"OK: all version-bearing sites already match the SoT ({ctx.core_tag}).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Propagate the version SoT (Cargo.toml core anchor + metadata/docs.yaml "
            "tool pins) to every hand-maintained consumer in this repo (ADR 0013)."
        )
    )
    parser.add_argument(
        "--check",
        "--dry-run",
        dest="check",
        action="store_true",
        help="report drift and exit non-zero without writing (drift-gate mode).",
    )
    args = parser.parse_args(argv)
    return run(DEFAULT_ROOT, check=args.check)


if __name__ == "__main__":
    sys.exit(main())
