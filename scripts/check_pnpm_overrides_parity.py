#!/usr/bin/env python3
"""Assert pnpm security override floors are declared where pnpm 11 still reads them.

WHY THIS EXISTS
---------------
AAASM-6133: this repository declared 13 security override floors in the
``pnpm.overrides`` field of ``package.json`` — 9 in ``dashboard/``, 4 in
``examples/aa-devint-reference-client/``. pnpm 11 no longer reads that field
(https://pnpm.io/settings), so a one-line bump of any ``pnpm/action-setup``
pin to 11 would have dropped all 13 floors with no error, no warning and a
green build. Several were not cosmetic: ``dompurify`` and ``undici`` are the
kind of floor that exists because a transitive dependency otherwise resolves
below a patched version, so losing one silently reinstates the advisory it was
raised to close.

The same defect class had already been a *real* regression twice — HORO-377
(a relock silently deleted the block) and AAASM-6032 in the sibling repository
``ai-agent-assembly/examples`` (four relocks dropped ``overrides:`` from the
lockfile, breaking every later ``pnpm install --frozen-lockfile`` with a
generic ``ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`` that named neither the directory
nor the package). Both were fixed by moving the declarations to
``pnpm-workspace.yaml``, the file pnpm 10 and pnpm 11 both read.

CONTRACT — two assertions, and the second is the reason this is not a copy
-------------------------------------------------------------------------
1. **Parity.** For every ``pnpm-workspace.yaml`` that declares an
   ``overrides:`` mapping, its sibling ``pnpm-lock.yaml`` must declare the
   identical mapping (same keys, same values).
2. **No stragglers.** No ``package.json`` in the tree may declare a non-empty
   ``pnpm.overrides``, because pnpm 11 ignores it.

Assertion 1 alone is what ``ai-agent-assembly/examples`` ships. Ported
verbatim into this repository it would have been a *vacuous pass*: it iterates
``rglob("pnpm-workspace.yaml")``, of which there were none here, so the loop
body never executed and it exited 0 reporting "0 overrides-carrying
director(y/ies) checked, 0 mismatches". A green check that asserts nothing is
worse than no check, because it reads as coverage. Assertion 2 is what makes
the exit code mean something on this tree: it is the assertion that fails on
the pre-migration state, and it keeps failing if anyone reintroduces a floor
in the field pnpm 11 has stopped reading.

Exit 0 if both assertions hold. Exit 1 and list every violation otherwise.

This is a declaration-site and parity check, not a lockfile validator — it
does not evaluate whether an override's version range is itself high enough to
close an advisory, only that the floor is declared where pnpm will read it and
that the lockfile agrees. Applying the range to installed packages is
``pnpm install --frozen-lockfile``'s job, and that already runs on every PR.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Installed/derived trees only. Deliberately short: every name added here is a
# place a real `pnpm.overrides` could hide from assertion 2, so `dist/` and
# `build/` are NOT excluded even though they are also derived — nothing is
# committed under them today (`git ls-files` lists exactly three package.json
# files in this repository) and a future one must not be skipped silently.
# `target/` is excluded because Rust's build directory holds tens of thousands
# of files and would dominate the walk.
EXCLUDE_DIR_NAMES = {"node_modules", ".git", ".venv", "target"}

WORKSPACE_FILENAME = "pnpm-workspace.yaml"
LOCK_FILENAME = "pnpm-lock.yaml"
MANIFEST_FILENAME = "package.json"


def _iter_tree_files(root: Path, filename: str) -> list[Path]:
    found = []
    for path in root.rglob(filename):
        if any(part in EXCLUDE_DIR_NAMES for part in path.parts):
            continue
        found.append(path)
    return sorted(found)


def _parse_flat_mapping(lines: list[str], header: str) -> dict[str, str] | None:
    """Extract a simple `header:\\n  key: value` block's contents as a dict.

    Handles the two shapes both files actually use: bare keys (``esbuild:``)
    and single/double-quoted keys (``'@scope/name':``). Values are taken
    verbatim (after stripping matching quotes) — good enough for a parity
    comparison, since both files are written by the same pnpm and use the
    same quoting rules for the same key.
    """
    for i, line in enumerate(lines):
        if line.rstrip() != f"{header}:":
            continue
        mapping: dict[str, str] = {}
        for follow in lines[i + 1 :]:
            stripped = follow.strip()
            # Comments carry no entry at any indentation. Testing `follow`
            # rather than `stripped` here missed indented ones, so a
            # justification comment written between two override entries ended
            # the block early and every entry below it read as absent from the
            # config.
            if stripped == "" or stripped.startswith("#"):
                continue
            if not follow.startswith(("  ", "\t")):
                break  # dedented past the end of this block
            if ":" not in stripped:
                break
            key, _, value = stripped.partition(":")
            key = key.strip().strip("'\"")
            value = value.strip().strip("'\"")
            mapping[key] = value
        return mapping
    return None


def _parse_overrides(path: Path, header: str) -> dict[str, str] | None:
    lines = path.read_text(encoding="utf-8").splitlines()
    return _parse_flat_mapping(lines, header)


def manifest_overrides(path: Path) -> dict[str, object]:
    """Return a ``package.json``'s ``pnpm.overrides`` mapping, or {} if absent.

    Parsed with ``json`` rather than the line scanner above: a manifest is
    authored by hand, so its nesting and formatting are not guaranteed to be
    the flat two-space shape pnpm writes.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path}: not readable as JSON: {exc}") from exc
    if not isinstance(data, dict):
        return {}
    pnpm_field = data.get("pnpm")
    if not isinstance(pnpm_field, dict):
        return {}
    overrides = pnpm_field.get("overrides")
    if not isinstance(overrides, dict):
        return {}
    return overrides


def find_manifest_violations(root: Path) -> list[str]:
    """Assertion 2: no package.json may declare a non-empty pnpm.overrides."""
    violations: list[str] = []
    for manifest in _iter_tree_files(root, MANIFEST_FILENAME):
        overrides = manifest_overrides(manifest)
        if not overrides:
            continue
        rel = manifest.relative_to(root)
        detail = ", ".join(f"{k}={v!r}" for k, v in sorted(overrides.items(), key=lambda kv: str(kv[0])))
        violations.append(
            f"{rel}: declares {len(overrides)} pnpm.overrides entr(y/ies) that pnpm 11 "
            f"does not read: {detail}. Move them to "
            f"{manifest.parent.relative_to(root) / WORKSPACE_FILENAME}"
        )
    return violations


def find_parity_violations(root: Path) -> tuple[list[str], int]:
    """Assertion 1: pnpm-workspace.yaml overrides must match the sibling lockfile."""
    violations: list[str] = []
    checked = 0

    for workspace_file in _iter_tree_files(root, WORKSPACE_FILENAME):
        config_overrides = _parse_overrides(workspace_file, "overrides")
        if not config_overrides:
            continue

        lock_file = workspace_file.parent / LOCK_FILENAME
        rel = workspace_file.parent.relative_to(root)
        if not lock_file.exists():
            violations.append(
                f"{rel}: {WORKSPACE_FILENAME} declares overrides "
                f"{sorted(config_overrides)} but no {LOCK_FILENAME} exists alongside it"
            )
            continue

        checked += 1
        lock_overrides = _parse_overrides(lock_file, "overrides") or {}

        missing = {k: v for k, v in config_overrides.items() if lock_overrides.get(k) != v}
        extra = {k: v for k, v in lock_overrides.items() if k not in config_overrides}

        if missing:
            detail = ", ".join(
                f"{k}={v!r} (lockfile has {lock_overrides.get(k)!r})" for k, v in sorted(missing.items())
            )
            violations.append(f"{rel}: {LOCK_FILENAME} missing/mismatched overrides: {detail}")
        if extra:
            detail = ", ".join(f"{k}={v!r}" for k, v in sorted(extra.items()))
            violations.append(f"{rel}: {LOCK_FILENAME} has overrides not in {WORKSPACE_FILENAME}: {detail}")

    return violations, checked


def main() -> int:
    manifest_violations = find_manifest_violations(REPO_ROOT)
    parity_violations, checked = find_parity_violations(REPO_ROOT)

    if manifest_violations or parity_violations:
        print("check_pnpm_overrides_parity: FAIL", file=sys.stderr)
        if manifest_violations:
            print("  pnpm.overrides still declared in package.json (pnpm 11 ignores it):", file=sys.stderr)
            for v in manifest_violations:
                print(f"    {v}", file=sys.stderr)
        if parity_violations:
            print(f"  {WORKSPACE_FILENAME} / {LOCK_FILENAME} disagree:", file=sys.stderr)
            for v in parity_violations:
                print(f"    {v}", file=sys.stderr)
        print(
            f"\n{len(manifest_violations) + len(parity_violations)} violation(s) across "
            f"{checked} overrides-carrying director(y/ies). Fix: move each "
            f"`pnpm.overrides` block into a sibling {WORKSPACE_FILENAME} preserving "
            "keys and values exactly, then relock in that directory with the pnpm "
            "version its `packageManager` field pins (`corepack pnpm@<version> install "
            "--no-frozen-lockfile`) and confirm the lockfile's `overrides:` block is "
            "unchanged.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check_pnpm_overrides_parity: OK — {checked} overrides-carrying "
        f"director(y/ies) checked, 0 mismatches, 0 package.json still declaring "
        "pnpm.overrides"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
