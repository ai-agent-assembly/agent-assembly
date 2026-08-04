#!/usr/bin/env python3
"""Sync/audit contact identity literals against the canonical org registry.

WHY THIS EXISTS
---------------
AAASM-5520: the org's public contact identities (canonical `.com` addresses,
their legacy `.dev` aliases, and the structured security-response SLAs) are
owned by the canonical metadata registry in `ai-agent-assembly/.github`
(`metadata/org-profile.yaml`, projected to `metadata/generated/registry.json`,
per ADR 0014 / AAASM-5519). This repo previously hand-copied the security
reporting address into `SECURITY.md` and `README.md` — literals that drift
silently when the org migrates addresses.

Consumer strategy (least intrusive per artifact):

* `SECURITY.md` — two **bounded generated regions**:
  - `security_contact_email`: the canonical reporting address + legacy-alias note.
  - `security_sla`: the two SHARED SLA table rows (acknowledgement, assessment).
  The header row and the repo-specific "Patch or mitigation" row stay OUTSIDE
  the region, and the whole deployment-posture / DI-API prose is untouched.
* `README.md` — a **precise single-literal sync** of the one security email in
  the "Security & Support" bullet. No other byte of the README is rewritten.

CROSS-REPO DISTRIBUTION CONTRACT
--------------------------------
We **pin** the canonical facts to a specific `.github` commit (see
`REGISTRY_SOURCE`) rather than fetching mutable `main` at build time:
reproducible, network-free in CI, and fail-closed (a missing file or an
inconsistent pin errors rather than silently passing).

Nothing here claims the `.com` mailbox is live. The org has no Workspace tenant
yet (registry `mail_platform.*_status == planned`); the legacy `.dev` address
keeps receiving via Cloudflare Email Routing during the migration, and the
rendered note says exactly that.

Usage:
    python scripts/check_contact_metadata.py            # write/sync in place
    python scripts/check_contact_metadata.py --check     # exit non-zero on drift
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REGISTRY_SOURCE = {
    "repo": "ai-agent-assembly/.github",
    "commit": "14db28db8fa31e7a26cc29be7c1bfcd2fb0be4aa",
    "path": "metadata/generated/registry.json",
    "blob": "af1e3842984e97ca57fd0680a1f053ad6b827f04",
}

CANONICAL = {
    "security_email": "security@agent-assembly.com",
    "security_legacy_alias": "security@agent-assembly.dev",
    "sla_acknowledgement": "2 business days",
    "sla_initial_assessment": "5 business days",
}


class ContactDriftError(RuntimeError):
    """Raised when a consumed file cannot be read or is structurally wrong."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _replace_bounded(text: str, block_id: str, body: str, where: str) -> str:
    begin = f"<!-- BEGIN GENERATED: {block_id} -->"
    end = f"<!-- END GENERATED: {block_id} -->"
    b = text.find(begin)
    e = text.find(end)
    if b < 0 or e < 0 or e < b:
        raise ContactDriftError(
            f"{where}: bounded region {block_id!r} not found — expected "
            f"{begin!r} ... {end!r}"
        )
    return f"{text[: b + len(begin)]}\n{body}\n{text[e:]}"


# ---------------------------------------------------------------------------
# SECURITY.md generated bodies
# ---------------------------------------------------------------------------
def _security_email_body() -> str:
    return "\n".join(
        [
            f"Alternatively, email **{CANONICAL['security_email']}**",
            "",
            f"> **Legacy address.** `{CANONICAL['security_legacy_alias']}` remains "
            "a legacy compatibility alias. During the in-progress migration to "
            f"the canonical `{CANONICAL['security_email']}` identity, the legacy "
            "address continues to receive mail via Cloudflare Email Routing, so "
            "a report sent there still reaches us. The canonical mailbox is not "
            "yet live-sending.",
        ]
    )


def _security_sla_body() -> str:
    return "\n".join(
        [
            f"| Initial acknowledgement | Within {CANONICAL['sla_acknowledgement']} |",
            f"| Severity assessment | Within {CANONICAL['sla_initial_assessment']} |",
        ]
    )


def _security_synced(text: str) -> str:
    text = _replace_bounded(
        text, "security_contact_email", _security_email_body(), "SECURITY.md"
    )
    text = _replace_bounded(text, "security_sla", _security_sla_body(), "SECURITY.md")
    return text


# ---------------------------------------------------------------------------
# README.md — precise single-literal sync of the security email.
# ---------------------------------------------------------------------------
_README_EMAIL_RE = re.compile(
    r"(email `security@agent-assembly\.)(dev|com)(`)"
)


def _readme_synced(text: str) -> str:
    def _sub(m: re.Match[str]) -> str:
        return f"{m.group(1)}com{m.group(3)}"

    new_text, n = _README_EMAIL_RE.subn(_sub, text)
    if n != 1:
        raise ContactDriftError(
            "README.md: expected exactly one security email literal to sync, "
            f"found {n} — refusing to guess (fail closed)"
        )
    return new_text


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _consistency_guard() -> None:
    if not CANONICAL["security_email"].endswith("@agent-assembly.com"):
        raise ContactDriftError("pinned security_email is not a .com address")
    if not CANONICAL["security_legacy_alias"].endswith("@agent-assembly.dev"):
        raise ContactDriftError("pinned legacy alias is not a .dev address")


def _targets(root: Path) -> dict[Path, str]:
    security = root / "SECURITY.md"
    readme = root / "README.md"
    return {
        security: _security_synced(security.read_text(encoding="utf-8")),
        readme: _readme_synced(readme.read_text(encoding="utf-8")),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if any consumer file drifts from the pinned registry.",
    )
    args = parser.parse_args(argv)

    root = _repo_root()
    try:
        _consistency_guard()
        targets = _targets(root)
    except (ContactDriftError, FileNotFoundError, OSError) as exc:
        print(f"ERROR: contact-metadata check failed — {exc}", file=sys.stderr)
        return 2

    drifted = [
        p for p, desired in targets.items() if p.read_text(encoding="utf-8") != desired
    ]
    if not drifted:
        print("Contact metadata is in sync with the pinned registry.")
        return 0

    if args.check:
        for p in drifted:
            print(f"DRIFT: {p.relative_to(root)} does not match the registry.", file=sys.stderr)
        print("Run: python scripts/check_contact_metadata.py", file=sys.stderr)
        return 1

    for p, desired in targets.items():
        if p in drifted:
            p.write_text(desired, encoding="utf-8")
            print(f"Wrote {p.relative_to(root)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
