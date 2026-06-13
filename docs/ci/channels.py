"""Doc-versioning channel computation (AAASM-2752).

This module is the single source of truth for how the Docs workflow turns the
full set of published versions (prior live manifest + committed source manifest
+ the version being cut this run) into the ``versions.json`` consumed by the
mdBook version selector and warning banner.

It is factored out of ``.github/workflows/docs.yml`` so the channel logic --
in particular the **pre-release semver gate** -- is unit-testable without a
GitHub Actions run.

The semver gate (THE RULE):

    The ``pre-release`` channel entry is emitted ONLY IF the newest pre-release
    version is strictly greater (by SemVer precedence) than the newest stable
    version. Otherwise no ``pre-release`` channel is emitted -- that version
    stays reachable in ``archived[]`` but is not surfaced as a moving channel.

    - ``X.Y.Z-<pre>`` < ``X.Y.Z`` (a pre-release precedes its release).
    - Pre-release identifiers compare per SemVer §11: numeric identifiers
      compare numerically, alphanumeric identifiers compare in ASCII order,
      numeric < alphanumeric, and a larger set of fields (when all preceding
      are equal) is greater. This yields ``alpha < beta < rc``.
    - When there is no stable version, any pre-release is shown.

The channel set is recomputed from the FULL version set every run, so when a
stable release supersedes the newest pre-release the pre-release channel simply
disappears from ``channels[]`` on the next computation.
"""

from __future__ import annotations

import re
from typing import Any

# A parsed version tag: (major, minor, patch, pre) where pre is the tuple of
# dot-separated pre-release identifiers, or None for a stable release.
ParsedVersion = tuple[int, int, int, tuple[str, ...] | None]
# A channel entry as it appears in versions.json: {"id", "title", "target"}.
Channel = dict[str, str]
# An archived entry in versions.json: {"id", "title"}.
Archived = dict[str, str]
# A parsed versions.json manifest (loosely typed; values come from JSON).
Manifest = dict[str, Any]

# A release version tag: vX.Y.Z optionally followed by -<pre>.
_VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)(?:-(.+))?$")


def parse_version(tag: object) -> ParsedVersion | None:
    """Parse a ``vX.Y.Z[-pre]`` tag into a structured tuple.

    Returns ``(major, minor, patch, pre)`` where ``pre`` is ``None`` for a
    stable release or a tuple of dot-separated identifiers for a pre-release.
    Returns ``None`` when ``tag`` is not a recognised version tag.
    """
    if not isinstance(tag, str):
        return None
    m = _VERSION_RE.match(tag)
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    pre_ids = tuple(pre.split(".")) if pre else None
    return (int(major), int(minor), int(patch), pre_ids)


def _pre_identifier_key(identifier: str) -> tuple[int, int, str]:
    """SemVer §11 ordering key for a single pre-release identifier.

    Numeric identifiers always have lower precedence than alphanumeric ones, so
    numeric identifiers are tagged ``0`` and compared as integers, alphanumeric
    identifiers are tagged ``1`` and compared as ASCII strings.
    """
    if identifier.isdigit():
        return (0, int(identifier), "")
    return (1, 0, identifier)


def _compare_pre(a_pre: tuple[str, ...] | None, b_pre: tuple[str, ...] | None) -> int:
    """Compare two pre-release field tuples per SemVer §11.

    ``None`` means "no pre-release" (a stable release), which has *higher*
    precedence than any pre-release. Returns -1, 0, or 1.
    """
    if a_pre is None and b_pre is None:
        return 0
    # A version without a pre-release outranks one with a pre-release.
    if a_pre is None:
        return 1
    if b_pre is None:
        return -1
    for a_id, b_id in zip(a_pre, b_pre):
        ka, kb = _pre_identifier_key(a_id), _pre_identifier_key(b_id)
        if ka < kb:
            return -1
        if ka > kb:
            return 1
    # All shared identifiers equal: the larger set of fields wins.
    if len(a_pre) < len(b_pre):
        return -1
    if len(a_pre) > len(b_pre):
        return 1
    return 0


def compare_versions(a: str, b: str) -> int:
    """Compare two ``vX.Y.Z[-pre]`` tags by SemVer precedence.

    Returns -1 if ``a < b``, 0 if equal, 1 if ``a > b``. A version that does not
    parse sorts below any parseable version (and ties with other unparseable
    versions), so the gate degrades safely rather than raising.
    """
    pa, pb = parse_version(a), parse_version(b)
    if pa is None and pb is None:
        return 0
    if pa is None:
        return -1
    if pb is None:
        return 1
    a_core, b_core = pa[:3], pb[:3]
    if a_core < b_core:
        return -1
    if a_core > b_core:
        return 1
    return _compare_pre(pa[3], pb[3])


def channel_title(cid: str, target: str) -> str:
    """Build a human-readable channel title for ``cid`` pointing at ``target``."""
    if cid == "latest":
        return "latest (master)"
    if cid == "stable":
        return f"stable ({target})"
    if cid == "pre-release":
        return f"pre-release ({target})"
    return cid


def _archived_sortkey(item: Archived) -> tuple[int, int, int, str]:
    """Build a newest-first archived ordering key (a release sorts after its pres)."""
    parsed = parse_version(item["id"])
    if parsed is None:
        return (0, 0, 0, "")
    major, minor, patch, pre = parsed
    # release (no pre) sorts after its pre-releases at the same x.y.z
    return (major, minor, patch, ".".join(pre) if pre else "~")


def apply_pre_release_gate(channels: dict[str, Channel]) -> dict[str, Channel]:
    """Drop the pre-release channel unless it leads the stable channel.

    Mutates and returns the ``channels`` dict (id -> {id,title,target}). The
    pre-release entry is kept only when no stable channel exists, or when the
    pre-release target is strictly greater than the stable target by SemVer
    precedence.
    """
    pre = channels.get("pre-release")
    stable = channels.get("stable")
    if pre is None or stable is None:
        return channels
    if compare_versions(pre.get("target", ""), stable.get("target", "")) <= 0:
        del channels["pre-release"]
    return channels


def compute_versions(
    version: str,
    channel: str,
    prior: Manifest | None = None,
    source: Manifest | None = None,
    extra_archived: list[str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Compute the published ``versions.json`` document for one docs cut.

    Parameters
    ----------
    version:
        The concrete subpath being published this run (e.g. ``"v0.1.0-rc.1"``)
        or ``"latest"`` for a master-push cut.
    channel:
        The channel being cut: ``"latest"``, ``"stable"`` or ``"pre-release"``.
    prior:
        The previously-published live manifest (parsed ``versions.json``), or
        ``None`` on first deploy.
    source:
        The committed ``docs/versions.json`` source manifest, or ``None``.
    extra_archived:
        Additional version ids to seed into ``archived[]`` (e.g. the full list
        of release git tags reachable at the time of the cut). The workflow
        rebuilds a versioned subpath for every git tag on every deploy, so
        ``extra_archived`` makes ``versions.json`` self-healing against a
        prior live manifest that has lost entries (AAASM-2827). Unrecognised
        version strings are dropped silently.

    Returns a dict ``{"channels": [...], "archived": [...]}`` with channels in
    display order (latest, pre-release, stable) and archived newest-first. The
    pre-release semver gate is applied to the fully-assembled channel set.
    """
    channels: dict[str, Channel] = {}  # id -> {id,title,target}
    archived: dict[str, Archived] = {}  # id -> {id,title}

    # Seed from the prior live manifest.
    if isinstance(prior, dict):
        for c in prior.get("channels", []):
            if isinstance(c, dict) and c.get("id") and c.get("target"):
                channels[c["id"]] = {
                    "id": c["id"],
                    "title": c.get("title") or channel_title(c["id"], c["target"]),
                    "target": c["target"],
                }
        for a in prior.get("archived", []):
            if isinstance(a, dict) and a.get("id"):
                archived[a["id"]] = {"id": a["id"], "title": a.get("title") or a["id"]}

    # Seed the committed source manifest (ensures `latest` always exists).
    if isinstance(source, dict):
        for c in source.get("channels", []):
            if isinstance(c, dict) and c.get("id") and c.get("target"):
                channels.setdefault(
                    c["id"],
                    {
                        "id": c["id"],
                        "title": c.get("title") or channel_title(c["id"], c["target"]),
                        "target": c["target"],
                    },
                )

    # Seed extra archived entries supplied by the workflow (typically the full
    # list of release git tags). This is the authoritative source of truth: if
    # the prior live manifest lost an entry but its tag still exists in git,
    # this restores it on the next cut.
    if extra_archived:
        for tag in extra_archived:
            if isinstance(tag, str) and parse_version(tag) is not None:
                archived.setdefault(tag, {"id": tag, "title": tag})

    # Always guarantee a latest channel.
    channels.setdefault(
        "latest", {"id": "latest", "title": "latest (master)", "target": "latest"}
    )

    # Apply this cut.
    if channel == "latest":
        channels["latest"] = {
            "id": "latest",
            "title": "latest (master)",
            "target": "latest",
        }
    else:
        # Repoint the moving channel to this concrete tag and archive it.
        channels[channel] = {
            "id": channel,
            "title": channel_title(channel, version),
            "target": version,
        }
        archived[version] = {"id": version, "title": version}

    # Gate the pre-release channel on the full, recomputed channel set.
    apply_pre_release_gate(channels)

    # Order channels: latest, pre-release, stable (priority/display order).
    channel_order = ["latest", "pre-release", "stable"]
    ordered_channels = [channels[c] for c in channel_order if c in channels]

    ordered_archived = sorted(archived.values(), key=_archived_sortkey, reverse=True)

    return {"channels": ordered_channels, "archived": ordered_archived}
