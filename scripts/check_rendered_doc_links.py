"""Fail on any internal link that 404s in the *rendered* mdBook. AAASM-6213.

WHY A SECOND LINK CHECK EXISTS

`scripts/check-doc-links.sh` resolves every repo-relative Markdown link
against the working tree. That is the right check for the regression it was
written for (AAASM-4635 / AAASM-4670) and it is not the check this one makes:
source-tree validity and rendered-book validity are different properties.
A link can exist in the tree and still 404 for every reader, because mdBook
applies rendering rules the source-level gate does not model:

  * mdBook renders exactly the chapters `SUMMARY.md` names. A page that
    lives under `docs/src/` but is absent from `SUMMARY.md` renders
    nowhere, and `mdbook build` exits 0 without a warning. The orphan gate
    cannot see it either -- `book.toml` sets `src = "src"`, and
    `scripts/check-doc-orphans.sh` only considers Markdown *outside* the
    render root.
  * mdBook renders `foo/README.md` to `foo/index.html`, but emits a source
    link whose target is `foo/README.md` verbatim as `foo/README.html` --
    a file it never produces.
  * A link that leaves the render root (`../../.claude/skills/x/SKILL.md`,
    `../../aa-sandbox/README.md`) has its extension rewritten to `.html`;
    the target was never rendered into the book, so it 404s.

AAASM-6213 measured 38 such dangling occurrences across 16 published pages
resolving to 14 distinct missing targets, none of them visible to any gate.

WHAT THIS SCRIPT CHECKS

It crawls the *build output* and fails if any relative `href` names a path
that is not present in the build directory. Because it reads what readers
actually get, it cannot drift from the published artefact, and it closes all
three classes above with one rule. It deliberately keys on dangling links and
not on `SUMMARY.md` membership: the six `docs/src/generated/*.md` files are
include snippets rather than chapters, nothing links to them as pages, and a
membership rule would wrongly demand they be published.

WHAT IT CANNOT SEE

Only internal links. External URLs are skipped, so there is no network call
and the check is deterministic. Anchor fragments are not resolved -- a link to
a real page with a stale `#section` still passes. `print.html` is skipped
because it concatenates every chapter, so each dangling link in the book would
otherwise be reported a second time from there.

Zero network access. Reads local build output only.

Run from the repo root:  python3 scripts/check_rendered_doc_links.py docs/book
Self-test (anti-vacuity): python3 scripts/check_rendered_doc_links.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote

# `href` in an HTML tag, single- or double-quoted.
HREF = re.compile(r"""href\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)

# Script and style bodies are stripped before extraction. mdBook's own theme
# JS builds hrefs by concatenation -- `href="' + stableHref + '"` -- which is
# not a link and would otherwise be reported as a dangling target on every
# page in the book.
INERT_BODY = re.compile(r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL)

# Anything with a scheme, a protocol-relative host, or a bare fragment is not
# ours to resolve.
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//|#)", re.IGNORECASE)

# Concatenated over every chapter, so its links duplicate the per-page ones.
SKIP_PAGES = {"print.html"}


def page_links(html: str) -> list[str]:
    """Every quoted `href` value outside a script or style body."""
    inert_stripped = INERT_BODY.sub("", html)
    return [double or single for double, single in HREF.findall(inert_stripped)]


def resolve(book: Path, page: Path, href: str) -> Path | None:
    """The file a reader lands on, or None if the link is not ours to resolve.

    A directory target resolves to its `index.html`, which is what mdBook
    generates for a `README.md` chapter.
    """
    if EXTERNAL.match(href):
        return None
    target = unquote(href.split("#", 1)[0].split("?", 1)[0])
    if not target:
        return None
    # Root-absolute is resolved against the book root. The published site
    # serves this book under a version subpath, so such a link is broken for
    # a reader even when the file exists -- resolving it here still reports
    # it, because the path below the root will not match.
    base = book if target.startswith("/") else page.parent
    resolved = (base / target.lstrip("/")).resolve()
    if resolved.is_dir():
        resolved = resolved / "index.html"
    return resolved


def dangling(book: Path) -> list[tuple[Path, str, str]]:
    """(referring page, href, why) for every link that does not resolve."""
    book = book.resolve()
    found: list[tuple[Path, str, str]] = []
    for page in sorted(book.rglob("*.html")):
        if page.name in SKIP_PAGES:
            continue
        for href in page_links(page.read_text(encoding="utf-8", errors="replace")):
            resolved = resolve(book, page, href)
            if resolved is None:
                continue
            if not resolved.is_relative_to(book):
                found.append((page, href, "leaves the rendered book"))
            elif not resolved.exists():
                found.append((page, href, "no such file in the build output"))
    return found


def report(book: Path) -> int:
    book = book.resolve()
    if not book.is_dir():
        print(f"::error::check-rendered-doc-links: no build output at {book}", file=sys.stderr)
        return 1
    pages = [p for p in book.rglob("*.html") if p.name not in SKIP_PAGES]
    if not pages:
        print(
            f"::error::check-rendered-doc-links: {book} contains no HTML pages; "
            "did `mdbook build` run?",
            file=sys.stderr,
        )
        return 1
    found = dangling(book)
    for page, href, why in found:
        print(
            f"::error file={page.relative_to(book.parent.parent)}::"
            f"dangling link in the rendered book -> {href} ({why})",
            file=sys.stderr,
        )
    if found:
        targets = sorted({href for _, href, _ in found})
        print(
            f"check-rendered-doc-links: {len(found)} dangling occurrence(s) over "
            f"{len({p for p, _, _ in found})} page(s), {len(targets)} distinct target(s)",
            file=sys.stderr,
        )
        return 1
    print(f"check-rendered-doc-links: every internal link in {len(pages)} rendered page(s) resolves")
    return 0


def selftest() -> int:
    """Prove the check fails when a rendered link is broken, and why.

    A gate that only ever passes proves nothing, so this builds a miniature
    book in a temporary directory and asserts each rule fires on its own
    minimal case -- and that the clean case still passes.
    """
    cases: list[tuple[str, dict[str, str], int, str | None]] = [
        (
            "clean book passes",
            {
                "index.html": '<a href="guide/index.html">guide</a>',
                "guide/index.html": '<a href="../index.html">home</a>',
            },
            0,
            None,
        ),
        (
            "a README link mdBook never renders is caught",
            {
                "index.html": '<a href="guide/README.html">guide</a>',
                "guide/index.html": "<p>guide</p>",
            },
            1,
            "guide/README.html",
        ),
        (
            "a chapter missing from SUMMARY.md is caught via the link to it",
            {"index.html": '<a href="adr/0038-leases.html">ADR 0038</a>'},
            1,
            "adr/0038-leases.html",
        ),
        (
            "a link that leaves the rendered book is caught",
            {"qa/policy.html": '<a href="../../.claude/skills/x/SKILL.html">skill</a>'},
            1,
            "../../.claude/skills/x/SKILL.html",
        ),
        (
            "a directory target resolves through index.html",
            {
                "index.html": '<a href="guide/">guide</a>',
                "guide/index.html": "<p>guide</p>",
            },
            0,
            None,
        ),
        (
            "an href built by theme JS is not mistaken for a link",
            {"index.html": "<script>el.innerHTML = '<a href=\"' + h + '\">x</a>';</script>"},
            0,
            None,
        ),
        (
            "an external URL is left alone",
            {"index.html": '<a href="https://example.invalid/missing.html">x</a>'},
            0,
            None,
        ),
    ]

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for i, (name, files, want, want_target) in enumerate(cases):
            book = Path(tmp) / f"case{i}"
            for rel, body in files.items():
                path = book / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            found = dangling(book)
            got = 1 if found else 0
            if got != want:
                print(f"selftest FAILED: {name}: expected exit {want}, got {got} ({found})")
                failures += 1
                continue
            if want_target is not None:
                hrefs = [href for _, href, _ in found]
                if want_target not in hrefs:
                    print(f"selftest FAILED: {name}: {want_target} not named in {hrefs}")
                    failures += 1
                    continue
                pages = {p.name for p, _, _ in found}
                if not pages:
                    print(f"selftest FAILED: {name}: the referring page is not reported")
                    failures += 1
                    continue
            print(f"selftest ok: {name}")

    if failures:
        print(f"::error::check-rendered-doc-links selftest: {failures} case(s) failed", file=sys.stderr)
        return 1
    print(f"check-rendered-doc-links selftest: {len(cases)} case(s) behave as specified")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "book",
        nargs="?",
        default="docs/book",
        help="the mdBook build output directory (default: docs/book)",
    )
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove the check fails on a deliberately broken link, then exit",
    )
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    return report(Path(args.book))


if __name__ == "__main__":
    sys.exit(main())
