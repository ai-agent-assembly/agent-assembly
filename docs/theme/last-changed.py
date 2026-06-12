#!/usr/bin/env python3
"""mdBook preprocessor that appends a per-page git "last updated" footer.

For every chapter with a non-null source path, this preprocessor runs
``git log -1`` against that file and appends a footer of the form::

    ---

    *Last updated: 2026-06-12 by <committer>*

The preprocessor's working directory is the book root (``docs/``), so source
paths are resolved relative to ``src/``. Pages with no git history (for
example, newly created files not yet committed) are left untouched.

mdBook preprocessor protocol:

* ``<cmd> supports <renderer>`` -> exit 0 (this preprocessor supports every
  renderer).
* Otherwise read ``[context, book]`` as a JSON array from stdin, mutate
  ``book``, and print the modified ``book`` object as JSON to stdout.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import Any


def git_last_changed(path: str) -> tuple[str, str] | None:
    """Return ``(date, author)`` for the last commit touching ``src/<path>``.

    Returns ``None`` when the file has no git history or git is unavailable.
    The date is the committer date in ``YYYY-MM-DD`` form (``%cs``) and the
    author is the human author name (``%an``); the two are separated on the
    git side by an ASCII unit separator (``\\x1f``) so neither field can be
    confused with the other.
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%cs%x1f%an", "--", f"src/{path}"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    output = result.stdout.strip()
    if not output or "\x1f" not in output:
        return None

    date, author = output.split("\x1f", 1)
    if not date or not author:
        return None
    return date, author


def append_footer(content: str, date: str, author: str) -> str:
    """Append the last-updated footer to a chapter's markdown ``content``."""
    return f"{content}\n\n---\n\n*Last updated: {date} by {author}*\n"


def process_chapter(chapter: dict[str, Any]) -> None:
    """Append the footer to ``chapter`` in place and recurse into sub-items."""
    path = chapter.get("path")
    if isinstance(path, str) and path:
        changed = git_last_changed(path)
        if changed is not None:
            date, author = changed
            content = chapter.get("content")
            if isinstance(content, str):
                chapter["content"] = append_footer(content, date, author)

    for sub_item in chapter.get("sub_items", []):
        process_item(sub_item)


def process_item(item: Any) -> None:
    """Process one ``book["items"]`` entry.

    An item is either a dict keyed ``"Chapter"`` (the only kind carrying
    content), or a ``"PartTitle"`` / ``"Separator"`` marker which is ignored.
    """
    if isinstance(item, dict) and "Chapter" in item:
        process_chapter(item["Chapter"])


def main() -> None:
    """Entry point implementing the mdBook preprocessor protocol."""
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)

    _context, book = json.load(sys.stdin)
    for item in book.get("items", []):
        process_item(item)
    json.dump(book, sys.stdout)


if __name__ == "__main__":
    main()
