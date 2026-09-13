#!/usr/bin/env python3
"""Print only the key NAMES declared in a `.env`-style file — never values.

Implements the "repo-declared `.env*`/config, names-only inspection" step
of `governance/engineering/security.md`'s Credential Discovery & Safe
Consumption Protocol (HORO-980): confirm a required key is *declared*
without ever reading, printing, or logging its assigned value.

Usage:
    python3 parse_dotenv_keys.py path/to/.env

Prints one key name per line, sorted and deduplicated. Never prints a
value, a value fragment, or the content of a line it could not parse —
a malformed line is skipped silently rather than echoed, since a
malformed line could itself contain a value fragment (e.g. a stray
`=SECRET` continuation).

Parsing rules (deliberately conservative — a line only contributes a key
when it unambiguously looks like a declaration):

  * Optional leading `export ` / `export\t` prefix is stripped.
  * A key must match `[A-Za-z_][A-Za-z0-9_]*` immediately followed by `=`
    (after optional horizontal whitespace) — anything else on that
    logical line is treated as malformed and skipped.
  * Comment lines (`#...`) and blank lines are skipped.
  * Single- and double-quoted values are scanned for their closing quote
    character-by-character, INCLUDING across literal newlines inside the
    quotes (`KEY="line1\nline2"` spanning two physical lines) — this
    keeps a multi-line quoted value from being misread as a second,
    bogus `KEY` declaration or a leaked value fragment.
  * A backslash inside a double-quoted value escapes the next character
    (so `\"` does not end the quote early).
  * Duplicate keys collapse to one entry in the output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _skip_to_eol(text: str, i: int) -> int:
    """Advance past the rest of the current line, including its newline."""
    n = len(text)
    while i < n and text[i] not in "\r\n":
        i += 1
    if i < n and text[i] == "\r":
        i += 1
    if i < n and text[i] == "\n":
        i += 1
    return i


def parse_dotenv_keys(text: str) -> list[str]:
    """Return the sorted, deduplicated key names declared in `text`.

    Never returns or constructs anything derived from a value's content.
    """
    if text.startswith("﻿"):  # strip a UTF-8 BOM so it doesn't corrupt line 1's key
        text = text[1:]

    keys: set[str] = set()
    i = 0
    n = len(text)

    while i < n:
        # Skip leading horizontal whitespace.
        while i < n and text[i] in " \t":
            i += 1

        if i >= n:
            break

        # Blank line.
        if text[i] in "\r\n":
            i = _skip_to_eol(text, i)
            continue

        # Comment line.
        if text[i] == "#":
            i = _skip_to_eol(text, i)
            continue

        # Optional `export ` / `export\t` prefix.
        if text[i : i + 7] in ("export ", "export\t"):
            i += 7
            while i < n and text[i] in " \t":
                i += 1

        # Key: [A-Za-z_][A-Za-z0-9_]*
        key_start = i
        if i < n and (text[i].isalpha() or text[i] == "_"):
            i += 1
            while i < n and (text[i].isalnum() or text[i] == "_"):
                i += 1
        key = text[key_start:i]

        j = i
        while j < n and text[j] in " \t":
            j += 1

        if not key or j >= n or text[j] != "=":
            # Malformed line — skip silently, never echo its content.
            i = _skip_to_eol(text, key_start)
            continue

        i = j + 1  # past '='
        while i < n and text[i] in " \t":
            i += 1

        if i < n and text[i] == '"':
            i += 1
            while i < n:
                if text[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            keys.add(key)
            i = _skip_to_eol(text, i)
            continue

        if i < n and text[i] == "'":
            i += 1
            while i < n and text[i] != "'":
                i += 1
            if i < n:
                i += 1
            keys.add(key)
            i = _skip_to_eol(text, i)
            continue

        # Unquoted value — key is declared regardless of what follows.
        keys.add(key)
        i = _skip_to_eol(text, i)

    return sorted(keys)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="parse_dotenv_keys.py",
        description=(
            "Print only the key NAMES declared in a .env-style file, sorted "
            "and deduplicated. Never prints a value or a value fragment."
        ),
    )
    parser.add_argument("path", help="Path to the .env-style file to inspect.")
    args = parser.parse_args(argv)

    target = Path(args.path)
    if target.is_symlink():
        # Refuse a symlink outright rather than silently following it — a
        # caller-supplied path (including one an agent was tricked into
        # passing) should never be able to redirect a "read this .env file"
        # request onto an arbitrary resolved target via a symlink hop.
        print(f"error: refusing to follow symlink {args.path!r}", file=sys.stderr)
        return 1

    try:
        resolved = target.resolve(strict=True)
    except OSError as exc:
        print(f"error: could not read {args.path!r}: {exc.__class__.__name__}", file=sys.stderr)
        return 1

    if not resolved.is_file():
        print(f"error: {args.path!r} is not a regular file", file=sys.stderr)
        return 1

    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"error: could not read {args.path!r}: {exc.__class__.__name__}", file=sys.stderr)
        return 1

    for key in parse_dotenv_keys(text):
        print(key)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
