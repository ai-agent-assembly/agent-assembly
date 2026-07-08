# Shared docs metadata

A small number of values are referenced from multiple pages of this mdBook site
— the workspace runtime version, the wire protocol version, canonical URLs, the
one-line installer command. Before AAASM-4310 those values were duplicated as
literals in every page that mentioned them, and had to be updated by hand on
every release. This page tells you how to add a new shared value, or update an
existing one, without introducing docs drift.

## What lives where

| Value | Source | Rationale |
|---|---|---|
| Workspace / runtime version | `Cargo.toml` `[workspace.package].version` | Already the authoritative source for every crate; not duplicated in docs config. |
| Protocol version, canonical URLs, installer endpoints | `metadata/docs.yaml` | Not encoded elsewhere in the tree; deliberately docs-scoped. |
| Rendered snippets for pages to include | `docs/src/generated/*.md` | Checked in so `mdbook build docs` needs no Python at build time. |

The generator that ties them together lives at
[`scripts/generate_docs_metadata.py`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/scripts/generate_docs_metadata.py).

## How pages consume a snippet

Use mdBook's line-anchored include syntax so the `DO NOT EDIT` banner on line 1
of each snippet is elided from the rendered page:

```markdown
The current protocol version is **`\{{#include generated/protocol-version.md:2}}`**.
```

(The leading backslash above is an mdBook escape used only in this maintainer
note so the example itself is not preprocessed — real usage in a docs page
omits it.) The `:2` suffix means "include from line 2 to end of file". Every
snippet in `docs/src/generated/` uses this convention.

## Adding a new shared value

1. Add the key to `metadata/docs.yaml` with a short comment explaining what it
   is and why it belongs there. Keep the value on a single line, optionally
   quoted with `"` or `'`.
2. Extend `scripts/generate_docs_metadata.py` — add a `write_snippet(...)`
   call using your new key. Reuse the docstring style of the existing calls.
3. Run the generator locally:
   ```sh
   python3 scripts/generate_docs_metadata.py
   ```
4. Commit the new snippet under `docs/src/generated/` alongside your
   `docs.yaml` and generator changes.
5. Reference the snippet from a docs page with
   `\{{#include generated/<name>.md:2}}` (drop the leading backslash when
   writing the real include — it is shown here only to keep this maintainer
   note from being preprocessed).

## Updating an existing shared value

Edit the source (`metadata/docs.yaml` for docs values, `Cargo.toml` for the
workspace version), then re-run the generator and commit the regenerated
snippet in the same PR. The docs CI drift check (`.github/workflows/docs.yml`)
runs `python3 scripts/generate_docs_metadata.py` and fails on any leftover
diff in `docs/src/generated/`, so an incomplete update is caught in review.

## What must NOT be templated

- Historical release notes and per-tag notes under `docs/release/` — those
  must preserve the exact values they shipped with.
- The Compatibility Matrix rows in `docs/src/compatibility.md` — each row is
  a historical record for one release.
- The version-pinning examples in `docs/src/quick-start/installation.md` and
  the top-level `README.md` — those are guarded by
  `scripts/check-docs-versions.sh` on release-tag cut, which greps for the
  exact literal strings and would break if replaced with an include.

If you are unsure whether a value is a good candidate, ask on the docs channel
before adding it.
