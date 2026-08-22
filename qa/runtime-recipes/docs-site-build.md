# Runtime recipe: docs site (mdBook) local build

Used by `qa-reliability-docs` for doc/command integrity checks (J21) and by
`qa-design` when a live local preview is needed for a docs-site design check.
This is a **local build**, not the published docs site — for J21's "every
documented command and internal link works" checks, prefer this local build
(faster, always matches the exact SHA under test) over hitting the deployed
site.

## Preconditions

- `agent-assembly/docs/` checkout at the SHA under test.
- `mdbook` installed (and `mdbook-mermaid` if the book uses Mermaid
  preprocessing — a preprocessor-version mismatch warning is non-fatal and
  does not block the build).

## Build

```bash
cd agent-assembly/docs
mdbook build --dest-dir "$(mktemp -d)"   # never write into a shared/committed path
```

## Readiness observation

Build exits 0 and `<dest-dir>/index.html` exists.

## Minimal behavior probe

```bash
test -f "$DEST_DIR/index.html" && echo ready
# for a link/command integrity check, grep the rendered HTML or the source
# docs/src/*.md for the specific command/link under test — see
# docs/src/qa/evidence-and-worker-result-contract.md's docs-contract lane.
```

For a live-preview design check instead of a static build:

```bash
mdbook serve --dest-dir "$(mktemp -d)" --port 0   # port 0 = OS picks a free port, avoids clashing with a dev server
```

Read the actual bound port from mdbook's own startup log line rather than
assuming a fixed port — do not bake a specific port number into this recipe
or a committed script (would collide with a concurrent local dev server).

## Cleanup

```bash
rm -rf "$DEST_DIR"   # or Ctrl-C / kill the `mdbook serve` process for the live-preview form
```

## Platform constraints

None observed — pure static-site tooling.

## Verified

Executed 2026-08-22 against `remote/main` (`ce4638405`): `mdbook build` to a
throwaway temp dest completed in ~4.5s, `index.html` present, cleanup
removed the temp dir. The one non-fatal warning (`mdbook-mermaid` built
against an older mdbook version than the one running) is tracked as a known
non-blocking signal, not treated as a build failure.
