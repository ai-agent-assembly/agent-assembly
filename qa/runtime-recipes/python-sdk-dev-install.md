# Runtime recipe: Python SDK — source development install

**Public-artifact vs. source-development**: this is the **source-
development** recipe. It installs the local `python-sdk/` checkout in
editable/dev mode via `uv`. It must **not** be used to satisfy a public
golden-journey check (AAASM-4522 J05 "Install the Python SDK" or J08 "Quick
Start"/J56 "Golden Path") — those verify the *published* PyPI package
(`pip install agent-assembly`). A separate published-artifact recipe is
required for those journeys; this repo did not yet have network access
budgeted in this run to verify the live PyPI path end-to-end (see "Left out"
in `qa/runtime-recipes/README.md`), so it is intentionally not claimed here.

Use this recipe for `qa-sdk-journey`'s source-development-path checks (e.g.
J32 "SDK contributor") and for diagnosing an SDK behavior against the exact
in-repo source when a published-path finding needs source-level triage.

## Preconditions

- `python-sdk/` checkout (sibling repo to `agent-assembly/`) at the SHA under
  test.
- `uv` installed.
- No secrets required.

## Install

```bash
cd python-sdk
uv sync --quiet
```

`uv sync` is idempotent against the repo's own persistent `.venv` — it does
not create a throwaway environment, so there is no cleanup step for this
recipe (unlike the CLI recipe's isolated `CARGO_TARGET_DIR`).

## Readiness observation

```bash
.venv/bin/python -c "import agent_assembly; print(agent_assembly.__name__)"
# expect: agent_assembly
.venv/bin/aasm --version
# expect: aasm <version>  (the SDK's bundled CLI entrypoint)
```

## Minimal behavior probe

```bash
.venv/bin/python -m pytest test/unit/cli/test_loader.py -q
# or any single fast, representative unit test — this is a readiness/sanity
# probe for the recipe itself, NOT a substitute for qa-sdk-journey's actual
# outside-in Quick-Start/Golden-Path behavioral verification.
```

## Cleanup

None required — `uv sync` operates on the repo's persistent dev `.venv`,
which is expected to remain for the next dev/QA session (this is the
project's normal dev-setup path per `python-sdk`'s own README, not a
QA-created throwaway).

## Platform constraints

None observed on macOS; native-core presence should be re-checked on Linux
per `python-sdk`'s own CONTRIBUTING notes if this recipe is run there.

## Verified

Executed 2026-08-22 against `python-sdk`'s checked-out HEAD: `uv sync
--quiet` completed in ~4.3s, `import agent_assembly` succeeded, `aasm
--version` printed `aasm 0.0.1rc6`. No dependency on any pre-existing
process; only precondition was the sibling checkout being present.
