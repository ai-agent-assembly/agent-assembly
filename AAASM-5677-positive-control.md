# AAASM-5677 — positive control (round 2)

Not for merge.

The first positive control used `verification-reports/AAASM-5677-positive-control.md`.
That was valid when it ran and is no longer: closing acceptance criterion 3
brought `verification-reports/**/*.md` inside `docs.yml`'s router, so that file
now matches a router glob and can no longer demonstrate the property.

This file sits at the repository root and was checked against all 108 router
globs across the six governance-bearing workflows, using picomatch itself: it
matches none of them.

**What must hold:** all six aggregate checks report a conclusion with every
gated job skipped. An *absent* check cannot be required — it would block the
pull request forever, which is the trap #2014 closed.
