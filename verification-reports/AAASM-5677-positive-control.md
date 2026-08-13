# AAASM-5677 — positive control

Not for merge. This file exists so a pull request can change exactly one path
that matches **no** router filter of any governance-bearing workflow.

Before AAASM-5677, a pull request of this shape produced only CodeQL check runs
(PR #1976 was measured at 6, all CodeQL). After it, every governance-bearing
workflow must still deliver its aggregate check with a real conclusion. If any
of them is absent, the required check would never arrive and the pull request
would block forever — the trap #2014 fixed and this ticket must not reopen.
