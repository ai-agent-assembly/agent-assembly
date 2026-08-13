# design/v3 — hi-fi handoff

Anticipated by ADR-0025 and ADR-0027 as the next design handoff after `design/v2`.
This first v3 drop is scoped to the **login / authentication** surface (AAASM-5438).

## Why v3 exists

The OSS dashboard login page (`dashboard/src/pages/LoginPage.tsx`) previously cited
its design source as `agent-assembly-cloud/design/hi-fi/saas-shell.jsx` — a file in
a **different repo** that OSS design-QA cannot resolve. `design/v2/hi-fi/` carries
only `shell.jsx` (no login). v3 brings the login design in-repo so design-QA has an
authoritative source.

## Contents

- `hi-fi/login.jsx` — the authoritative login hi-fi. The surface is driven by
  `GET /api/v1/auth/methods` (ADR 0031 D2/§Q5) and has two authoritative states:
  - **State A** `methods=["api_key"]` (in-memory/SQLite): API-key field + a note
    that account login needs Postgres. No password form.
  - **State B** `methods=["api_key","password"]` (Postgres): two-tab Sign in /
    Sign up (email + password), API-key fallback link.

## Hard constraints (ADR 0031 D4)

- No OAuth / social login (no Google/GitHub button) anywhere.
- No "or continue with email" divider.
- Sign-up collects **email + password only** — no workspace / organisation /
  team-name field (OSS is single-workspace).
- The API-key path is always reachable.

## Verification status

Both states were real-user verified against a live server on 2026-08-03
(State A: shipped `aa-api-server`; State B: the Postgres QA harness) — the running
UI matches this handoff. Design-QA should assert future changes against this file.
