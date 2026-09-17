# Post-release certification — v<version>

> Reusable post-release test specification + per-release plan/report artifact
> (AAASM-6121). Runs **after** `/release-validate-channels` (which is one
> *input* to this campaign, not the entirety of it) against the ACTUALLY
> PUBLISHED artifacts users receive — not a local build, not the source tree.
>
> **Copy this file to `v<version>.md`** and fill it in. This `TEMPLATE.md` is
> the spec + template only.
>
> This is evidence, not a transcript: literal commands + their output for
> every row, not narrative confidence language.

## What every published AASM release must prove (reusable spec)

Distinguish these states explicitly per channel/artifact — never collapse
them into "released":

| State | Meaning |
|---|---|
| `PUBLISHED` | Artifact exists at the registry/channel under the release version |
| `INSTALLABLE` | A clean environment can fetch/install it by explicit version |
| `EXECUTABLE` | The installed artifact runs (binary executes, package imports) |
| `FUNCTIONALLY_VERIFIED` | A representative real operation succeeds against it |
| `SECURITY_VERIFIED` | Checksum/provenance/signature verified; no packaging-introduced privilege/secret regression |
| `CHANNEL_INCOMPLETE` | Published but the channel's normal default-install path is broken/stale (e.g. dist-tag) |

At minimum, every release must prove, where the channel applies:

- published-artifact identity/provenance (checksums, cosign, R9/R10 post-publish evidence);
- GitHub Release (assets present, correct SHA, not draft, prerelease flag correct);
- crates.io (every publishable crate's latest `vers` = release version);
- PyPI (active release, full wheel matrix, no yanked shadow above it);
- npm (all packages at explicit version; `rc`/channel dist-tag correct;
  default/`latest` dist-tag state reported separately — never silently
  assumed correct. **Release-type-aware `latest` PASS criteria** — see
  node-sdk's `docs/release/npm-dist-tags.md` for the authoritative, durable
  contract this criteria mirrors:
    - **Pre-GA / pre-1.0 project, RC or pre-release:** PASS when `latest`
      equals the *highest published SemVer version across every channel*
      (this is a deliberate policy, not a placeholder — freezing `latest`
      before any GA exists would make a bare `npm install <pkg>` resolve to
      an ancient pre-release, which is the AAASM-3840/4730/4994 bug class).
    - **Post-GA project, any release:** PASS when `latest` equals the
      current stable GA and an RC publish leaves it untouched — the
      pre-GA policy above converges to this automatically via SemVer
      precedence, no separate logic needed.
  A project not yet at 1.0 does **not** get flagged for "RC shouldn't be
  latest" — that's the wrong contract for it; check which contract this
  project has actually adopted before asserting PASS/FAIL.);
- Homebrew (formula version + sha256s match the release `SHA256SUMS`);
- GHCR (expected image tags present, `latest` moved where applicable);
- SDK consumers (representative install/import/basic call from the *published* artifact, not a workspace-local dependency);
- clean install / explicit-version install;
- upgrade from the immediately preceding supported release, preserving user configuration;
- repair / uninstall / remove / rollback, non-destructively;
- cross-channel version + provenance consistency;
- package metadata/dependencies sane (no stale pin, no scope-broadening);
- privilege boundaries (install/package scripts gain no unintended privilege, mutate no unrelated host config);
- smallest meaningful post-release adversarial/security assertion for release-critical guarantees actually shipped this release;
- cleanup (no leftover process/state from the certification run itself).

**PASS/FAIL/NOT_MEASURED/EXTERNAL_UNAVAILABLE semantics:**

- `PASS` — the check ran against a real published artifact and the assertion held.
- `FAIL` — the check ran and the assertion did not hold; always gets a linked finding.
- `NOT_MEASURED` — the check was not executed this campaign (say why: infra constraint, deliberately deferred, deprioritized). Never silently omitted — must appear in the matrix as a row.
- `EXTERNAL_UNAVAILABLE` — the check could not run because of a third-party/infra condition outside engineering control (e.g. no disposable Windows runner on hand). Distinguish from a genuine credential/process defect, which is `FAIL` on a release-ops finding, not `EXTERNAL_UNAVAILABLE`.

**Evidence requirement:** every PASS/FAIL row carries the literal command run
and its output (or a pointer to a linked finding for FAIL), never a bare
verdict.

## Per-release instantiation — v<version>

- **Tag / candidate merge SHA:** `<sha>`
- **Previous certified release:** `<prev>`
- **Channels/packages in scope:** <list>
- **Environment matrix:** <clean/disposable environments used>
- **Test ordering:** <read-only channel probes first, then install/functional, then security/adversarial, then cleanup>
- **Known constraints / exceptions this run:** <list>
- **Stop/escalation conditions:** continuing would destroy/invalidate evidence; continuing is unsafe; a release-wide invariant broke; a required human credential/privileged action blocks the next step; a patch RC is provably required.

## Channel certification matrix

| Channel | Published | Install tested | Runtime tested | Security tested | Upgrade tested | Cleanup tested | Provenance verified | Findings | Disposition |
|---|---|---|---|---|---|---|---|---|---|

## Findings

| Severity | Finding | Jira | Status |
|---|---|---|---|

## Verdict

Verdict: <one of POST_RELEASE_CERTIFIED | CERTIFIED_WITH_NON_BLOCKING_FOLLOWUPS | REQUIRES_PATCH_RC | CHANNEL_INCOMPLETE | RELEASE_REGRESSION_FOUND>
