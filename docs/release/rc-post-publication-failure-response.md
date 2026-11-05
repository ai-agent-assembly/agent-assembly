# rc post-publication failure response

Status: procedure, AAASM-6424. Governing decision: Core ADR 0042 (update
AAASM-6424). Applies to `-rc.N` tags only, after the tag has been pushed on a
`CANDIDATE_VERIFIED` record and a post-publication check owed by that record
reports `FAIL`.

Every pending check in a committed obligations file points at one section below
through its `failure_response` field (`docs/release/rc-post-publication-failure-response.md#<anchor>`);
`scripts/qa/check-release-evidence.py` refuses an rc record whose anchor is not a
heading in this file. The checks themselves are run by
`scripts/qa/post-publish-verify.py` against the published tag.

## What the tools report

`post-publish-verify.py` reports one of `PASS`, `FAIL` or `INCONCLUSIVE` per check.
`FAIL` means the published artifact is definitively absent or wrong.
`INCONCLUSIVE` means the probe could not tell (auth refusal, redirect, network, or no
automated runner); it is not a pass and is handled as "still owed", not as a failure.
A `PASS` proves that check's own assertion only: it does not prove the published bytes
equal the locally built candidate bytes.

## Common first steps

1. Do not announce the release. Record the result: the check id, the command output,
   the tag and the run URL of the workflow that should have produced the artifact.
2. Open a Bug sub-ticket under the Jira Story of the journey that owns the check, with
   that output attached.
3. Notify the release owner and the QA orchestrator. The deadline recorded in the
   obligations file for the rc.8 journeys is 24 hours.
4. Decide with the release owner between the two outcomes below. Neither is automatic.
   - **Repair in place**: only when the published artifact is missing or incomplete
     because a workflow step failed and the candidate itself is unchanged
     (re-trigger the workflow, then re-run the failing check).
   - **Supersede**: when published bytes are wrong, or a defect is in the candidate.
     Fix on a new candidate, cut the next rc number through
     `scripts/release-tag-guard.sh`, and treat the failed rc as withdrawn.
5. Re-run `post-publish-verify.py` for the repaired or superseding tag. A failed check
   is closed only by a later run that reports `PASS`.

## What the release mechanics allow

These are the existing mechanics; this procedure adds none.

- A tag is never moved or replaced; `release-tag-guard.sh` refuses an existing tag.
  A fix is a new tag.
- Registries never free a version number (RUNBOOK sections 1.1 and 6). crates.io, PyPI
  and npm versions cannot be republished; a bad rc is superseded by the next rc number.
- Yanking is a registry operation, not a repository one: it hides a version from new
  resolution without deleting it and without freeing the number. Any yank, unpublish or
  deletion of a published asset needs the release owner's explicit approval; the
  obligations file already states this for the rc.8 journeys.
- `release.yml` marks every tag containing `-` as a GitHub pre-release
  (`prerelease: ${{ contains(github.ref_name, '-') }}`), so an rc is already a
  pre-release; a failed rc stays a pre-release and its release notes can say it is
  withdrawn and name the superseding rc.
- RUNBOOK section 6 says a channel workflow is re-triggered with `workflow_dispatch`
  and its `release_tag` input. `release.yml`'s publish jobs are conditioned on a tag
  `push`, so whether that route re-runs them was not verified when this was written;
  re-running the failed job of the tag's own workflow run is the other route. Fix the
  cause first.

No security advisory is published by this procedure. If the failed check shows a
security defect in published bytes, that is a security incident handled by the owner
under `SECURITY.md`, not a release-check failure.

## GHCR image check fails

Applies to the `aa-gateway` and `aa-runtime` image checks (tag resolves, digest
immutable, multi-arch index, SBOM attestation, bundle contents).

- Missing tag, wrong digest or wrong platform set: repair in place by re-running the
  image publish job for the same tag (`docker.yml` publish step on the release tag),
  then re-run the failing check. Re-publishing changes which bytes the tag resolves
  to, so record the new digest in the Bug.
- A published image that is wrong rather than absent is superseded, not overwritten.
- Notify: release owner, QA orchestrator.

## GitHub release asset check fails

Applies to the release-assets check (tarballs and `SHA256SUMS` for every required
platform).

- Missing asset: re-run the `release.yml` publish stage for the tag only if the cause
  is a failed step; confirm the candidate is unchanged first.
- Wrong or mismatched asset: supersede with the next rc. The published release stays a
  pre-release; edit its notes to mark it withdrawn.
- Notify: release owner, QA orchestrator.

## Installer check fails

Applies to checks that run the published installer (`install.sh` served at
`agent-assembly.com`) against the tagged release.

- The served installer is deployed by an owner-gated step (the Cloudflare Worker in
  `infra/install-endpoint`); what is deployed is not controlled by the tag. A failure
  may be a deploy-state problem rather than a release defect: confirm which installer
  version is served before deciding. Redeploying is an owner action.
- A failure caused by the installer script in the tagged commit is superseded with the
  next rc.
- Notify: release owner, QA orchestrator.

## Homebrew tap check fails

Applies to checks of the `aasm` formula in `ai-agent-assembly/homebrew-tap`.

- `update-homebrew-tap` opens a PR; until it is merged the formula is unchanged
  (RUNBOOK section 4). An unmerged or stale tap PR is the usual cause: merge or close
  it as that section describes, then re-run the check.
- A formula that points at wrong bytes is corrected by a new tap commit through the
  tap's own PR process, never by editing the published release.
- Notify: release owner, QA orchestrator.

## Published binary or runtime check fails

Applies to checks that download published binaries or run a published image and
exercise it (golden path, health probe).

- Reproduce against the published artifact, then against the candidate artifact the
  record's digests name. A difference means the build or publish changed the bytes:
  supersede. No difference means the defect is in the candidate: supersede.
- These checks may write local state (a container runtime, a temp directory); clean up
  only what the check itself created.
- Notify: release owner, QA orchestrator.

## Who is notified

For every section above: the release owner and the QA orchestrator, within the
deadline in the obligation's `failure_response`. The owner decides yank, withdrawal or
supersession; no agent or workflow performs a yank, unpublish or deletion on its own.

## What this procedure does not do

- It does not authorize a tag or a publish; `CANDIDATE_VERIFIED` is technical
  eligibility only.
- It does not change the final-release gate: a final tag still needs checker exit 0
  with no pending checks.
- It does not record post-publication results as evidence. Evidence is immutable
  (Core ADR 0037); a post-publication `PASS` needs a new evidence attempt, which is not
  built yet.
