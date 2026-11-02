# Assembling the publication obligations file (B1)

Status: procedure note, AAASM-6419. Governing decision: Core ADR 0042
(`docs/src/adr/0042-publication-pending-release-evidence.md`) and the founder
decision for B1: no blanket waiver for J04, J08, J17, J53, J56 and J59. Each is
split into candidate checks (bound to the candidate SHA and artifact digests)
and publication-dependent checks, recorded `PENDING`, never `PASS`.

This note describes how the rc.8 obligations file will be built. It is not that
file, and no rc.8 evidence exists yet: the file needs the final candidate SHA and
the digests of the final candidate artifacts, which do not exist before the
candidate freeze.

## What the registry already fixes

`qa/golden-journeys.yaml` declares `publication_checks` (`id`, `channel`,
`summary`) for the six journeys. The obligation's `pending_checks` ids must equal
those ids exactly, and `id|channel|summary` feed the journey's registry digest, so
the owed checks cannot be added, dropped or renamed without a registry change that
drifts R2. The command, expected result and `failure_response` are not in the
registry; they live only in the obligation file.

| Journey | Pending ids come from | Candidate harness |
|---|---|---|
| J04, J17 | `scripts/qa/b1/candidate_harness.py` (PR #2801) | exists |
| J53, J59 | `scripts/qa/j53-candidate-harness.py`, `j59-candidate-harness.py` (PR #2803) | exists |
| J08, J56 | provisional ids, no harness emits them | none (blocked on D5 / python-sdk #387 and the SDK pin) |

## Procedure, after the final candidate freeze

1. Fix the candidate commit and build the candidate artifacts. Record the SHA and
   the artifact set; do not proceed on a moving candidate.
2. Run each harness against the final candidate. J04/J17 print one JSON result
   per journey and exit 0 only when every candidate check passed and nothing was
   skipped; J53/J59 write a `b1-candidate-report/1` report. Keep a fragment only
   from a run that reached `CANDIDATE_VERIFIED` (J04/J17: exit 0,
   `CANDIDATE_PASS_PUBLICATION_PENDING`). A failed, incomplete or unpinned-control
   run yields no fragment.
3. Take each journey's `obligation_fragment` and complete it:
   - `registry_digest`: `registry_digest.per_journey_digest(entry)` for the
     journey's registry entry at the candidate commit. J04/J17 fragments carry
     `null` here (listed in `_unfilled`); J53/J59 omit it.
   - `depends_on`: J04/J17 carry `null` and need `{repo, event}` entries; J53/J59
     supply them.
   - Remove the harness-only keys (`_unfilled`, `_note`).
   - Pending statuses in a J04/J17 fragment are already `PUBLICATION_PENDING`;
     `publication_obligations.validate_obligation` does not read that field.
4. Write `{"journeys": [...]}` to
   `docs/release/qa-signoff/v0.0.1-rc.8.publication-obligations.json`, one entry
   per journey, and check every entry with `publication_obligations.validate_obligation`
   against the registry entry before committing. No assembler script exists; do
   not hand-edit digests or statuses.
5. The QA sign-off marks each such row `PUBLICATION_PENDING` and the verdict
   `CANDIDATE_VERIFIED`. `build-release-evidence.py` embeds the obligation and
   stamps `candidate_sha`; `check-release-evidence.py` then exits 3, never 0.

A journey with no admissible obligation cannot be pending. J08 and J56 have no
harness, so until one exists their candidate checks are NOT_COVERED and the rc.8
record is `BLOCK` for them. A waiver is not the substitute. The same applies to
J59 while its harness reports any step NOT_COVERED, because that harness withholds
its fragment in that case.

## Two commits: code freeze F and candidate commit C

The checker reads the obligation file at the candidate commit and at the tag target
and blocks unless the two are byte-identical ("the obligation must be final at the
candidate"), so the file has to be committed at or before the commit named as
`candidate_sha` in the evidence. The harnesses need a checkout whose HEAD is the commit
they are told about (J04/J17 compare the installer, policy and harness files byte for
byte against `--candidate-sha`) and they only produce a fragment after they run.

This is resolved by using two commits, as Core ADR 0037 already does for sign-offs:

- **F, the code freeze.** The artifacts are built from F and the harnesses run with
  `--candidate-sha F`. Their fragments record the artifact digests of that build.
- **C, the candidate commit.** A docs-only commit on top of F that adds the final
  sign-off and `v0.0.1-rc.8.publication-obligations.json`. The evidence names C as
  `candidate_sha` (the commit that contains the final sign-off).

This works because an obligation entry in the file carries no `candidate_sha`
(`check-release-evidence.py` compares the embedded obligation to the file entry with
that key removed) and `build-release-evidence.py` stamps C onto the embedded copy.
The file is therefore not self-referential. The cost is that C must change nothing the
harnesses tied to F (the installer, the policy and the harness sources), which the
harness check on F already proves for the files it reads. This reading follows the
checker and builder code; it has not been exercised end to end on a real candidate.

## After publication

Evidence is immutable (Core ADR 0037). Recording a post-publication result is a new
evidence attempt, not an edit of the pending record, and no appender exists yet.
`scripts/qa/post-publish-verify.py` (PR #2803) has allowlisted runners only for the
J53/J59 GHCR and release-asset ids (the J53 run-healthy and J59 published-binaries
checks are manual and report INCONCLUSIVE); the J04/J17 pending ids carry shell
commands and, as of that PR, have no runner, so it reports them INCONCLUSIVE. Each pending
check's `failure_response` in the obligation file says what to do when it fails.
