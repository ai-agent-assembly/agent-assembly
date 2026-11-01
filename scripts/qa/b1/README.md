# B1 staged artifact verification: J04 / J17 candidate harness

Founder decision (AAASM-6419, B1): journeys J04 and J17 get no blanket waiver.
Each is split into pre-publication CANDIDATE checks that run now against the
final local candidate artifacts, and checks that truly need published artifacts,
which are recorded `PENDING` (never `PASS`) with a prepared post-publication
command and failure response.

```sh
python3 -I scripts/qa/b1/candidate_harness.py j04 --mirror-dir <candidate-assets-dir> \
    --version v0.0.1-rc.8 --candidate-sha <40-hex candidate commit> > j04.json
python3 -I scripts/qa/b1/candidate_harness.py j17 ... > j17.json
```

`--mirror-dir` is a release-asset-shaped directory: `SHA256SUMS`, the cli tarball
`aasm-<arch>-<os>.tar.gz`, and `aasm-{api,runtime,proxy}-<tag>-<os>-<arch>.tar.gz`.
It is snapshotted into the sandbox; digests are of the snapshot bytes the
installer consumed, and the source is re-hashed at the end (drift is a FAIL).
The real `scripts/install-cli.sh` runs against it through a `curl` shim that
serves only that tag's assets plus a stand-in latest-release API reply; any other
URL is refused and fails the check. No network, credentials or sudo; one mktemp
directory, removed on exit and on SIGTERM/SIGHUP/SIGINT, and any gateway/API
process the harness started is killed. (SIGKILL cannot be handled: a hard-killed
harness can leave its own gateway/API child running on a loopback port.)
`--platform <os>/<arch>` simulates another target with a `uname` shim; binaries
are then not executed.

## Exit codes and states

| Exit | `overall` | Meaning |
|---|---|---|
| 0 | `CANDIDATE_PASS_PUBLICATION_PENDING` | every candidate check PASS, nothing not run |
| 1 | `CANDIDATE_FAIL` | any candidate check FAIL |
| 2 | (usage error) | bad arguments, missing paths |
| 3 | `INCOMPLETE` | no FAIL, but `not_run` is non-empty (foreign platform, runtime or proxy tarball missing) |
| 3 | `UNPINNED_CONTROL` | no FAIL, but `--allow-unpinned-control` was used |

`not_covered` lists acceptance criteria no check covers; it never counts as a pass.

## Checks

Candidate (fidelity `real_local_process`):

- Both journeys first run `<journey>.source_matches_candidate_sha`: the checkout's HEAD must be
  `--candidate-sha` and the installer, policy and harness files must equal their blobs in that
  commit (dirty, foreign or out-of-checkout files FAIL), so `candidate_sha` is not just a label.
- J04: `j04.sha256sums_match_artifacts`, `j04.installer_default_installs_all_binaries`
  (installed bytes equal the tarball members), `j04.installer_version_pin_env`,
  `j04.installer_latest_resolution` (unpinned, via `/releases/latest` and the
  `per_page=1` fallback), `j04.installer_refuses_tampered_tarball` (the installer's
  own checksum verification must say `SHA256 mismatch`),
  `j04.installer_uninstall_removes_binaries`, `j04.installer_components_cli_runtime`,
  `j04.installer_profile_local_installs_runtime`, `j04.installer_profile_full`,
  `j04.installed_aasm_version_output`, `j04.installed_gateway_version_output`,
  `j04.installed_api_server_starts` (aa-api-server has no `--version`; any run starts the
  server, so it is started on a free loopback port with a throwaway key),
  `j04.negative_control_old_installer_fails`.
- J17: `j17.installer_places_gateway_beside_aasm`, `j17.installed_gateway_version_output`,
  `j17.gateway_serves_sample_policy` (control: a missing policy path must fail),
  `j17.aasm_gateway_start_status_stop` (control: `aasm gateway status` non-zero before start),
  `j17.negative_control_old_installer_has_no_gateway`.

PENDING (publication; never executed here): `j04.published_install_sh_default`,
`j04.published_release_checksums_and_signature`, `j04.published_homebrew_tap_install`,
`j04.published_homebrew_runtime`, `j04.published_latest_resolves_to_candidate`
(GitHub API: newest release is the candidate and an unpinned install resolves to it; rc tags are
prereleases and may be absent from `/releases/latest`), `j04.published_crates_io_aa_cli`,
`j17.published_installer_profile_full_gateway`, `j17.published_homebrew_gateway`,
`j17.published_container_image_manifest`.

Each pending `command` is one self-contained `sh -c` script with the tag and the
candidate digests substituted, runnable verbatim. It downloads what it checks,
verifies in the right directory, and compares published bytes with the candidate's
digests (tarballs and installed members). Install-style checks use their own temp
dir and `HOME`. The Homebrew checks `brew upgrade || brew install` in the real Homebrew prefix
(`side_effects` says so); a stale install cannot false-PASS because version and
candidate digest are asserted. Test-only environment overrides:
`B1_RELEASE_BASE`, `B1_INSTALL_SH_URL`, `B1_POLICY_URL`.

Not covered (also in the JSON `not_covered`): J04 `cargo install aa-cli` docs decision;
J17 docs-not-only-`cargo run`; J17 policy-format-unambiguous; J17 `aasm status` /
`aasm topology` / `aasm agent list` healthy (they read the HTTP API, which the
gateway-only OSS mode does not serve; only gRPC liveness via `aasm gateway
start/status/stop` is covered).

## Negative control

`fixtures/install-cli.pre-aaasm-6414.sh` is a byte-identical copy of
`scripts/install-cli.sh` at `4b461d4ef` (parent of the PR #2791 merge `1f6a2011f`),
sha256 pinned in the harness. The control must show its specific defect (exit 0,
`aasm` installed, no `aa-gateway`, no `aa-api-server`); any other failure is not
accepted. A control whose digest differs fails unless `--allow-unpinned-control`.

## Output shape (fits `scripts/qa/publication_obligations.py`, PR #2798)

Flat summary: `candidate_checks[]` (`id`, `status`, `fidelity`, `evidence_ref` (a
command string, not a file), `candidate_sha`, `negative_control`, `artifact_digests`
as `name -> sha256:<64 hex>`), `pending_checks[]` (status `PENDING`), `not_run`,
`not_covered`, `failure_response`. `obligation_fragment` is the journey entry in the
module's shape (pending status `PUBLICATION_PENDING`); `registry_digest` and
`depends_on` are explicit `null` placeholders (`_unfilled`) for the obligation
builder. A fragment from a run that is not exit 0 must not be committed.

## Self-test

```sh
python3 -I scripts/tests/test_b1_candidate_harness.py
```

About 4 minutes (37 tests, against a throwaway fixture git repo so results do not depend on the real checkout; the gateway-never-listens cases wait on timeouts). The fragment-validation test FAILs if `publication_obligations.py` cannot be loaded unless
`B1_ALLOW_SKIP_FRAGMENT_TEST=1`. It
asserts PASS on good fixtures with every expected id; FAIL on the old-script control,
a tampered SHA256SUMS, a tampered tarball, an installer patched to skip checksum
verification, a gateway that never listens, one that ignores a missing policy, a
wrong version and an API server that does not start; INCOMPLETE for foreign platform
and missing runtime/proxy; pinned/unpinned/non-specific control handling; the
fragment validating against the real `validate_obligation`; pending commands passing
`sh -n`, passing against a local stand-in mirror, and failing on non-candidate bytes
or a stale version; and no orphan gateway or temp dir after SIGTERM mid-start.
