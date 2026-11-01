# B1 staged artifact verification: J04 / J17 candidate harness

Founder decision (AAASM-6419, B1): journeys J04 and J17 get no blanket waiver.
Each is split into pre-publication CANDIDATE checks that run now against the
final local candidate artifacts, and checks that truly need published artifacts,
which are recorded `PENDING` (never `PASS`) with a prepared post-publication
command and failure response.

```sh
python3 -I scripts/qa/b1/candidate_harness.py j04 --mirror-dir <candidate-assets-dir> --version v0.0.1-rc.8 > j04.json
python3 -I scripts/qa/b1/candidate_harness.py j17 --mirror-dir <candidate-assets-dir> --version v0.0.1-rc.8 > j17.json
```

`--mirror-dir` is a release-asset-shaped directory (`SHA256SUMS`, the cli tarball
`aasm-<arch>-<os>.tar.gz`, `aasm-api-<tag>-<os>-<arch>.tar.gz`, optionally the
runtime tarball). The real `scripts/install-cli.sh` runs against it through a
`curl` shim that serves only that directory; any other URL is refused and fails
the check. No network, credentials or sudo; all state lives in one `mktemp`
directory removed on exit. Exit 0 = all candidate checks PASS, 1 = any FAIL,
2 = usage. `--platform <os>/<arch>` simulates another target with a `uname`
shim; binaries are then not executed and those checks are listed in `not_run`
(never PASS).

## Checks

| Id | Kind |
|---|---|
| `j04.sha256sums_match_artifacts`, `j04.installer_default_installs_all_binaries`, `j04.installer_version_pin_env`, `j04.installer_refuses_tampered_tarball`, `j04.installer_uninstall_removes_binaries`, `j04.installed_aasm_version_output` (host-native only), `j04.installer_profile_local_installs_runtime` (only if a runtime tarball is present), `j04.negative_control_old_installer_fails` | candidate |
| `j17.installer_places_gateway_beside_aasm`, `j17.installed_gateway_version_output` and `j17.gateway_serves_sample_policy` (host-native only; start on a free loopback port with `policy-examples/low-risk.yaml`, control: a missing policy path must fail), `j17.negative_control_old_installer_has_no_gateway` | candidate |
| `j04.published_install_sh_default`, `j04.published_release_checksums_and_signature`, `j04.published_homebrew_tap_install`, `j04.published_homebrew_runtime`, `j04.published_crates_io_aa_cli` | PENDING (publication) |
| `j17.published_installer_profile_full_gateway`, `j17.published_homebrew_gateway`, `j17.published_container_image_manifest` | PENDING (publication) |

Not covered even as PENDING: the Journey text's `aasm status` / `aasm topology`
healthy-report criterion and the policy-format-ambiguity criterion (J17); they
need a running full stack and a docs judgement, not an artifact.

## Negative control

`fixtures/install-cli.pre-aaasm-6414.sh` is a byte-identical copy of
`scripts/install-cli.sh` at `4b461d4ef` (parent of the PR #2791 merge
`1f6a2011f`). Its default install never places `aa-gateway` or `aa-api-server`.
Every harness run executes it as `--control-installer` and requires the
default-install assertion to FAIL; if it passes, the harness reports FAIL.
The copy is verified against git history by the self-test when history exists.

## Output shape (fits `scripts/qa/publication_obligations.py`, PR #2798)

`candidate_checks[]`: `id`, `status`, `fidelity` (`real_local_process`),
`evidence_ref`, `negative_control` (when present), `artifact_digests`
(`name -> sha256:<64 hex>`, the installer, SHA256SUMS and each tarball
consumed; the control check also lists the control installer's digest).
`pending_checks[]`: `id`, `channel`, `why_publication_only`, `command`,
`expected`, `failure_response`, `deadline_hours`. Top-level `failure_response`:
`proposed_actions`, `notify`, `deadline_hours`. Pending commands are read-only
against registries (they install only into a temp HOME). Turning this output
into the committed obligation file and the registry `publication_checks` is a
separate change after #2798 merges.

## Self-test

```sh
python3 -I scripts/tests/test_b1_candidate_harness.py
```

Builds fixture mirrors with fake binaries (no candidate needed) and asserts:
PASS on good; FAIL on the old-script control, a tampered SHA256SUMS, a tampered
tarball, a cli tarball without `aa-gateway`, a gateway that never listens and a
wrong version string; the control-that-passes is itself a FAIL; pending checks
are never PASS.
