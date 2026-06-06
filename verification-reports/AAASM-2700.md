# AAASM-2700 — Verification: signed installer (cosign + notarization)

Verifies Story **AAASM-2700** against the implementation in subtask **AAASM-2701**
(PR #988, stacked on #987 / AAASM-2339). This subtask is **AAASM-2702**.

## How verified

| # | Method |
|---|--------|
| 1 | `yaml.safe_load(release.yml)` — clean; asserted `jobs.publish.permissions.id-token == write` and a build-job step named `…notarize…` exists. |
| 2 | Inspected the publish job: `sigstore/cosign-installer@398d4b0…` (SHA-pinned) + `cosign sign-blob --bundle SHA256SUMS.cosign.bundle --output-signature/--output-certificate SHA256SUMS`; the three signature files added to the `action-gh-release` `files:` list. |
| 3 | `sh -n scripts/install-cli.sh` clean; `AASM_LIB=1 . install-cli.sh` loads `verify_signature` **without** running `main` (sourcing guard works). |
| 4 | Authored `tests/install_cli_sh.bats` (4 cases) exercising the pure verify logic (no network). |
| 5 | `mdbook build` clean; `installation.html` rendered; `installation.md` registered in `SUMMARY.md`. |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| `release.yml` cosign-signs `SHA256SUMS` (keyless) + uploads `.sig`/`.pem`/bundle; `id-token: write` | ✅ Pass | publish job: cosign-installer + `sign-blob` steps; `id-token: write` added; 3 artifacts in upload list |
| Installer verifies signature when cosign present, always checksum; `AASM_REQUIRE_SIGNATURE=1` mandatory; graceful fallback | ✅ Pass | `verify_signature()` runs `cosign verify-blob` against the pinned release-workflow OIDC identity, called before `sha256_verify`; `AASM_REQUIRE_SIGNATURE` honored; warns + continues without cosign |
| macOS notarization steps gated on `secrets.APPLE_*` (no-op until provisioned) | ✅ Pass | build job step gated `if: runner.os == 'macOS' && vars.MACOS_SIGNING_ENABLED == 'true'`; `secrets.APPLE_*` consumed only inside; skipped without them |
| `install_cli_sh.bats` covers the signature path; trust model documented | ✅ Pass | 4 bats cases; `docs/src/installation.md` documents cosign identity + manual `verify-blob` |
| All YAML valid; publishing unchanged when no Apple secrets set | ✅ Pass | YAML loads; cosign steps gated on `github.event_name == 'push'`; notarization gated off by default |

## Outcome

- All ACs **pass**. The OSS install path is now a **signed installer**: keyless
  cosign signature over `SHA256SUMS` (verified by the installer against a pinned
  release-workflow identity) + the existing checksum, with macOS notarization
  scaffolded and dormant until the operator provisions Apple credentials.
- **Owner-side activation (not code):** to turn macOS notarization on, set the
  `MACOS_SIGNING_ENABLED` repo variable and the `APPLE_*` secrets. cosign signing
  needs nothing extra (OIDC keyless) and is live on the next tagged release.
- Behaviour is unchanged for releases cut before this lands (older releases have
  no bundle → installer warns + uses checksum) and for users without cosign.
