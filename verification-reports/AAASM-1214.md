# AAASM-1214 — F111 verification

**Story:** [AAASM-1201 — Homebrew tap + curl|sh installer for the `aasm` CLI](https://lightning-dust-mite.atlassian.net/browse/AAASM-1201)
**Epic:** [AAASM-1199 — Release & Distribution Pipeline](https://lightning-dust-mite.atlassian.net/browse/AAASM-1199)
**Date:** 2026-05-23
**Verifier:** Bryant Liu

## Scope

Verification of the three implementation sub-tickets under F111:

| Sub-ticket | PR | Repo |
| --- | --- | --- |
| [AAASM-1210](https://lightning-dust-mite.atlassian.net/browse/AAASM-1210) | [ai-agent-assembly/homebrew-agent-assembly#1](https://github.com/ai-agent-assembly/homebrew-agent-assembly/pull/1) | `homebrew-agent-assembly` (new) |
| [AAASM-1211](https://lightning-dust-mite.atlassian.net/browse/AAASM-1211) | [ai-agent-assembly/homebrew-agent-assembly#2](https://github.com/ai-agent-assembly/homebrew-agent-assembly/pull/2) | `homebrew-agent-assembly` |
| [AAASM-1212](https://lightning-dust-mite.atlassian.net/browse/AAASM-1212) | [ai-agent-assembly/agent-assembly#713](https://github.com/ai-agent-assembly/agent-assembly/pull/713) | `agent-assembly` |
| [AAASM-1213](https://lightning-dust-mite.atlassian.net/browse/AAASM-1213) | [ai-agent-assembly/agent-assembly#719](https://github.com/ai-agent-assembly/agent-assembly/pull/719) | `agent-assembly` |

## Static checks

| # | Check | Target | Tool | Result |
| - | --- | --- | --- | --- |
| S1 | Formula style | `Formula/aasm.rb` (AAASM-1211 branch) | `brew style` | ✅ PASS — `1 file inspected, no offenses detected` |
| S2 | Shell syntax | `scripts/install-cli.sh` (AAASM-1212 branch) | `sh -n` | ✅ PASS — exit 0 |
| S3 | Workflow YAML | `.github/workflows/release.yml` (AAASM-1213 branch) | `python3 -c "yaml.safe_load(...)"` | ✅ PASS — jobs: `build`, `publish`, `publish-crate`, `update-homebrew-tap`; the new job has 6 steps in the expected order |

`brew audit --strict --online` is intentionally **not** run as part of CI for the tap repo until a real release tag publishes downloadable assets — the formula ships with `sha256 "0000…0000"` placeholder values that AAASM-1213's automation rewrites on every tag. The tap-repo `tests.yml` workflow runs `brew style` + `brew audit --strict` (no `--online`).

## Smoke tests of the SHA256 verification logic

Fixture (`/tmp/aaasm-1214-smoke/`):

```
aasm                                        # fake binary, content "fake aasm binary content"
aasm-x86_64-unknown-linux-gnu.tar.gz        # tarball of fake binary
SHA256SUMS                                  # one line: <hash>  aasm-…linux-gnu.tar.gz
```

| # | Test | Result |
| - | --- | --- |
| T1 | `sha256_compute <tarball>` matches `shasum -a 256` output | ✅ PASS — both produce `d91257968cf1072eadfe9e0de45aa2f9c6b0f12f97654279727e2d445412fa63` |
| T2 | `sha256_verify` accepts a matching tarball/SHA256SUMS pair | ✅ PASS — prints `SHA256 verified.`, returns 0 |
| T3 | `sha256_verify` rejects a tampered tarball (one extra byte appended) | ✅ PASS — prints `SHA256 mismatch (got 5dcdf3c7…, want d9125796…)`, returns 1 |

Functions extracted verbatim from `scripts/install-cli.sh` for in-isolation execution; their behaviour is unchanged from the integrated `main()` flow.

## Acceptance criteria — Story AAASM-1201 status

| AC | Status | Notes |
| --- | --- | --- |
| `brew install agent-assembly/tap/aasm` on macOS ARM64 | ⏸ Gated — first real release | Formula + URL pattern verified statically (S1, S3); end-to-end requires a published GitHub Release tag and AAASM-1213's auto-update PR merged on the tap. |
| `brew install agent-assembly/tap/aasm` on macOS x86_64 | ⏸ Gated — first real release | Same as above |
| `brew install agent-assembly/tap/aasm` on Linux x86_64 + ARM64 | ⏸ Gated — first real release | Same as above |
| `curl -fsSL https://get.agent-assembly.io \| sh` on Linux x86_64 + macOS ARM64 | ⏸ Gated — DNS + hosting | Script logic verified (T1–T3); requires `get.agent-assembly.io` to be configured to serve `scripts/install-cli.sh`. Tracked separately under the distribution infra backlog. |
| Installer script verifies SHA256 checksum before placing binary | ✅ PASS | Confirmed by T2 (accept) + T3 (reject on tamper); see [AAASM-1212 PR](https://github.com/ai-agent-assembly/agent-assembly/pull/713) |
| CI release workflow auto-updates formula SHA256 values on new tag push | ✅ PASS (design) | Verified statically (S3) — the 6-step `update-homebrew-tap` job exists, downloads SHA256SUMS, extracts four per-platform shas, rewrites `Formula/aasm.rb`, opens a PR via `peter-evans/create-pull-request@v7`. End-to-end requires `HOMEBREW_TAP_TOKEN` repo secret to be configured + the next real tag push. |

## Gating notes — what still needs to happen post-merge

1. Engineer creates a fine-grained PAT for `ai-agent-assembly/homebrew-agent-assembly` (Contents + Pull requests: read/write) and adds it to `ai-agent-assembly/agent-assembly` as `HOMEBREW_TAP_TOKEN` repo secret.
2. Engineer sets up `get.agent-assembly.io` to serve `scripts/install-cli.sh` from `master` (Cloudflare Pages, GitHub Pages, or equivalent). Out of scope for F111; tracked separately.
3. First real release tag (e.g. `v0.1.0`) triggers `release.yml` → publishes binaries + SHA256SUMS → `update-homebrew-tap` opens its first PR on the tap repo with real sha values.
4. After that tap PR merges, the end-to-end checklist items above can be ticked on the 4 supported platforms.

## Sign-off

All design-time checks pass. The implementation matches the Story's acceptance criteria. The remaining `⏸ Gated` items require deployment artefacts (token, DNS, real release tag) that are outside the scope of this Story but well-defined for follow-up.

**Verification result: APPROVED — ready to ship pending the post-merge operational steps above.**
