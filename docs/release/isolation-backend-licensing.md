# Execution-isolation backend: licensing, distribution and provenance

Release-engineering reference for AAASM-5714 (Epic AAASM-5702). It covers any
**execution-isolation backend** that Agent Assembly distributes, downloads,
builds or invokes as a supported component.

> **This is not legal advice.** Everything below describes license *identifiers*
> and the obligations *as written in the license texts themselves*, plus the
> engineering process built around them. It does not draw legal conclusions
> about any particular distribution, and it is not a substitute for review by
> someone qualified to give one.
>
> **Status — reduced scope.** The first backend (Sandlock) is built by
> **AAASM-5708** and does not exist yet. This document and its gate deliver the
> **mechanism**: the manifest schema, the channel matrix, the notices
> scaffolding and the enforcement. The Sandlock row in
> [`metadata/isolation-backends.json`](../../metadata/isolation-backends.json)
> is deliberately empty. No version, source URL, checksum or license identifier
> has been invented for it, because none has been measured.

## 1. The gap this closes

`cargo deny check --all-features` — the `Dependency checks` job in `ci.yml`,
configured by [`deny.toml`](../../deny.toml) — is the workspace's license and
advisory gate. It evaluates **crates in the cargo dependency graph**.

An isolation backend does not have to be a crate. If it ships as a **prebuilt
binary** — bundled into a release tarball, fetched by `install-cli.sh`, or baked
into a container image — it never enters the cargo graph. cargo-deny never sees
it. No license is checked, no advisory is matched, and **nothing fails**.

Before this ticket, **no mechanism covered that class of artifact at all.** That
is the hole. The closure has three parts:

| Part | File |
|---|---|
| Machine-readable provenance + policy | [`metadata/isolation-backends.json`](../../metadata/isolation-backends.json) |
| Enforcement (fail-closed) | [`scripts/check-backend-license-compliance.sh`](../../scripts/check-backend-license-compliance.sh) |
| Attribution for redistributed bytes | [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) |

The gate runs as the `backend-license` job in `ci.yml` and is a member of the
required `ci-success` aggregate.

### Modelled on the eBPF precedent, not invented

The eBPF probe objects are this repository's existing pattern for a bundled
artifact that is not a crate: built by a single shared script
(`scripts/build-ebpf-probes.sh`), uploaded as a CI artifact, digested into
`EBPF_SHA256SUMS` in `release.yml`, and cosign keyless-signed alongside the
binary `SHA256SUMS`. A bundled backend should follow the same shape — a
dedicated checksum manifest, signed with the same keyless OIDC flow — rather
than acquire a new one.

## 2. Distribution channel matrix

Each channel states what it ships, who owns it, whether it is an **OSS** or a
**proprietary** distribution tier (this selects which license allowlist
applies), and what SBOM coverage exists for it **today**.

| Channel | What ships | Owner | Tier | Backend strategy | SBOM coverage today |
|---|---|---|---|---|---|
| `github-release` | `aasm-*.tar.gz` + `SHA256SUMS` (cosign-signed) | `.github/workflows/release.yml` | OSS | *pending AAASM-5708* | **none** |
| `crates-io` | Published workspace crates (source) | `release.yml` → `publish-crates` | OSS | *pending AAASM-5708* | **none** |
| `homebrew-tap` | Formulas in `ai-agent-assembly/homebrew-tap` | `release.yml` → `update-homebrew-tap` | OSS | *pending AAASM-5708* | **none** (inherits `github-release`) |
| `ghcr-container` | `ghcr.io` images | `.github/workflows/docker.yml` | OSS | *pending AAASM-5708* | image-layer SBOM (`sbom: true`) |
| `shell-installer` | Fetches release assets, verifies via cosign | `scripts/install-cli.sh` | OSS | *pending AAASM-5708* | **none** |
| `enterprise` | Self-hosted gateway + control-plane extensions | `agent-assembly-enterprise` (separate repo) | **proprietary** | *pending AAASM-5708* | n/a |
| `saas` | Hosted control plane / runners | `cloud` (separate repo) | **proprietary** | *pending AAASM-5708* | n/a |

**SBOM coverage is thinner than it looks.** Only container images have SBOM
generation today. The released *binaries* have none, and neither does the cargo
graph in notice-enumerated form. A backend bundled into a release tarball is
therefore **not** covered by any existing SBOM; the gate requires a bundled
backend to state how it is accounted for (`sbom.covered_by`) precisely so that
gap is recorded rather than assumed away.

Two channel notes worth keeping straight:

- **`homebrew-tap` inherits.** The tap uses a generator model — `metadata/versions.rb`
  *in the tap repo* is the source of truth and formulas are regenerated from it.
  Formulas resolve GitHub Release assets, so whatever `github-release` ships,
  this channel ships.
- **`crates-io` is source-only.** A `build.rs` that downloaded a backend binary
  would silently convert this into a `downloaded` channel. That is not permitted
  without an explicit reviewed decision recorded in the manifest.

### Strategy vocabulary

Each backend declares one of these per channel. A channel with no declared
strategy fails the gate — a silent gap is the failure mode being prevented.

| Strategy | Meaning | License-gated? | Notices required? |
|---|---|---|---|
| `bundled` | AASM redistributes the backend's bytes in its own artifact | yes | **yes** |
| `downloaded` | AASM fetches it from an upstream origin at install/run time | yes | no |
| `source` | AASM ships a recipe that builds it from upstream source | yes | no |
| `system` | The operator must already have it installed | no | no |
| `not-distributed` | The channel does not carry or acquire it at all | no | no |

`system` and `not-distributed` are ungated because the operator supplies the
bytes on their own terms. The gate's self-test pins this in both directions, so
"denied" is a meaningful result rather than a blanket one.

## 3. License policy — two tiers, allowlist, implicit deny

The policy is an **allowlist with implicit deny**, the same model
[`deny.toml`](../../deny.toml) uses for crates. A license that is merely
*unrecognised* fails the build. It is never a warning.

There are **two** allowlists, and this is the point of the whole gate:

- `oss_allowed_spdx` — applies to the Apache-2.0 open-source channels.
- `proprietary_allowed_spdx` — a **strict subset**, applies to Enterprise/SaaS.

**A license cleared for OSS distribution is not thereby cleared for a
proprietary bundle.** That specific accident — a backend reviewed once for the
open-source release and then quietly picked up by a proprietary distribution
path — is what this gate exists to prevent.

The current delta between the two lists is **MPL-2.0**: allowed for OSS,
withheld for proprietary. MPL-2.0 §3.2 attaches per-file source-availability
obligations to distributing a covered work in executable form. Whether a given
proprietary bundle satisfies those obligations is a per-case decision, so the
default is *stop and decide*, not *allow*. Moving MPL-2.0 into the proprietary
list **is** that decision being taken explicitly — which is the behaviour the
ticket asks for.

`known_incompatible_spdx` (AGPL, GPL, SSPL, BUSL, Elastic-2.0, CC-BY-NC) is
**diagnostic only**. It turns a denial into a legible message. It is not the
enforcement mechanism: removing an entry from it permits nothing, because the
allowlist is what enforces.

### Open-source license rights vs hosted-service terms

These are different instruments and are easy to conflate:

- An **open-source license** (Apache-2.0, MIT, BSD, ISC, MPL-2.0, …) is a grant
  from the copyright holder covering copying, modification and distribution, on
  the conditions the license text states — typically retention of copyright and
  license notices, and for Apache-2.0 §4(b) a statement of changes for modified
  files. Those conditions are what the gate and
  [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) track.
- **Hosted-service terms** (the terms under which Agent Assembly's SaaS is
  offered) are a contract between the operator and the user. They govern use of
  a *service*; they are not a copyright grant, and they neither extend nor
  reduce the rights an upstream license gives.

Two consequences that matter for backend selection:

1. A backend's license granting broad redistribution rights says **nothing**
   about what the hosted service may promise about it (availability, support,
   indemnity). Do not cite the license as the basis for a service commitment.
2. Some licenses attach obligations to **running a service**, not only to
   distributing bytes — AGPL-3.0 §13's network-use source-disclosure condition
   is the standard example. A review that only asks "do we redistribute this?"
   would miss it, which is why `saas` is a declared channel in the matrix even
   though nothing is redistributed through it.

### What this ticket does *not* change

Agent Assembly's own license and its open-core packaging are **unchanged**. This
work adds a gate over third-party backends; it takes no position on how the
project itself is licensed or split. Changing either requires a separate,
explicit decision.

## 4. Upstream modifications

Every active backend must declare `modifications.modified` as a real boolean.
"We did not check" is not an accepted value, because whether AASM carries
patches is what decides whether a statement-of-changes obligation applies
(Apache-2.0 §4(b) among the allowlisted licenses).

If `true`, `modifications.notice_path` must point at a file that exists in the
repository describing the changes. The gate verifies existence, not content —
keep the patch set itself reviewable (a directory of patches, or a fork with a
documented branch point).

## 5. Runbook: adding or upgrading a backend

A backend upgrade is **not** a version bump. The gate enforces this by requiring
fields a bump alone cannot satisfy: `review.ticket`, `review.reviewed_at` and
`review.capability_evidence`. Bumping `version` without refreshing these leaves
the manifest attesting to a review that did not happen for the new version.

1. **Capability evidence.** Confirm the new version still provides the isolation
   capabilities the epic depends on, and record where that was measured
   (`review.capability_evidence`). A changelog entry is not evidence.
2. **Security review.** Check upstream advisories and the delta since the pinned
   version. Note that `cargo-deny`'s advisory database does **not** cover a
   non-crate backend — this step has no automated backstop.
3. **License re-check.** Re-read the upstream `LICENSE` at the new version;
   projects relicense. Update `spdx_license` if it changed, and confirm it is
   allowlisted for **every** channel the backend is `bundled`/`downloaded`/`source`
   on, including the proprietary ones.
4. **Provenance.** Update `version`, `source_url` and `release_sha256` together.
   The checksum must be of the exact artifact that will be redistributed.
5. **Modifications.** Re-apply, re-verify or drop any local patches; update
   `modifications` and its notice.
6. **Notices.** Update the `### <backend id>` section in
   [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) if the backend is
   bundled anywhere. The gate fails if that section is missing.
7. **SBOM.** Update `sbom.covered_by`. If the backend became bundled on a
   channel with no SBOM coverage, say so rather than leaving it implied.
8. **Review record.** Set `review.ticket` and `review.reviewed_at` to *this*
   review, not the previous one.

Then run the gate and its negative control locally:

```bash
bash scripts/check-backend-license-compliance.sh --self-test
bash scripts/check-backend-license-compliance.sh
```

Changing either allowlist in `license_policy` additionally requires the
security/licensing reviewer in `.github/CODEOWNERS` — same reason `[advisories]
ignore` in `deny.toml` must stay empty: each added entry silently widens what
can ship.

## 6. What the gate rejects

Enumerated because a gate nobody can describe is a gate nobody maintains. Each
of these is covered by a case in `--self-test`, which mutates one known-good
baseline a single field at a time and asserts both the rejection *and* its
reason.

- Manifest missing, unparseable, or on an unknown `schema_version`.
- A `pending` backend with no tracking ticket — or, conversely, one carrying
  **any** provenance field. A placeholder version or checksum would pass every
  downstream check while attesting to something nobody measured, so an invented
  provenance row is treated as strictly worse than an absent one.
- A license not on the applicable allowlist, including one that is simply
  unrecognised.
- A license allowed for OSS but used on a **proprietary** channel.
- A `release_sha256` that is not 64 lowercase hex; a `source_url` that is not
  `https://`; a missing `version` or `upstream_name`.
- `modifications.modified` missing or non-boolean; declared modifications with
  no notice path, or a notice path that does not exist on disk.
- A missing `review` block or absent `capability_evidence`.
- A channel with no declared strategy, an unknown strategy, or a strategy
  declared for a channel the manifest does not define.
- A bundled backend with no `### <id>` section in the notices file, or no
  `sbom.covered_by` statement.
- Incoherent policy: a proprietary list wider than the OSS list, or a license
  appearing in both an allowlist and `known_incompatible_spdx`.

The notices check matches an **exact** `### <id>` heading rather than a
substring, so a `### Pending: <id>` placeholder cannot satisfy the requirement
for a backend that actually ships.

## 7. Open items for AAASM-5708 and the final wave

- Fill the Sandlock row with measured provenance and flip `status` to `active`.
  Every requirement above turns on at that moment.
- Decide and record the per-channel strategy for it, especially whether
  `github-release` bundles the binary or the installer downloads it.
- If bundled: add a checksum manifest to `release.yml` on the `EBPF_SHA256SUMS`
  pattern, cosign-sign it with the same keyless flow, and add the notices
  section.
- If it ships a helper **workspace binary**, classify it in
  `RELEASE_BINARIES` or `UNRELEASED_BINARIES` in
  `scripts/check-release-completeness.sh` — a workspace binary in neither list
  already fails that gate.
- Binary-level SBOM generation for release artifacts remains unimplemented and
  is not in this ticket's scope.
