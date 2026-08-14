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
> **Status.** This document and its gate deliver the **mechanism**: the
> manifest schema, the channel matrix, the notices scaffolding and the
> enforcement. The first backend (Sandlock) landed with **AAASM-5708**, and its
> row in [`metadata/isolation-backends.json`](../../metadata/isolation-backends.json)
> now carries measured provenance — version, source URL, release digest and
> SPDX identifier, each taken from the artifact rather than from upstream
> documentation. AASM does not redistribute the backend on any channel, so no
> channel is license-gated by it.

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

| Channel | What ships | Owner | Tier | Sandlock strategy | Packaging surface read by the gate | SBOM coverage today |
|---|---|---|---|---|---|---|
| `github-release` | `aasm-*.tar.gz` + `SHA256SUMS` (cosign-signed) | `.github/workflows/release.yml` | OSS | `system` | `release.yml` | **none** |
| `crates-io` | Published workspace crates (source) | `release.yml` → `publish-crates` | OSS | `not-distributed` | `release.yml` | **none** |
| `homebrew-tap` | Formulas in `ai-agent-assembly/homebrew-tap` | `release.yml` → `update-homebrew-tap` | OSS | `system` | `release.yml` (**partial** — formula bodies live in the tap repo) | **none** (inherits `github-release`) |
| `ghcr-container` | `ghcr.io` images | `.github/workflows/docker.yml` | OSS | `system` | `docker.yml`, `aa-*/Dockerfile`, `docker/Dockerfile.*` | image-layer SBOM (`sbom: true`) |
| `shell-installer` | Fetches release assets, verifies via cosign | `scripts/install-cli.sh` | OSS | `system` | `install-cli.sh`, `install.sh` | **none** |
| `enterprise` | Self-hosted gateway + control-plane extensions | `agent-assembly-enterprise` (separate repo) | **proprietary** | `system` | **none in this repo** (`packaging_owner: external-repo`) | n/a |
| `saas` | Hosted control plane / runners | `cloud` (separate repo) | **proprietary** | `system` | **none in this repo** (`packaging_owner: external-repo`) | n/a |

**The strategy column is corroborated, not asserted.** Each channel declares
`packaging_paths` — the files *in this repository* that decide what it ships —
and the gate greps them for the backend's executable name
(`distribution_probe.binary_names`). A backend claiming `system` /
`not-distributed` on every channel must appear **nowhere** in that surface; a
backend claiming `bundled` / `downloaded` / `source` must appear **somewhere**
in the surface of a channel it claims. A glob matching no file is an error, and
the gate's own inputs (this manifest, the notices file, the gate script) are
excluded from every surface, so a scan cannot pad its floor by reading its own
text. The two channels owned by other repositories declare an empty surface
explicitly: that blind spot is written down rather than left looking like
coverage.

`ci.yml` installs this exact binary in its `isolation-backend-linux` job. That
is correct and does not trip the probe: a CI test lane is not a distribution
channel, so `ci.yml` is in no channel's packaging surface.

**SBOM coverage is thinner than it looks.** Only container images have SBOM
generation today. The released *binaries* have none, and neither does the cargo
graph in notice-enumerated form. A backend bundled into a release tarball is
therefore **not** covered by any existing SBOM. The gate requires every channel
where AASM *acquires* a backend — `bundled`, `downloaded` **and** `source` — to
carry a `sbom.channel_coverage.<channel>` row stating `covered`, `partial` or
`none` plus the mechanism. `partial` and `none` are first-class answers so a
gap is recorded accurately; a `covered` claim is the one that gets checked, by
requiring the channel's packaging surface to actually contain a
bill-of-materials directive. Sandlock carries no such row because it is
acquired on no channel.

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
7. **SBOM.** Update `sbom.covered_by` and the `sbom.channel_coverage` row for
   every channel the backend is `bundled`/`downloaded`/`source` on. If a
   channel has no coverage, say `none` — do not write `covered` to make the
   row look complete; the gate checks that claim against the channel's
   packaging surface and rejects it when nothing there produces one.
7b. **Distribution probe.** If the upstream executable was renamed, update
   `distribution_probe.binary_names` in the same edit. A stale name makes the
   whole packaging corroboration pass on a string nobody ships any more.
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
- A channel with no `packaging_paths`; a `packaging_paths` glob matching no
  file; a surface resolving only to the gate's own inputs; or an empty surface
  not declared `packaging_owner: external-repo`.
- An active backend with no `distribution_probe.binary_names` — the field that
  makes its per-channel strategy contradictable at all.
- **A backend claiming `system`/`not-distributed` on every channel whose
  executable name appears in the packaging surface**, and the converse: a
  backend claiming acquisition that no packaging file references. Also
  rejected: a non-distribution claim where *no* channel offers a scannable
  surface, which would leave the claim resting on nothing.
- An acquiring channel with no `sbom.channel_coverage` row, a row whose
  `status` is not `covered`/`partial`/`none`, a row with no `mechanism`, or a
  `covered` claim on a channel whose packaging surface produces no SBOM.
- Incoherent policy: a proprietary list wider than the OSS list, or a license
  appearing in both an allowlist and `known_incompatible_spdx`.

The notices check matches an **exact** `### <id>` heading rather than a
substring, so a `### Pending: <id>` placeholder cannot satisfy the requirement
for a backend that actually ships.

## 7. Open items for AAASM-5708 and the final wave

- ~~Fill the Sandlock row with measured provenance and flip `status` to
  `active`.~~ Done in AAASM-5708.
- ~~Decide and record the per-channel strategy for it.~~ Done in AAASM-5708:
  every channel is `system` except `crates-io`, which is `not-distributed`
  because the consuming crate carries `publish = false`. Nothing is bundled or
  downloaded, so the bundled-artifact items below remain open only for a future
  backend that *is* shipped.
- If bundled: add a checksum manifest to `release.yml` on the `EBPF_SHA256SUMS`
  pattern, cosign-sign it with the same keyless flow, and add the notices
  section.
- If it ships a helper **workspace binary**, classify it in
  `RELEASE_BINARIES` or `UNRELEASED_BINARIES` in
  `scripts/check-release-completeness.sh` — a workspace binary in neither list
  already fails that gate.
- **Binary-level SBOM generation for release artifacts remains unimplemented.**
  Nothing in this repository produces an SBOM for `aasm-*.tar.gz` or for the
  crates in it. AC4 ("SBOM/release checks include any backend artifact AASM
  distributes") is satisfied today because the set of distributed backend
  artifacts is **empty** and the gate now proves that against the packaging
  code, not because binary SBOM coverage exists. The moment a backend becomes
  `bundled`/`downloaded`/`source` on a channel, the gate forces the coverage
  status for that channel to be stated, and `covered` cannot be claimed for a
  channel that generates nothing — so the honest answer there will be `none`
  until binary SBOM generation is built. That work is separate and unscheduled.
- The `homebrew-tap` surface is **partial**: only the `update-homebrew-tap` job
  is in this repository. A backend added directly to a formula in the tap repo
  would not be seen from here. It could still only reach a user through a
  GitHub Release asset, which `release.yml` does cover — but the tap repo has
  no equivalent gate of its own.
