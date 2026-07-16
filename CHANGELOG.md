# Changelog

All notable changes to **AI Agent Assembly** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1-rc.6] — 2026-07-16 (pre-release)

> **Not for production use.** Sixth **release candidate** in the v0.0.1 series
> (patch on the `rc` channel). A **test-quality + tooling-hardening** cut:
> dashboard test/quality fixes clearing the outstanding SonarCloud findings,
> a `DOCS_RS` guard so the eBPF crate builds on docs.rs, a handful of
> correctness/authz fixes in the API and CLI surface, and release-process /
> CI-docs improvements. No API, ABI, or wire-protocol stability commitment at
> `0.x.y`; `protocol/v1` unchanged.

### Added

- **`/health` alias endpoint** (`aa-api`) — a `/health` route returning the same
  health JSON as the existing health endpoint, for probes that expect that path.

### Fixed

- **Tenant ownership enforced in `register_op`** (`aa-api`) — the op-registration
  path now rejects cross-tenant registration instead of trusting the request's
  tenant, closing a cross-tenant authorization gap (regression test added).
- **`OpsRegistry::register` preserves an existing op** (`aa-gateway`) — registering
  a name that already exists no longer clobbers the prior op.
- **`aa-cli` sends the `Authorization` header on audit/logs requests** — the audit
  and logs subcommands now attach the auth header so they work against an
  authenticated gateway.
- **`aa-ebpf` skips its probe subprocess build under `DOCS_RS`** (AAASM-4715) —
  the read-only docs.rs sandbox cannot run the probe build step, so it is skipped
  when `DOCS_RS` is set, unbreaking the docs.rs build.
- **Dashboard test-quality / SonarCloud fixes** (AAASM-4694) — parameterized the
  `ApprovalAnalyticsPanel`, `FilterBar`, and `FleetHealthPanel` tests (S5976),
  keyed heatmap cells by date rather than index (S6479), named a `useState` setter
  symmetrically (S6754), switched base64url decoding to `replaceAll` (S7781), and
  used `Set.has` for JWT scope validation (S7776).
- **Docs link fixes** — repointed the README architecture/CLI/dashboard links and
  fixed dead introduction/architecture `README.html` links after the docs reorg;
  corrected the `McpDecision::Redact` doc to match the proxy-scanner redaction.

### Changed

- **Release-process & CI-docs improvements** (AAASM-4670 / 4671 / 4674 / 4679 /
  4724) — unified branch naming onto the 3-part `<release-or-phase>/<ticket>/<short_summary>`
  scheme, added a DCO sign-off checkbox to the PR template and a no-ticket
  community contribution path, added an internal README doc-link check in CI,
  reminded `release-tag-cut` to advance the Jira Fix Version ladder, and extended
  `release-docs-sync` to cover the README maturity/version string.
- Dependency bumps: `clap`, `which`, `regex`, `redis`, `toml`,
  `SonarSource/sonarqube-scan-action`, and `actions/setup-node`.
- Workspace version bumped `0.0.1-rc.5` → `0.0.1-rc.6` (all crates inherit via
  `version.workspace = true`; `Cargo.lock` + `sonar.projectVersion` realigned).

## [0.0.1-rc.5] — 2026-07-14 (pre-release)

> **Not for production use.** Fifth **release candidate** in the v0.0.1 series
> (patch on the `rc` channel). A **dashboard-embedding + onboarding-docs** cut:
> the dashboard SPA is now compiled into the `aa-api` binary so local serving no
> longer 404s, `aasm` fails loudly on a missing API key before it claims to be
> serving, and the mdBook docs gain a tabs widget with tabbed, anchor-stable
> installation instructions. No API, ABI, or wire-protocol stability commitment
> at `0.x.y`; `protocol/v1` unchanged.

### Added

- **Embedded dashboard SPA** (AAASM-4517) — the built dashboard is embedded into
  the `aa-api` binary at compile time via a `build.rs` + `include_dir!`, so a
  locally-served gateway ships its UI in-process instead of returning a 404 for
  the dashboard route (the rc.4 dashboard-404 regression).
- **mdBook tabs widget** (AAASM-4566) — a reusable tabbed-content widget for the
  docs site, used to present per-platform / per-tool instructions side by side.
- **Tabbed installation instructions** (AAASM-4567) — `installation.md` reworked
  onto the new tabs widget, with stable per-tab anchors (AAASM-4573 / 4574) so
  deep links to a specific install method survive re-rendering.
- **Homebrew tap via `versions.rb` generator** (AAASM-4520) — the tap formula is
  now produced by a `versions.rb` generator rather than hand-maintained.

### Fixed

- **API-key validated before the serving banner** (AAASM-4572) — `aasm` now
  validates `AASM_API_KEY` up front and fails loudly on a missing/invalid key
  instead of printing a "serving" banner it cannot honor.

### Changed

- Dependency bumps: `rustls`, `tokio-tungstenite`, `uuid`, `open`,
  `EmbarkStudios/cargo-deny-action`, and `softprops/action-gh-release`.
- Workspace version bumped `0.0.1-rc.4` → `0.0.1-rc.5` (all crates inherit via
  `version.workspace = true`; `Cargo.lock` + `sonar.projectVersion` realigned).

## [0.0.1-rc.4] — 2026-07-12 (pre-release)

> **Not for production use.** Fourth **release candidate** in the v0.0.1 series
> (patch on the `rc` channel). Primarily a **release-artifact completeness** cut
> — the `aa-api-server` binary and the `aa-gateway` container image are now part
> of the published release set — folded together with the accumulated
> security-hardening sweeps and the local-mode gRPC registration surface merged
> since `rc.3`. No API, ABI, or wire-protocol stability commitment at `0.x.y`;
> `protocol/v1` unchanged.

### Added

- **Local-mode gRPC agent registration** (AAASM-4447) — `aa-api` now serves the
  gRPC `AgentLifecycleService` on loopback in local mode, backed by a durable
  SQLite registry, so an SDK-registered agent is visible over REST without a
  full gateway. Covered by new conformance registration-surface contract tests.
- **Analytics API + dashboard** (AAASM-4131 / 4138 / 4142 / 4155 / 4158) — seven
  `/api/v1/analytics/*` endpoints (KPIs, cost-breakdown, action-volume,
  tool-usage, approvals, policy-effectiveness, fleet-health) with the dashboard
  Analytics/Costs pages wired to live data, per-panel error isolation, and
  server-side windowed audit reads.
- **`aa-gateway` container image** (AAASM-4480) — distroless `cargo-chef`
  Dockerfile, built on PR validation and published to GHCR on tag.
- **`file_delete` capability governance** (Epic AAASM-4092) — `FileMode::Delete`
  → `Capability::FileDelete`, an allow-write-deny-delete policy example, and
  RBAC-gated mutating dashboard controls.

### Fixed

- **Release-artifact completeness** (the rc.4 driver) — `aa-api-server` is now
  built (`-p aa-api`), verified, and packaged into the `api` component tarball;
  the `components.json` glob includes `aasm-api` (AAASM-4449). A
  release-artifact completeness gate script now runs on PRs (AAASM-4456).
- **Hardcoded error messages** (AAASM-4457) — `aasm start` / `observe` and the
  copilot launch path now name the real `aasm` binary and the actual config
  paths in their error output instead of stale placeholders.
- Dashboard chart/analytics guards against non-finite values, invalid dates, and
  out-of-range time domains; accessibility fixes on scrim/modal elements.

### Security

- **`tools: "*"` wildcard** now honored across all three tool stages (allow /
  rate-limit / approval) on both the single-file and cascade paths (Epics
  AAASM-4149 / 4163) — previously fail-open.
- **Rate-limit bypass fixes** — anonymous shared-bucket path (AAASM-4190),
  multiple-policy application, and per-tenant bucket keying (AAASM-4171 / 4173).
- **Policy loader fails closed** on unknown top-level and nested section keys
  (AAASM-4189 / 4330).
- **Budget fail-closed** — conservative fallback price for unknown LLM models,
  org/team tier caps and ancestor monthly cap enforced in preflight, negative
  raw spend clamped at the accrual boundary, `prompt_tokens<=0` floored
  (Epic AAASM-4092).
- **Cascade allow-list** fails closed when the merged allow-list is empty; the
  capability stage is now enforced on the primary and single-file paths
  (AAASM-4120 / 4123).
- **Panic-DoS hardening** — agent-id parsing uses `hex::decode` (AAASM-4149 /
  4150); gRPC `max_decoding_message_size` set; MitM root CA constrained with
  X.509 NameConstraints.
- **Credential scanner** detects `gho_` / `ghu_` / `ghr_` / `github_pat_` /
  `xapp-` / `xoxr-` / `ASIA` prefixes with redaction; overlapping-finding span
  dedupe.
- **Proxy** decompresses-then-scans (or withholds) request and MCP response
  bodies by `Content-Encoding`; credential-DLP runs on all MitM'd request bodies.
- **Self-registration downgrade** of `enforcement_mode` ignored (AAASM-4121);
  agent-scoped controls bound to the token-derived id.
- **Dashboard auth** moved from `localStorage` to `sessionStorage` via a
  `tokenStorage` helper; identity claim rendered (not the raw token); strict
  Content-Security-Policy; legacy token purged on logout.

### Changed

- Docs repointed at the canonical `docs.agent-assembly.com` host; generated
  docs-metadata snippets with a CI drift check; repo-URL references updated
  after the org prefix rename.
- Dependency bumps: `ed25519-dalek` 3 (major), `reqwest` 0.13 (major),
  `crossbeam-epoch` 0.9.20 (RUSTSEC-2024-0587), plus in-range workspace and
  dashboard updates.
- Workspace version bumped `0.0.1-rc.3` → `0.0.1-rc.4` (all crates inherit via
  `version.workspace = true`; `Cargo.lock` + `sonar.projectVersion` realigned).

## [0.0.1-rc.3] — 2026-07-03 (pre-release)

> **Not for production use.** Third **release candidate** in the v0.0.1 series
> (patch on the `rc` channel). A large security-hardening cut; no API, ABI, or
> wire-protocol stability commitment at `0.x.y`. `protocol/v1` unchanged.

### Security

- **Epic AAASM-3913** (1 High / 7 Med / 4 Low) — invalidation-subscribe caller
  binding, dashboard REST-poll terminal sanitization, eBPF descendant-confinement
  (fork/exec propagation), storage tenant-isolation, SDK fail-open hardening.
- **Epic AAASM-3979** (2 High / 13 Med / 4 Low) — WebSocket event/alert streams
  now tenant-isolated (fail-closed per-frame gate); tool-scoped policies now
  actually evaluated (were dead-loaded); atomic budget reserve (TOCTOU); gateway
  RPC deadline → fail-closed Deny; proxy host-canonicalization + plaintext DLP
  refusal; email-scanner linearization; sandbox table/epoch caps; op-control NATS
  boot posture; SDK codec caps + `resolve_decision` → Deny.
- **Epic AAASM-4010** (1 High / 6 Med / 5 Low) — eBPF Layer 3 wired to the
  privileged loaderd (was dormant in prod; validated on a real kernel); file-io
  attach-list completed; node/python/go SDK enforce fail-closed parity; LangChain
  co-install governance bypass fixed; aa-sandbox memory/table/instance count caps;
  release-job GitHub Environment protection; npm OIDC Trusted Publishing; aa-api
  `parse_agent_id` panic-DoS; tenancy-posture guard; supply-chain CI hardening.
- **Follow-ups AAASM-4031/4032/4033/4034** — is_sensitive propagated to the audit
  event; `TenancyMode` wired from config + tenanted registration invariant;
  runtime→loaderd orchestration e2e (real-kernel validated); langchain-installed
  `__getattr__` contract test.
- **Epic AAASM-3898** — aa-auth crate extraction (leaf crate; gateway guards
  `/admin/status`; zero-config bypass-default preserved).

### Release security posture

Stage-0 `/release-security-gate` (patch tier) **PASS** — see
[`docs/release/security-signoff/v0.0.1-rc.3.md`](docs/release/security-signoff/v0.0.1-rc.3.md).
`cargo deny check advisories` ok; 0 open CodeQL / Dependabot; no unaddressed
Critical/High (every sweep High fixed + adversarially re-verified). Residual items
are deployment-config (GitHub Environments / npmjs Trusted-Publisher) and tracked
out-of-scope follow-ups.

### Changed

- Workspace version bumped `0.0.1-rc.2` → `0.0.1-rc.3` (all crates inherit via
  `version.workspace = true`; `Cargo.lock` + `sonar.projectVersion` realigned).

## [0.0.1-rc.2] — 2026-06-27 (pre-release)

> **Not for production use.** Second **release candidate** in the v0.0.1 series
> (patch on the `rc` channel). Security-hardening + test-coverage + docs; no API,
> ABI, or wire-protocol stability commitment at `0.x.y`.

### Security

- **AAASM-3788** — gRPC per-RPC auth + mTLS scaffold on the agent plane
  (fail-closed interceptor; approval decisions bound to the authenticated caller);
  closes the unauthenticated-gateway gap (AAASM-3416).
- **AAASM-3790 / 3824 / 3825** — REST cross-tenant IDOR hardening: tenant
  ownership + write-scope across agent/alert/op handlers; `get_agent_capabilities`
  gated; `get_agent_graph` traversal tenant-filtered.
- **AAASM-3789** webhook SSRF guard + masked-secret round-trip; **AAASM-3787**
  eval cache key includes action args (prevents wrong-decision cache reuse).

### Documentation

- **AAASM-3774** — every published crate ships a `README.md` (renders on
  crates.io/docs.rs); release-readiness enforces it. Docs use `docs.agent-assembly.com`.

### Build / quality

- **AAASM-3765** versioned container base images; large test-coverage expansion
  (aa-api/aa-cli/aa-gateway/aa-proxy/aa-runtime/dashboard); Rust + dashboard
  coverage stabilisation; SonarCloud smell/deprecation cleanups.

### Changed

- Workspace + inter-crate path-dependency versions bumped `0.0.1-rc.1` → `0.0.1-rc.2`.

## [0.0.1-rc.1] — 2026-06-26 (pre-release)

> **Not for production use.** First **release candidate** in the v0.0.1 series,
> promoting the channel from `0.0.1-beta.4`. A security-hardening + release-QA
> cut; no API, ABI, or wire-protocol stability commitment at `0.x.y`.

### Security

- **AAASM-3726** — REST agent-lifecycle handlers (delete/suspend/resume +
  subtree-burn) gated with write-scope + tenant ownership (IDOR closed).
- **AAASM-3728** — network egress fails closed on an empty allowlist (cascade
  and single-file paths share one fail-closed helper).
- **AAASM-3689** — credential scanner / redaction hardening (case/whitespace
  variant detection, overlapping-finding coalescing, no fragment leaks).
- **AAASM-3751** — policy cascade + budget lineage anchored to the credential
  token's registered owner (defense-in-depth); webhook `secret_header` masked
  in destination responses and preserved on masked round-trip.

### Fixed

- **AAASM-3732** install script, **AAASM-3733** `latest/` channel alias,
  **AAASM-3736** dashboard partial-data guards, **AAASM-3719** SonarCloud
  residuals.

### Changed

- Workspace + inter-crate path-dependency versions bumped `0.0.1-beta.4` →
  `0.0.1-rc.1` (path-dep pins realigned to the release version).

## [0.0.1-beta.4] — 2026-06-24 (pre-release)

> **Not for production use.** Fourth pre-release in the v0.0.1 beta
> channel — a forward-roll cut on top of `0.0.1-beta.3` carrying the
> org-wide security-hardening initiative, the SDK version handshake, and
> the 2026-06-24 pre-release QA pass. No API, ABI, or wire-protocol
> stability commitment.

### Added

- **AAASM-3560** (Epic) — core defense-in-depth security hardening across
  the enforcement stack: eBPF bytecode integrity + least privilege
  (AAASM-3561), proxy credential isolation (AAASM-3562), sandbox
  defense-in-depth (AAASM-3563), multi-tenant Postgres row-level-security
  isolation (AAASM-3564), devtool supply-chain hardening (AAASM-3565),
  and a release-gated security sign-off process (AAASM-3566).
- **AAASM-3567** (Epic) — SDK security hardening: distribution
  supply-chain (AAASM-3568), SDK↔runtime Ed25519 IPC authentication
  (AAASM-3569), token hygiene (AAASM-3570), and bypass observability
  (AAASM-3571).
- **AAASM-3666 / AAASM-3683** — the language-SDK version is now signed
  into the SDK↔runtime handshake and passed through to the gateway.
- **AAASM-3508 / AAASM-3509 / AAASM-3510** — dashboard Overview, Costs,
  and Audit-log pages.
- **AAASM-3519 / AAASM-3517 / AAASM-3521** — limited-function self-host
  Docker Compose example, infra dataflow diagram, and self-host /
  Kubernetes ADR (research-spike only).

### Fixed

- **AAASM-3702 / AAASM-3703** — dashboard defensive guards for
  partial/missing data (mermaid null guard, partial-data guards).
- **AAASM-3506 / AAASM-3507** — dashboard dark-theme heatmap tooltip and
  Monaco theme fixes.
- **AAASM-3526 / AAASM-3527 / AAASM-3467** — Docker registry-org
  correction, runtime image entrypoint fix, and node images.
- **AAASM-3650** — fixed a flaky `healthz` timing test.
- **AAASM-3677** — resolved SonarCloud code smells.
- 2026-06-24 pre-release QA pass — docs accuracy, dashboard defensive
  guards, and example/harness fixes.

### Changed

- **AAASM (release)** — bumped the workspace `[workspace.package].version`
  from `0.0.1-beta.3` to `0.0.1-beta.4` (all crates inherit via
  `version.workspace = true`) and regenerated `Cargo.lock`. Coordinated
  release across agent-assembly + python-sdk + node-sdk + go-sdk; drives
  `@agent-assembly/sdk@0.0.1-beta.4`, `agent-assembly==0.0.1b4`, and
  `github.com/ai-agent-assembly/go-sdk@v0.0.1-beta.4` downstream.

## [0.0.1-beta.2] — 2026-06-15 (pre-release)

> **Not for production use.** Second pre-release in the v0.0.1 beta
> channel — a forward-roll cut on top of `0.0.1-beta.1` carrying the
> AAASM-3000 IPC deadlock fix. No API, ABI, or wire-protocol stability
> commitment.

### Fixed

- **AAASM-3000** — `aa-sdk-client` IPC event reporting is now
  fire-and-forget, closing the deadlock that occurred when the runtime
  accepted but did not ack the event report. `send_event` returns as
  soon as the codec has accepted the frame instead of blocking on a
  runtime ack.

### Changed

- **AAASM-2959** — release pipeline now syncs `aa-ffi-python` and
  `aa-ffi-node` `Cargo.lock` when bumping the workspace SDK pins, so
  the published native bindings always match the tagged
  `aa-sdk-client` revision.
- **AAASM-3004** — bumped workspace + 16 path-dep version literals from
  `0.0.1-beta.1` to `0.0.1-beta.2`. Coordinated release across
  agent-assembly + python-sdk + node-sdk + go-sdk; drives
  `@agent-assembly/sdk@0.0.1-beta.2`, `agent-assembly==0.0.1b2`, and
  `github.com/ai-agent-assembly/go-sdk@v0.0.1-beta.2` downstream.

## [0.0.1-beta.1] — 2026-06-14 (pre-release)

> **Not for production use.** First beta-channel pre-release in the v0.0.1
> series — promotes the channel up from `0.0.1-alpha.9`. No API, ABI, or
> wire-protocol stability commitment.

### Added

- **AAASM-2934** — full multi-page **Examples** sections across the SDK
  docs surfacing the runnable `agent-assembly-examples` demos: node-sdk
  (AAASM-2935), python-sdk (AAASM-2936), go-sdk (AAASM-2937), plus an
  agent-assembly core-docs Examples pointer (AAASM-2938).

### Changed

- **AAASM-2951** — bumped workspace + 16 path-dep version literals from
  `0.0.1-alpha.9` to `0.0.1-beta.1`. Coordinated release across
  agent-assembly + python-sdk + node-sdk + go-sdk; drives
  `@agent-assembly/sdk@0.0.1-beta.1`, `agent-assembly==0.0.1b1`, and
  `github.com/ai-agent-assembly/go-sdk@v0.0.1-beta.1` downstream.

## [0.0.1-alpha.9] — 2026-06-13 (pre-release)

> **Not for production use.** Ninth pre-release in the v0.0.1 dry-run
> series. First coordinated release after the AAASM-2851 SDK release
> decoupling chapter — validates that the `repository_dispatch` fan-out
> still works end-to-end after the restructure.

### What rides this tag

agent-assembly master content since alpha-8:

- **AAASM-2199** — README link to `agent-assembly-examples`
- **AAASM-2827** — docs archive retention (`extra_archived` seed +
  rebuild-every-tag-from-git CI)
- **AAASM-2833** — dynamic GitHub-release badge in README + docs
- **AAASM-2841** — version-selector typography polish
- **AAASM-2858** — SDK runbook cross-link

node-sdk content riding the `@agent-assembly/sdk` npm publish:

- **AAASM-2851 chain** — full SDK release decoupling (AAASM-2852 through
  AAASM-2869 — schema, Resolve, publish_mode gating, version-docs,
  runbooks, dry-run, verification, F1 live, main-only fix, %0A%0A fix,
  README badges)
- **AAASM-2842** — public `GatewayClient` + `createNoopGatewayClient`
  re-exports
- **AAASM-2870** — README badge polish

python-sdk content riding the `agent-assembly` PyPI publish:

- **AAASM-2851 chain** — symmetric python-sdk side (AAASM-2856, 2857
  schema + Resolve refactor + composite action rename)
- **AAASM-2863** — property-test for tag → PEP 440 conversion
- **AAASM-2868** — docs CI gate fix
- **AAASM-2869** — runbook documentation of both publish-release-tag
  and deploy-release-docs gates

### Expected post-tag sequence

1. `release.yml` → builds binaries → GH Release → `publish-crates`
   re-publishes all 14 publishable crates at `0.0.1-alpha.9`.
2. `docker.yml` → ghcr.io images at the new tag.
3. `notify-downstream` → `repository_dispatch` to node-sdk + python-sdk.
4. node-sdk publishes `@agent-assembly/sdk@0.0.1-alpha.9` + 4 sub-packages
   — **live-validates AAASM-2857's refactored Resolve step + composite
   action on the `repository_dispatch` path**.
5. python-sdk publishes `agent-assembly==0.0.1a9`.
6. `update-homebrew-tap` opens a tap PR.

### Behaviour delta on the crates.io `aasm` binary

Unchanged from alpha-5 through alpha-8. The published `aasm` binary
omits the `aasm run <tool>` and `aasm tools` subcommands while the
dev-tool subsystem is being finished. Local source builds
(`cargo build -p aa-cli`) expose the full surface unchanged.

### Refs

- This tag's prep: `AAASM-2849`
- Predecessor: `AAASM-2805` (alpha-8)
- AAASM-2851 chain (closed before this release): AAASM-2852 through AAASM-2870

---

## [0.0.1-alpha.8] — 2026-06-13 (pre-release)

> **Not for production use.** Eighth pre-release in the v0.0.1 dry-run
> series. Re-runs the full release pipeline with the AAASM-2797
> storage-crate path-dep version fix baked into master.

### Why a fresh bump rather than recovering alpha-7

alpha-7 published only `aa-core@0.0.1-alpha.7` to crates.io then
`publish-crates` died: 5 publishable storage/cache crates added
between alpha-3 and alpha-5 (aa-storage, aa-storage-memory,
aa-storage-redis, aa-storage-sqlite-buffer, aa-cache) carried path-
deps without the `version = "..."` literal that cargo publish demands.

`gh run rerun --failed` uses the workflow definition at the time of
the original tag push, so re-running cannot pick up the post-merged
improvement. Bumping to alpha-8 with a fresh tag validates the entire
release flow.

### Recovery fix verified by this tag

* **AAASM-2797 (PR #1024)** — Added `version = "0.0.1-alpha.7"` to 8
  path-dep declarations across 5 storage/cache crates. Pattern matches
  the existing publishable workspace crates.

### What this tag adds to crates.io for the first time

The 5 storage/cache crates publish for the FIRST TIME on this
release. The 9 historical publishable crates (aa-core, aa-proto,
aa-ebpf-common, aa-ebpf, aa-runtime, aa-proxy, aa-sandbox, aa-gateway,
aa-cli) publish at alpha-8 alongside their existing rows.

### Still-open follow-up

* **Homebrew `brew install + test (macOS)`** silent SIGKILL — the
  AAASM-2792 revert to `--release` didn't fix it (post-AAASM-2575,
  `--release` is the fast profile, not size-optimized). Suspect is a
  new transitive dep added since alpha-5. The Homebrew tap formula is
  correct and users can install manually; only the CI gate fails.
  Investigation tracked separately.

### Install

```bash
# Native binaries (Homebrew + GH Release tarballs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm  # may need --force
curl -L https://github.com/ai-agent-assembly/agent-assembly/releases/download/v0.0.1-alpha.8/aasm-aarch64-apple-darwin.tar.gz | tar xz

# crates.io — first end-to-end validated publish of all 14 crates ever
cargo install aasm --version 0.0.1-alpha.8

# Container images
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.8

# Language SDKs
pip install --pre agent-assembly==0.0.1a8
npm install @agent-assembly/sdk@0.0.1-alpha.8
```

### Refs

* This tag's prep: `AAASM-2805`
* Predecessor: `AAASM-2786` (alpha-7)
* Recovery fix: `AAASM-2797` (PR #1024)
* Multi-layer chain (4-layer clear-out complete): `AAASM-2346` → `AAASM-2463` → `AAASM-2775` → `AAASM-2797`

---

## [0.0.1-alpha.7] — 2026-06-13 (pre-release)

> **Not for production use.** Seventh pre-release in the v0.0.1 dry-run
> series. Re-runs the full release pipeline with the AAASM-2775
> strip-for-publish fix baked into master.

### Why a fresh bump rather than recovering alpha-6

alpha-6 published 4 of 5 channels (GH Release, Homebrew tap PR, npm,
PyPI, Go module proxy). crates.io ended up unpublished this cycle:
the `publish-crates` job failed with a workspace resolver error
because `aa-integration-tests/Cargo.toml` still referenced
`aa-gateway/audit-consumer` after the strip script removed that
feature from `aa-gateway/Cargo.toml`. `aa-integration-tests` is
`publish = false`, but cargo-workspaces walks the full workspace
graph during publish and resolution fails on the dangling reference.

`gh run rerun --failed` uses the workflow definition at the time of
the original tag push (pre-AAASM-2775 fix), so re-running cannot pick
up the post-merged improvement. Bumping to alpha-7 with a fresh tag
validates the entire release flow end-to-end with the fix in place.

### Recovery fix verified by this tag

* **AAASM-2775 (PR #1021)** — strip-for-publish now also wraps
  `aa-integration-tests/Cargo.toml`'s `audit-consumer` feature
  forward with `strip-for-publish:begin audit-consumer` / `:end`
  markers, and the file is added to `MARKED_FILES` in
  `.ci/strip-for-publish.sh`. The published workspace graph no
  longer references the stripped feature.

### Companion SDK-workflow fixes (settings-only, no code change)

The alpha-6 fan-out also surfaced two SDK-release-workflow
breakages that have been resolved via repo / org settings:

* **node-sdk `release-node.yml`** — "Open docs-version PR" step
  failed with `GitHub Actions is not permitted to create or
  approve pull requests`. Org-level setting was off; flipped to
  `true` and auto-propagated to all 6 org repos.
* **go-sdk `Docs Site`** — `deploy` job died in 1s with 0 steps on
  the `v0.0.1-alpha.5` tag push because the `github-pages`
  environment's deployment-branch-policy was master-only. Added a
  `v*` tag policy alongside; the rerun succeeded.

### Install

```bash
# Native binaries (Homebrew + GH Release tarballs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
curl -L https://github.com/ai-agent-assembly/agent-assembly/releases/download/v0.0.1-alpha.7/aasm-aarch64-apple-darwin.tar.gz | tar xz

# crates.io — first end-to-end validated publish of all 9 crates ever
cargo install aasm --version 0.0.1-alpha.7

# Container images
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.7
docker pull ghcr.io/ai-agent-assembly/python:3.14-slim

# Language SDKs
pip install --pre agent-assembly==0.0.1a7
npm install @agent-assembly/sdk@0.0.1-alpha.7
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.5
```

### Behaviour delta on the crates.io `aasm` binary

Unchanged from alpha-5 / alpha-6. The published `aasm` binary omits
the `aasm run <tool>` and `aasm tools` subcommands while the
dev-tool subsystem is being finished. Local source builds
(`cargo build -p aa-cli`) expose the full surface unchanged. See
`docs/src/compatibility.md` for the restoration recipe.

### Refs

* This tag's prep: `AAASM-2786`
* Predecessor: `AAASM-2767` (alpha-6)
* Recovery fix: `AAASM-2775` (PR #1021)
* Multi-layer chain: `AAASM-2346` → `AAASM-2463` → `AAASM-2775`
* Parent Story: `AAASM-1234` (F118 release-notes authoring)

---

## [0.0.1-alpha.6] — 2026-06-12 (pre-release)

> **Not for production use.** Sixth pre-release in the v0.0.1 dry-run
> series. Re-runs the full release pipeline with the two alpha-5
> recovery fixes (AAASM-2463 / PR #871) baked into master.

### Why a fresh bump rather than recovering alpha-5

alpha-5 published 5 of 6 channels (GH Release, Homebrew, npm, PyPI,
ghcr.io). crates.io ended up partially published: only `aa-core`,
`aa-proto`, and `aa-ebpf-common` landed at `0.0.1-alpha.5`. The
remaining 6 crates (`aa-ebpf`, `aa-runtime`, `aa-proxy`, `aa-sandbox`,
`aa-gateway`, `aa-cli`) were blocked because `cargo workspaces
publish` runs `cargo publish --verify` before upload, and
`aa-ebpf/build.rs` renames a staged `Cargo.toml.embedded` →
`Cargo.toml` inside the extracted-tarball build directory — cargo's
source-mutation guard refuses the publish.

`gh run rerun --failed` uses the workflow definition at the time of
the original tag push (pre-AAASM-2463 fix), so re-running cannot pick
up the post-merged improvement. Bumping to alpha-6 with a fresh tag
validates the entire release flow end-to-end with both fixes in place.

### Recovery fixes verified by this tag

* **AAASM-2463 commit 1 (PR #871)** — `release.yml` now passes
  `--no-verify` to `cargo workspaces publish` so the publish step
  does not trip on the `cargo publish --verify` source-mutation
  guard. The actual uploaded tarball is unchanged
  (`_embedded/aa-ebpf-probes/` keeps its `.embedded`-suffixed
  manifest); pre-tag CI already validates the workspace builds
  cleanly, so the per-crate verify step is redundant.
* **AAASM-2463 commit 2 (PR #871)** — removed the `smoke-test:` job
  from `release.yml`. The job was declared at the same `needs:`
  level as `publish-crates`, so it ran in parallel with the publish
  steps and raced both `cargo install aasm` and the homebrew tap
  formula merge. Removed for this cycle; re-introducing it correctly
  ordered (or as a separate `workflow_run`) is a future follow-up.

### Install

```bash
# Native binaries (Homebrew + GH Release tarballs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
curl -L https://github.com/ai-agent-assembly/agent-assembly/releases/download/v0.0.1-alpha.6/aasm-aarch64-apple-darwin.tar.gz | tar xz

# crates.io — first end-to-end validated publish of all 9 crates post AAASM-2463
cargo install aasm --version 0.0.1-alpha.6

# Container images
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.6
docker pull ghcr.io/ai-agent-assembly/python:3.14-slim

# Language SDKs
pip install --pre agent-assembly==0.0.1a6
npm install @agent-assembly/sdk@0.0.1-alpha.6
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.6
```

### Behaviour delta on the crates.io `aasm` binary

Unchanged from alpha-5. The published `aasm` binary omits the
`aasm run <tool>` and `aasm tools` subcommands while the dev-tool
subsystem is being finished. Local source builds
(`cargo build -p aa-cli`) expose the full surface unchanged. See
`docs/src/compatibility.md` for the restoration recipe.

### Refs

* This tag's prep: `AAASM-2767`
* Predecessor: `AAASM-2461` (alpha-5)
* Recovery fixes: `AAASM-2463` (PR #871)
* Parent Story: `AAASM-1234` (F118 release-notes authoring)

---

## [0.0.1-alpha.5] — 2026-06-03 (pre-release)

> **Not for production use.** Fifth pre-release in the v0.0.1 dry-run
> series. Validates the entire release pipeline end-to-end with all the
> alpha-4 recovery fixes baked into master.

### Why a fresh bump rather than recovering alpha-4

alpha-4 published successfully to 5 of 6 channels (GH Release,
Homebrew, npm, PyPI, ghcr.io). Only crates.io is partially-published:
`aa-core` landed at `0.0.1-alpha.4`, the other 8 crates never
published because `cargo workspaces publish` tripped on dirty-tree
before AAASM-2346's `--allow-dirty` fix.

`gh run rerun --failed` uses the workflow definition at the time of
the original tag push (pre-2346 fix), so re-running cannot pick up
the post-merged improvements. Bumping to alpha-5 with a fresh tag
validates the entire release flow end-to-end with all fixes applied.

### Recovery fixes verified by this tag

* **AAASM-2346 (PR #846)** — `cargo workspaces publish` invocation in
  `release.yml` now passes `--allow-dirty` so the topological publish
  step does not fail on the transient working-tree dirtiness caused by
  the `.ci/strip-for-publish.sh` step that runs right before it.
* **AAASM-2455 (PR #848)** — `smoke-curl-installer` channel `pip`
  invocation pinned to avoid the newest pip surfacing a transient
  dependency-resolver bug on the smoke job. (Superseded by AAASM-2457
  which restructured the smoke matrix.)
* **AAASM-2456 (PR #849)** — New `docs/release/RUNBOOK.md` operator
  playbook plus `scripts/release-readiness.sh` (10-check pre-tag gate)
  and `release-status-aggregator` workflow job that posts a single
  per-channel verdict comment on each GH Release.
* **AAASM-2457 (PR #867)** — Smoke matrix restructured: SDK smoke jobs
  dropped from `release.yml` (each SDK repo owns its own publish-time
  smoke) and a new `cargo install aasm --version <tag>` smoke channel
  added. Net 6 → 6 smoke channels with sharper accountability.
* **AAASM-2459 (python-sdk PR #75)** — `release-python.yml` now syncs
  `pyproject.toml` `version` AND `agent_assembly/__init__.py`
  `__version__` to the dispatched tag via a shared composite action
  (`.github/actions/sync-version/`); previously only `pyproject.toml`
  was bumped, leaving `__version__` stuck on the previous alpha.
* **AAASM-2460 (python-sdk PR #76)** — Deleted broken upstream
  Chisanan232 personal bumper workflows that were duplicating
  release-time version sync and racing the new composite action.

### Companion fixes in SDK repos

* **node-sdk PR #67 (AAASM-2344)** — `package.json` `repository.url`
  lowercased to satisfy npm registry strict-mode validation that
  alpha-4's mixed-case URL had tripped.
* **python-sdk PR #74 (AAASM-2345)** — Multiple `release-python.yml`
  Stage-step bugs fixed (artifact name collision, missing env var
  hoist, wheel-build job ordering).

### Install

```bash
# Native binaries (Homebrew + GH Release tarballs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
curl -L https://github.com/ai-agent-assembly/agent-assembly/releases/download/v0.0.1-alpha.5/aasm-aarch64-apple-darwin.tar.gz | tar xz

# crates.io — first end-to-end validated publish of all 9 crates
cargo install aasm --version 0.0.1-alpha.5

# Container images
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.5
docker pull ghcr.io/ai-agent-assembly/python:3.14-slim

# Language SDKs
pip install --pre agent-assembly==0.0.1a5
npm install @agent-assembly/sdk@0.0.1-alpha.5
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.5
```

### Behaviour delta on the crates.io `aasm` binary

Unchanged from alpha-4. The published `aasm` binary omits the
`aasm run <tool>` and `aasm tools` subcommands while the dev-tool
subsystem is being finished. Local source builds
(`cargo build -p aa-cli`) expose the full surface unchanged. See
`docs/src/compatibility.md` for the restoration recipe.

### Refs

* This tag's prep: `AAASM-2461`
* Predecessor: `AAASM-2343` (alpha-4)
* Parent Story: `AAASM-1234` (F118 release-notes authoring)

---

## [0.0.1-alpha.4] — 2026-06-02 (pre-release)

> **Not for production use.** Fourth pre-release in the v0.0.1 dry-run
> series. Verifies the three release-infra fixes that landed since alpha-3,
> the most significant being that `cargo install aasm` now works for the
> first time.

### Release-infra fixes verified by this tag

* **AAASM-2340 (PR #843)** — `cargo install aasm` works for the first
  time. The workspace is published to crates.io in topological order
  via [cargo-workspaces](https://github.com/pksunkara/cargo-workspaces).
  Nine crates publish: `aa-core`, `aa-proto`, `aa-runtime`,
  `aa-ebpf-common`, `aa-ebpf`, `aa-proxy`, `aa-sandbox`, `aa-gateway`,
  `aa-cli`. Sibling content needed by the binary is bundled into crate
  tarballs through `_embedded/` mirrors — the dashboard SPA
  (`aa-cli/_embedded/dashboard/dist/`), the gRPC proto contract
  (`aa-proto/_embedded/proto/`), and the BPF probe source
  (`aa-ebpf/_embedded/aa-ebpf-probes/`, compiled at install time when
  nightly + `bpfel-unknown-none` are present, otherwise graceful stubs).
  New `aasm sandbox run` / `aasm sandbox info` subcommands expose the
  WASI tool-execution sandbox (highlight ④ of the product spec) to OSS
  users. The dev-tool surface (`aasm run` / `aasm tools` + the three
  `aa-devtool*` crates) is held back from this alpha via a build-time
  strip script (`.ci/strip-for-publish.sh`) driven by
  `strip-for-publish:begin` / `:end` markers; sources remain in the
  repo and re-publish is a one-line workflow change once the subsystem
  ships.

* **AAASM-2339 (PR #841)** — `smoke-curl-installer` channel gated with
  `if: false` until `get.agent-assembly.io` is provisioned. Smoke
  matrix now runs 6 green channels per release. Wiring preserved so
  re-enabling at v0.1+ is one flag flip.

* **AAASM-2336 (PR #842 + node-sdk#66)** — `release.yml` gains a
  `notify-downstream` job that fires `repository_dispatch` (event-type
  `agent-assembly-release-published`) to BOTH node-sdk and python-sdk
  after the GH Release object is published. node-sdk's `release-node`
  listens for the dispatch and drops its retry-with-backoff workaround
  (AAASM-2328 superseded). python-sdk's listener (AAASM-2342 / PR
  python-sdk#73) lands in the same release cycle.

### CI performance work (AAASM-2340 follow-up)

* `aa-integration-tests/tests/common/cli.rs` adds an `aasm_command()`
  helper that honours `AASM_BIN_PATH`; CI workflows pre-build `aasm`
  once and export the path to nextest, skipping per-test `cargo run`
  overhead. Cut the Test job from ~60 min → ~9 min, Coverage from
  ~60 min+ → ~18 min, SonarCloud from failing → ~22 min SUCCESS,
  and both Integration tests jobs from 20-min timeout → ~10–15 min.

### Install

```bash
# NEW — works for the first time
cargo install aasm --version 0.0.1-alpha.4

# Existing channels (homebrew, docker, language SDKs)
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.4
pip install --pre agent-assembly==0.0.1a4
npm install @agent-assembly/sdk@0.0.1-alpha.4
go get github.com/ai-agent-assembly/go-sdk@v0.0.1-alpha.4
```

### Behaviour delta on the published `aasm` binary

The crates.io-published `aasm` binary omits the `aasm run <tool>` and
`aasm tools` subcommands while the dev-tool subsystem is being
finished. Local source builds (`cargo build -p aa-cli`) expose the
full surface unchanged. See `docs/src/compatibility.md` for the
restoration recipe.

### Refs

* Verify: `AAASM-2343` (this tag's prep) + the standing AAASM-2340 ACs
  (clean-machine `cargo install aasm` smoke test, publish-crates
  pipeline observed on this real tag)
* Predecessor: `AAASM-2312` (alpha-3)
* Companion: `AAASM-2342` (python-sdk repository_dispatch listener)

---

## [0.0.1-alpha.3] — 2026-06-01 (pre-release)

> **Not for production use.** Third pre-release in the v0.0.1 dry-run
> series. Verifies the 3 release-infra fixes that landed since alpha-2.

### Release-infra fixes verified by this tag

* **AAASM-2188 (PR #832)** — Docker matrix parallel cargo cache race
  (`File exists (os error 17)` when unpacking same crate concurrently).
  Fixed by per-Dockerfile cache `id` + `sharing=locked` on all 6
  language Dockerfiles.
* **AAASM-2189 (python-sdk#68)** — `Release Python SDK` maturin wheel
  builds missing protoc. Fixed by downloading official protoc 32.1
  binary in `before-script-linux` with SHA256 verification + retry.
* **AAASM-2190 (node-sdk#59)** — `release.yml` `pnpm publish` E402
  for scoped package. Fixed by adding `--access public`.

### Still unfixed (separately tracked, not blocking this dry-run)

* `Publish to crates.io` — AAASM-2094 deeper issue (internal crates
  not on crates.io). Architectural decision pending under AAASM-1200.
* `node-sdk release-node` cross-repo race (release not found).
* `smoke-test.yml` Docker pull uses old namespace.
* 6× AAASM-1253 smoke-test findings.

### Install

```bash
cargo install aasm --version 0.0.1-alpha.3
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.3
```

### Refs

* Verify: `AAASM-2316`
* Predecessor: `AAASM-2107` (alpha-2)

---

## [0.0.1-alpha.2] — 2026-05-28 (pre-release)

> **Not for production use.** Second pre-release in the v0.0.1 dry-run series.
> Continues exercising the release CD pipeline while verifying the 6
> release-infra fixes that landed since alpha-1.

### Release-infra fixes verified by this tag

* **AAASM-2093** — `docker.yml` language images now push to the correct
  `ghcr.io/ai-agent-assembly/` namespace (was `ghcr.io/agent-assembly/`,
  which caused `denied: not_found: owner not found`).
* **AAASM-2094** — `aa-cli/Cargo.toml` workspace path-deps now carry
  explicit `version` literals so `cargo publish -p aa-cli` passes
  manifest verification (the deeper crates.io dep-resolution issue is
  tracked separately; the publish job will still fail at that step).
* **AAASM-2095** — `release.yml` now sets `prerelease: true` on the
  GitHub Release object for SemVer pre-release tags (`-alpha.*`,
  `-rc.*`).
* **AAASM-2096** — F119 smoke-test now chains off `release.yml` via
  `workflow_call` instead of `release: published` (which was blocked
  by the GITHUB_TOKEN downstream-trigger restriction).
* **AAASM-2097** (node-sdk) — `pnpm publish` now derives the npm
  dist-tag from the SemVer pre-release identifier (`--tag alpha` for
  `-alpha.*`, `--tag rc` for `-rc.*`, etc.) instead of hardcoded
  `--tag alpha`.
* **AAASM-2098** (node-sdk) — `pnpm-lock.yaml` no longer drifts when
  the workspace version bumps; `optionalDependencies` use the
  `workspace:*` protocol.

### What remains unfixed (still expected to surface on alpha-2)

* **crates.io publish** — still fails at dep resolution (internal
  crates not on crates.io). Architectural decision under AAASM-1200.
* **F119 smoke-test channel jobs** — the 6 AAASM-1253 findings (PyPI
  name, curl endpoint, Docker tag scheme, Homebrew tap GA, smoke-test
  PyPI name, curl pipefail) are still pending.

### Install

```bash
cargo install aasm --version 0.0.1-alpha.2
brew install ai-agent-assembly/homebrew-agent-assembly/aasm  # version-pinned to alpha.2 via tap formula
docker pull ghcr.io/ai-agent-assembly/aa-runtime:v0.0.1-alpha.2
```

### Refs

* Verify ticket: `AAASM-2107` — alpha-2 cross-repo release verification
* Predecessor: `AAASM-1936` — alpha-1 release-pipeline verification

---

## [0.0.1-alpha.1] — 2026-05-25 (pre-release)

> **Not for production use.** This is the first pre-release of AI Agent Assembly,
> published to **dry-run the full v0.0.1 distribution pipeline** before cutting the
> v0.0.1 GA tag. Functional scope is identical to the upcoming v0.0.1 GA — this
> release does not add features beyond what GA will ship.

### Pre-release purpose

- Verify the cross-repo release workflows (`agent-assembly`, `python-sdk`,
  `node-sdk`, `go-sdk`) function end-to-end before cutting v0.0.1.
- Exercise the F119 smoke-test workflow (`.github/workflows/smoke-test.yml`)
  against real published artifacts.
- Surface any release-infrastructure bugs (Homebrew tap location, PyPI package
  name, curl installer endpoint, GHCR tag scheme, secret configuration) in a
  low-stakes channel before the GA release.

### Channel-specific dist-tag behaviour

Pre-release artifacts publish only under pre-release tags on each channel, so
unpinned `npm install` / `pip install` continue to resolve to the previous GA
version (or skip pre-releases entirely):

| Channel       | How to install the alpha-1 explicitly                         |
| ---           | ---                                                           |
| npm           | `npm install @agent-assembly/sdk@0.0.1-alpha.1` (or `@alpha`) |
| PyPI          | `pip install --pre agent-assembly-python==0.0.1a1`            |
| crates.io     | `cargo install aasm --version 0.0.1-alpha.1`                  |
| Docker (GHCR) | `docker pull ghcr.io/agent-assembly/python:0.0.1-alpha.1`     |
| Homebrew      | tap formula not auto-updated on pre-releases                  |

For the GA release scope, see the upcoming [0.0.1] entry, which will be authored
under AAASM-1247 once the alpha-1 dry-run passes and the GA tag is cut.

[0.0.1-alpha.1]: https://github.com/ai-agent-assembly/agent-assembly/releases/tag/v0.0.1-alpha.1
