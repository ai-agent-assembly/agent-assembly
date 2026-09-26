# The personal-observe deployment profile (HORO-1375)

This page documents `observation.profile = personal_observe` in full. The key
is **public** — there is no security-by-obscurity here — and this page is the
single source of truth for what it does, what it cannot do, and its known
coverage gaps.

## Exact config key, env var, and a complete YAML example

`~/.aasm/config.yaml`:

```yaml
observation:
  profile: personal_observe   # default: standard
```

Env override (takes precedence over the YAML value):

```console
AASM_OBSERVATION_PROFILE=personal_observe
```

Accepted values for both the YAML key and the env var: `standard` (the
default) and `personal_observe`. Any other value is a startup error
(`ConfigError::InvalidObservationProfile`).

## Exact scope: what it changes

personal-observe changes exactly one thing: **the policy-default slot** that
`resolve_enforcement_mode` falls back to for an agent that declares **no
per-agent `enforcement_mode` override**, on the `CheckAction` / `BatchCheck`
hot path of the **local single-process `aa-api-server` entrypoint only**
(`aa-api::serve_local`). Under `Standard` that default is `Enforce`; under
`personal_observe` it is `Observe`.

It never writes `AgentRecord.enforcement_mode` or
`AgentRecord.enforcement_mode_expires_at`. It is not implemented anywhere
else in this codebase:

* `aa-gateway` (the standalone gRPC server, `--mode local`, `--mode remote`,
  and the legacy-grpc entrypoint) refuses to start if
  `observation.profile = personal_observe` is set — see
  [Boot-refusal behaviour](#boot-refusal-behaviour) below.
* `aa-core/src/integration/plan.rs`'s `ObserveOnly` is a **different axis**
  entirely — the devtool-integration plan's own mode, not the gateway's
  policy-decision path — and is untouched by this profile.
* `PolicyDocument.enforcement_mode` is **not** consulted by the resolver
  today (both production `CheckAction`/`BatchCheck` callers hardcode a
  `PolicyDefaultMode`) and must not be wired without routing through this
  same gate — see [Known coverage gaps](#known-coverage-gaps), G4.

## Prerequisites

personal-observe is granted only when **all** of the following hold at boot
(checked by `aa_core::observation::authorize_personal_observe`):

* The deployment is running in **local mode** (`mode: local`, not `remote`).
* Storage is the local SQLite backend, not Postgres.
* The REST listener binds to a **loopback** address.
* No enterprise-coupling signal is detected — see the full signal list below.

If any signal fires, the process **refuses to start** — see
[Boot-refusal behaviour](#boot-refusal-behaviour).

## What it CANNOT override

* **A managed enterprise policy is never weakened.** `PolicyDocument`
  contents, scopes, and cascade resolution are completely unaffected.
* **Any per-agent `enforcement_mode` override always wins**, unconditionally,
  including an enterprise temporary shadow window. `resolve_enforcement_mode`
  is `agent_override.unwrap_or(policy_default)` — the capped column is always
  consulted first, and personal-observe supplies only the fallback.

## Enterprise temporary-shadow semantics are UNCHANGED

An enterprise-authorized temporary shadow window (`Some(Observe)` with a
mandatory `enforcement_mode_expires_at`) is completely separate machinery and
behaves exactly as it did before this ticket:

* Still capped at **≤ 72 hours** (`SHADOW_MAX_HOURS`).
* Still auto-reverts to `Enforce` via the shadow-expiry reconciler.
* Still requires Admin scope + a non-empty reason to create.

personal-observe being active on the same deployment changes none of this —
an agent with an active enterprise shadow window still reverts to `Enforce`
at its deadline, and personal-observe does not "re-shadow" it afterward.

## personal-observe's own semantics

* **Does NOT time-expire.** The shadow-expiry reconciler only ever selects
  records with `enforcement_mode = Some(Observe)` — a `None` record (the only
  thing personal-observe affects) is structurally invisible to it.
* **Is not a renewable shadow grant.** It does not use the 72h shadow-window
  machinery at all; there is no expiry to renew.
* **Is a deployment profile**, not a per-agent or per-request setting. It is
  removed by removing `observation.profile` from `~/.aasm/config.yaml` (or
  unsetting `AASM_OBSERVATION_PROFILE`) and restarting.

## Boot-refusal behaviour

Two layers check for enterprise coupling:

* **Layer 1** (`GatewayConfig::validate()`) is **advisory only**. Three of
  the six non-test `GatewayConfig::load()` call sites in this codebase
  swallow every `ConfigError` and continue with defaults
  (`aa-api/src/state.rs::resolve_local_registry_db_path`,
  `aa-gateway/src/server.rs`'s two challenge-store selection sites) — Layer 1
  does no useful work there.
- **Layer 2** (`aa_core::observation::authorize_personal_observe`) is
  **authoritative**. It is what actually mints the grant
  `serve_local` needs, and it re-derives every config-shaped signal directly
  — it is never bypassed by a caller discarding `validate()`'s error.

The full signal list Layer 2 checks (config-shaped signals are also checked,
independently, by Layer 1):

1. `mode == remote`
2. `storage.backend == postgres`
3. `remote.database_url` is set
4. `remote.redis_url` set, or `storage.redis.enabled`
5. `remote.tls` configured
6. `agent.api_key` set
7. `agent.gateway_url` is not loopback
8. `local.host` is not loopback
9. an audit archive destination is configured (`cold_action = archive`)
10. the REST bind address is not loopback
11. `AA_LOCAL_ALLOW_REMOTE` is set
12. `AASM_API_KEY` is set
13. `AA_MODE=remote`
14. `AA_OPCONTROL_NATS_URL` is set (cross-process op-control)
15. an audit-publisher / NATS endpoint is configured (`AA_AUDIT_NATS_URL`)
16. `AA_GATEWAY_URL` points off-host
17. `AA_AUDIT_DIR` points outside the user's home
18. a database URL is configured (`DATABASE_URL` / `AASM_DATABASE_URL`)

If any signal fires, the process refuses to start with:

```text
refusing to start: observation.profile = personal_observe, but this deployment looks
enterprise-managed. Detected signals: <comma-separated signal strings>.
personal-observe is a PERSONAL, UNMANAGED deployment profile; it must never weaken enforcement
that an organisation is managing. Remove `observation.profile` from ~/.aasm/config.yaml (or unset
AASM_OBSERVATION_PROFILE) to start normally.
NOTE: this detector is BEST-EFFORT and NOT UNIVERSAL. Its NOT refusing is not proof that a
deployment is unmanaged. See docs/src/security/personal-observe-profile.md#known-coverage-gaps.
```

`aa-gateway` refuses unconditionally when the key is set, with:

```text
refusing to start: observation.profile = personal_observe is not implemented by aa-gateway.
This key is honoured only by the local single-process aa-api-server entrypoint. aa-gateway will
not silently ignore it, because ignoring it would leave you believing personal-observe is active
when enforcement is in fact live. Unset the key to run aa-gateway. Tracking: HORO-1492.
```

When granted, the following line is logged at `WARN` (not `INFO`, so it
survives default filters) immediately after the local agent-plane gRPC
listener successfully binds — never before, and never if that bind fails:

```text
personal-observe profile ACTIVE (HORO-1375): agents with NO per-agent enforcement_mode
override now default to Observe — policy denies are AUDITED, NOT ENFORCED. Unchanged and still
authoritative: any per-agent enforcement_mode override (including an enterprise temporary shadow
window, which remains capped at <=72h and still auto-reverts to Enforce) takes precedence over
this default. personal-observe itself does NOT time-expire.
The enterprise-coupling detector that permitted this boot is BEST-EFFORT, NOT UNIVERSAL: it
checked only <N> named signals and CANNOT observe management channels it does not know about
(MDM/EDR host agents, sidecar or eBPF interception, proxy-level enforcement, out-of-band org
policy). An undetected channel is an UNKNOWN, never a proven-safe result. Known gaps:
docs/src/security/personal-observe-profile.md#known-coverage-gaps
```

If the local agent-plane gRPC port (`127.0.0.1:50051`) is already held by
another process (typically a co-located `aa-gateway`) while personal-observe
is requested, `aa-api-server` **refuses to start** rather than degrading to
REST-only: that other process is the one actually enforcing policy, is not
running personal-observe, and letting `aa-api-server` come up anyway would
report personal-observe as active while denies are in fact live-enforced
elsewhere on the host.

## Wording discipline

No log line, doc sentence, API field, or status string produced by this
feature may state or imply that a host is **unmanaged, safe, verified, or
compliant** as a posture claim. The only permitted claim is "no coupling
signal detected among the checked signals" — a statement about what was
checked, not about ground truth. This is enforced by an automated wording
test (`personal_observe_wording_never_claims_unmanaged` / N4) in addition to
review.

## Known coverage gaps

The detector is **best-effort and NOT universal**. Its not refusing to start
is never proof that a host is unmanaged. Concretely, it cannot see:

| Gap | Description | Tracking |
|---|---|---|
| G1 | MDM / host-management channels (macOS configuration profiles, Jamf, Intune, group policy). | HORO-1488 |
| G2 | EDR / sidecar / eBPF / kernel-level interception, or a transparent enforcing proxy on the egress path. | HORO-1489 |
| G3 | Org policy delivered out-of-band — a managed policy file dropped into `$AA_POLICY` by a fleet tool is indistinguishable from a user-authored one. | HORO-1490 |
| G4 | `PolicyDocument.enforcement_mode` is dead on the `CheckAction` hot path today; it must not be wired without routing through this same gate. | HORO-1491 |
| G5 | `aa-gateway` does not implement personal-observe; it refuses instead. Whether to implement it there is undecided. | HORO-1492 |
| G6 | Signals are checked at **boot only**. A management channel that appears after boot is not re-detected — there is no runtime re-check. | HORO-1493 |
| G7 | `AgentRecord.enforcement_mode` is a `pub` field; this gate and the registry write-side guard close the primitive and the rehydrate path, but a direct field assignment inside `aa-gateway` remains structurally possible. | HORO-1494 |

(A pre-existing, separate defect — the local audit hash chain being rooted
under a temp directory and reseeded on every restart — was found and fixed
as part of this same ticket; see [Durable audit location](#durable-audit-location-and-what-is-recorded)
below. It is tracked for traceability as HORO-1495, since any chain written
before this fix is permanently forked and unverifiable across that boundary,
but it is not a personal-observe coverage gap.)

These gaps are tracked as sub-tasks of HORO-1369.

## Durable audit location and what is recorded

The local single-process entrypoint's governance-audit JSONL hash chain is
rooted at `aa_gateway::server::default_audit_dir()` — `AA_AUDIT_DIR` when
set, else `dirs::data_dir()/aa/audit` — the **same directory**
`aa-gateway`'s own audit sink writes to on the same host. This is a
deliberate unification (not a merge of two previously-separate trails):
`AuditReader` globs every `*.jsonl` file in its directory, so
`/api/v1/audit/*` now also surfaces gateway-written entries from the same
host, giving one governance trail per host instead of two that could
silently fork. The audit/retention SQLite backend is a separate file,
`~/.aasm/audit.db` (`local.audit_storage_path`), kept apart from the agent
registry's `~/.aasm/local.db` so this does not change SQLite lock
contention for the registry.

Under personal-observe, an action that would have been denied is **audited,
not enforced**: the decision is rewritten to `Allow`, and an `AuditEntry`
with `dry_run = true` and a `shadow_decision` naming the original decision
(`"deny"` / `"pending"`) is recorded to that same durable chain. The entry
survives a restart and verifies (`AuditWriter::verify_chain` reports
`Verified`) across the restart boundary.
