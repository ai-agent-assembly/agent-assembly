# Limitations and known bypasses

Everything on this page is a limit that exists **today**, in the shipped code, on
the platform the MVP targets. It is written so that a security reviewer can read
it instead of reverse-engineering the integration, and so that nothing here has
to be discovered the hard way.

The evidence base is `verification-reports/AAASM-5276-claude-code-mechanism-matrix.md`
— the measured mechanism matrix from the Claude Code lifecycle Spike — plus the
adapter code that shipped in
[AAASM-5281](https://lightning-dust-mite.atlassian.net/browse/AAASM-5281). A
claim that traces to neither is not on this page.

## Capability status legend

| Status | Meaning |
|---|---|
| **Supported** | Shipped and exercised by tests. |
| **Experimental** | Shipped, but its evidence is incomplete or its shape may change. |
| **Planned** | Not built. The ticket that builds it is named. |
| **Unsupported** | Deliberately not offered, with a reason. |

| Capability | Status | Note |
|---|---|---|
| Managed settings write / merge / restore | **Supported** | Four owned keys; every other key preserved. |
| Proxy CA materialisation + `NODE_EXTRA_CA_CERTS` injection | **Supported** | AAASM-5276 condition C1. |
| HTTPS interception and redaction on the model path | **Supported** | Measured against the real binary; see [`verify`](#what-verify-adjudicates-and-when-it-still-exits-6) for what raises the *level*. |
| Side-channel scoping (`*.anthropic.com`) | **Supported** | Condition C5. |
| MCP loading control (`enabledMcpjsonServers` / `disabledMcpjsonServers`) | **Supported** | Optional, defence-in-depth. Never required for protection. |
| Drift detection and repair | **Supported** | Detected at `status`/`verify` time, not in real time. |
| Adjudicating protection probe | **Supported** | Shipped as the default probe (AAASM-5300); see [`verify`](#what-verify-adjudicates-and-when-it-still-exits-6). |
| `strict` blocking on a high-severity scanner finding | **Planned** | [AAASM-5277](https://lightning-dust-mite.atlassian.net/browse/AAASM-5277), [AAASM-5281](https://lightning-dust-mite.atlassian.net/browse/AAASM-5281). Today `strict` redacts, like `recommended`. |
| Endpoint managed-settings file | **Installable, opt-in and authorized** | [AAASM-5298](https://lightning-dust-mite.atlassian.net/browse/AAASM-5298). `--install-managed-settings`; verified by read-back. |
| Endpoint managed-settings *enforcement* keys | **Still unmeasured** | Documented as non-overridable; no real override attempt has been measured on any host. [How it would be measured](managed-device-measurement.md). |
| Byte-exact configuration restore | **Unsupported** | Semantics-exact by accepted constraint (C3). |
| `ANTHROPIC_BASE_URL` redirection as a protection mechanism | **Unsupported** | Measured delivering the raw secret. |
| Host-level bypass prevention | **Unsupported** | Explicit non-goal. |
| Lifecycle for Codex / Copilot / Windsurf | **Planned** | Carried by `LegacyAdapterShim`; apply is refused. |
| Windows / Linux | **Unsupported** | macOS is the MVP platform. |

---

## Known bypasses: demonstrated versus inferred

This split is published deliberately. Presenting the two groups as one
undifferentiated list would overstate what has actually been tested — a
demonstrated bypass is a measurement, an inferred one is a documented belief, and
a reader deciding how much to trust this integration needs to know which is
which.

### Demonstrated by the AAASM-5276 harness

Three, each asserted positively by a test:

1. **`ANTHROPIC_BASE_URL` pointed at any endpoint removes Agent Assembly from
   the path; the raw secret arrives.** Shown with both the real `claude 2.1.220`
   binary and an emulated client.
2. **Launching `claude` outside the managed path (no `HTTPS_PROXY`) is
   unprotected.**
3. **`Observe`/`AlertOnly` forwards the secret unchanged** — correct behaviour,
   and the reason observe-only must never render as protection.

### Inferred, not demonstrated

Documented, **not measured** by the Spike:

`--dangerously-skip-permissions` · `defaultMode: bypassPermissions` · `--bare` ·
unsetting the proxy env in the shell · repointing `CLAUDE_CONFIG_DIR` ·
symlinking `.claude` · replacing the binary · calling the API directly with the
user's own key · switching provider (`CLAUDE_CODE_USE_BEDROCK` /
`CLAUDE_CODE_USE_VERTEX`) · running a pre-managed-settings release · a hook
exiting `1` instead of `2`.

> The Spike's summary sentence counts these as *ten*; the enumeration above is
> its own list and contains eleven items, because two permission-bypass flags are
> enumerated separately. **The list is the claim, not the count.**

Neither list is asserted to be exhaustive. "No finding" is not "no bypass".

### Which of these the shipped integration can actually see

Detection is not prevention. Where a bypass is detectable, the shipped adapter
names it, lowers the reported protection level, and puts it in `status`; where it
is not, the plan states so explicitly rather than leaving you to infer it from
silence (`aa-devtool-claude-code/src/bypass.rs`).

| Bypass | Detected? | Where it is looked for |
|---|---|---|
| `permissionMode` / `permissions.defaultMode` = `bypassPermissions` | **Yes** | The managed settings document. Becomes **Absent** evidence: the rules are still written and still read back, but nothing can be concluded from them about what the tool will do. |
| `ANTHROPIC_BASE_URL` / `CLAUDE_CODE_API_BASE_URL` | **Yes** | The shell environment *and* a settings `env` block. |
| `CLAUDE_CODE_USE_BEDROCK` / `_VERTEX` | **Yes** | The shell environment. |
| `NODE_TLS_REJECT_UNAUTHORIZED` | **Yes** | The shell environment and a settings `env` block. |
| `--dangerously-skip-permissions`, `--allow-dangerously-skip-permissions`, `--bare` | **Yes** | The launch arguments. Reported and **passed through unchanged** — Agent Assembly's interception sits *below* Claude Code's own permission enforcement, so stripping the flag would change your session without changing what is protected. |
| Launching `claude` outside `aasm run` | **No** | No proxy or CA is injected; there is nothing to observe. |
| Repointing `CLAUDE_CONFIG_DIR` | **No** | — |
| Symlinking `.claude` | **No** | — |
| Editing the settings file directly | **No** *(as a bypass)* | Surfaces later as **drift** at the next `status`/`verify`, not as a bypass at launch. |
| Replacing the `claude` binary | **No** | — |
| Calling the Anthropic API from another program with your own key | **No** | Not this tool, not this path. |
| A hook exiting `1` instead of `2` | **No** | Hooks carry no sensitive-data claim here (see below). |

**A bypass is not a failure.** An unprotected launch is reported as a bypass, not
as an Agent Assembly error, because the remedy is different and blaming the
system trains people to ignore real failures.

---

## `ANTHROPIC_BASE_URL` is routing, not protection

Redirecting Claude Code's model endpoint is **unsuitable for protection** and is
deliberately not offered as a mechanism (AAASM-5276 condition **C4**).

It was measured, with both the real binary and an emulated client, delivering the
synthetic secret to the provider **with no Agent Assembly component anywhere in
the path**. Setting it in the shell additionally suppresses Claude Code's
server-managed settings fetch.

This is why the lifecycle contract keeps `ModelPathInterception` and
`ModelGatewayBaseUrl` as separate capabilities. They look alike and they are
opposites: the first is a protection capability, the second is routing that
*removes* protection.

## What `verify` adjudicates, and when it still exits `6`

`aasm integrations verify claude-code` **passes on a correctly installed
integration** whose protected path was exercised and adjudicated (AAASM-5300).

Raising the level to `Gateway Protected` requires *exercised* evidence, and
exercised means the traffic was produced **and adjudicated**. Adjudicating means
knowing what the payload leaving the machine actually carries — which a client on
the **near side of the proxy cannot see for itself**. So the shipped probe does
not try to. It marks its own request with an opaque correlation identifier, and
the proxy — the component that runs the credential scanner and constructs the
bytes that would be forwarded — answers on that request's own connection with
what it decided, plus a re-inspection of the payload it resolved to forward.
`Redacted` is reported only when the proxy says it scrubbed the body **and** that
the scrubbed bytes carry no credential
(`aa-devtool-claude-code/src/adjudicating_probe.rs`,
`aa-proxy/src/probe_adjudication.rs`).

Two properties of that exchange are worth knowing:

- **The probe learns nothing but its own verdict.** There is no verdict store and
  no query surface — a verdict exists only as the response to the request that
  produced it, and is accepted only when it echoes the identifier that run
  minted. The correlation identifier is 32 hex characters of OS entropy and is
  derived from nothing about the payload.
- **The probe's traffic never reaches the provider.** The proxy terminates a
  correlated request instead of relaying it, and the probe sends a credential-free
  preflight first — so a path with nothing adjudicating on it never receives the
  synthetic secret at all.

A probe that returned `Redacted` because nothing obviously failed would be a
**vacuous pass**, which is precisely what the evidence model exists to prevent.
That rule is unchanged, and `verify` still exits `6` (`verification_failed`)
whenever it cannot measure:

| Condition | Why it cannot pass |
|---|---|
| The path was never exercised | No trust material in the receipt, so there is no intercepted model path to drive. |
| The certificate authority is not trusted | The MitM handshake fails, so nothing inspected the traffic. AAASM-5276 condition **C1**. |
| Nothing adjudicates the path | The peer answered, but not with an adjudication — no component reported what it did. |
| The core is stopped | Nothing is accepting connections; there is no verdict to read. |
| The exchange times out | Bounded and reported, never assumed. |
| A verdict for a different request | A verdict the probe did not produce is not evidence about the probe. |
| `alert_only` is configured | The finding is recorded and the payload forwarded unchanged — observing is not protecting. |

Read exit `6` on an otherwise-clean install as **"not measured"**, not as
**"measured and failed"** — and read `status` for which it is.

## The managed-settings file can be installed; its enforcement is still unmeasured

`/Library/Application Support/ClaudeCode/managed-settings.json` is the endpoint
managed-settings file. Its managed-only keys —
`allowManagedPermissionRulesOnly`, `disableBypassPermissionsMode`,
`allowManagedMcpServersOnly`, `allowManagedHooksOnly` —
are **the strongest available counters to the bypasses listed above**.

Since [AAASM-5298](https://lightning-dust-mite.atlassian.net/browse/AAASM-5298),
Agent Assembly can install that file — through an **opt-in, explicitly
authorized** path, never as part of a default install. See
[`--install-managed-settings`](cli.md) and
[Protection levels → Host Enforced](protection-levels.md#host-enforced).

**What Agent Assembly verifies**, by reading the file back after the write:

* its bytes are exactly the bytes you were shown and authorized;
* it parses as a managed-settings document and carries the managed-only keys;
* it is owned by the expected principal (root at the canonical path);
* no account other than its owner can rewrite it.

**What Agent Assembly does not measure**, and will not claim:

* that Claude Code honours each managed-only key at runtime. Anthropic documents
  these keys as non-overridable; Agent Assembly has **not** measured a real
  override attempt on **any** host. AAASM-5276 condition **C6** is closed for
  the *install* half and open for the *enforcement* half.

What would close it is written down rather than left as "we need a device":
[Measuring managed-settings enforcement](managed-device-measurement.md) is the
procedure, and `scripts/measure-claude-code-managed-enforcement.sh` refuses to
run anywhere it could not produce real evidence. The measurement needs a real
privileged write on a real host — which
[AAASM-5308](https://lightning-dust-mite.atlassian.net/browse/AAASM-5308) scopes
as *"a managed/MDM-enrolled macOS device, or one where the file can be
provisioned with administrator consent"* — and, for the override attempts, an
account that is not an administrator. Until that has been run, none of it is
claimed.

> Read a `Host Enforced` level as: *"the managed policy is installed at the
> OS-managed path, owned as expected and not writable by you."* Do not read it as
> *"this bypass has been demonstrated to fail."* Every status that reports it
> carries that caveat in the evidence detail.

### What the install will not do

* It will not elevate anything but the single file placement. `aasm` never runs
  as root, and no other step in any plan asks for authorization.
* It will not replace a managed-settings file Agent Assembly did not write — for
  example one deployed by your organisation's device management. That is a
  refusal, and moving the file aside is your explicit decision to make, not
  Agent Assembly's.
* It will not run without a terminal. A non-interactive invocation fails
  immediately rather than blocking on a credential prompt nobody can answer.
* It will not report success on the authorization mechanism's word. A read-back
  that does not match rolls the write back and fails.

## Restore is semantics-exact, not byte-exact

Accepted constraint C3
([ADR 0030 — Accepted risks](../adr/0030-developer-integration-boundaries-and-trust-model.md);
AAASM-5276 condition **C3**, accepted by
[AAASM-5278](https://lightning-dust-mite.atlassian.net/browse/AAASM-5278)).

`aa-devtool-claude-code/src/apply.rs` **reserialises the whole settings
document** on every write. A user file in non-canonical formatting — hand-chosen
key order, unusual indentation, trailing layout — therefore cannot survive an
install → remove cycle byte-for-byte, no matter how good the receipt is.

What removal **does** restore is the document's *meaning*:

* every value Agent Assembly displaced is put back;
* every key Agent Assembly added is deleted;
* every key you changed after installation is carried through untouched.

Two consequences follow deliberately from accepting this rather than working
around it. Fingerprints are taken over **canonical JSON**, so a reformat is
correctly reported as *no drift*. And a removal report **states the limitation**
rather than implying a guarantee the write path cannot keep.

The alternative — preserving the original document verbatim — was rejected as
disproportionate for the MVP: it needs a format-preserving JSON editor no in-tree
adapter has, and it buys byte-identity in a file the tool itself rewrites. If an
adapter's write path ever stops reserialising, this becomes a *choice* rather
than a constraint and should be revisited rather than inherited.

## The scanner only recognises the shapes it knows

Detection is deterministic and **pattern-based** (`aa-security`'s
`CredentialScanner`). "Detected" means *matched by the pattern set*; it does not
mean *understood*.

A credential whose shape is not in the pattern set passes through
unrecognised — a bespoke internal token, a secret with no distinguishing prefix,
a value split across fields. There is no claim of complete detection, and the
Spike explicitly does not license one.

Two knock-on limits worth stating:

* **An undetected secret is not absent from audit records.** If the scanner never
  classified a value as a secret, it was never redacted, and it may appear in a
  recorded payload like any other content.
* **Redaction is not encryption and not a DLP product.** An oversized field that
  cannot be scanned reliably is replaced wholesale with `[REDACTED:OVERSIZED]` —
  the scanner fails closed — but that is a containment behaviour, not detection.
* **A flagged undecodable payload loses its whole audit content.** A `bytes` field
  that is not valid UTF-8 — a binary body, or multi-byte text cut by a chunk
  boundary — is still scanned, but a detected secret cannot be excised precisely,
  because the finding's offsets index the lossy decoding rather than the payload.
  The field is therefore replaced *in full* with `[REDACTED:UNDECODABLE]`. The
  secret is contained, but so is everything else that was in the field: the
  surrounding content does not reach the audit record. A **clean** undecodable
  field is unaffected and is forwarded byte-identical (AAASM-5346).

  **This is sharper for `zh-TW` traffic until [AAASM-5344] ships.** That defect
  makes ordinary Chinese text register as `GenericHighEntropy` findings, so a
  chunk-split Chinese payload is *dirty by false positive* and loses its entire
  `args_json` to the 22-byte marker — where previously it was forwarded corrupted
  but present. Containment is the correct trade, and a corrupted payload was
  never trustworthy audit content, but the loss is real and it is why ADR 0032's
  operational guidance treats `zh-TW` traffic as unsafe until AAASM-5344 lands in
  `v0.0.1-rc.7`. Once it does, benign Chinese text stops producing findings and
  this path stops being reached by ordinary traffic.

[AAASM-5344]: https://lightning-dust-mite.atlassian.net/browse/AAASM-5344

## Hooks cannot carry a sensitive-data claim

Claude Code hooks govern **tool and action execution**. They cannot see or modify
model-bound prompt content, so no hook can support a sensitive-data protection
claim. They remain available for tool governance; they are never a substitute for
in-path interception.

`NODE_TLS_REJECT_UNAUTHORIZED` is **never set** by Agent Assembly. Setting it
would make interception "work" by disabling certificate verification, and a TLS
failure is a finding, not something to suppress. If you have it set, `status`
reports it as a bypass.

## Other tools are not yet on this lifecycle

Codex, GitHub Copilot and Windsurf Cascade are carried by `LegacyAdapterShim`
(ADR 0030 §7). They can be **discovered, planned and reported on**, but their
plan steps name no destination file, so the service **refuses to apply** rather
than reporting a success that performed nothing. Their per-capability tiers in
the [capability matrix](../governance/capability-matrix.md) come from their
adapters' declarations, not from a measured Spike. Superseded per-tool detail for
each — predating the consolidated matrix — is kept at
[Governance Limits by Tool](governance-limits/claude-code.md) (also covering
[Codex](governance-limits/codex.md), [Copilot](governance-limits/copilot.md) and
[Windsurf](governance-limits/windsurf.md)).

This page is scoped to locally-running tools. If the tool in question is a
SaaS-hosted coding agent (Claude.ai, ChatGPT, Cursor cloud), see
[SaaS Coding-Agent Governance Limits](governance-limits.md) instead — those
adapters are capped at `L1Observe` for a structural reason (no local process to
intercept), not a maturity gap like the tools above.

## Timing and freshness

* **Drift is found when `status`/`verify` runs**, so a window exists between a
  change and its discovery. Between two verifications a state can be reported
  that has since become false. The evidence carries its timestamp — the claim is
  *"verified at T"*, not *"true now"* — but a consumer that ignores the timestamp
  will over-read it.
* **Protection state is re-derived on read, never cached.** AAASM-5276 measured
  ~0.07 ms from core stop to connections being refused; a cached level would keep
  displaying protection that no longer exists.
* **Repair is deliberately narrow.** It will not overwrite a key it does not own,
  even when that key is the cause of the drift — it reports and stops.

---

## What stays local, and what is never recorded

These two are guarantees rather than limitations, but they belong beside the
limitations because each has its own edge.

**Raw content is processed locally.** Scanning and redaction happen in the Agent
Assembly runtime on your machine. Raw file contents and raw prompt text are not
shipped to Agent Assembly infrastructure in order to be analysed.

> That is not the same as *your content stays on your machine*. The point of the
> tool is to send prompts to a model provider; Agent Assembly's job is to make
> what is sent safe, not to prevent sending. Where an org deployment is
> configured, policy documents, audit **metadata** and decision records may be
> forwarded to a control plane. Metadata is not raw content, but it is not
> nothing either.

**Raw secret material is never written** to logs, traces, audit events,
installation receipts, API responses or diagnostic output. Findings are recorded
as metadata — kind, position, count — and the redaction record deliberately
stores no raw value (`aa-security/src/redaction.rs`). Diagnostics produced for
support are subject to the same rule; troubleshooting is not an exemption.

This is enforced by the **shape of the types**, not by a redaction pass someone
can forget to call. Across the DI-API, a rendered settings body becomes a
`content_sha256` plus the owned key names; an environment value becomes the
variable's **name**; a model base URL becomes the setting's **name**, because a
URL can carry a token in its query string. `StepView` — the sharpest edge — has
**no field a step value could land in**. A bypass report likewise echoes variable
names only and never their values, asserted by a test that plants a sentinel
value and fails if it appears.

> The edge: this does not govern the tool's own records. Claude Code's
> transcripts, your shell history and your provider's server-side logs are
> outside Agent Assembly's control entirely.

---

## What is never claimed

Stated positively so it can be quoted:

* **No host-level bypass prevention.** A user or process able to launch the tool
  outside the managed path is outside enforcement, at every level available.
* **No protection for unmanaged direct provider connections.**
* **No complete secret detection.**
* **No protection while the core is stopped.** Protection is a running-system
  property; when the core is down the product says *not protected*, not
  *protection unknown*.
* **No universal interception of every AI development tool.**
* **No claim that a settings file alone proves model-egress protection.** A
  configuration is intent; a level is behaviour.
* **No claim that MCP is required for, or equivalent to, protection.** It is one
  optional mechanism among several.

---

## References

* [Onboarding a Developer Integration](onboarding.md)
* [Protection levels](protection-levels.md)
* [Product Capability Brief](product-brief.md) §8 (guarantees and their limits),
  §10.3 (non-goals)
* [L0–L3 Capability Matrix](../governance/capability-matrix.md)
* [SaaS Coding-Agent Governance Limits](governance-limits.md) — the equivalent
  honest-boundaries page for Claude.ai, ChatGPT and Cursor cloud
* [ADR 0030 — Developer Integration boundaries and trust model](../adr/0030-developer-integration-boundaries-and-trust-model.md)
* `verification-reports/AAASM-5276-claude-code-mechanism-matrix.md` — the measured
  evidence this page is derived from (in-repo; not part of the published book)
