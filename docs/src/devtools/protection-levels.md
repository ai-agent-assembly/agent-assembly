# Protection levels

A **profile** is what you chose. A **level** is what the system can prove it is
currently doing. They are separate because you can choose `strict` on a machine
where the tool is not routed through the gateway — and the honest answer there is
`Integrated`, not *strict protection active*.

> **The governing rule: the existence of a configuration file is never sufficient
> evidence for a protection level.** Configuration expresses intent. A level is a
> claim about behaviour, and a claim about behaviour requires an observation of
> behaviour.

This page restates [product brief](product-brief.md) §7 as an operational
reference. Where the two differ, the brief is canonical.

---

## The ladder

| Level | One-line claim | Reachable today? |
|---|---|---|
| **Integrated** | The tool's *startup posture* is governed and its actions are attributable. | **Yes.** |
| **Gateway Protected** | Model-bound and tool-bound traffic is inspected, redacted and allow/deny-enforced in flight. | **Mechanism proven; not reportable on a default build** — see [below](#why-gateway-protected-is-not-reportable-today). |
| **Host Enforced** | The tool's policy lives on a surface the developer cannot rewrite, verified by read-back after an authorized write. | **Opt-in only** — `--install-managed-settings`, macOS. A default install can never reach it. |

Two reporting rules apply at every rung:

* **Report the highest level whose criteria are *currently* met**, re-derived on
  read rather than cached. A level earned at install time is not still true after
  the core stops — AAASM-5276 measured ~0.07 ms from core stop to connections
  being refused, so a cached level would be displaying protection that no longer
  exists.
* **Report the mechanisms behind the level**, split into *exercised* and *read
  back*. A user who can see which is which can reason about their own risk; a
  user shown a single word cannot.

---

## Integrated

| | |
|---|---|
| **What it protects** | The tool's startup posture. The managed settings constrain what Claude Code will agree to do — permission allow/deny lists, `permissionMode`, and which MCP servers it may load — and the tool is registered with the gateway so its actions are attributable and auditable. |
| **Testable entry criteria** | **All four** must hold: (1) a valid installation receipt exists; (2) every managed key read back from the live config equals the planned value by content hash; (3) the detected tool version is at or above the adapter's minimum; (4) the tool has been launched at least once through the managed path *and* the gateway observed the resulting registration event. Criterion 4 is what makes this a behavioural claim — (1)–(3) alone are configuration and are explicitly **not** sufficient. |
| **What it does *not* protect** | Anything on the model-bound path. **Nothing is inspecting model-bound content at this level**, so `Integrated` carries no sensitive-data claim at all. |
| **Bypasses that remain** | Launching the tool outside the managed path. Editing the managed config by hand (detectable as drift, but only at the next status check). All model-bound traffic. Anything the tool's own config surface cannot express. |
| **Maps to L0–L3** | `L1Observe` as a floor, rising to `L3Native` **for the individual capability dimensions the tool's own configuration genuinely governs** — for Claude Code, the MCP enable/disable lists and the permission keys. See the [capability matrix](../governance/capability-matrix.md). |
| **Honest limit** | Cannot claim host-level bypass prevention. Cannot claim sensitive-data protection. |

## Gateway Protected

| | |
|---|---|
| **What it protects** | Model-bound and tool-bound traffic in flight. Requests traverse the Agent Assembly proxy, so the runtime scanner inspects them, detected secrets are redacted before egress, egress allowlists are enforced, approvals can halt an action, and every decision is audited. |
| **Testable entry criteria** | Everything required for `Integrated`, **plus a completed protection exercise within the current configuration**: a synthetic secret placed in a model-bound path resulted in (a) the controlled endpoint receiving no raw secret, (b) a redaction finding recorded, and (c) the agent receiving a semantics-preserving placeholder. A reachable gateway is not sufficient. A configured proxy address is not sufficient. **Traffic must have been observed and acted on.** |
| **What it does *not* protect** | Traffic from tools other than the governed one. Content the deterministic scanner does not match — detection is pattern-based, so *unknown* secret shapes pass through. Anything at all if the core is stopped. |
| **Bypasses that remain** | Direct provider connections that do not honour the injected proxy — an unmanaged launch, a redirected base URL, a separate credential. Certificate-pinned clients that reject the proxy CA. See [Limitations](limitations.md). |
| **Maps to L0–L3** | `L2Enforce` — allow/deny, approval, redaction and budget enforcement, which is precisely what traversal of the gateway provides. |
| **Honest limit** | Also cannot claim host-level bypass prevention. It protects the paths it sees. A user or agent able to start a process outside the managed path is outside its scope by construction. |

### How `Gateway Protected` becomes reportable

> **`aasm integrations verify claude-code` exits `0` once the protected path has
> been exercised and adjudicated (AAASM-5300); until then the level stays at
> `Integrated`.**
>
> Raising the level requires *exercised* evidence, and exercised means traffic
> was produced **and adjudicated**. Adjudicating means knowing what the payload
> leaving the machine actually carries — which **a client on the near side of the
> proxy cannot see for itself**. So the shipped probe does not infer it: it marks
> its own request with an opaque correlation identifier, and the proxy — the
> component that runs the scanner and builds the forwarded bytes — answers on
> that request's own connection with what it decided and with a re-inspection of
> the payload it resolved to forward. `Redacted` is reported only when both agree
> (`aa-devtool-claude-code/src/adjudicating_probe.rs`).
>
> **Everything it cannot measure still exits `6`**: an untrusted certificate
> authority, a path nothing adjudicates, a stopped core, a timeout, or a verdict
> belonging to a different request. A probe that reported `Redacted` because
> nothing obviously failed would be exactly the vacuous pass this system exists
> to prevent, and the guard that pins that rule is still in the suite.
>
> **The mechanism itself was measured working.** AAASM-5276 ran the real
> `claude 2.1.220` binary against a TLS-terminating mock provider: all four
> upstream requests traversed the proxy, the deterministic scanner matched the
> synthetic secret, and the forwarded body carried `[REDACTED:AnthropicKey]`
> while remaining valid Messages JSON — at sub-millisecond added cost.

## Host Enforced

| | |
|---|---|
| **What it protects** | The tool's *policy surface*, not just its configuration. The governing document lives where the developer running the tool cannot rewrite it, so unsetting a variable or editing a settings file cannot widen it. |
| **Testable entry criteria** | `Gateway Protected`, **plus** an endpoint managed-settings file that Agent Assembly installed under explicit administrator authorization and then **read back and verified**: exact authorized bytes, valid managed-settings document carrying the managed-only keys, owned by the expected principal, not writable by anyone else. |
| **Availability** | **Opt-in, macOS only.** Reached only through `aasm integrations install claude-code --install-managed-settings`. Never part of a default install, never implied by a profile, never reachable at `--scope user` or `--scope project`. |
| **Reporting requirement** | Named and reported with its reason whenever it is *not* active, and reported with its caveat whenever it *is*. |
| **Maps to L0–L3** | Nothing. It is *not* `L3Native`: `L3Native` means Agent Assembly writes the tool's own native configuration so governance survives Agent Assembly going offline — a property of `Integrated`. Host enforcement is orthogonal to the L0–L3 scale. |

### The one privileged operation

The default install is fully unprivileged. `--install-managed-settings` adds
**exactly one** step that changes host state: placing a single file at
`/Library/Application Support/ClaudeCode/managed-settings.json`, owned by root.
`aasm` itself never runs as root, and no other step in any plan asks for
authorization.

Before authorization is requested, the plan states the exact target path, why
the privileged write is required, the exact bytes and their diff against what is
already there, any existing-file conflict, and the backup and rollback
behaviour. `aasm integrations remove claude-code` reverses it symmetrically —
restoring the file that was there before, or leaving a host that had none with
none.

### What this level does and does not claim

> `Host Enforced` means: **the managed policy is installed at the OS-managed
> path, owned as expected, and not writable by you.** It does **not** mean a
> bypass has been demonstrated to fail. Anthropic documents the managed-only
> keys as non-overridable; Agent Assembly has not measured a real override
> attempt against a managed device, and the evidence detail behind every
> `Host Enforced` reading says so. See
> [Limitations](limitations.md#the-managed-settings-file-can-be-installed-its-enforcement-is-still-unmeasured).

Kernel-level enforcement remains out of scope: macOS Endpoint Security and
Network Extension are explicit non-goals, and `aa-ebpf` is Linux-only and is a
*detection* layer — it observes SSL and exec/file syscalls but cannot modify
traffic in flight.

---

## Evidence: exercised versus read-back

This split is the whole mechanism by which a level stays honest, so `status`
prints it rather than summarising it.

| Evidence kind | What it establishes | Highest level it can justify |
|---|---|---|
| **Exercised** | Traffic was produced on the protected path and the core adjudicated what happened to it. | `Gateway Protected` |
| **Read-back** | A managed value on disk matches what the receipt says was written. Proves a file is correct; proves nothing about traffic. | `Integrated` |
| **Host-attested** | An enforcement surface reported on itself and the report was attributed to this tool. For Claude Code this is the read-back of the endpoint managed-settings file after an authorized install — content, owner and permissions. | `Host Enforced` |
| **Absent** | A check could not be made. Recorded so the gap is legible. Absent readings only ever *lower* a state. | — |

A detected bypass becomes **Absent** evidence rather than a silent pass. With
`defaultMode: "bypassPermissions"` in effect, for instance, Agent Assembly's
permission rules are still written and still read back — but nothing can be
concluded from them about what the tool will actually do
(`aa-devtool-claude-code/src/bypass.rs`).

Every status carries `observed_at_unix_secs`. The claim is **"verified at T"**,
not "true now".

---

## How a profile interacts with a level

| | `recommended` | `strict` | `observe-only` |
|---|---|---|---|
| Highest level attainable | `Gateway Protected` | `Gateway Protected` | **None.** |
| What status says | The achieved level plus its evidence | The achieved level plus its evidence | *Monitoring*, with a standing not-enforcing warning |

**`observe-only` must never be displayed as protection.** Under
`EnforcementMode::Observe` the payload is forwarded unchanged — AAASM-5276
measured the synthetic secret reaching the provider — which is correct behaviour
and precisely why the profile that does not protect must not be able to look like
the one that does.

---

## Failure and degradation

Default posture is **fail closed**: when Agent Assembly cannot establish that
protection is active, it reports *not protected* and, where a decision is
required, denies. Failing closed does not mean bricking your tool — the tool
stays usable; what fails closed is the *protection claim*.

| Situation | Reported as |
|---|---|
| Core stopped or unreachable | *Not protected* — never "protection status unknown". Say when protection ended if it stopped mid-session. |
| Partial install | *Not protected*, rolled back. Never a reduced protection level. |
| Drift detected | Level drops **before** repair is attempted. |
| Protection test failed (synthetic secret reached the endpoint) | A **hard failure**, never a warning. The level stays at most `Integrated`. |
| Tool launched outside the managed path | A **bypass**, not an Agent Assembly error. The remedy is different, and blaming the system trains users to ignore real failures. |

---

## Status vocabulary

Use these words verbatim in any client. A user comparing the CLI, the dashboard
and an editor extension must see one word for one thing.

* **Profiles:** `Recommended`, `Strict`, `Observe`
* **Levels:** `Integrated`, `Gateway Protected`, `Host Enforced`
* **Overriding states:** `Drifted`, `Degraded`, `Incompatible`

---

## References

* [Onboarding a Developer Integration](onboarding.md)
* [Limitations and known bypasses](limitations.md)
* [Product Capability Brief](product-brief.md) §6 (profiles), §7 (levels), §8
  (guarantees), §9 (failure journeys)
* [L0–L3 Capability Matrix](../governance/capability-matrix.md)
* [ADR 0030 — Developer Integration boundaries and trust model](../adr/0030-developer-integration-boundaries-and-trust-model.md)
* [Protection and enforcement](../security/protection-model.md)
