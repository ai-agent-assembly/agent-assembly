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
| **Host Enforced** | The *machine* is constrained, so a process cannot escape by launching outside the managed path. | **No.** Reported as *unavailable on this platform*, never omitted. |

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

### Why `Gateway Protected` is not reportable today

> **`aasm integrations verify claude-code` exits `6` on a default build, so the
> level stays at `Integrated`.**
>
> Raising the level requires *exercised* evidence, and exercised means traffic
> was produced **and adjudicated**. Adjudicating means knowing what the provider
> actually received — which **a client on the near side of the proxy cannot
> see**. The shipped default probe, `UnadjudicatedProbe`, therefore reports
> `Inconclusive` with its reason and produces no traffic at all
> (`aa-devtool-claude-code/src/probe.rs`).
>
> This is not a broken installation, and it is not the protection failing. It is
> the evidence model refusing a vacuous pass: a probe that reported `Redacted`
> because nothing obviously failed would be exactly the claim this system exists
> to prevent.
>
> **The mechanism itself was measured working.** AAASM-5276 ran the real
> `claude 2.1.220` binary against a TLS-terminating mock provider: all four
> upstream requests traversed the proxy, the deterministic scanner matched the
> synthetic secret, and the forwarded body carried `[REDACTED:AnthropicKey]`
> while remaining valid Messages JSON — at sub-millisecond added cost.
>
> **Planned:** a deployment that can observe the forwarded payload supplies a
> probe that adjudicates. The probe is an injected capability precisely so this
> can land without changing the evidence model. Until it does, read exit `6` on
> an otherwise-clean install as *not measured*, not as *measured and failed*.

## Host Enforced

| | |
|---|---|
| **What it would protect** | The machine, not the integration. Enforcement at the operating-system boundary, so a process could not escape by unsetting an environment variable, launching the tool directly, or opening its own socket. |
| **Testable entry criteria** | An OS-level enforcement facility is installed, active, and **demonstrated to block a deliberately unmanaged launch** — the bypass that defeats both levels above must be shown to fail. |
| **Availability** | **Not available.** macOS Endpoint Security and Network Extension are explicit non-goals; Windows and Linux host enforcement are out of scope. `aa-ebpf` is Linux-only and is a *detection* layer — it observes SSL and exec/file syscalls but cannot modify traffic in flight, so it cannot supply this level either. |
| **Reporting requirement** | The level is **named and reported as unavailable**, not hidden. Silence reads as "there is nothing above what I have", which is the over-claim this whole model exists to prevent. |
| **Maps to L0–L3** | Nothing. It is *not* `L3Native`: `L3Native` means Agent Assembly writes the tool's own native configuration so governance survives Agent Assembly going offline — a property of `Integrated`. Host enforcement is orthogonal to the L0–L3 scale, which describes what a tool adapter achieves, not what the OS enforces. |

> **No non-overridable-enforcement claim is made anywhere in this product.** The
> strongest available bypass counters live in Claude Code's endpoint
> managed-settings file, that file was deliberately never written to, and its
> managed-only keys remain **unmeasured**. See
> [Limitations](limitations.md#the-managed-settings-path-is-unmeasured).

---

## Evidence: exercised versus read-back

This split is the whole mechanism by which a level stays honest, so `status`
prints it rather than summarising it.

| Evidence kind | What it establishes | Highest level it can justify |
|---|---|---|
| **Exercised** | Traffic was produced on the protected path and the core adjudicated what happened to it. | `Gateway Protected` |
| **Read-back** | A managed value on disk matches what the receipt says was written. Proves a file is correct; proves nothing about traffic. | `Integrated` |
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
