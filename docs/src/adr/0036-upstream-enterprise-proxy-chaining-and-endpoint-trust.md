# ADR 0036: Trusted Upstream Proxy Endpoint & Declared Enterprise Destinations (v1: explicit-destination chaining only)

**Status**: Accepted. Ninth draft, applying review #8's fixes (one blocking
self-contradiction in the `--no-proxy`/one-spawn scoping, one truthfulness
narrowing on D-C's provenance claim) plus two closure-check edits from a
final targeted verification pass (a leftover contradicting parenthetical,
and explicitly naming the trusted-config-artifact authorship case alongside
gaps #1/#3's disclosure). Nine total drafts, eight full adversarial review
rounds plus one narrow closure check — full history below. Substantive
security properties hold and were independently re-confirmed at closure:
normal-destination SSRF unchanged, no generic bypass flag, no undeclared
destination enters the chained path, fail-closed with no silent fallback, no
credential broker, truthful (disclosed-limitation) protection-state. Full
history below. Review #4 verdict on draft 4 was ADOPT
WITH NAMED FIXES (N1-N11: three of F1-F10 incompletely applied, plus two new
defects the fix round itself introduced — a nonexistent forward-reference
`D-G`/content-free `D8`/`D9` headings, and an unspecified second-hop CONNECT
authority). Draft 5 applied N1-N11. Review #5 verdict on draft 5 was again
ADOPT WITH NAMED FIXES (R1-R11): most of N1-N11 verified correct against
current code, but review #5 found a second ambient-env routing-bypass channel
D6 never modeled (`launch_env::installed_environment`, rooted in the same
ambient `AASM_STATE_DIR`, R1), a real ordering contradiction between two of
D6's own rules (R2), a validation/runtime predicate mismatch reintroducing
F3's original failure one level down (R3), confirmation that D2b's
LLM-class-elevation mechanism does not exist in current code and needs new
routing plumbing, not a bar correction (R9), that a proposed post-dial
chained-evidence mechanism (then labeled D-G) didn't fit the actual pre-dial
timing of the existing audit record or the actual per-tool (not per-route)
shape of `highest_justified_level` (R4/R5), and that Test 1's redaction
assertion point was the wrong hop (R10), plus smaller code-block/counting
corrections (R6-R8, R11). Draft 6 applied R1-R11. **Review #6 verdict on
draft 6 was ADOPT WITH NAMED FIXES again (M1-M5, S1-S2, P1-P3)**: R1's fix
(a blanket name-filter on `installed_environment`) would have broken every
receipted governed launch that relies on that store's legitimate
`HTTPS_PROXY`/`HTTP_PROXY` value (M1); R2's unified ordering invariant
silently changed the documented `--no-proxy` opt-out's behavior (M3); R3's
`mitm_hosts` union crossed a wildcard-matching grammar boundary and a
host-vs-host+port keying mismatch (M4); the R4/R5 chained-evidence redesign
(`D-G`) was found to require breaking changes to `ExerciseOutcome`'s pinned
receipt shape and to `aa-core`'s shared, cross-integration `ladder()`
aggregation logic — out of proportion to this ADR's scope (M2); plus smaller
signature/labeling gaps (S1-S2) and revision-history/wording drift (P1-P3).
Draft 7 resolved M2 by dropping the chained-specific evidence mechanism
entirely rather than continuing to redesign it — v1's `ProtectionState` for
a chained route uses the same, unmodified evidence model as any other MITM'd
host, with the resulting limitation recorded honestly rather than built
around — and applied M1/M3/M4/S1/S2/P1-P3 directly. **Review #7 verdict on
draft 7 was ADOPT WITH NAMED FIXES**: M2 was verified genuinely correct and
internally consistent (no further changes needed there). But M1's
provenance-based fix was found not to actually close the gap — the
"supervisor" and the adapter constructing `installed_environment`'s state
root are the same in-process call, reading the same ambient `AASM_STATE_DIR`
one stack frame apart, so relocating the read doesn't relocate the trust
boundary; and two of the fix's own consequences went unaddressed: the step-3
injection-set enumeration never named the launch-env store's legitimate
receipted value (so applied literally it would have stripped it, the same
regression class as M1 from a different angle), and the `lifecycle.rs`
boundary reads *two* `installed_environment` stores, only one of which the
fix named. Also found: `--no-proxy` is not a plumbed concept at the four
devtool spawn boundaries at all, so M3's "step 0" fix cannot apply there as
written. **This draft (8) resolves the M1 gap the same way M2 was
resolved — by disclosing it as a named limitation rather than re-designing
a third time** (a genuinely non-ambient fix requires either a
tree-wide `--state-dir` operator flag or per-read receipt-fingerprint
verification, both materially larger than this ADR's scope), names the
receipted store explicitly in the injection set, names both
`lifecycle.rs` reads, and scopes `--no-proxy` handling to the one boundary
where it is an actual, plumbed concept. Pending review #8.
**Date**: 2026-08
**Ticket**: [AAASM-5912](https://lightning-dust-mite.atlassian.net/browse/AAASM-5912)

---

This ADR fixes the v1 architectural contract for AASM's local enforcement proxy
(`aa-proxy`) forwarding traffic for **explicitly declared enterprise
destinations** through a second, operator-configured corporate proxy/gateway,
and for trusting a custom (non-Anthropic-default) model endpoint for
interception. It **complements and does not supersede**
[ADR 0030](0030-developer-integration-boundaries-and-trust-model.md) or
[ADR 0033](0033-canonical-governance-and-enforcement-architecture.md), and it
does **not** weaken [AAASM-3130](https://lightning-dust-mite.atlassian.net/browse/AAASM-3130)'s
SSRF guard for any destination outside the explicit declaration this ADR
defines.

## Context

[AAASM-5892](https://lightning-dust-mite.atlassian.net/browse/AAASM-5892) →
[AAASM-5896](https://lightning-dust-mite.atlassian.net/browse/AAASM-5896) →
[AAASM-5912](https://lightning-dust-mite.atlassian.net/browse/AAASM-5912) is
the ticket chain; see AAASM-5912 for the full incident/coexistence background.
Target topologies (CC-Switch, when present, only *selects* the Claude Code
endpoint/provider — nothing in this repo evidences it as a network hop, and it
is not modeled as one):

```
TOPOLOGY A: CC-Switch -> Claude Code -> AASM proxy -> enterprise model proxy/gateway -> upstream provider
TOPOLOGY B:               Claude Code -> AASM proxy -> enterprise model proxy/gateway -> upstream provider
```

### Revision history

**Draft 1** proposed a generic "configured upstream proxy," read via
`ProxyConfig::from_env()`. Independent review #1 rejected it: conflicts with
the AAASM-3130 SSRF guard (private-address dial with no clean resolution), and
its "never read from ambient `HTTPS_PROXY`" rule didn't hold because the
replacement config was itself ambient-readable.

**Draft 2** introduced `TrustedUpstreamProxyEndpoint` as a single, narrow,
pinned trust class (owner decision: option (b), reject a generic SSRF-guard
relaxation, accept a single exact endpoint instead). Independent review #2
found this resolved the *endpoint* trust question but left an undecided
**scope** question: which *destinations* get routed through that endpoint.
Because `is_blocked_ip` is the only address-level check anywhere in `aa-proxy`
and three call sites depend on it (`dial_upstream_tls`, `dial_upstream_plain`,
`transparent_tunnel`), silently chaining "everything" through the trusted
proxy would delete that check for every destination, not just the intended
one — an agent-named hostname resolving to RFC1918, or a DNS-rebound name,
would reach internal address space via an otherwise correctly-configured
trusted proxy. Review #2 also found 10 concrete, independent defects (D1b's
strip-list, `AASM_STATE_DIR` provenance, `pinned_addr` provenance, TLS
trust-anchor env vars, the governed-tool child's proxy env, cleartext proxy
auth, D2b/D9's probe-evidence conflict, a false loop/timeout claim, a false
"no relaxation flag exists" claim, and a vacuous negative control).

**Draft 3 (v1 scope decision, owner, 2026-08-25)**: **option (i)** — chaining
applies **only** to explicitly declared enterprise destinations. Every other
destination keeps the existing, entirely unmodified,
`connect_revalidated`/`is_blocked_ip` direct path. This required separating
two trust decisions draft 2 conflated into one struct, and fixing all 10
review-#2 defects.

**Independent review #3** found draft 3's core design flawed in one specific
way: D-D described the new eligibility check as an early-return gate ahead of
`handle_connect_tunnel`'s existing dispatch (the function draft 3 mis-cited as
`handle_connect` — corrected throughout this draft). An early return there
would have skipped `egress_deny_reason` (the gateway network-policy stage,
AAASM-5851) if placed too early, or skipped MITM/DLP/redaction/credential
injection and made D2b's full-LLM-enforcement claim (and Test 14's redaction
requirement) structurally unimplementable if placed too late or as a
replacement branch. Review #3 also found: the new dial function would bypass
the AAASM-5358 `ForwardAuthorized` typestate invariant (a mint-only token
required by every existing route to the wire) with no mention in the ADR; a
`DeclaredEnterpriseDestination` not independently made MITM-eligible would
silently fall to `transparent_tunnel` with *zero* inspection — the opposite of
what D2b claims and exactly what Test 1 as originally worded would have
failed to catch; the env-stripping fix (D6) was diagnosed at the wrong level
(a returned `HashMap`, not the spawned `Command`) and empirically verified
(with a positive control) to leave the *existing* 2-variable case leaking
today, plus missed 2 of 4 real spawn boundaries; `dial_via_trusted_upstream_proxy`
was never told to ignore `skip_upstream_tls_verify`/`upstream_override`; the
new destination's `port` was never actually checked by the matcher; and six
of the fifteen negative controls needed rewording to test the right thing at
the right level. None of this reopens the resolved chaining-scope or
SSRF-relaxation decisions — review #3's verdict was **ADOPT WITH NAMED
FIXES**, not a new trust-boundary stop. **Draft 4 applies all ten fixes
(F1-F10)**, detailed inline below at the sections they correct.

**Independent review #4** verified most of F1-F10 landed correctly, but found
three incompletely applied and two new defects the fix round itself
introduced: the port-check fix (F7) referenced a `connect_port` variable that
didn't exist anywhere in the surrounding code (N1); the "substitute at dial
call sites" design was type-impossible for the case D5 makes mandatory —
`dial_upstream_tls` returns a concrete, non-generic stream type, and nesting
TLS-to-proxy inside TLS-to-destination doesn't type-check against it (N2);
the `ForwardAuthorized` fix named the wrong function as the token-holder
(N3); F3's MITM-eligibility precondition was satisfiable from the same
ambient-influenceable `mitm_hosts`/`AASM_STATE_DIR` union it was meant to be
independent of (N4); only 4 of the real 6 spawn boundaries were named,
missing `aa-devtool-codex`/`aa-devtool-windsurf` (N5); the "extend to all 8
variants" injection rule was incoherent for `ALL_PROXY`/`NO_PROXY` (N6); the
debug-mode TLS-verification exclusion was wrongly qualified on whether proxy
auth happened to be configured (N7); several tests needed rewording (N8);
one stale `handle_connect` citation survived a "corrected throughout" claim
(N9); and — new, introduced by draft 4's own fixes — a forward reference to
a `D-G` section that was never written, alongside content-free `D8`/`D9`
headings (N10), and an unspecified second-hop CONNECT authority construction
that left room for a stale/attacker-influenced hostname to reach the trusted
proxy (N11). Verdict: **ADOPT WITH NAMED FIXES**, no reopened trust-boundary
decision. **Draft 5 applies N1-N11.**

**Independent review #5** verified most of N1-N11 correct against current
code, but found: a second ambient-env routing-bypass channel D6 never
modeled (`launch_env::installed_environment`, rooted in the same ambient
`AASM_STATE_DIR`, bypassing `aa-proxy` entirely at the two Claude Code spawn
boundaries — R1); a real ordering contradiction between two of D6's own
rules, where following the Claude Code case's rule at the `spawn_and_wait`
boundary would have stripped the governed proxy value it exists to protect
(R2); N4's fix reintroducing F3's original failure one level down, because
the validation-time and runtime-routing predicates were left as two
different, driftable sets (R3); confirmation that D2b's LLM-class-elevation
mechanism does not exist in current code at all and needs new routing
plumbing, not a bar correction (R9); that the proposed post-dial
chained-evidence mechanism (then labeled `D-G`) didn't fit the actual
pre-dial timing of the existing forwarding-audit record, or the actual
per-tool (not per-route) shape of `highest_justified_level` (R4/R5); and
that Test 1's redaction assertion point was the wrong hop — the trusted
proxy itself only ever sees opaque TLS bytes once destination-TLS is layered
on top, so asserting cleanliness there passes vacuously regardless of
whether redaction ran (R10) — plus smaller code-block/counting corrections
(R6-R8, R11). Verdict: **ADOPT WITH NAMED FIXES**, no reopened trust-boundary
decision. **Draft 6 applies R1-R11.**

**Independent review #6** verified most of R1-R11 correct, but found: R1's
fix (a blanket name-filter on `installed_environment`'s read) would itself
have broken every receipted governed launch relying on that store's
legitimate `HTTPS_PROXY`/`HTTP_PROXY` value — an ungoverned-launch-reporting
-as-governed regression reintroduced through a different mechanism than R2's
original mistake (M1); R2's unified ordering invariant, applied literally,
silently changed the documented `--no-proxy` opt-out's behavior (M3); R3's
union into `config.mitm_hosts` crossed a wildcard-matching grammar boundary
(a declared host of literal `*` would MITM everything) and a host-vs-
host+port keying mismatch (M4); the R4/R5 evidence redesign, on closer
inspection of `aa-core`'s actual types, would have required a breaking
change to `ExerciseOutcome`'s pinned, fieldless receipt shape, and — more
fundamentally — could only ever *raise* the achieved protection level, never
*withhold* `GatewayProtected` pending chained-specific evidence, because
`highest_justified_level`'s aggregation is `any()`-based across capabilities
and the ordinary local probe alone already independently satisfies it (M2);
plus two smaller signature/labeling gaps (S1: `handle_llm_mitm` needs an
`LlmApiPattern` for a declared endpoint and none was specified; S2:
`transparent_tunnel`'s new parameter wasn't enumerated) and revision-history/
wording drift (P1-P3). Verdict: **ADOPT WITH NAMED FIXES**, no reopened
trust-boundary decision. **Draft 7 (this draft) resolves M2 by dropping the
chained-specific evidence mechanism entirely** rather than attempting a
third redesign — building the conjunctive evidence model M2's fix would
require changing `aa-core`'s shared, cross-integration `ladder()`
aggregation logic, disproportionate to this ADR's scope; v1 instead uses the
existing, unmodified evidence model for a chained route exactly as for any
other MITM'd host, and the resulting gap (cannot yet distinguish "chained
traffic proven" from "ordinary MITM path proven, a chained route happens to
be configured") is recorded as a named, honest limitation rather than built
around. M1, M3, M4, S1, S2, and P1-P3 are fixed directly, detailed inline
below.

**Independent review #7** verified M2 genuinely correct and internally
consistent — no further changes needed there. But it found M1's
provenance-based fix doesn't actually close the gap: `ClaudeCodeAdapter` is
constructed in-process, so "the supervisor resolves it and passes it" reads
the identical ambient `AASM_STATE_DIR` one stack frame apart, not across a
real trust boundary. It also found two of that fix's own consequences
unaddressed — the step-3 injection-set enumeration never named the
launch-env store's legitimate receipted value (so, applied literally, it
would have stripped it), and the `lifecycle.rs` boundary reads two
`installed_environment` stores, only one of which the fix named — plus that
`--no-proxy` is not a plumbed concept at the four devtool spawn boundaries
at all. Verdict: **ADOPT WITH NAMED FIXES**, no reopened trust-boundary
decision. **Draft 8 resolves the M1 gap the same way M2 was resolved** — by
disclosing it as named un-closed gap #3 rather than attempting a third
redesign — and applies the other three fixes as scoping corrections.

**Independent review #8** found draft 8's scoping fix for the `--no-proxy`
finding introduced a genuine self-contradiction: treating
`aa-devtool-claude-code`'s spawn boundary as independent from `spawn_and_wait`
and requiring unconditional removal inside it would make the `aa-cli`
boundary's own `--no-proxy` carve-out unreachable for the one path that
matters in production (`aasm run <tool>`, where the adapter's env is applied
*after*, and wins over, `build_child_env`'s) — breaking the documented
`--no-proxy` opt-out this ADR elsewhere claims to leave untouched. It also
found the D-C provenance fix's "genuinely closed" framing overstated: content
validation establishes well-formedness, not authorship, and the same
pre-launch `AASM_STATE_DIR` attacker gaps #1/#3 already name can author a
well-formed artifact of their own choosing. Verdict: **ADOPT WITH NAMED
FIXES** (one blocking, one minor-but-required, three cosmetic), explicitly
assessed as the tail of a converging process — no reopened trust-boundary
decision, and the reviewer's own recommendation was to apply the fixes and
end the loop rather than continue indefinitely. **This draft (9) applies
both**: the `aasm run <tool>` case is corrected to recognize the
`aa-devtool-claude-code`/`spawn_and_wait` boundary as one spawn, not two,
with removal performed once at the outer site so the `--no-proxy` carve-out
actually reaches it; and D-C's provenance claim is narrowed to what it
actually closes (post-spawn environment tampering), with the pre-launch
state-root case folded into the existing gap #1/#3 disclosure rather than
claimed shut.

## Decision

### D-A — Two separate trust decisions, two separate types

```rust
/// WHO AASM may hand traffic to as a second hop.
/// Exact operator/supervisor-approved corporate proxy infrastructure.
/// Trusting this endpoint does NOT by itself authorize any destination.
struct TrustedUpstreamProxyEndpoint {
    scheme: UpstreamProxyScheme,  // Https only when proxy auth is configured — see D5
    host: String,                 // exact hostname or literal IP, no wildcards
    port: u16,
    pinned_addr: SocketAddr,      // resolved by aa-proxy itself — see D-C
    auth: Option<ProxyAuth>,       // see D5
}

/// WHICH destination is authorized to use that second hop.
/// Exact host identity, v1. Does not imply the reverse (naming a proxy does
/// not name a destination, and vice versa).
struct DeclaredEnterpriseDestination {
    host: String,   // exact hostname only in v1 — see D-B
    port: u16,
}
```

A connection is eligible for the chained path **if and only if** its CONNECT
target hostname exactly matches an entry in the configured
`DeclaredEnterpriseDestination` set **and** a `TrustedUpstreamProxyEndpoint` is
configured. Neither fact alone is sufficient. This is enforced at exactly one
call site (D-D) — not by weakening `connect_revalidated` and not by branching
inside `transparent_tunnel`/`dial_upstream_plain`.

### D-B — v1 destination declaration: exact host only, no wildcards

`DeclaredEnterpriseDestination` entries are exact hostnames (or literal IPs),
matched case-insensitively, exactly like `detect_api`'s existing 3-host
match — no `*`/suffix wildcard grammar (unlike `mitm_hosts`, which does
support wildcards for a materially lower-stakes decision: MITM-eligibility,
not SSRF-adjacent routing). Wildcard support is explicitly deferred: it widens
the destination set that gets chained without a corresponding narrowing of
what the operator actually reviewed, and is a separate, threat-model-worthy
decision this ADR declines to bundle in. The declaration is owned by the same
trusted-configuration path as `TrustedUpstreamProxyEndpoint` (D-C) — never
learned from traffic, agent/model output, request content, ambient
environment, DNS observation, or CC-Switch mutation alone.

### D-C — Trusted configuration provenance, precisely scoped (fixes review-#2 items A, B, C)

Both `TrustedUpstreamProxyEndpoint` and the `DeclaredEnterpriseDestination` set
are constructed **only** from an explicit, operator-authored configuration
artifact, with the following provenance chain, closing every gap review #2
found:

- **The config-root path is passed explicitly, not re-derived by `aa-proxy`
  from its own inherited environment (fixes B, narrowed per review #8/F-B).**
  `aasm run`/`ProxyGuard` resolves the state directory once and passes the
  **resolved, absolute path** to the config artifact explicitly to `aa-proxy`
  at spawn time (an argument, not an inherited-and-re-derived env var) — this
  closes the specific gap review #2 named (`aa-proxy` itself re-reading
  `AASM_STATE_DIR` from its *own*, potentially-tampered, post-spawn
  environment) and, independently, `aa-proxy` validates the artifact's
  content (well-formed host/port, no wildcard, `Https` where auth is
  configured, MITM-eligible, non-loopback) regardless of who authored it.
  **What this does not close (review #8, F-B, matching gap #3's own
  reasoning)**: `aasm run`'s own resolution of that state directory is
  itself the standard `${AASM_STATE_DIR:-~/.aasm}` order — the same ambient
  variable gaps #1 and #3 already name as attacker-controllable *before*
  `aasm run` starts. An attacker with that pre-launch capability can author
  a well-formed artifact of their own at the resulting root; content
  validation establishes well-formedness, not authorship. This is not a new
  gap — it is the identical discriminating fact as gaps #1/#3, and is folded
  into the same disclosure rather than claimed closed here (Test 9(a)).
- **The artifact is parsed and validated by `aa-proxy` itself, never
  accepted pre-computed (fixes C).** `aa-proxy` reads the config file
  contents (hostnames, port, scheme, optional auth reference) and performs its
  own DNS resolution to produce `pinned_addr` internally. **No serialized
  `pinned_addr`, or any other pre-resolved address, crosses the `aa-cli`→
  `aa-proxy` boundary as a trusted value.** If a value resembling one were
  ever present in the process's inherited environment (e.g. left over from a
  prior process, or injected by something upstream of `aasm run`), it is
  never read as a source of trust for this feature — only the explicitly
  passed config-file path is.
- **The AASM-specific variable itself cannot survive ambient inheritance
  (fixes A).** `ProxyGuard::build_command` unconditionally
  `cmd.env_remove()`s every AASM trusted-upstream/declared-destination
  variable name before conditionally re-`cmd.env()`-setting them **only**
  when the supervisor has actual validated configuration to inject. There is
  no code path where "supervisor had nothing to configure" plus "ambient
  environment happened to have the same variable name" results in that
  ambient value being used — removal is unconditional, injection is
  conditional-and-explicit, in that order, every time.

### D-D — One decision point, one threaded value; the dial functions gain a parameter, not a decision (revised across reviews #3-#6, F1/F2/F7, N1/N2/N3/N11, R3/R6 — the MITM-eligibility precondition itself lives in D2b, not here)

The relevant function is `handle_connect_tunnel` (`aa-proxy/src/proxy/mod.rs`),
not `handle_connect` (draft 3's citation was wrong — corrected). Its real
control flow: canonicalise the CONNECT authority → `egress_deny_reason`
(gateway network policy, `denied_hosts`, allowlist — AAASM-5851) → reply `200
Established` → `llm_only && !should_mitm` branches to `transparent_tunnel` →
otherwise MITM, which itself branches on `detect_api`/`should_mitm` into
`handle_llm_mitm` or `handle_non_llm_mitm`, both of which eventually call
`dial_upstream_tls`. **Review #3 found an early-return gate placed anywhere
in this flow breaks something** — before `egress_deny_reason` skips gateway
network policy entirely for a declared destination; between
`egress_deny_reason` and the MITM branch skips DLP/redaction/credential
injection/probe adjudication, making D2b's full-enforcement claim
unimplementable; replacing the MITM branch makes chaining and D2b mutually
exclusive.

**Fixed design: thread a value, don't early-return.** Immediately after
`egress_deny_reason` passes (so the gate is still fed only by D-C's
supervisor-provenance configuration, and gateway network policy still applies
to a declared destination exactly like any other host), compute:

```rust
// N1: `host` (canonical_host(target)) has its port stripped; `egress_deny_reason`
// even hardcodes 443 for its own purposes. The port actually present on the
// CONNECT authority must be parsed separately, bracket-aware (reusing
// strip_host_port's parsing, not egress_deny_reason's literal 443), and an
// absent/unparseable port is treated as a NON-match, never defaulted to 443.
let connect_port: Option<u16> = parse_connect_authority_port(target);
let chained_route: Option<ChainedRoute> = connect_port.and_then(|port| {
    declared_enterprise_destinations.exact_match(host, port)
        .zip(trusted_upstream_proxy.as_ref())
        .map(|(dest, endpoint)| ChainedRoute { dest, endpoint })
});
```

`chained_route` flows unchanged through the existing `should_mitm`/MITM
branching — it does not skip or replace any existing stage.

**N2 (review #4) — the substitution point is inside `dial_upstream_tls`, not
a new top-level dial function.** `dial_upstream_tls` returns a concrete
`tokio_rustls::client::TlsStream<TcpStream>` today, and both its call sites
immediately split it — a genuinely separate `dial_via_trusted_upstream_proxy`
returning a *second*, TLS-to-destination-over-TLS-to-proxy stream would be
`TlsStream<TlsStream<TcpStream>>`, which does not type-check against those
call sites, and is exactly the case D5 makes mandatory (HTTPS to the proxy
when proxy auth is configured) nested with the TLS this function already does
to the real destination. Fixed design: `dial_upstream_tls`'s existing
`upstream_tcp` selection (currently a two-branch match on
`upstream_override`) gains a **third branch**, and the function's transport
type is generalized to a boxed trait object
(`Box<dyn AsyncRead + AsyncWrite + Unpin + Send>`) so both existing call sites
keep their current shape:

```rust
// R6: corrected to match dial_upstream_tls's actual current signature
// (`target`, and the `authorized: ForwardAuthorized` token it already takes
// and must keep threading through on every arm, not drop on the new one).
let upstream_tcp: BoxedTransport = match (chained_route, config.upstream_override) {
    (Some(route), _) => establish_trusted_proxy_tunnel(&route, authorized).await?, // new helper, below
    (None, Some(addr)) => Box::new(TcpStream::connect(addr).await?),               // unchanged, test-only
    (None, None) => Box::new(self.connect_revalidated(target, authorized).await?), // unchanged
};
```

**R6 — this is not a same-shape drop-in.** Generalizing `dial_upstream_tls`'s
transport to a boxed trait object is a real signature change with two
concrete consequences an implementer must handle, not "keep their current
shape" as an earlier draft claimed: `relay_mcp_response` explicitly names
`tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>` today and
must be updated for the boxed type; and `handle_llm_mitm`/`handle_non_llm_mitm`
(the two existing callers) must each gain a `chained_route: Option<&ChainedRoute>`
parameter to pass through to `dial_upstream_tls` — "the dial functions gain a
parameter" was stated but not enumerated; it means these two specifically.
`dial_upstream_tls`'s own doc comment currently asserts it sits on "the
*shared bottom* of every route to the wire" via `connect_revalidated` — that
sentence becomes inaccurate for the chained arm and must be corrected in the
same change, not left as a stale invariant for the next reader.

`establish_trusted_proxy_tunnel` (new, private helper — not a second public
dial function): (1) TCP-connects to `route.endpoint.pinned_addr` (D-C,
already-pinned, never re-resolved); (2) if `route.endpoint.scheme == Https`,
performs a TLS handshake to the proxy itself, verified via the OS-native
trust store (D-E) — this protects the CONNECT request/`Proxy-Authorization`
header in transit to the proxy, independent of the TLS handshake to the real
destination that follows; (3) sends `CONNECT <authority> HTTP/1.1` on that
connection (plus `Proxy-Authorization` if `route.endpoint.auth` is set),
**where `<authority>` is constructed verbatim from `route.dest.host` and
`route.dest.port` — never from `target`, `host`, or any in-tunnel header**
(N11 — `target` is deliberately left un-canonicalised, e.g. trailing-dot
forms are tolerated by DNS/connect but must not be forwarded upstream
unverified; using the validated config's own host/port is what makes option
(i)'s "never hand an undeclared hostname to the trusted proxy" property
actually hold); (4) reads the `200` response; (5) returns the resulting
stream, boxed, for `dial_upstream_tls` to layer its normal
TLS-to-real-destination handshake on top of, exactly as it already does for
the direct-dial case. **`connect_revalidated`/`is_blocked_ip` is not touched,
not parameterized, not branched inside** — arm `(None, None)` above is
byte-for-byte today's code. `handle_plain_http` (the separate non-CONNECT
entry point) is unaffected and never chains — declared destinations are HTTPS
model/API endpoints, reached only via CONNECT.

**F2/N3 — forwarding-typestate invariant preserved, on the right function.**
Every existing route to the wire in `aa-proxy` requires a `ForwardAuthorized`
token (`transmission_evidence.rs`, mint-only via `ForwardObservation::persist`).
Because there is no separate `dial_via_trusted_upstream_proxy` function
(N2 — the chained case is an internal branch inside `dial_upstream_tls`),
the token requirement is unchanged from today: `dial_upstream_tls` itself
takes `ForwardAuthorized` by value, exactly as it already does, for both the
chained and direct-dial arms. A chained forward is not exempt from recording
`ExecutionEvidence` because it goes through the same function, not a second,
unaudited one.

**F7/N1 — port is part of the match, not just the host, and the port must
actually be parsed (not assumed).** `DeclaredEnterpriseDestination` declares
`{ host, port }` (D-A); the CONNECT authority's *actual* port (parsed per the
code block above, bracket-aware for IPv6, never defaulted) must equal
`dest.port` for a match — `CONNECT declared-host.corp:22` when only `:443`
was declared does **not** match and falls through to the unmodified path
(fail-closed on mismatch, not fail-open); a CONNECT authority whose port
cannot be parsed at all is likewise treated as no match, not as "assume 443."

**Explicitly**: the trusted proxy's *own* hostname being in `mitm_hosts` or
otherwise MITM-eligible does not make it a declared destination, and being a
declared destination does not exempt it from D2b's MITM-eligibility
requirement below — these are related but independently validated facts.

### D1 — `TrustedUpstreamProxyEndpoint` may dial a private address; nothing else may

Unchanged from draft 2's D0: no `allow_private`/`disable_ssrf_guard`-style
flag is added. **Corrected claim (fixes review-#2 item I)**: the accurate
statement is not "no such flag exists in the codebase" —
`allow_private_connect_targets` (`aa-proxy/src/config.rs:190`) *is* exactly
that kind of flag, already present. The accurate, defensible property is: **it
is not reachable from the untrusted/ambient configuration path** —
`ProxyConfig::from_env()` hardcodes it `false` (`config.rs:283`), and this ADR
introduces no new way to set it from ambient environment, agent traffic, or
any untrusted input. The one new private-address-capable path (the `establish_trusted_proxy_tunnel`
branch inside `dial_upstream_tls`, N2) is separately gated by D-D, is not a
parameter on `allow_private_connect_targets`, and does not touch it.

### D2 — Custom/enterprise endpoint MITM-eligibility (unchanged)

Via the existing `mitm_hosts` allowlist mechanism. Independent of D-A/D-B —
see D-D's explicit note above.

### D2b — Explicitly-declared enterprise LLM endpoints get full LLM-class enforcement (revised: evidence bar corrected, fixes review-#2 item G)

**R9 (review #5) — this mechanism does not exist today and is new routing
plumbing, not a config toggle on existing logic; earlier drafts' "unchanged
mechanism from draft 2" framing was wrong.** `handle_llm_mitm` is reached
from exactly one place, gated solely on `detect_api(host) != Unknown` — a
hardcoded 3-host match with no config input at all. A `mitm_hosts` entry gets
a host MITM'd but always lands it in `handle_non_llm_mitm`, which has no
credential-injection call (that exists only inside `handle_llm_mitm`) and a
different, weaker adjudication path. There is currently **no way** for an
operator to route a declared destination to the stronger tier. This ADR
requires building that selector: the MITM-branch dispatch gains a second
condition — `detect_api(host) != Unknown` **or** `host` matches an
operator-declared enterprise-LLM-endpoint entry (a distinct, narrower
declaration than plain `mitm_hosts`/`DeclaredEnterpriseDestination`
membership, per the original D2b framing) — routing to `handle_llm_mitm` in
either case. This is new conditional logic on the hot dispatch path, sized
accordingly in Implementation breakdown below (not the "bar correction, not
new plumbing" characterization an earlier draft gave it).

**S1 (review #6) — `handle_llm_mitm` still needs an `LlmApiPattern` value for
a declared endpoint, and this ADR does not add a new one.** `pattern` is used
only to populate the audit event's provider label; `detect_api` returns
`Unknown` for any declared host that isn't one of the 3 built-ins, and that
`Unknown` value type-checks as `handle_llm_mitm`'s argument without any code
change. This ADR does not add an `LlmApiPattern` variant for
"declared-enterprise" — the audit event for a declared endpoint's traffic is
therefore honestly labeled `Unknown` provider, same as it would be if it had
reached `handle_non_llm_mitm` instead, even though it now receives full
`handle_llm_mitm`-tier enforcement. This is stated explicitly so it is not
mistaken for a labeling bug later; adding a distinguishing variant, if
wanted, is separate follow-up scope.

**F3 — a `DeclaredEnterpriseDestination` must be MITM-eligible, enforced at
validation time, not left as an independent fact.** Review #3 found that
without this, a declared destination that is not a built-in LLM host
(`detect_api`) and not separately added to `mitm_hosts` falls, under the
default `llm_only=true`, straight to `transparent_tunnel` — **zero**
inspection, the opposite of what this section claims, and a state Test 1
(before this fix) would not have caught. `aa-proxy` therefore refuses to
accept a `DeclaredEnterpriseDestination` config entry that does not also
satisfy `should_mitm` — declaring an enterprise destination and making it
MITM-eligible are two operator actions, but the second is a hard startup
precondition for the first, not an independent fact left to chance.

**N4 (review #4) — this precondition's own input must come from the trusted
artifact, not the ambient-influenceable `mitm_hosts` set.** `should_mitm`
consults `config.mitm_hosts`, itself a union of `AA_PROXY_MITM_HOSTS`
(ambient env, not stripped by D6 — it is a MITM-eligibility signal, not a
proxy-routing variable, so D6's strip list correctly does not touch it) and
`integration_mitm_hosts()` (files under `${AASM_STATE_DIR}/integrations/
mitm-hosts.d/`, and `AASM_STATE_DIR` is itself ambient-readable per D-C's own
finding about `integration_state_dir()`). Neither fact can by itself create a
chained route — declaration still requires an entry in the trusted
declared-destinations artifact — so this is a **hardening gap, not a
bypass**. To close it rather than merely note it: F3's precondition check
must accept satisfaction only via `detect_api` (the 3 hardcoded hosts) **or**
an operator-authored entry in the *same trusted config artifact* as the
`DeclaredEnterpriseDestination` itself (D-C's provenance chain) — not via the
ambient-influenceable `mitm_hosts` union. An operator who wants a declared
destination MITM-eligible via the general `mitm_hosts` mechanism may still do
so, but F3's hard precondition is satisfied only by the trusted-artifact path,
so ambient `AA_PROXY_MITM_HOSTS`/`AASM_STATE_DIR` manipulation alone cannot
make an otherwise-invalid declared-destination config pass validation. (No
config-reload/SIGHUP path exists in `aa-proxy` today, so there is no
post-validation drift risk to additionally guard against.)

**R3 — N4's fix, alone, reintroduces F3's own failure one level down.**
Startup validation (F3/N4) checks eligibility against the trusted artifact,
but the *runtime* routing decision (`should_mitm`, gating the
`llm_only && !should_mitm → transparent_tunnel` branch) reads
`config.mitm_hosts` — the ambient-influenceable union N4 deliberately did
**not** treat as satisfying validation. If those two are left as different
sets, a declared destination that passed validation via the trusted artifact
alone (not also present in `config.mitm_hosts`) can still fall to
`transparent_tunnel` at runtime under `llm_only=true` (the default for a
non-gateway governed launch) — zero inspection, D4's fail-closed guarantee
silently not applied, D2b's enforcement claim false, and no error raised.
**Fix, two parts:**
1. At validation time, `aa-proxy` unions every `DeclaredEnterpriseDestination`
   host that passed the artifact-or-`detect_api` eligibility check into
   `config.mitm_hosts` itself — the validation-time predicate and the
   runtime-routing predicate become the same set by construction, not by two
   independently-maintained checks that can drift apart. **M4 (review #6) —
   this union crosses a grammar boundary and needs two additional
   constraints**: `mitm_hosts` is matched by a wildcard-interpreting matcher
   (`*` matches everything, `*.suffix` is a suffix wildcard), while
   `DeclaredEnterpriseDestination` is exact-host-only (D-B) — validation must
   **reject any declared host containing `*`** before performing the union,
   or a declared value of literally `*` would MITM every destination
   regardless of `llm_only`. Second, the union is necessarily **host**-keyed
   (matching `mitm_hosts`' own grammar) while the declaration is
   **host+port** (D-A) — a declared host reached on a *different*,
   non-declared port correctly gets no chained route (F7) but becomes
   MITM-eligible via this union regardless, so non-HTTPS/non-model traffic
   to that host on another port is now MITM'd rather than
   transparent-tunnelled. This is a narrowing of transparent-tunnel
   eligibility for that one host, not a chaining/SSRF issue, but it is a
   real behavior change beyond the declared port and must be documented as
   such, not silently absorbed into "the same host."
2. **Defense-in-depth, independent of (1) being correct:** `transparent_tunnel`
   (`async fn transparent_tunnel(self: &Arc<Self>, stream: TcpStream, target:
   &str)`, gains one new parameter, `chained_route: Option<&ChainedRoute>`,
   passed from its one call site where `chained_route` is already in scope —
   an enumerated signature change, per the standard R6 set for every other
   touched function) checks `chained_route.is_some()` before dialing; if
   true, it refuses (D4's fail-closed) rather than tunneling direct — a
   declared destination must never reach an uninspected raw tunnel, even if
   (1) has a bug. This is the single check that keeps a future regression in
   (1) from silently reopening this exact gap again.

**Evidence requirement — v1, corrected twice (fixes review-#2 item G; then
review #5's R4/R5, then review #6's M2 — see below for why the intervening
design is abandoned rather than patched again).** Draft 2's D9 required
"probe traffic actually adjudicated end-to-end through the full chain" to
justify `GatewayProtected` for a chained route. Draft 5 tried to build a
dedicated post-dial chained-evidence mechanism for this (a new
`ChainedEnterpriseForwarding` capability, an extended `ExerciseOutcome`
payload, a rule making `GatewayProtected` conditional on it). Review #6 found
that design does not fit the actual shape of `aa-core`'s types on three
independent grounds: (a) `ExerciseOutcome` is a fieldless, `Copy`,
serde-derived enum whose persisted shape is pinned across several modules —
adding a payload field is a breaking change to existing receipts, not an
extension; (b) `StateDerivation::ladder()`/`highest_justified_level` are
`any()`-based across capabilities and produce **one** level for the whole
integration — a new capability can only ever **raise** the achieved level,
never **withhold** `GatewayProtected` pending its own evidence, because the
existing `ModelPathInterception` capability (satisfied by the ordinary local
probe, which D2b explicitly keeps running for a chained route) already
independently justifies `GatewayProtected` on its own; and (c) even granting
(a)/(b), `ProtectionState::Degraded` is per-integration, not per-capability,
so "reports **that capability** `Degraded`" describes a shape that does not
exist. Patching the wording without changing the underlying claim would
repeat the exact `EvidenceKind`-variant mistake review #5 already found for
a different type: a mechanism whose own effect is structurally impossible.

**M2 (review #6) — resolution: do not build new withholding machinery for
v1; state the real ceiling honestly instead.** A conjunctive rule (chained
routes only reach `GatewayProtected` with additional evidence) is
achievable, but it requires changing `StateDerivation::ladder()`'s actual
aggregation logic to be conditional on configuration — a materially larger,
riskier change to a shared, already-hardened core module than this ADR's
scope justifies for v1, and not something to bolt on as a one-line "add a
capability" claim. **v1's actual behavior, stated truthfully rather than
aspirationally**: a chained route's `ProtectionState` is derived by the
*existing*, unmodified evidence model — exactly as for any other MITM'd
host. The existing local probe (unchanged, still terminates locally, per its
own documented rationale) is sufficient to justify `GatewayProtected` for a
tool with `ModelPathInterception` satisfied, **whether or not** a request has
actually traversed the configured trusted proxy to a declared destination.
This means v1 **cannot yet distinguish** "this tool's chained route has been
proven to work end-to-end" from "this tool's ordinary MITM path was proven,
and a chained route happens to also be configured" — the same honest gap
D-F names for full-egress support, recorded the same way: **a named,
disclosed v1 limitation**, not a claim this ADR makes and cannot keep.
Building the conjunctive evidence model described above (Test 14/1's real
chained-traffic assertion remains valuable as *test* coverage — it proves the
implementation works — it just does not yet feed back into the
`ProtectionState` claim) is recorded as follow-up scope alongside D-F, not
built in this implementation. Forbidden design 6 and D9 are worded
accordingly below — they forbid a *false* claim (installed/configured alone
implying `Protected`), not a promise this v1 cannot honor about
distinguishing evidence tiers it does not yet compute.

### D3 — Auth ownership (unchanged from draft 2)

Provider/PAT/session auth: unowned by AASM, passthrough, no new mechanism.
Corporate-proxy auth (D5): new narrow credential class, `Secret`-backed.

### D4 — Fail-closed, no fallback (unchanged from draft 2)

A declared-destination request whose trusted proxy is unreachable refuses the
CONNECT. No fallback to the (now entirely separate) direct-dial path. No
bypass flag.

### D5 — Corporate-proxy auth requires a secure transport (fixes review-#2 item F)

If `ProxyAuth` is configured for a `TrustedUpstreamProxyEndpoint`, `scheme`
**must** be `Https` — `aa-proxy` refuses to start (or refuses that specific
endpoint's configuration) if auth is present with `scheme: Http`, rather than
silently sending `Proxy-Authorization` in cleartext across the corporate LAN.
The TLS trust anchor for that leg is the OS-native trust store
(`rustls_native_certs`, D-E below) — an operator whose corporate proxy uses an
internal CA installs that CA at the OS level, exactly as already required for
the existing destination-verification path; this ADR adds no new mechanism
for trusting a corporate CA, reusing the existing precedent instead of
inventing a parallel one.

**F8 — the trusted-proxy leg never honours the two existing debug-only TLS
escape hatches.** `dial_upstream_tls` installs a no-op certificate verifier
when `config.skip_upstream_tls_verify` is set (`AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY`,
honoured in debug builds only, hardcoded `false` in release —
`config.rs:561-574`), and separately supports `upstream_override` for
test-only dial redirection. `establish_trusted_proxy_tunnel`'s TLS-to-proxy handshake (N2) **must not
consult either flag, in any build profile, unconditionally** — not qualified
on whether `ProxyAuth` happens to be configured (review #4 found the earlier
wording's qualifier left an authless HTTPS-scheme endpoint silently
MITM-able in a debug build, which is itself a trust-anchor failure
independent of the auth-cleartext concern D5 names). This is a hard
requirement in the new helper's own logic — it does not call the same
`skip_upstream_tls_verify`-consulting code path `dial_upstream_tls` uses for
the destination leg; it constructs its own `ClientConfig` from
`rustls_native_certs` unconditionally. Separately, `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY`
itself reaching the spawned `aa-proxy` process ambiently (D6 does not strip
it — it is not a proxy-*routing* variable) is pre-existing behavior on the
pre-existing destination-TLS leg; this is not fixed by this ADR and is
recorded as a named, un-closed gap below, not silently left implicit.

### D-E — TLS trust-anchor environment: explicit, not silently preserved (fixes review-#2 item D)

Draft 2 preserved `SSL_CERT_FILE`/`SSL_CERT_DIR` uncritically as "unrelated
to proxy routing." They are not unrelated: `rustls_native_certs` (used by
`dial_upstream_tls`'s existing destination-TLS handshake, and by
`establish_trusted_proxy_tunnel`'s new proxy-TLS handshake, N2) honours both,
so an ambient value redirects the trust anchor for **every** upstream TLS leg
in the process, including the newly-added trusted-proxy leg. This ADR does
**not** blindly strip them either — legitimate enterprise CA support depends
on being able to point at a corporate root — but the trust decision is made
explicit rather than accidental: `ProxyGuard::build_command` explicitly
documents and passes through `SSL_CERT_FILE`/`SSL_CERT_DIR` as a
**named, intentional** input (an operator's enterprise-CA configuration,
which is legitimate and expected), while D-C's unconditional-removal rule
(D6 below extends the same treatment to proxy-routing variables specifically,
which are a materially different class — routing destination vs. trust
anchor). The distinction recorded here: **routing variables are removed
unless explicitly supervisor-injected; trust-anchor variables are passed
through and documented as an accepted, intentional input a corporate operator
is expected to set.** This is not an oversight — it is the resolution to
"do not blindly strip legitimate enterprise CA support either," made
explicit rather than left implicit as draft 2 did.

### D6 — Ambient proxy-routing variables stripped at every real spawn boundary (seven, D6/R1/R2/R7), one coherent ordering invariant, at the `Command`/store level

Draft 2's D1b only hardened `ProxyGuard::build_command` (the `aa-proxy`
child). Review #2 found the governed **tool** child only strips/sets
uppercase `HTTPS_PROXY`/`HTTP_PROXY`, and that no code path anywhere touches
lowercase `https_proxy`/`http_proxy`, `ALL_PROXY`/`all_proxy`, or
`NO_PROXY`/`no_proxy` — several HTTP client stacks prefer the lowercase form,
so an ambient lowercase value can route agent traffic around `aa-proxy`
entirely while the session still reports governed.

**F4 — review #3 found draft 3's fix was diagnosed at the wrong level and
verified, empirically, not to work.** `build_child_env` returns a `HashMap`
that a caller (`effective_child_env`) turns into a child-process spawn; the
existing "removal" (`env.remove(...)`) only drops the key from that
in-memory map. Nothing calls `env_clear()` or `Command::env_remove()`
anywhere in `aa-cli`'s spawn path, so **the variable is inherited from the
launching process's real environment regardless of what the returned map
says** — reproduced with a positive control (remove nothing → child sees the
ambient value; call `Command::env_remove` → child does not). This means the
**existing, shipped, 2-variable (`HTTPS_PROXY`/`HTTP_PROXY`) case has this
exact defect today**, not merely the new 6 variables this ADR would add if it
repeated the same pattern. **Fix: the removal must happen on the
`std::process::Command` itself** (`cmd.env_remove("HTTPS_PROXY")` etc.,
immediately before spawn, for all 8 case variants), not on an intermediate
`HashMap` that a later stage may or may not honour. This is a **pre-existing
defect being fixed alongside this ADR's new work**, not a new requirement
introduced by it — call this out explicitly in the implementing ticket rather
than bundling it silently into "new feature" scope.

**N5/N6/R7 — seven real spawn boundaries (corrected count), and
removal/injection are not symmetric.** Two additional governed-tool
boundaries beyond the Claude Code case (`aa-devtool-codex`,
`aa-devtool-windsurf` — each sets only `HTTPS_PROXY`, strips nothing) plus
`aasm proxy start`'s own spawn path bring the real count to **seven**, not
six (an earlier draft's header undercounted its own enumerated list by one —
corrected here). "Extend to all 8 variants" is incoherent for the
*injection* half: `NO_PROXY`/`no_proxy` is a negative/exclusion list, not a
routing target, and `ALL_PROXY`/`all_proxy` is a distinct routing key —
injecting a trusted endpoint's URL into all 8 makes no sense, and naively
applying it would leave ambient `ALL_PROXY`/lowercase values live on an
otherwise-trusted launch.

**R2 — the ordering rule must be a single, coherent invariant, not two
site-specific rules that disagree.** An earlier draft said "removal before
injection" for `ProxyGuard::build_command` and "removal must be the last
step" for the Claude Code case — applied literally at `spawn_and_wait`
(where removal already runs *after* the governed env is assembled), "removal
last" would strip the very `HTTPS_PROXY`/`HTTP_PROXY` this feature is trying
to guarantee reaches the child, producing an ungoverned launch that reports
as governed — the exact failure this ADR family exists to prevent. **The one
correct invariant, stated once, applies everywhere:**

> Immediately before spawn: (0) **if `--no-proxy` was passed for this
> launch, do none of the following** — this preserves the existing,
> documented, deliberately-untouched-ambient-proxy opt-out
> (`build_child_env_leaves_the_ambient_proxy_alone_under_no_proxy`) exactly
> as it exists today; steps 1-3 below apply only when `--no-proxy` was not
> passed. (1) remove `ALL_PROXY`/`NO_PROXY` and their lowercase forms
> unconditionally (they are never legitimately injected by anything, per the
> injection-set rule below); (2) remove `HTTPS_PROXY`/`HTTP_PROXY` and their
> lowercase forms; (3) if — and only if — a supervisor-owned trusted value
> exists to inject for this launch (a trusted endpoint or an
> ambient-observed-and-vouched-for proxy applies per existing
> `build_child_env` logic), set `HTTPS_PROXY`/`HTTP_PROXY` to that value,
> last, so nothing after it can reintroduce an ambient one.

This is "removal-then-conditional-injection-last, except under the existing
`--no-proxy` opt-out" everywhere, which satisfies both the `ProxyGuard` case
(never injects anything, so step 3 is always a no-op — equivalent to "remove
and stop"; `--no-proxy` is a tool-launch concept and does not apply to this
boundary at all) and the Claude Code/`spawn_and_wait` case (step 3 must be
the actual last write, after any later overlay such as `spec.env`, not
merely after the first removal, and step 0 must be checked first so the
documented opt-out's contract does not silently change — a map-level test of
the old behavior would keep passing while `Command`-level behavior changed
underneath it, the same failure shape F4 found in reverse).

**R1 — a second ambient-routing channel exists and is worse: it bypasses
`aa-proxy` entirely, and D6 as previously drafted never named it.**
`aa-devtool-claude-code`'s two `build_launch_command` implementations both
loop over `launch_env::installed_environment(...)` and `cmd.env()` **every**
name/value pair found under `${state}/claude-code/<scope>/launch-env/` — a
file-per-variable store whose only filter is "is this a syntactically valid
env-var name," which does not exclude `ALL_PROXY`/`all_proxy`/`https_proxy`/
etc. `state` here resolves through `ClaudeCodePaths::from_env()`, which is
rooted in the same ambient `AASM_STATE_DIR` this ADR already treats as
untrusted for the new artifact (D-C). An attacker with env-write capability
can therefore point `AASM_STATE_DIR` at a directory containing a file named
`all_proxy` and route the governed tool's traffic around `aa-proxy`
entirely, while the launch still reports as governed.

**M1 (review #6) — a blanket name-filter at this read is the wrong fix: this
store is the product's own legitimate carrier of `HTTPS_PROXY`/`HTTP_PROXY`**
(`StepAction::ConfigureProxy` writes exactly those two names into it as the
receipted fallback value used when no runtime `proxy_addr` is pinned for a
given launch — both `build_launch_command` implementations' own doc comments
say so: "a proxy address the caller pinned for this run wins over the
receipted one"). A name-filter that strips `HTTPS_PROXY`/`HTTP_PROXY` from
this read breaks every receipted-value governed launch.

**Review #7 found the provenance fix proposed above does not actually close
the gap, and this ADR accepts that finding rather than re-proposing a third
design.** `ClaudeCodeAdapter` is constructed *in-process* (no supervisor/
callee process boundary exists to carry an explicitly-resolved path across)
and every state-root resolution in this crate tree — the new trusted-config
artifact (D-C), `mitm_hosts`/`integration_mitm_hosts()`, and this
`installed_environment` store — bottoms out in the same ambient
`AASM_STATE_DIR` (or its `$HOME/.aasm` default), read one stack frame apart.
"The supervisor resolves it and passes it" reads the identical variable
through the identical fallback chain; it relocates the read, not the trust
boundary. Making this genuinely non-ambient would require either an
operator-facing `--state-dir` flag that takes precedence over the env var
everywhere in the tree, or a receipt-fingerprint verification at every read
site (the executor already computes one per `ConfigureProxy` step, so this
is buildable) — both are materially larger changes than this ADR's stated
scope, touching every existing `AASM_STATE_DIR` consumer, not just the two
new artifacts this ADR introduces.

**Resolution (consistent with M2's own pattern: state the real ceiling
honestly rather than re-designing a third time): this is recorded as named
un-closed gap #3** (alongside gap #1, which already concedes the identical
ambient `mitm_hosts`-widening channel, and, per D-C's own narrowed claim,
also concedes that the same pre-launch `AASM_STATE_DIR` attacker can author
their own well-formed `TrustedUpstreamProxyEndpoint`/
`DeclaredEnterpriseDestination` artifact at that root — `aa-proxy`'s content
validation catches malformed/wildcarded/loopback-targeting input, not
attacker authorship) — **not fixed by this ADR.** An attacker who can set
`AASM_STATE_DIR` before `aasm run` starts can plant a file under
`launch-env/` that reaches the governed child's real environment (gap #3),
exactly as they could already widen `mitm_hosts` (gap #1) or author the
trusted-config artifact itself (D-C's narrowed claim). Closing this — a
non-ambient state root, or receipt-fingerprint verification at read time —
is separate follow-up scope alongside D-F and gap #1, not built here.

The seven boundaries, with the R1/R2 fixes folded in:
- `ProxyGuard::build_command` (`aa-cli/src/commands/proxy/guard.rs`, `aa-proxy`
  spawn) — the R2 invariant (step 0's `--no-proxy` carve-out does not apply
  here; this boundary has no such concept), all 8 variants, 2-variable
  injection set only; this boundary never has a trusted value to inject, so
  step 3 is a no-op.
- `build_child_env`'s consumer, `spawn_and_wait`
  (`aa-cli/src/commands/run.rs`) — the full R2 invariant including step 0's
  `--no-proxy` carve-out (this is the one boundary where `--no-proxy` is an
  actual, plumbed CLI concept — `build_child_env`'s existing `no_proxy: bool`
  parameter), fixed at the `Command` level per F4 (the channel already
  exists: `removed` → `tokio_cmd.env_remove`, fed by `effective_child_env`'s
  adapter-`None` entries — this is the fix site, not `build_child_env`'s own
  `HashMap` return).
- **`aa-devtool-claude-code::build_launch_command`** (`aa-devtool-claude-code/src/lib.rs`)
  **and** **`ClaudeCodeIntegration::build_launch_command`**
  (`aa-devtool-claude-code/src/lifecycle.rs`) — **review #8 found a
  self-contradiction in an earlier version of this section and corrects it
  here**: for the real, only-production path — `aasm run <tool>` — this
  boundary and the `spawn_and_wait` boundary above are **not two
  independent spawns; they are one spawn**. `launch_command` calls
  `self.adapter.build_launch_command(...)` (this boundary), and its
  returned `Command`'s env is what `spawn_and_wait`/`effective_child_env`
  actually removes-from/spawns — the adapter's env is applied *last and
  wins* over anything `build_child_env` computed. Requiring "steps 1-3
  apply unconditionally, no `--no-proxy` skip" **inside the adapter**, as an
  earlier version of this section said, would make it impossible for the
  `aa-cli` boundary's step-0 carve-out to ever actually apply to this
  spawn — the exact documented `--no-proxy` opt-out (`build_child_env`'s
  `None => {}` arm and its test,
  `build_child_env_leaves_the_ambient_proxy_alone_under_no_proxy`) would
  break for every governed Claude Code launch, the opposite of "exists
  today, unchanged." **Fix**: the R2 invariant's removal step (1)/(2), for
  this spawn, is performed once, at the `aasm run` spawn site
  (`run.rs`'s `spawn_and_wait`/`effective_child_env`, where `no_proxy` is
  already in scope) — **not** duplicated unconditionally inside the
  adapter. The adapter's own `build_launch_command` is left to do what it
  does today (including its `installed_environment` loop injecting the
  receipted value, point 2 below); `--no-proxy`'s step-0 carve-out, applied
  once at the outer spawn site, correctly leaves that injected value alone
  when the operator asked for it, and correctly removes it (steps 1-3)
  otherwise. A direct caller of the adapter *outside* `aasm run` (none
  exists in production today for this boundary) would get no removal —
  named explicitly rather than silently assumed away.
  1. **Step 3's injection set, at the outer `aasm run` spawn site, must
     explicitly include the `installed_environment` store's receipted
     value** as a thing to *preserve* (not blanket-strip), not just "a
     trusted endpoint or ambient-observed-and-vouched-for proxy" (the
     `aa-cli` boundary's original enumeration, which predates this store) —
     omitting it would strip the very value the adapter's own loop just
     set, reintroducing an ungoverned-reporting-as-governed launch by a
     different route than M1's original filter mistake. This receipted
     value carries the same trust caveat as un-closed gap #3 below: it is
     legitimate product behavior, not attacker-proof.
  2. **The `lifecycle.rs` implementation reads two stores, not one** — it
     delegates to the adapter's own `build_launch_command` first (which
     reads `installed_environment` rooted in `ClaudeCodePaths::from_env()`),
     then overlays a *second* `installed_environment` read against
     `self.paths`, applied *before* `spec.env` (which is layered last).
     `LaunchableTool`/`ClaudeCodeIntegration::build_launch_command` has no
     production caller today — `aasm run` uses the 4-arg `DevToolAdapter`
     path (point 1 above) exclusively — so this point is recorded for
     completeness/future-caller safety, not because it changes the outer
     -spawn-site fix's applicability today.
- **`aa-devtool-codex`** and **`aa-devtool-windsurf`** (`src/lib.rs` in each
  crate) — currently set only `HTTPS_PROXY` and strip nothing; brought up to
  the same standard: removal/injection performed once at whatever spawn
  site actually launches the child (today, also `aasm run`'s
  `spawn_and_wait`, per the same one-spawn reasoning above — confirm this
  remains the only production call path at implementation time rather than
  assuming it), not duplicated inside the adapter itself. Neither reads
  `installed_environment`, so gap #3 below does not apply to them today.
- `aasm proxy start`'s spawn path — `proxy_child_env`
  (`aa-cli/src/commands/proxy/start.rs`) returns `Vec<(&'static str, String)>`
  and **cannot express a removal**; the R2 invariant's removal/injection
  sequence belongs in that command's `dispatch` function, immediately before
  the `Command` built from `proxy_child_env`'s output is spawned.

(`aa-devtool-copilot` and `aa-devtool-saas` return errors rather than
spawning a process and are not spawn boundaries — confirmed, not assumed.)

### D7 — Loop prevention: corrected claim, real bound specified (fixes review-#2 item H)

Draft 2 claimed `dial_via_trusted_upstream_proxy` would inherit
`connect_revalidated`'s "timeout/loop-detection discipline." **That claim was
false** — `connect_revalidated` has no timeout wrapper and no loop detection
at all (verified: the only `tokio::time::timeout` calls in `proxy/mod.rs` are
`#[cfg(test)]`-only). This ADR specifies, instead of assumes:
- Startup validation rejects a `TrustedUpstreamProxyEndpoint` whose
  `pinned_addr` is loopback-equivalent to `aa-proxy`'s own bound listen
  address (`127.0.0.1`/`::1`/`0.0.0.0`-binds-to-any-local equivalence
  classes) — checked **after** `aa-proxy` binds its own listen socket
  (`AA_PROXY_ADDR=127.0.0.1:0` is ephemeral, so the real port is not known
  until bind completes), meaning this check runs alongside, not before, the
  rest of D-C's config validation, and against the real bound port, not the
  requested `:0`.
- `establish_trusted_proxy_tunnel` (N2) wraps its connect-and-CONNECT sequence
  in an explicit `tokio::time::timeout` (new, not inherited from anywhere)
  with a bounded duration, so a live multi-hop loop this ADR's single-hop
  check cannot see degrades to a bounded failure (feeding D4's fail-closed)
  rather than a hang.

### D8 — Ambient proxy variables are observed, never trusted

Unchanged product semantics from AAASM-5897: an ambient
`HTTPS_PROXY`/`HTTP_PROXY` (any case, D6) is warned about, never silently
adopted as routing configuration for the governed *tool* child. This ADR adds
a second, distinct instance of the same principle: an ambient value resembling
`TrustedUpstreamProxyEndpoint`/`DeclaredEnterpriseDestination` configuration
is never adopted for the *chained* path either (D-C, D6, N4's precondition
fix) — the same "observed and warned about, never trusted" posture applies to
both the pre-existing tool-routing case and this ADR's new corporate-proxy
-routing case, not two different postures accidentally.

### D9 — Protection-state semantics

No new `ClaimTerm`/`CapabilitySupport`/`ProtectionState`/`IntegrationCapability`/
`EvidenceKind` types (M2 — v1 deliberately does not build a chained-specific
evidence tier; see the evidence-requirement discussion under D2b for why).
Summary of the full ladder for a tool with a configured
`TrustedUpstreamProxyEndpoint`:
`NotInstalled`/`DetectedNotIntegrated`/`PartiallyIntegrated`/`Integrated`/
`GatewayProtected` follow the existing, unmodified rules, driven by the same
`ModelPathInterception`-capability evidence (the local probe) any other
MITM'd host uses — a chained route reaching `GatewayProtected` means the
ordinary MITM/redaction path was proven, exactly as it does today, and v1
does not additionally require or represent proof that traffic specifically
traversed the trusted-proxy hop (the named limitation from D2b's evidence
discussion). An enterprise destination that is declared but fails F3's
MITM-eligibility precondition never reaches a valid configuration state at
all (refused at validation, D2b) — there is no `ProtectionState` for it to be
reported, correctly, since it cannot exist as a running configuration.

## Consequences

- The v1 feature is strictly narrower than "full corporate-proxy egress": only
  explicitly declared destinations chain. Deployments requiring **all**
  outbound traffic to traverse a corporate proxy are **not fully served by
  v1** — recorded truthfully as a limitation (D-F below), not silently
  claimed as covered.
- Every non-declared destination's SSRF posture is unchanged because
  `chained_route` is `None` for it and every dial function's non-`Some`
  behavior is byte-for-byte what it is today (D-D) — one decision point, one
  threaded value, not a claim resting on a single test.
- The one new private-address-capable branch (`establish_trusted_proxy_tunnel`,
  inside `dial_upstream_tls`, N2) is reachable only through an exact-match
  gate fed exclusively by supervisor-provenance configuration (D-C, D-D) —
  closing the "chaining leaks to arbitrary destinations" concern
  structurally rather than by convention.
- Operators get a materially more explicit setup: `TrustedUpstreamProxyEndpoint`
  config + `DeclaredEnterpriseDestination` list (host-exact) + optional
  MITM/LLM-endpoint declarations (D2/D2b) + optional proxy auth (D5,
  HTTPS-only) — more steps than draft 2, in exchange for the destination-level
  guarantee holding structurally.
- `GatewayProtected` for a chained route uses the same, unmodified
  `ModelPathInterception`/local-probe evidence any other MITM'd host does
  (D9/M2) — v1 does **not** build a dedicated mechanism to additionally
  prove traffic specifically traversed the trusted-proxy hop; this is a
  named, disclosed limitation (D2b's evidence discussion), not silently
  glossed over as a capability this ADR doesn't actually deliver.

### D-F — Deliberate v1 limitation: corporate-proxy-only (full-egress) networks are not fully served

Some enterprise environments require **all** outbound traffic, not just
declared enterprise destinations, to traverse the corporate proxy. Option (i)
does not weaken the SSRF guarantee to claim universal compatibility with that
requirement — a deployment in that category can chain its declared model/API
destinations through this feature, but other outbound traffic AASM's proxy
touches keeps using its existing direct/allowlist logic, unaffected by
whether a trusted upstream proxy is configured. This is recorded as a
**known, deliberate v1 gap**, not silently glossed over. A materially
different trust model — where the corporate proxy itself becomes part of the
destination-enforcement boundary (i.e., AASM defers SSRF-relevant judgment to
the corporate proxy for a broader traffic class) — is a separate,
follow-up architectural question requiring its own independent review; it is
not blocked on this implementation, and this implementation is not blocked on
it. See Implementation breakdown for the follow-up ticket.

## Forbidden designs

1. No generic SSRF-guard relaxation flag (unchanged from draft 2).
2. Do not read `TrustedUpstreamProxyEndpoint`/`DeclaredEnterpriseDestination`
   config, or `pinned_addr`, from ambient process environment or as a
   pre-computed value crossing the `aa-cli`→`aa-proxy` boundary (D-C).
3. Do not re-resolve the trusted endpoint's hostname per connection (pin
   inside `aa-proxy`, once, D-C).
4. Do not fall back to a direct dial when the trusted proxy is unreachable
   for a declared destination (D4).
5. Do not build a credential broker (D3).
6. Do not report a route `Protected` merely because an integration is
   installed, an endpoint is configured, or a locally-terminated probe
   succeeds (D2b/D9).
7. Do not allow request/agent/tool content to influence
   `TrustedUpstreamProxyEndpoint` or `DeclaredEnterpriseDestination`.
8. Do not use CIDR/subnet-style matching for either type — exact host/port
   only (D-A, D-B).
9. **New**: do not chain any destination that is not an exact
   `DeclaredEnterpriseDestination` match, regardless of how the trusted
   proxy is configured (D-D) — this is the v1 scope decision; do not
   generalize it in this implementation.
10. **New**: do not send `Proxy-Authorization` over a plaintext transport (D5).
11. **New**: do not silently strip TLS trust-anchor environment variables
    without documenting the resulting trust model, and do not silently
    preserve them without acknowledging they affect the new leg too (D-E).

## Alternatives rejected

- **Option (ii): chain all traffic, validate locally before handing the
  hostname upstream.** Rejected for v1 per owner decision: weaker security
  guarantee than option (i), because the corporate proxy performs its own,
  independent DNS resolution after AASM's local validation — DNS rebinding,
  split-horizon DNS, and general resolver disagreement all mean AASM's
  validated address is not provably what the corporate proxy actually
  connects to (TOCTOU between AASM's resolution and the proxy's). Option (i)
  avoids this entirely by never handing an undeclared hostname to the trusted
  proxy in the first place. May be revisited as a materially different,
  separately-reviewed trust model (D-F) if full-egress support becomes a
  requirement.
- Remaining alternatives (generic SSRF relaxation, `ANTHROPIC_BASE_URL`
  destination discovery, ambient-env inheritance, auto-widening `mitm_hosts`/
  LLM-endpoint status, full credential broker, per-connection re-resolution):
  unchanged from draft 2, still rejected for the same reasons.

## Test strategy (chain-aware negative controls, revised per review #3, F9)

| Test | Scenario | Required outcome |
|---|---|---|
| 1 | Declared enterprise destination (MITM-eligible per F3/D2b, LLM-class declared), configured trusted proxy, **synthetic secret in the request** | Chained path used, request succeeds, **AND redaction assertion asserted at the mock destination BEHIND the trusted proxy** (R10 — the trusted proxy itself only ever sees opaque TLS-tunneled bytes once `dial_upstream_tls`'s destination-TLS is layered on top per N2, so asserting "absent from bytes reaching the trusted proxy" would pass vacuously regardless of whether redaction ran): original secret absent from the mock destination's received bytes — folds in draft 3's Test 14 |
| 2 | Same trusted proxy configured, host NOT in `DeclaredEnterpriseDestination` (including a host that only coincidentally matches on hostname but not `port`, per F7) | Falls through to existing direct path — chained path NOT used |
| 3 | Agent-selected hostname resolving to RFC1918, chaining enabled elsewhere | Denied by unmodified `connect_revalidated`/`is_blocked_ip` |
| 4 | Matched-population comparison: the *same* set of non-declared destinations (including one resolving to RFC1918) dialed once with chaining configured and once without | Identical outcome both times — proves chaining introduces no reachability delta for non-declared traffic, not just "no change" asserted on a single config |
| 5 | DNS-rebound destination not in the declared set | Cannot use chained path |
| 6 | Ambient uppercase `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` set directly in the launching shell (not via the launch-env store — that channel is gap #3, tested separately at Test 9), `--no-proxy` **not** passed, asserted by **probing the spawned child's actual environment** (not the pre-spawn `HashMap`/`Vec`) at all seven implementation sites (the `aasm run <tool>` case exercises the outer spawn-site removal once, per the one-spawn correction above; `ProxyGuard::build_command` and `aasm proxy start` are genuinely independent) | Absent from the child's real environment — catches F4's defect class, which a map-level assertion would miss |
| 6b | The `aasm run <tool>` (Claude Code) case specifically, with **no runtime `proxy_addr` pinned, `--no-proxy` NOT passed, and a legitimate receipted `HTTPS_PROXY`/`HTTP_PROXY` value in the launch-env store**, placed there through the store's normal write path (not by directly manipulating `AASM_STATE_DIR`) — this is the positive control Test 6 alone doesn't cover, and its precondition explicitly excludes `--no-proxy` (review #8 correction — conflating this case with the `--no-proxy` case is exactly the self-contradiction the one-spawn fix above corrects) | The receipted value **is** injected into the child's real environment — proves the outer spawn site's step 3 correctly names this store as a legitimate injection source and does not strip a legitimately-configured governed launch |
| 6c | The same case as 6b, but **`--no-proxy` IS passed** | The receipted `HTTPS_PROXY`/`HTTP_PROXY` value, and any ambient proxy env, is left completely untouched — the documented opt-out holds for this spawn exactly as it does at the `aa-cli` boundary alone, proving the one-spawn fix didn't just move the self-contradiction rather than resolve it |
| 7 | Ambient lowercase equivalents, same child-environment-level assertion, same seven boundaries | Same as Test 6 |
| 8 | Ambient AASM trusted-upstream/declared-destination variable, no supervisor config, same child-environment-level assertion | Not adopted — `Command::env_remove()` proven unconditional at the process level |
| 9 | Manipulated/attacker-controlled `AASM_STATE_DIR`, set **before** `aasm run`/`aasm proxy start` begins — covering (a) the new `TrustedUpstreamProxyEndpoint`/`DeclaredEnterpriseDestination` artifact's own content (review #8, F-B: `aa-proxy`'s content validation is genuinely independent of `installed_environment`'s pass-through weakness, but it validates well-formedness, not *authorship* — an attacker who controls the pre-launch state root can still author a well-formed artifact of their own choosing at that root; this is the same discriminating fact as gaps #1/#3, not a closure — see below), (b) F3/N4/M4's precondition (a declared destination must not pass MITM-eligibility validation via an `AASM_STATE_DIR`-manipulated `mitm_hosts` entry alone, nor via a wildcard host surviving into the union — gap #1), and (c) `launch_env::installed_environment` — a file named `all_proxy`/`HTTPS_PROXY`/etc. dropped under an attacker-redirected state dir (gap #3) | **All three reach their target** when the attacker controls `AASM_STATE_DIR` *before* `aasm run` starts — this row asserts the documented, honestly-disclosed behavior for (a)/(b)/(c) alike, not a closure for any of them. (D-C's genuinely-enforced property is narrower than "cannot redirect the trusted config root" — it is: `aa-proxy` refuses a malformed/wildcarded/loopback-targeting artifact regardless of who authored it, and, separately, an attacker who can only influence `aa-proxy`'s *already-running* inherited environment post-spawn — not the pre-launch state root — cannot redirect it. A pre-launch state-root attacker is covered by the same gap as (b)/(c), not by D-C's validation.) |
| 10 | Corporate proxy auth configured with `scheme: Http` | Refused at validation/startup, not silently sent cleartext |
| 11 | Trusted proxy unreachable, declared destination requested | Fail closed, no direct-dial fallback |
| 12 | Trusted proxy configured to resolve to `aa-proxy`'s own listen address | Rejected as a loop at validation; bounded timeout as defense-in-depth |
| 13 | Existing normal-destination SSRF regression suite | Remains green, unmodified |
| 14 | *(retired — folded into Test 1, see above)* | — |
| 15 | `AA_PROXY_NETWORK_FAIL_OPEN=1` ambient, combined with a declared destination — asserting the **real** interaction: this flag is consulted only in `gateway_egress_deny_reason` (gateway network-policy stage), not anywhere in the dial path, so its actual effect is bypassing *gateway* network policy for the declared destination too, not defeating D4's fail-closed dial behavior | Gateway-network-policy bypass, if any, is documented and intentional per existing `network_fail_open` semantics; D4's fail-closed dial behavior is independently unaffected — draft 3's stated interaction (flag defeats fail-closed dial) does not exist in current code and must not be asserted as if it did |

**Named, un-closed gaps (not fixed by this ADR, recorded rather than left
implicit)**:
1. `AASM_STATE_DIR` still widens the *general* `mitm_hosts` allowlist today
   via the pre-existing `integration_state_dir()` mechanism, which D2b makes
   newly security-relevant for a host an operator chose to declare as an LLM
   endpoint *through that general mechanism* (as opposed to F3/N4's hard
   precondition, which does not accept it as satisfaction). Closing the
   general mechanism's ambient-readability, if warranted, is separate
   follow-up scope.
2. `AA_PROXY_SKIP_UPSTREAM_TLS_VERIFY` reaching the spawned `aa-proxy`
   process ambiently (D6 does not strip it, correctly — it is not a
   proxy-routing variable) is pre-existing behavior affecting the
   pre-existing destination-TLS leg (`dial_upstream_tls`'s own handshake to
   the real destination) — unrelated to, and not fixed by, this ADR's D5/F8
   guarantee for the *new* trusted-proxy leg, which never consults this flag
   regardless (D5/F8).
3. **(review #7, findings #1-#4)** `launch_env::installed_environment` — the
   Claude Code governed-launch fallback store — is rooted in the same
   ambient `AASM_STATE_DIR` as gap #1, and no non-ambient state-root or
   receipt-fingerprint-verification mechanism is built in this ADR to close
   it. An attacker able to set `AASM_STATE_DIR` before `aasm run` starts can
   plant a file (e.g. `all_proxy`, or even `HTTPS_PROXY` pointed at an
   attacker proxy) that reaches the governed child's real environment at
   both `build_launch_command` boundaries — this is the more severe sibling
   of gap #1 (it bypasses `aa-proxy` entirely rather than merely widening
   its MITM scope). This ADR's D6 work at these two boundaries is limited to
   correctly threading the R2 removal/injection invariant around this
   store's read (so the store's *legitimate* value is preserved, and any
   *ambient shell-set* `ALL_PROXY`/etc. alongside it is still stripped) —
   it does not, and cannot without materially larger scope, prevent the
   store's own location from being attacker-redirected. Closing this — an
   operator `--state-dir` flag taking precedence over the env var
   tree-wide, or per-read receipt-fingerprint verification — is separate
   follow-up scope alongside gap #1 and D-F, not built here. The same store
   also carries `NODE_EXTRA_CA_CERTS` (a TLS trust-anchor value, D-E's
   class) — noted so this gap and D-E's are understood as sharing one
   underlying channel, not two disjoint risks.

## Implementation breakdown

`TrustedUpstreamProxyEndpoint` + `DeclaredEnterpriseDestination` types + D-C
provenance/validation + F3/N4/R3's MITM-eligibility precondition and its
runtime-predicate union + `transparent_tunnel` defense-in-depth refusal
(`aa-proxy`, MATERIAL); `establish_trusted_proxy_tunnel` internal branch
inside `dial_upstream_tls` (N2/R6), threading `authorized`/`chained_route`
through `handle_llm_mitm`/`handle_non_llm_mitm` + `relay_mcp_response`'s
transport-type update + F2/N3's `ForwardAuthorized` typestate compliance +
F7/N1's port-parsing fix + N11's second-hop CONNECT-authority spec
(`aa-proxy`, MATERIAL); D6 env sanitization at **all seven** real spawn
boundaries (D6/R1/R2/R7), one coherent
removal-then-conditional-injection-last invariant, `--no-proxy` carve-out
scoped to the one boundary where it's a real plumbed concept (R2/M3, review
#7 finding #3), `Command`-level, correctly naming the launch-env store's
receipted value as a legitimate step-3 injection source at **both**
`installed_environment` reads on the `lifecycle.rs` boundary (review #7
findings #2/#4) — **not** a content filter (a filter alone was found to
break receipted governed launches, R1/M1) and **not** a provenance fix
either (review #7 finding #1: no in-process provenance boundary exists to
relocate the read across — this remains named un-closed gap #3, not solved
by this ADR), including fixing the **pre-existing** 2-variable leak found by
F4 (`aa-cli` + `aa-devtool-claude-code` + `aa-devtool-codex` +
`aa-devtool-windsurf`, MEDIUM-LARGE given the second
channel — call out the pre-existing-defect-fix portion explicitly in the
ticket, don't bundle it silently into new-feature scope); **D2b is new
MITM-branch-dispatch routing logic** (R9 — not a bar correction on existing
plumbing, as an earlier draft mischaracterized it: `handle_llm_mitm`'s
single existing entry point, `detect_api(host) != Unknown`, gains a second,
config-driven condition; S1's honest `LlmApiPattern::Unknown` labeling
consequence) (`aa-proxy`, MEDIUM); F3/N4/R3/M4's `mitm_hosts` union with
wildcard rejection (`aa-proxy`, folded into the D-C/D2b work above); D5/F8/N7
auth + HTTPS-only enforcement + unconditional (not auth-configured-qualified)
exclusion of `skip_upstream_tls_verify`/`upstream_override` (`aa-proxy`,
SMALL, reuses `Secret`); install-time flags for both new declaration types
(`aa-cli`/`aa-devtool-claude-code`, SMALL); Test 1-13, 15 (F9/R10/M5's
corrected set — Test 14 retired into Test 1; all new coverage); docs
(`limitations.md` — must state the D-F full-egress gap, the D9/M2 evidence
limitation, and both named un-closed gaps). **This ADR deliberately does
NOT include** a chained-specific evidence/`ProtectionState` mechanism (D9/M2
— the honest v1 limitation, not deferred as an oversight) — do not add one
under this Spike's implementation tickets without a fresh ADR amendment,
since it would require changing `aa-core`'s shared `ladder()` aggregation
logic, out of scope here. **Follow-up, separate tickets, not blocking this
implementation**: "enterprise full-egress proxy mode" Spike (D-F); a
conjunctive chained-evidence `ProtectionState` mechanism (D9/M2's named
limitation, requires an `aa-core` design of its own); optionally, closing
the two named un-closed gaps — search Jira first per campaign governance
before creating any of these.

## Risk

Medium. The v1 scope decision (D-D) bounds a defect in the new code to
declared-destination traffic — every other path is unchanged by construction,
not by convention, since D-D threads a value through the existing control
flow rather than early-returning around it, and the private-address-capable
logic lives inside `dial_upstream_tls`'s existing, already-audited call sites
(N2) rather than a new, separately-reachable function. Mitigated by: single
exact immutable trust value (D1), no generic escape hatch (Forbidden
designs), DNS pinning inside `aa-proxy` only (D-C), the `ForwardAuthorized`
typestate preserved on the same function for chained forwards (F2/N3),
fail-closed with a correctly-described fail-open-flag interaction and
documented `--no-proxy` opt-out (D4/Test 15, R2/M3), HTTPS-only proxy auth
with an unconditional debug-mode TLS-verification exclusion (D5/F8/N7),
explicit TLS trust-anchor model (D-E), a real (not inherited-and-nonexistent)
loop/timeout bound (D7), a truthfully-scoped protection-state claim that
does not promise chained-specific evidence this v1 does not build (D9/M2),
an honestly-scoped ambient-routing gap for the launch-env store rather than
a claimed-but-unreal provenance closure (gap #3), and a required eighth
independent adversarial review before Accepted.

## Independent security review

Required before Status moves to Accepted. Seven prior rounds converged
progressively (draft 1: SSRF-guard conflict; draft 2: undecided chaining
scope; draft 3: implementability/typestate/env-level defects; draft 4: three
of ten fixes incompletely applied plus two new defects the fix round itself
introduced; draft 5: most of N1-N11 verified correct, but a second
ambient-routing channel found (R1), an ordering contradiction (R2), a
validation/runtime predicate mismatch reintroducing F3's failure (R3), D2b's
mechanism confirmed nonexistent (R9), and a proposed evidence design shown
not to fit the actual pre-dial timing or per-tool/per-capability shape of
`aa-core`'s types (R4/R5), plus a vacuous test assertion point (R10); draft 6:
R1's proposed provenance fix, on closer inspection, was found not to
actually exist (no in-process boundary separates a "supervisor" from the
adapter reading the same ambient `AASM_STATE_DIR`) (M1), R2's invariant
contradicted the documented `--no-proxy` opt-out (M3), R3's `mitm_hosts`
union crossed a wildcard-matching grammar boundary (M4), and the R4/R5
evidence redesign was found to require changing `aa-core`'s shared
`ladder()` aggregation logic — resolved in draft 7 by dropping the
chained-specific evidence mechanism entirely rather than building it (M2);
draft 7: M2 verified genuinely correct and consistent, but M1's "fix" was
found to be a same-process relocation, not a real trust-boundary closure,
and two of its own consequences (the injection set never naming the
receipted store, and `lifecycle.rs`'s second `installed_environment` read
left unpinned) went unaddressed, plus `--no-proxy` found unplumbed at the
four devtool boundaries entirely — all seven verdicts ADOPT WITH NAMED
FIXES, no reopened trust-boundary decision) — this is the eighth pass,
applying review #7's four findings by disclosure (gap #3) and scoping
corrections, matching M2's own resolution pattern. Reviewer must
specifically attempt to prove: an undeclared destination can enter the
chained path by any means (including a host/port combination that partially
matches, or a malformed/unparseable CONNECT port, or a declared host
containing a wildcard metacharacter surviving into the `mitm_hosts` union);
`transparent_tunnel` or any other unmodified path gains reachability from
this feature, including via a declared destination whose runtime
`mitm_hosts` union (R3/M4) somehow diverges from what validation checked, or
whose defense-in-depth refusal (R3 part 2) doesn't actually fire; ambient
environment (any variable, any case, at any of the **seven** real spawn
boundaries, or via `AASM_STATE_DIR`) can create privileged routing or
redirect the trusted config root **beyond what gaps #1 and #3 already,
honestly, disclose as un-closed** — i.e. confirm nothing *new* beyond those
two named gaps exists, and confirm gap #3's scope claim is accurate (does
not also silently affect the new `TrustedUpstreamProxyEndpoint`/
`DeclaredEnterpriseDestination` artifact itself, which D-C's own validation
is claimed to protect independently); that Test 6b's positive control and
the R2 invariant's step-3 injection-set correctly preserve a legitimate
receipted launch-env value at *both* `lifecycle.rs` reads (review #7
findings #2/#4); that `--no-proxy`'s scoping to the single `aa-cli` boundary
is accurate and the four devtool boundaries' documented "no such concept,
steps 1-3 always apply" behavior is what the code actually does (review #7
finding #3); the env-removal fix actually reaches the spawned child's real
environment (not just a returned map/vec) at every boundary, that
`HTTPS_PROXY`/`HTTP_PROXY` are still correctly injected last per R2's
invariant, and that the documented `--no-proxy` opt-out at the `aa-cli`
boundary still leaves ambient proxy env completely untouched (M3); the
second-hop CONNECT authority can be influenced by `target`/in-tunnel headers
rather than only `route.dest` (N11); TLS trust or proxy auth can be
redirected, downgraded via a debug-mode flag (unconditionally, not just when
auth happens to be configured), or exposed in cleartext; a
false `Protected`/`GatewayProtected` state can be produced — including via
the locally-terminated probe mechanism, which D9/M2 now explicitly
*acknowledges* can justify `GatewayProtected` without proof of chained
traversal (verify this disclosed limitation is stated honestly, not that it
is "blocked," since v1 deliberately does not block it) — or via a declared
destination that isn't actually MITM-eligible; any listed negative control
would pass vacuously or test the wrong thing. Findings get fixed and
re-reviewed until clean, or a newly discovered, materially different
unresolved trust-boundary question is escalated rather than resolved
unilaterally.
