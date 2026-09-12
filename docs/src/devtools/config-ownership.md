# Config ownership and non-destructive mutation guarantee

> **Guarantee:** Agent Assembly modifies only configuration it explicitly
> owns. Install, repair, and remove preserve unrelated developer-tool
> configuration and any changes you make to it afterwards. **`repair`**
> specifically never reasserts an AASM-owned value over one you changed
> after install without your explicit say-so — see [Repair and an
> AASM-owned key changed
> externally](#repair-and-an-aasm-owned-key-changed-externally). This does
> **not** yet extend to re-running `install` against an already-installed
> tool, which still merges AASM's managed keys back in unconditionally —
> see [Known gaps](#known-gaps).

This page is the authoritative statement of that guarantee for every
productized Developer Integration, what backs it in code, where it does not
yet apply, and how to recover if you believe it was violated. It exists
because of [AAASM-6091](https://lightning-dust-mite.atlassian.net/browse/AAASM-6091):
a real, confirmed defect (fixed in
[#2431](https://github.com/ai-agent-assembly/agent-assembly/pull/2431)) where
one code path did not honour it. See [Known gaps](#known-gaps) for what
remains open, and [Repair and an AASM-owned key changed
externally](#repair-and-an-aasm-owned-key-changed-externally) for the
fail-safe default this page's guarantee was tightened to require.

## The ownership model

Every mutation surface this product touches falls into exactly one of these
categories, and the category determines what AASM is allowed to write:

| Category | Example | AASM may |
|---|---|---|
| **User/organization-owned state** | Everything else already in `~/.claude/settings.json` before AASM ever ran | Never touch |
| **AASM-owned keys inside a shared artifact** | `permissions`, `permissionMode`, `enabledMcpjsonServers`, `disabledMcpjsonServers` in Claude Code's `settings.json` | Read, write, and remove *those keys only* — and only reassert a value that changed externally after an explicit reconcile (see below) |
| **AASM-owned artifact** | A settings file that did not exist before install and holds nothing but AASM's own keys | Create, and delete outright on removal |
| **Privileged, exclusively-AASM-owned surface** | `/Library/Application Support/ClaudeCode/managed-settings.json` | Replace wholesale — this is the one surface designed for it (see [Privileged managed-settings](#privileged-managed-settings-replace-is-correct-here)) |
| **Unknown/unattributable state** | A pre-AAASM-5278 receipt with no restoration evidence | Fail safe — see [Legacy receipts](#legacy-receipts) |

**Preferred mutation order**, applied in this priority:

1. A native, dedicated AASM-owned drop-in surface, when the tool has one.
2. A key/object-level patch on a shared config (the common case — see
   below).
3. A dedicated AASM artifact (its own file), when the tool supports one.
4. Full-file replacement — **only** when AASM provably owns the entire
   artifact, meaning either it created the file from nothing, or the surface
   is architecturally exclusive to AASM (the privileged managed-settings
   case).

## How the guarantee is actually enforced

For the four keys Claude Code, Codex, Copilot, and Windsurf let AASM govern
in a file the tool itself also reads, the mutation is a **key/object-level
merge**, not a rewrite:

- `aa-core::integration::fingerprint::merge_managed_keys` parses the existing
  document, inserts only the named keys, and leaves everything else in the
  parsed structure untouched — including nested objects, arrays, and keys
  the schema doesn't know about yet.
- A parse failure on the existing document **refuses the write** rather than
  treating the file as empty. This is the exact invariant AAASM-6091 was
  opened over — see [Known gaps](#known-gaps) for the defect this closes.
- Removal (`aa-core::integration::fingerprint::restore_managed_keys`) reads
  the file **fresh at removal time**, not from an install-time snapshot, and
  restores only the keys the install step displaced — see [Install → edit →
  repair → edit → remove](#install-edit-repair-edit-remove).

### Why a structured key snapshot, not a file backup

The restoration record (`PriorSettingsState`) stores the prior value of only
the four managed keys, plus which of them didn't exist before (so removal
deletes rather than restores them), plus a fingerprint of the whole document
for drift detection. It deliberately does **not** store a copy of the whole
file. A whole-file backup would:

- put every unrelated key you keep in the same file into a second copy AASM
  now owns and has to protect, and
- restore the file to install-time state on removal, silently discarding
  everything you changed afterwards — exactly the A+B+C → A scenario this
  guarantee forbids.

A value that trips the credential scanner is not stored at all; its key is
named as `withheld_keys` and removal reports it as a residual rather than
guessing. This is a deliberate fail-closed choice (Core ADR 0015): an incomplete
restoration is always disclosed, never silently treated as complete.

### Privileged managed-settings: replace *is* correct here

`/Library/Application Support/ClaudeCode/managed-settings.json` is the one
surface where AASM performs a full-file `Replace`, through a dedicated
`ManagedSettingsInstaller` (not the generic engine): it discloses the exact
content and its digest before any privileged write, requires real OS
administrator authorization, verifies the write by reading it back against
the disclosed digest, and refuses outright if the file already exists and
was not written by AASM. This is architecturally sound *because* the surface
is designed to be exclusively AASM's — Claude Code does not merge into it
from anywhere else — which is exactly preferred-order tier 4 above. It is
not the same operation as the unprivileged merge into your personal
`settings.json`, and the two must not be confused.

## Install → edit → repair → edit → remove

The invariant this guarantee reduces to:

```
A              existing configuration
A + B          after AASM install (B = AASM's managed keys)
A + B + C      after you make an unrelated change (C)
A + C          after AASM remove — only B disappears
```

`Engine::repair()` re-applies the merge against the file's **current**
content, not a stale snapshot, and deliberately does not overwrite the
*original* `prior_state` captured at install time — overwriting it would
make a later removal restore the tampered values repair just corrected,
rather than your own original values. `Engine::remove()` reads the file
fresh and restores only what `prior_state` says AASM displaced.

## Repair and an AASM-owned key changed externally

Repair distinguishes two different kinds of drift, and treats them
differently on purpose:

- **A missing or reset AASM artifact** (`AasmArtifactMissing`) — nothing
  else has an opinion about this value, so repair restores it by default.
- **An AASM-owned key whose *value* no longer matches what AASM applied**
  (`AasmManagedValueChanged`) — something else wrote to a key AASM owns
  since AASM last set it. Founder decision for AAASM-6091: this is an
  **ownership conflict**, not routine drift, and the default is **fail-safe
  / no-clobber** — repair makes zero mutation to that key, leaves the
  external value exactly as it is, and reports the conflict rather than
  silently reasserting AASM's value. The reasoning: the receipt recording
  that AASM once owned the key is not proof that reasserting AASM's value is
  still what you want — something (you, another tool, an MDM profile) wrote
  over it since, and guessing which side should win is exactly the kind of
  destructive assumption AAASM-6091 exists to forbid.

A refused step surfaces as an
[`OwnershipConflict`](../../../aa-core/src/integration/engine.rs) naming the
exact step and its managed keys, the artifact path, and the current value of
those keys (screened through the same credential scanner
`PriorSettingsState` uses — a value that trips it is withheld and named in
`withheld_keys` rather than shown). Nothing about the conflict disclosure
broadens beyond the keys that step already owns.

**Restoring AASM's value requires an explicit reconcile.**
`IntegrationLifecycle::repair`'s `reconcile` parameter names the specific
step ids authorized to have their `AasmManagedValueChanged` drift
overwritten; every other refused step is left untouched and still reported.
Reconciling one step never touches any other step, and never touches a
user-authored key the reconciled step does not own — the same key/object-
level merge described above applies to the reconcile write, it is just no
longer gated on "the value already matches the receipt".

As of this writing, the `reconcile` override is reachable through
`IntegrationLifecycle` directly and through the conformance test harness's
`repair_reconciling()`. It is **not yet exposed** over the DI-API wire
protocol or in `aasm integrations repair` — every repair request through
either of those today gets the fail-safe default, and an externally-changed
owned key surfaces there as `unrepairable` rather than as a mutation. Wiring
the override through to the CLI is a tracked follow-up, not a silent gap:
the fail-safe default is what ships either way, and no path anywhere
reasserts an AASM value over an external change without it.

## Known gaps

The confirmed defect ([AAASM-6091](https://lightning-dust-mite.atlassian.net/browse/AAASM-6091),
fixed in [#2431](https://github.com/ai-agent-assembly/agent-assembly/pull/2431)):
`DevToolAdapter::apply_settings` — the mutation path `aasm run <tool> ...`
calls on every launch, separate from the receipt-backed engine described
above — silently treated a **malformed existing config file** as empty and
overwrote it with only AASM's managed keys, in all four adapters
(`aa-devtool-claude-code`, `aa-devtool-codex`, `aa-devtool-copilot`;
`aa-devtool-windsurf` was worse — an unconditional blind replace with no
read of the existing file at all). Fixed: a parse failure now refuses the
write; Windsurf's path now reads-merges-writes. This defect never affected
`aasm integrations install/repair/remove`, whose engine has always failed
closed on a parse error.

The following AAASM-6091 acceptance items are closed:

- A realistic end-to-end preservation test exercising the full
  install→edit→repair→edit→remove cycle against a config with nested
  objects, arrays, and unknown future keys.
- Adversarial/race coverage (a corrupt/tampered receipt, a settings step
  with no prior state, an out-of-range tool upgrade, repeated
  install/repair/remove cycles).
- A named `legacy_ownership_unknown` classification for a receipt with no
  restoration evidence at all.
- A named shared contract-test suite enforcing the preservation invariants.
- The fail-safe/no-clobber default for an AASM-owned key changed
  externally, described above.

Not yet closed — do not read this page as claiming otherwise:

- The `reconcile` override is not yet exposed over the DI-API wire protocol
  or `aasm integrations repair` (see the section above).
- **`Engine::apply()`** — the path `aasm integrations install` re-runs
  against an already-installed tool — has no drift/conflict check at all.
  It unconditionally merges the plan's managed-key values back over
  whatever is currently on disk, the same way `repair` used to before this
  page's fail-safe default. `realistic_preservation_e2e_install_edit_repair_edit_remove`
  in `aa-core/src/integration/engine.rs` demonstrates this directly: it
  externally changes `permissionMode`, calls `apply()` again, and the
  external value is silently overwritten. The founder's decision and this
  page's guarantee are scoped to `repair`; making `apply()` conflict-aware
  the same way is a follow-up, not something this change did.
- **Concurrent external edit racing an install, and a stale plan executed
  against a receipt that changed underneath it** — the adversarial/race
  coverage closed above covers a corrupt receipt, a settings step with no
  prior state, an out-of-range upgrade, and repeated install/repair/remove
  cycles, but not an edit racing an in-flight `apply`/`install`, nor a plan
  authored against stale receipt state. Requirement 5 of the fail-safe
  decision ("stale receipt / concurrent edit cannot silently win") is
  therefore only partially covered — the stale-receipt half is tested
  (`a_corrupt_receipt_blocks_repair_instead_of_silently_reinstalling`), the
  concurrent-edit-racing half is not.

## Legacy receipts

A step whose receipt carries no `prior_state` at all — including a receipt
written before `PriorSettingsState` existed — is treated as **not provably
restorable**, never as "nothing to restore". Removal reports it as a
residual and keeps the receipt on disk rather than guessing at what to
restore or deleting the file outright. This is the fail-safe default
regardless of whether the step's action carries a `reversal` — a settings
step's reversal is never honoured without restoration evidence to back it,
because doing so could delete a file AASM only ever partially owned.

## Recovery and dry-run inspection

- `aasm integrations plan <tool>` and `aasm integrations install <tool>
  --dry-run` show every step and its target path before anything is
  written — nothing here is guessed at silently.
- `aasm integrations remove <tool> --dry-run` shows exactly what will be
  restored and what (if anything) will be left as a residual, before you
  confirm.
- If a removal reports a residual, the integration receipt is kept
  specifically so you can see what AASM has not yet cleaned up. Deleting the
  receipt by hand only after resolving the residual is the documented
  recovery step; deleting it first would remove the record of what remains
  to restore.

## Cross-tool status

See [Developer Integration ownership matrix](config-ownership-matrix.md) for
which of the above applies to each registered adapter today.
