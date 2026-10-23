# Developer Integration ownership matrix

Every `DevToolAdapter`/`DevToolIntegration` currently registered in this
repository (`aa-core::dev_tool::DevToolKind` plus what
`aa-runtime::devint::adapters::built_in_integrations` actually wires up),
audited for the AAASM-6091 config-ownership guarantee. This is the
authoritative inventory — a tool not listed here has no registered adapter
in this codebase.

**Note on scope:** there is no separate JetBrains adapter and no separate
VS Code `DevToolKind` — GitHub Copilot's adapter *is* the VS Code surface
(Copilot runs as a VS Code extension). JetBrains has no registered adapter
at all today.

| Tool | Surface | Ownership | Install mutation | Repair mutation | Remove mutation | Conflict behavior | Preservation evidence |
|---|---|---|---|---|---|---|---|
| **Claude Code** | `~/.claude/settings.json` or `<project>/.claude/settings.json` (unprivileged) | 4 named keys in a shared file | `aa-core::integration::engine::FilesystemExecutor::apply_settings`, `SettingsMerge::MergeManagedKeys` — key-level splice, parse failure refuses | Re-applies the merge against current content; never overwrites the original `prior_state` | Reads current content fresh, restores only the 4 keys' prior values, deletes only keys that were absent before | N/A today — no concurrent-write detection (see gaps) | `aa-core::integration::engine` test suite: `apply_writes_a_receipt_and_preserves_unmanaged_keys`, `remove_restores_prior_state_and_keeps_later_user_changes`, `remove_deletes_a_settings_file_it_created_outright`, `a_withheld_prior_value_becomes_a_residual_and_keeps_the_receipt` |
| **Claude Code** | `/Library/Application Support/ClaudeCode/managed-settings.json` (privileged, `--install-managed-settings`) | Exclusively AASM's own artifact | `ManagedSettingsInstaller` — full-file `Replace`, disclosed content + digest, real OS admin authorization, read-back verified | Not repairable via the generic engine — installer-specific | `installer.rollback()` — deletes the file only if AASM installed it; refuses if the file exists and was not AASM's write | Refuses outright if the file already exists and was not written by AASM | `aa-devtool-claude-code::executor` tests: `a_managed_settings_step_without_an_authorized_installer_refuses`, `an_authorized_managed_settings_step_is_applied_observed_and_rolled_back`, `a_denied_authorization_fails_the_step_rather_than_downgrading_it` |
| **Claude Code** | `aasm run claude-code ...` launch-time apply | Same 4 keys, different code path | `aa-devtool-claude-code::apply::apply_settings_at` — **was** the AAASM-6091 defect (malformed file → silent empty base); fixed in #2431 to refuse on parse failure | N/A — no repair concept on this path | N/A — no receipt, no reversal on this path (architectural gap, see below) | None | `apply_settings_does_not_destroy_a_malformed_existing_file`, `apply_settings_preserves_unmanaged_keys` |
| **Codex** | `~/.codex/config.toml` (only scope Codex supports — `ScopeError::UnsupportedScope` refuses Project/Managed) | Named keys in a shared TOML file | `aa-devtool-codex::apply_settings` — TOML table merge; fixed in #2431 to refuse on parse failure or a non-table document instead of `unwrap_or_default()` | Same engine as Claude Code's unprivileged path | Same engine as Claude Code's unprivileged path | Same as Claude Code unprivileged | `apply_settings_refuses_a_malformed_existing_config`, `apply_settings_preserves_unmanaged_keys`, plus the `aa-devtool-codex::wrapper` contract-test suite |
| **GitHub Copilot** | VS Code user `settings.json` (User scope only; Project and Managed scopes are refused) | One named key, `chat.tools.global.autoApprove`, in a shared file (`aasm integrations`); `aasm run copilot` still uses the legacy launch-time path below | `aa-devtool-copilot::CopilotIntegration` over the `aa-core` engine (`FilesystemExecutor::apply_settings`, `SettingsMerge::MergeManagedKeys`) — writes `false` only; a user value that is already `false` is never owned, any other value or a non-strict-JSON file is refused at plan time | Re-plans through the same engine; never overwrites the original `prior_state` | Restores only the owned key's prior value and deletes it only if it was absent; JSON is re-serialised, so restore is semantics-exact, not byte-exact (the removal plan says so) | An edit made after planning is refused at apply (content digest) | `a_stricter_user_value_survives_install_and_remove_and_is_never_owned`, `a_jsonc_settings_file_is_refused_at_plan_time_and_left_byte_identical`, `an_edit_made_after_planning_is_refused_at_apply`, `install_then_remove_leaves_no_key_the_user_never_had`, `an_already_strict_install_reports_truthfully_and_notices_later_loosening` (`aa-integration-tests::devtool_adapter_nondestructive_install`) |
| **Windsurf Cascade** | `~/.codeium/windsurf/admin_settings.json` | Named top-level keys (`mcp`, `terminal`, `policy`) in a shared file | `aa-devtool-windsurf::apply_settings` — **was** an unconditional blind `fs::write`, no read at all; fixed in #2431 to read-merge-write, matching what `apply_mcp_governance` on the same file already did | Not natively registered — `aasm integrations repair windsurf` plans and reports only | Same — no receipt-backed remove | None | `apply_settings_preserves_unmanaged_keys`, `apply_settings_refuses_a_malformed_existing_file` |
| **SaaS coding agents** (Claude.ai, ChatGPT, Cursor cloud webhook observability) | None — no local file | L0/L1 observe-only | `apply_settings` always returns `Err(Unsupported)` — no local mutation exists to get wrong | N/A | N/A | N/A | `aa-devtool-saas` — `build_launch_command_always_errors` and the adapter's refusal-by-construction |

## The native/legacy split, and why it matters for repair/remove

`aa-runtime::devint::adapters::built_in_integrations` registers exactly three
kinds — `DevToolKind::ClaudeCode`, `DevToolKind::Codex` and
`DevToolKind::GitHubCopilot` — as native
`DevToolIntegration` implementations with a real `plan_integration` /
`apply` / `plan_removal` / `verify_integration` lifecycle backed by the
receipt-storing engine described in [Config ownership](config-ownership.md).
Every other registered `DevToolAdapter` (Windsurf, and any
`Custom(String)` adapter) is wrapped in `LegacyAdapterShim`, which can plan
and report but cannot apply: its plan's one step carries
`StepAction::ApplyLegacyManagedSettings`, and `FilesystemExecutor` refuses
that action outright — "there is no file for the executor to write and no
prior state for a receipt to record." **`aasm integrations
install/repair/remove windsurf` therefore does not mutate
anything today** — it can only detect, plan, and report residual/manual
steps. Copilot is native, but its capability ceiling is deliberately low:
the managed key is a user-editable VS Code setting that nothing here
independently verifies VS Code honours, so tool-action approval is declared
unsupported, `verify` reports it unverifiable, and the plan/status ceiling is
`L0Discover`.

This means Windsurf's *only* live mutation path is
`aasm run <tool> ...`, which calls `DevToolAdapter::apply_settings` directly
(bypassing the shim and the engine entirely) — exactly the path AAASM-6091's
defect lived in, and exactly what #2431 fixed for all four adapters. There
is currently no receipt-backed repair or remove for Windsurf to
audit, because none exists; that absence is itself the honest cross-tool
finding, not a gap in this audit. Copilot's `aasm run copilot` launch-time
path is unchanged and still writes its legacy keys outside the engine; those
legacy keys (`chat.tools.autoApprove`, `chat.mcp.requireApproval`) do not
appear in VS Code's published approvals documentation and are not owned by the
native lifecycle.

## Gaps this matrix surfaces (tracked under AAASM-6091, not yet closed)

- **No concurrent-write detection.** If the same AASM-owned key is changed
  externally between plan and apply, or by another process during a merge,
  nothing today detects or refuses that race — the merge simply wins
  silently. AAASM-6091 §2/§8 requires a fail-safe/no-clobber report for this
  case; not yet implemented.
- **`aasm run`'s apply_settings path has no receipt.** Even after the
  AAASM-6091 fix, a launch-time apply on Copilot/Windsurf/Codex/Claude Code
  cannot be "removed" the way an `aasm integrations install` can — there is
  no receipt to reverse from. This is an architectural gap, not just a bug:
  closing it means either giving `aasm run` its own lightweight receipt or
  documenting the asymmetry explicitly as a permanent limitation.
- **Windsurf has no native repair/remove at all**, as noted above —
  extending it to a native `DevToolIntegration` (so it gets the same
  receipt-backed engine Claude Code, Codex and Copilot have) is a real scope
  item, not something this audit can retroactively grant it credit for. Its
  documented configuration surface is also unverified: the adapter reads
  `mcp_settings.json` / `admin_settings.json`, while the vendor documentation
  names `mcp_config.json`.
- **The engine deletes a settings file that was already an empty `{}`** on
  removal, because an empty restored document cannot be told apart from one
  AASM created (AAASM-6378).
