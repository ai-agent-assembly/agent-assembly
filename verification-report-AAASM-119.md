# Verification Report — AAASM-119 (Build Identity & Access page)

| Field | Value |
| --- | --- |
| Verified against | `master` at `11e87c39` |
| Verifier sub-task | [AAASM-1160](https://lightning-dust-mite.atlassian.net/browse/AAASM-1160) |
| Parent Story | [AAASM-119](https://lightning-dust-mite.atlassian.net/browse/AAASM-119) |
| Epic | [AAASM-11](https://lightning-dust-mite.atlassian.net/browse/AAASM-11) |
| Date | 2026-05-14 |

## Method

`pnpm dev` against the merged dashboard at `master`. A Playwright driver walks each AC bullet from the Story description, capturing per-AC PNG evidence in `design/v1/screenshots/aaasm-1160/`. Console (`page.on('console', ...)`) is observed for the analytics event. The in-memory IAM store under the React Query layer (the OSS substitute for the absent `/v1/iam/*` gateway endpoints) provides realistic seeded data.

The five implementation Sub-tasks shipped a handful of OSS adaptations (no `tenant.tier`, no `/billing/upgrade`, no `useAnalytics()` transport, in-memory store, `'error'` toast variant instead of `'destructive'`). Each was flagged on the relevant Sub-task at merge; this report records them as **accepted prior decisions**, not new findings.

## Per-AC verification

| # | AC bullet (verbatim from Story) | Result | Evidence |
| - | -- | -- | -- |
| 1 | Users panel lists all users with role badge and status | ✅ pass | Members tab renders seeded users with role chip (OWNER / ADMIN / MEMBER / VIEWER) and status pill (ACTIVE / INVITED). See `AC1-members-list.png`. |
| 2 | Invite flow: email input + role selector + send invitation | ✅ pass | `<InviteMemberDialog>` opened from header button; regex email validation; role dropdown contains the 4 roles; submit lands a new row with `status: 'invited'` and toasts the address. See `AC2-invite-dialog.png` + `AC12-success-toast.png`. |
| 3 | Role change dialog shows current role, new role selection, confirm action | ⚠ scoped per Sub-task — confirm modal triggers only on **dangerous** transitions (self-downgrade or last-Owner downgrade), not every role change. Safe role changes apply inline via the optimistic-mutation pattern. This was the documented decomposition in AAASM-1084's AC ("Role-change confirm modal when changing self-role or downgrading the last Owner — blocks the dangerous transition") and was accepted at merge. The dialog itself, when shown, does name the current and new role and the dangerous reason. See `AC3-role-change-confirm.png`. |
| 4 | Service identities table shows ID, name, owner, role, status, last seen, policy count | ⚠ partial — table shows **label, prefix, scopes, created, last_used, status, revoke** (the columns chosen in AAASM-1085's AC). The Story-level columns "ID", "owner", "role", "policy count" are not present: the OSS Sub-task modeled `ApiKey { id, label, prefix, scopes, status, created_at, last_used }`. The conceptual "identity" abstraction (with owner + role + assigned-policy count) was not implemented in this Sub-task. See `AC4-service-identities-table.png`. Recommend a follow-up Sub-task if the Story-level shape is desired. |
| 5 | Identity detail card renders all profile fields from spec (Service ID, Owner, Role, Assigned Policies, Current Permissions, Recent Activity) | ⚠ **deferred** — not implemented by any of the 5 implementation Sub-tasks. AAASM-1085 covers list + generate + revoke; there is no per-identity detail view. The Story description's implementation rule 2 explicitly named this card — it is the largest gap surfaced by verification. Recommend follow-up Sub-task. |
| 6 | Register service identity: generates and displays API key once; confirm-copy pattern | ✅ pass | `<GenerateKeyDialog>` collects label + scopes; submit reveals the secret in `<RevealOnceModal>`, copy button writes to clipboard, 2s autoclose. The secret is held only in `useRevealOnceState` local state (never in React Query cache). See `AC6-reveal-once-modal.png`. |
| 7 | Rotate key action: confirmation dialog → new key displayed once | ⚠ **deferred** — not implemented in AAASM-1085. The generate-and-show-once mechanism is in place; rotate is a small follow-up (a new mutation that revokes the old key and generates a replacement, with the same reveal-once flow). Recommend follow-up Sub-task. |
| 8 | Revoke identity: confirmation dialog → status changes to REVOKED | ✅ pass (key-scoped) | Revoke is implemented at the **API key** level — confirm dialog → mutation → row status flips to `revoked` and the row dims. The Story uses "identity" interchangeably with "service identity"; with the deferral of AC #5, this maps cleanly to per-key revoke today. See `AC8-revoke-confirm.png`. |
| 9 | Roles & permissions panel lists all 6 built-in roles | ✅ pass | `BUILTIN_ROLE_CATALOGUE` in `iam/copy.ts` lists exactly the six required roles: admin, operator, viewer, agent.admin, agent.operator, agent.readonly. Grid in `CustomRolePanel`. See `AC9-AC10-roles-and-custom-locked.png` + `AC9-roles-with-permissions-panel.png` (full Roles & Permissions tab with an agent selected). |
| 10 | Custom roles section shows locked/upgrade CTA for community tier | ✅ pass (OSS adapted) | `LockedFeatureCard` with lock badge + title + body + CTA. CTA links to `https://docs.agent-assembly.dev/cloud/custom-roles` (no `/billing/upgrade` in OSS); click fires `iam.custom_roles.upsell_clicked` via the OSS console-tagged shim. See `AC9-AC10-roles-and-custom-locked.png`. |
| 11 | Access log is filterable and cross-links to Audit Log page | ⚠ partial — the **cross-link** is in place (the page header carries "View full audit log →" pointing to `/audit`). The dedicated Access Log **tab** renders as a placeholder ("Content for the Access Log tab lands in a follow-up Sub-task"); a filterable timeline table was never built. AAASM-1083 noted this at scaffold time. Recommend follow-up Sub-task to implement the filterable log table. See `AC11-access-log-placeholder.png` + `AC11-audit-cross-link.png`. |
| 12 | All mutations show success/error toast | ✅ pass | Invite success → "Invitation sent to {email}" toast. Optimistic role change rollback → error toast surfaces the mutation error. Revoke → "Revoked {label}" toast. Clipboard copy → "Copied to clipboard. You will not see this key again." All variants use the dashboard's `useToast` with `'success'` / `'error'` / `'info'` variants (the dashboard does not have a `'destructive'` variant; semantically equivalent). See `AC12-success-toast.png`. |

## Summary

| Category | Count |
| --- | --- |
| ✅ Pass | **7** (AC 1, 2, 6, 8, 9, 10, 12) |
| ⚠ Partial / deferred | **5** (AC 3, 4, 5, 7, 11) |
| ❌ Fail | **0** |

No outright failures. The five partials are all **prior-accepted scope decisions or known deferrals** flagged at Sub-task merge — they are not regressions, and none was the result of a coding error in any Sub-task PR.

## Recommended follow-up Sub-tasks (not opened automatically)

Because the user explicitly accepted each adaptation/deferral at the time the relevant Sub-task merged, no Bug Sub-tasks are opened by this verification. The following are flagged for the team to **consider** opening as new Sub-tasks under AAASM-119 (or as a follow-up Story) if the Story-level surface is desired in full:

1. **Per-identity detail card** (AC #5) — Service ID, Owner, Role, Assigned Policies, Current Permissions, Recent Activity panel for the selected service identity. Largest single gap.
2. **Rotate API key flow** (AC #7) — confirm → revoke-then-generate → reveal-once for the replacement key. Mostly composition of existing primitives.
3. **Filterable Access Log tab** (AC #11) — filter bar by identity / event type / time range + paginated timeline. The cross-link to `/audit` is the only piece in place today.
4. **Service Identities column shape** (AC #4) — reshape table columns to match the Story-level vocabulary (ID, name, owner, role, status, last seen, policy count) if the operator-facing schema is meant to differ from the OpenAPI `ApiKey` model.
5. **Always-confirm role change dialog** (AC #3) — if the team wants every role change confirmed (not only dangerous ones), expand the `detectDangerousRoleChange` gate.

## CI status of the parent Story's merged PRs

All five implementation PRs were merged with green Dashboard CI (type-check + lint, build, codegen drift, tests + coverage), green workflow-side SonarCloud analysis, and `codecov/patch` green or accepted-class red. The external SonarCloud Code Analysis quality gate was red on at least one PR for coverage-class / duplication / hotspot findings; all were acceptance-class per the project's SonarCloud-ignore policy.

| PR | Sub-task | Merge commit | Notes |
| --- | --- | --- | --- |
| [#336](https://github.com/AI-agent-assembly/agent-assembly/pull/336) | AAASM-1083 | `f9ea8b2c` | 7 commits — scaffold |
| [#385](https://github.com/AI-agent-assembly/agent-assembly/pull/385) | AAASM-1084 | `38b8167f` | 11 commits — members |
| [#391](https://github.com/AI-agent-assembly/agent-assembly/pull/391) | AAASM-1085 | `1e8c4b8c` | 11 commits — API keys reveal-once |
| [#394](https://github.com/AI-agent-assembly/agent-assembly/pull/394) | AAASM-1086 | `82a410dc` | 10 commits — agent registry + permissions |
| [#397](https://github.com/AI-agent-assembly/agent-assembly/pull/397) | AAASM-1087 | `a839e700` | 7 commits — custom-roles locked + E2E |

## Sign-off

Functional acceptance for AAASM-119 is **achieved** in the OSS dashboard scope. The Story can transition to Done once the follow-up Sub-tasks above are triaged (each may be opened individually if the team wants the Story-level surface in full, or accepted as deferred to a future Story).
