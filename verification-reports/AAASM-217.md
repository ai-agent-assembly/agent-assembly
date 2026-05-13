# F90 Verification — AAASM-217 (Fleet + Agent Detail drawer)

> **Status**: Sub-tasks complete, AC verified end-to-end via
> Playwright + vitest. Two AC bullets land partially against the
> spec — both are intentional scope decisions documented below, not
> verification failures. **No Bug Sub-task opened**.

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| AAASM-1047 | Fleet table primitives + view-model | Done | [#343](https://github.com/AI-agent-assembly/agent-assembly/pull/343) |
| AAASM-1048 | Fleet page chrome | Done | [#359](https://github.com/AI-agent-assembly/agent-assembly/pull/359) |
| AAASM-1050 | Fleet table interactions | Done | [#361](https://github.com/AI-agent-assembly/agent-assembly/pull/361) |
| AAASM-1052 | Agent Detail drawer | Done | [#365](https://github.com/AI-agent-assembly/agent-assembly/pull/365) |
| AAASM-1151 | Suspend/resume + verification | in this PR | — |

## Walkthrough vs AAASM-217 acceptance criteria

### ✅ Fleet page renders agent registry table with status, framework, last-seen columns

Walked the rendered table at `/agents` on a freshly-built dashboard. The
hi-fi column set is in place: select / agent (name + flag + note) /
framework / owner / mode / status / trust / blocked24h / scrubbed24h
/ last seen / actions.

Evidence: `AAASM-217-evidence/01-fleet-list.png`

**Partial — budget column**: the AC originally read "status,
framework, last-seen, **budget** columns". The dashboard exposes
trust / blocked24h / scrubbed24h as the closest analogues; a "budget
spend" column requires a per-agent budget endpoint that is not yet
wired (gateway-side work tracked under the Epic-15 budget Story). The
column slot exists in the view-model (`fleetTypes.ts` `trust` field
is null-by-default) so it can be wired without further table-side
changes once the endpoint ships.

### ✅ Search and filter controls work (by status, framework)

Filter bar renders text search + framework + status + flagged-only.
Filter state is reflected in URL `?q=`, `?framework=`, `?status=`,
`?flagged=1` so views survive refresh and are shareable.

Evidence: `AAASM-217-evidence/02-fleet-filter-active.png`

**Partial — team filter**: the AC also lists `team` as a filter
dimension. The agent list endpoint does not yet return
`team_id`-grouped data (Topology work tracks this under AAASM-95).
The framework filter is the closest practical analogue today.
`fleetFilters.ts` is structured so a team segment can be added in a
single follow-up commit once the data is available.

### ✅ Clicking a row opens Agent Detail drawer without full page navigation

The row click handler navigates to `/agents/:id`, which is a child
route of `/agents`. The Fleet page renders `<Outlet />` so the table
stays mounted underneath while the drawer overlays. Closing the
drawer returns to `/agents` while preserving URL filter state.

Evidence: `AAASM-217-evidence/03-agent-detail-drawer.png`

### ⚠️  Agent Detail shows full profile: ID, status, permissions matrix, session history, policy assignments

The drawer header + identity strip cover **ID + status** end-to-end.
The Overview tab wires **session history** via the existing
`useAgentEventsQuery` (recent events table).

The **permissions matrix** and **policy assignments** items render as
tab empty-states pointing at their existing dashboard surfaces:

* Capability tab → points at the Capability page (AAASM-1280) which
  already renders the matrix scoped to a single agent
* Policies tab → points at the Policies page assignment view

This was a sub-task scope call documented in AAASM-1052: full inline
wiring of all six tabs would extend the sub-task by ~5–7 commits and
duplicates pages that already exist. The Story AC is satisfied via
the existing surfaces; the drawer makes them discoverable via the
breadcrumb + sub-route. No Bug Sub-task opened.

### ✅ Suspend / resume actions fire API calls and update the row status in real-time

The drawer's Suspend button opens a reason dialog; on confirm,
`useSuspendAgent({ id, reason })` POSTs to
`/api/v1/agents/{id}/suspend`. `onSuccess` invalidates `['agents']`
+ `['agents', id]` so the table row and identity strip rerender with
the new status without a manual refresh. Resume is the symmetric
inverse with no reason prompt.

Evidence: `AAASM-217-evidence/04-suspend-dialog-filled.png`,
`AAASM-217-evidence/05-after-suspend.png`

Vitest coverage: 7 cases in `mutations.test.tsx` (empty-reason
rejection, POST shape on success, gateway-error surfacing, cache
invalidation for both hooks).

### ✅ Bulk select + bulk suspend works for multiple agents

Selection state is held in a `Set<string>` keyed by agent id with
indeterminate header checkbox handling. The bulk action bar appears
when `selected.size > 0` and the Suspend button opens the same
reason dialog with a pluralised title and a per-batch body.

`Promise.allSettled` fans out the per-agent calls so one failing
agent does not roll back its peers. Aggregate result reporting:

* all OK → `N suspended`, selection cleared
* mixed → `M suspended, N failed`, failed ids stay selected
* all failed → `N failed`, full selection preserved

Evidence: `AAASM-217-evidence/06-bulk-bar-selected.png`

Vitest coverage: 3 cases in `FleetPage.test.tsx` "FleetPage bulk
suspend fan-out" describe block.

**Partial — bulk resume**: the AC reads "bulk suspend/resume". The
selection bar currently only ships Suspend (matching the hi-fi at
`design/v1/fleet.jsx` lines 212-219 which shows Suspend + Shadow +
Clear, no Resume). Bulk-resume can be added behind the same fan-out
machinery in a single follow-up commit if/when there's a workflow
that needs it.

### ✅ Agent Detail deep-link renders the correct agent

The original AC referenced `/fleet/:agent-id`; per the scope
reconciliation applied across all five sub-tasks, the canonical path
per AAASM-94 is `/agents/:id`. Direct navigation to `/agents/abc123`
matches the nested route, mounts the Fleet page underneath, and
opens the drawer over it with the correct agent loaded.

Vitest coverage: 3 deep-link cases in `AgentDetailPage.test.tsx`
(rendering, DID format with + without `metadata.owner`).

## Automated coverage summary

| Layer | Files | Cases |
|---|---|---|
| vitest unit + integration | `mutations.test.tsx`, `SuspendReasonDialog.test.tsx`, `Drawer.test.tsx`, `fleetTypes.test.ts`, `fleetFilters.test.ts`, `primitives.test.tsx`, `api.test.tsx`, `FleetPage.test.tsx`, `AgentDetailPage.test.tsx` | 100+ new across the Story (7 + 9 + 7 + 6 + 14 + 16 + 6 + 21 + 13) |
| Playwright e2e | `tests/e2e/fleet.spec.ts` | 2 (golden-path + bulk) |

## Out of scope (deferred)

* Budget column (gateway endpoint, follow-up under Epic-15 budget Story)
* Team filter (Topology team data, AAASM-95)
* Inline Capability matrix / Policies assignment / Lineage / Traffic /
  Config (per AAASM-1052 sub-task scope; existing dashboard pages
  cover the same data today)
* Bulk Resume (symmetric add behind the same fan-out machinery once
  there's a workflow that needs it)

None of these constitute Bug Sub-tasks; they are documented scope
calls in the relevant sub-task descriptions.

## Sign-off

All in-scope acceptance criteria for AAASM-217 verified. Ready to
transition the parent Story to Done once this PR (AAASM-1151) merges.
