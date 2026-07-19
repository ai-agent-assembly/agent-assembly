# AAASM-4892 — paginated OpenAPI contract fix: live validation

Validation that the dashboard **Live Ops** and **Overview** pages — which crashed
against a real gateway before this change — now render, and that the OpenAPI/handler
contract for the paginated list endpoints is aligned.

## The bug

`aa-api` list handlers return `PaginatedResponse { items, page, per_page, total }`,
but four (`/agents`, `/alerts`, `/policies`, `/logs`) were annotated `body = Vec<T>`,
so the OpenAPI advertised a bare array. Dashboard consumers that treated the response
as an array (`.map` / `.filter`) crashed the page into the AppShell ErrorBoundary
("Something went wrong"). `/approvals` was already correct (named `PaginatedApprovalResponse`).

## The fix

- **Server**: `PaginatedResponse<T>` now derives `utoipa::ToSchema`; the four handlers
  are annotated `body = PaginatedResponse<T>`; `openapi/v1.yaml` regenerated → each
  endpoint declares the `{ items, total, … }` object. A contract regression test
  (`paginated_list_endpoints_declare_object_body_not_array`) guards all five.
- **Dashboard**: `useAgentsQuery`, `usePoliciesQuery`, the audit-logs query, and
  `useAlertsQuery` (a custom-fetch hook that cast raw JSON, so types couldn't catch it)
  now read `.items`. `useApprovalsQuery` already did.

## Live validation (aa-api-server, prod dashboard build)

| Page | Before | After |
|---|---|---|
| `/live` (Live Ops) | ErrorBoundary `(f.data ?? []).map is not a function` | ✅ renders (`aaasm-4892-liveops-fixed.png`) |
| `/overview` (Overview) | ErrorBoundary `.map` → then `t.filter is not a function` | ✅ renders fully — posture scores, L1/L2/L3 cards, fleet snapshot (`aaasm-4892-overview-fixed.png`) |

Checked via `browser_evaluate`: `errorBoundary: false`, `mapError: false`,
`filterError: false`, main content present.

Automated: Rust `api_openapi_contract` 7/7 (incl. the new regression test),
`openapi_spec` 9/9; dashboard vitest **1501/1501**, type-check + lint clean.

## Artifacts

- `aaasm-4892-liveops-fixed.png` — Live Ops renders (app shell + content, no error).
- `aaasm-4892-overview-fixed.png` — Overview renders the full governance posture board.
