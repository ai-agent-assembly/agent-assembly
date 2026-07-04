# AAASM-4080 — Dashboard domain TLD fix, Front-End validation

**Bug**: [AAASM-4080](https://lightning-dust-mite.atlassian.net/browse/AAASM-4080) — dashboard hardcoded dead `agent-assembly.io` links; canonical is `.com` per ADR-0007.
**Epic**: [AAASM-4068](https://lightning-dust-mite.atlassian.net/browse/AAASM-4068) (2026-07-04 security + QA sweep fix wave)
**PR**: ai-agent-assembly/agent-assembly#1401
**Validated**: 2026-07-04, branch `v0.0.1/AAASM-4080/fix/dashboard_domain_tld`
**Method**: live Playwright drive of the built dashboard (vite dev + Prism OpenAPI mock backend on `127.0.0.1:8080`), logged in through the real API-key form.

## Change under test

Four user-facing hardcoded URLs retargeted `agent-assembly.io` → `agent-assembly.com`:

| File | Link |
|---|---|
| `src/features/alerts/EmptyStateNoAlerts.tsx` | `https://docs.agent-assembly.com/dashboard/alerts` |
| `src/pages/FleetPage.tsx` | `https://docs.agent-assembly.com/quickstart` |
| `src/features/onboarding/steps/Step2InstallSdk.tsx` | `https://api.agent-assembly.com` |
| `src/components/ErrorState.tsx` | `status.agent-assembly.com` |

## Evidence

| Check | Result |
|---|---|
| `pnpm type-check` (CI) | ✅ pass (0 errors) |
| `pnpm lint` (CI) | ✅ pass (0 warnings) |
| `grep -rn "agent-assembly\.io" dashboard/src` | ✅ empty (0 occurrences) |
| Live render — `/alerts` empty-state "Read the alerts docs →" anchor `href` | ✅ `https://docs.agent-assembly.com/dashboard/alerts` |
| Live render — any `agent-assembly.io` anchor on the alerts page | ✅ none (`anyDotIoLeft: false`) |
| Dashboard shell / routing / login | ✅ renders + navigates without crash (full 12-route walk done in the originating session) |

Live DOM assertion (Playwright `page.evaluate`):

```json
{
  "alertsDocsHref": "https://docs.agent-assembly.com/dashboard/alerts",
  "allAgentAssemblyLinksOnPage": ["https://docs.agent-assembly.com/dashboard/alerts"],
  "anyDotIoLeft": false
}
```

Screenshot captured during the session: `AAASM-4080-alerts-docs-link-dotcom.png` (alerts empty-state rendering the corrected `.com` docs link).

## Verdict

✅ Front-End behaves correctly. The link-target change is purely a URL string fix with no visual or behavioral delta; the alerts empty-state renders and its docs link now resolves to the canonical `docs.agent-assembly.com` host. No regression to dashboard rendering, routing, or the alerts view.
