import { BrowserRouter, Routes, Route, Navigate } from 'react-router'
import { ProtectedRoute } from './pages/ProtectedRoute'
import { AppShell } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'
import { ForgotPasswordPage } from './pages/ForgotPasswordPage'
import { FleetPage } from './pages/FleetPage'
import { AgentDetailPage } from './pages/AgentDetailPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { NotFoundPage } from './pages/NotFoundPage'
import { PoliciesPage } from './pages/PoliciesPage'
import { AnalyticsPage } from './pages/AnalyticsPage'
import { AlertsPage } from './pages/AlertsPage'
import { CapabilityPage } from './pages/CapabilityPage'
import { TraceViewPage } from './pages/TraceViewPage'
import { TopologyPage } from './pages/TopologyPage'
import { LiveOpsPage } from './pages/LiveOpsPage'
import { ScrubPage } from './pages/ScrubPage'
import { SensitiveDataPage } from './pages/SensitiveDataPage'
import { OnboardingPage } from './pages/OnboardingPage'
import { IdentityPage } from './pages/IdentityPage'
import { TeamDetailPage } from './pages/TeamDetailPage'
import { TeamsPage } from './pages/TeamsPage'
import { CostsPage } from './pages/CostsPage'
import { ViolationHeatmapPage } from './pages/ViolationHeatmapPage'
import { AuditLogPage } from './pages/AuditLogPage'
import { OverviewPage } from './pages/OverviewPage'
import {
  SettingsLayout,
  SettingsGeneralPlaceholder,
  SettingsApiKeysPlaceholder,
} from './pages/Settings'
import { RetentionPolicyPage } from './pages/Settings/RetentionPolicy'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppShell />}>
            {/* Landing — Overview per AAASM-5144 (mock: index.html route init + onboarding finish). */}
            <Route path="/" element={<Navigate to="/overview" replace />} />

            {/* ── Canonical 12 routes (AAASM-94 AC #5, #6) ──────────────── */}
            {/* monitor */}
            <Route path="/overview" element={<OverviewPage />} />
            <Route path="/agents" element={<FleetPage />}>
              {/* Agent Detail drawer overlays the Fleet page so filter state stays mounted. */}
              <Route path=":id" element={<AgentDetailPage />} />
            </Route>
            <Route path="/topology" element={<TopologyPage />} />
            <Route path="/live" element={<LiveOpsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/audit" element={<AuditLogPage />} />
            <Route path="/audit/violations" element={<ViolationHeatmapPage />} />
            {/* control */}
            <Route path="/capability" element={<CapabilityPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/scrub" element={<ScrubPage />} />
            <Route path="/sensitive-data" element={<SensitiveDataPage />} />
            {/* manage */}
            <Route path="/costs" element={<CostsPage />} />
            <Route path="/teams" element={<TeamsPage />} />
            <Route path="/identity" element={<IdentityPage />} />

            {/* ── Sub-routes for canonical pages ────────────────────────── */}
            <Route path="/agents/:id/trace/:sessionId" element={<TraceViewPage />} />
            <Route path="/teams/:teamId" element={<TeamDetailPage />} />

            {/* ── Non-canonical pages (kept for working features) ───────── */}
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />

            {/* ── First-run onboarding wizard (AAASM-1351) ────────────────── */}
            <Route path="/onboarding" element={<OnboardingPage />} />

            {/* ── Settings — AAASM-1592 S-K ─────────────────────────────── */}
            <Route path="/settings" element={<SettingsLayout />}>
              <Route index element={<SettingsGeneralPlaceholder />} />
              <Route path="general" element={<SettingsGeneralPlaceholder />} />
              <Route path="api-keys" element={<SettingsApiKeysPlaceholder />} />
              <Route path="storage/retention" element={<RetentionPolicyPage />} />
            </Route>
          </Route>
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
