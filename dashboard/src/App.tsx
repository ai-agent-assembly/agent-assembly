import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ProtectedRoute } from './pages/ProtectedRoute'
import { AppShell } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'
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
import { OnboardingPage } from './pages/OnboardingPage'
import { ComingSoon } from './pages/ComingSoon'
import { IdentityPage } from './pages/IdentityPage'
import { TeamDetailPage } from './pages/TeamDetailPage'
import { TeamsPage } from './pages/TeamsPage'
import { ViolationHeatmapPage } from './pages/ViolationHeatmapPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppShell />}>
            {/* Landing — keeps the working approvals queue at root for now. */}
            <Route path="/" element={<ApprovalsPage />} />

            {/* ── Canonical 12 routes (AAASM-94 AC #5, #6) ──────────────── */}
            {/* monitor */}
            <Route path="/overview" element={<ComingSoon name="Overview" />} />
            <Route path="/agents" element={<FleetPage />}>
              {/* Agent Detail drawer overlays the Fleet page so filter state stays mounted. */}
              <Route path=":id" element={<AgentDetailPage />} />
            </Route>
            <Route path="/topology" element={<TopologyPage />} />
            <Route path="/live" element={<LiveOpsPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/audit" element={<ComingSoon name="Audit Log" />} />
            <Route path="/audit/violations" element={<ViolationHeatmapPage />} />
            {/* control */}
            <Route path="/capability" element={<CapabilityPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/scrub" element={<ScrubPage />} />
            {/* manage */}
            <Route path="/costs" element={<ComingSoon name="Cost & Budget" />} />
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
          </Route>
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
