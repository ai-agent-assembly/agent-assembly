import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ProtectedRoute } from './pages/ProtectedRoute'
import { AppShell } from './components/AppShell'
import { LoginPage } from './pages/LoginPage'
import { AgentsPage } from './pages/AgentsPage'
import { AgentDetailPage } from './pages/AgentDetailPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { NotFoundPage } from './pages/NotFoundPage'
import { PoliciesPage } from './pages/PoliciesPage'
import { PolicyEditorPage } from './pages/PolicyEditorPage'
import { AnalyticsPage } from './pages/AnalyticsPage'
import { AlertsPage } from './pages/AlertsPage'
import { ComingSoon } from './pages/ComingSoon'
import { TeamDetailPage } from './pages/TeamDetailPage'

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
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/topology" element={<ComingSoon name="Topology" />} />
            <Route path="/live" element={<ComingSoon name="Live Ops" />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/audit" element={<ComingSoon name="Audit Log" />} />
            {/* control */}
            <Route path="/capability" element={<ComingSoon name="Capability" />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/scrub" element={<ComingSoon name="Secret Scrubbing" />} />
            {/* manage */}
            <Route path="/costs" element={<ComingSoon name="Cost & Budget" />} />
            <Route path="/teams" element={<ComingSoon name="Agent Groups" />} />
            <Route path="/identity" element={<ComingSoon name="Members & Access" />} />

            {/* ── Sub-routes for canonical pages ────────────────────────── */}
            <Route path="/agents/:id" element={<AgentDetailPage />} />
            <Route path="/policies/editor" element={<PolicyEditorPage />} />
            <Route path="/teams/:teamId" element={<TeamDetailPage />} />

            {/* ── Non-canonical pages (kept for working features) ───────── */}
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/analytics" element={<AnalyticsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
