import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { ProtectedRoute } from './pages/ProtectedRoute'
import { LoginPage } from './pages/LoginPage'
import { ApprovalsPage } from './pages/ApprovalsPage'
import { NotFoundPage } from './pages/NotFoundPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<ApprovalsPage />} />
          <Route path="/approvals" element={<ApprovalsPage />} />
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
