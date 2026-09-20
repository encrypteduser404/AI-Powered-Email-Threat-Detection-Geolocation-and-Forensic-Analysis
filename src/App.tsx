import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
import { AnalyzeEmail } from './pages/AnalyzeEmail'
import { Dashboard } from './pages/Dashboard'
import { Investigation } from './pages/Investigation'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<Navigate replace to="/dashboard" />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="analyze" element={<AnalyzeEmail />} />
          <Route path="investigation/:id" element={<Investigation />} />
          <Route path="reports" element={<Reports />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App