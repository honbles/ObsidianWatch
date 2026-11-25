import { useState, useEffect } from 'react'
import ErrorBoundary from './components/ErrorBoundary'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Shell } from './components/Shell'
import Prevention from './pages/Prevention'
import Hunt from './pages/Hunt'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Agents from './pages/Agents'
import Alerts from './pages/Alerts'
import ThreatIntel from './pages/ThreatIntel'
import AlertRules from './pages/AlertRules'
import Users from './pages/Users'
import AuditLog from './pages/AuditLog'
import Suppressions from './pages/Suppressions'
import ChangePassword from './pages/ChangePassword'
import Settings from './pages/Settings'
import Search from './pages/Search'
import Detections from './pages/Detections'
import ThreatGraph from './pages/ThreatGraph'
import Locations from './pages/Locations'
import CloudPage from './pages/Cloud'
import AgentBuilder from './pages/AgentBuilder'
import Response from './pages/Response'
import DevOps from './pages/DevOps'
import AlertPage from './pages/AlertPage'
import RepoPage from './pages/code/RepoPage'
import FindingPage from './pages/code/FindingPage'
import CloudFindingPage from './pages/cloud/FindingPage'
import NetworkProbes from './pages/NetworkProbes'
import Setup from './pages/Setup'
import Insights from './pages/Insights'

function Layout({ user, children }) {
  return <Shell user={user}>{children}</Shell>
}

export default function App() {
  const [user, setUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem('user')) } catch { return null }
  })
  const [requirePasswordChange, setRequirePasswordChange] = useState(() => {
    return localStorage.getItem('require_password_change') === 'true'
  })

  const handleLogin = (u, requireChange) => {
    setUser(u)
    setRequirePasswordChange(!!requireChange)
    if (requireChange) localStorage.setItem('require_password_change', 'true')
  }

  const handlePasswordChanged = () => {
    setRequirePasswordChange(false)
    localStorage.removeItem('require_password_change')
  }

  const ProtectedRoute = ({ children, adminOnly = false }) => {
    if (!user || !localStorage.getItem('token')) return <Navigate to="/login" replace />
    if (requirePasswordChange) return <Navigate to="/change-password" replace />
    if (adminOnly && user.role !== 'admin') return <Navigate to="/" replace />
    return <Layout user={user}><ErrorBoundary>{children}</ErrorBoundary></Layout>
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="/login" element={
          user ? <Navigate to="/" replace /> : <Login onLogin={handleLogin} />
        } />
        <Route path="/change-password" element={
          !user ? <Navigate to="/login" replace /> :
          <Layout user={user}><ChangePassword onChanged={handlePasswordChanged} /></Layout>
        } />
        <Route path="/"             element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
        <Route path="/events"       element={<ProtectedRoute><Events /></ProtectedRoute>} />
        <Route path="/agents"       element={<ProtectedRoute><Agents /></ProtectedRoute>} />
        <Route path="/alerts"       element={<ProtectedRoute><Alerts /></ProtectedRoute>} />
        <Route path="/alerts/:id"          element={<ProtectedRoute><AlertPage /></ProtectedRoute>} />
        <Route path="/alert-rules"  element={<ProtectedRoute><AlertRules /></ProtectedRoute>} />
        <Route path="/threat-intel" element={<Navigate to="/agents" replace />} />
        <Route path="/users"        element={<ProtectedRoute adminOnly><Users /></ProtectedRoute>} />
        <Route path="/audit-log"    element={<ProtectedRoute><AuditLog /></ProtectedRoute>} />
        <Route path="/suppressions" element={<ProtectedRoute><Suppressions /></ProtectedRoute>} />
        <Route path="/settings"      element={<ProtectedRoute adminOnly><Settings /></ProtectedRoute>} />
        <Route path="/search"        element={<ProtectedRoute><Search /></ProtectedRoute>} />
        <Route path="/threat-graph" element={<Navigate to="/agents" replace />} />
        <Route path="/locations"      element={<Navigate to="/agents" replace />} />
        <Route path="/cloud"           element={<ProtectedRoute><CloudPage /></ProtectedRoute>} />
        <Route path="/cloud/findings/:connector/:id" element={<ProtectedRoute><CloudFindingPage /></ProtectedRoute>} />
          <Route path="/detections"    element={<ProtectedRoute><Detections /></ProtectedRoute>} />
        <Route path="/agent-builder"   element={<ProtectedRoute adminOnly><AgentBuilder /></ProtectedRoute>} />
        <Route path="/response"         element={<ProtectedRoute><Response /></ProtectedRoute>} />
        <Route path="/live-response"    element={<Navigate to="/response?tab=live" replace />} />
        <Route path="/devops"             element={<ProtectedRoute><DevOps /></ProtectedRoute>} />
        <Route path="/devops/repos/:connector/:repo" element={<ProtectedRoute><RepoPage /></ProtectedRoute>} />
        <Route path="/devops/findings/:fid" element={<ProtectedRoute><FindingPage /></ProtectedRoute>} />
        <Route path="/network"            element={<ProtectedRoute><NetworkProbes /></ProtectedRoute>} />
        {/* [NET-ROUTES-BEGIN] - Network build adds /network/* routes here */}
        {/* [NET-ROUTES-END] */}
        {/* [APP-ROUTES-BEGIN] - Application build adds /applications/* routes here */}
        {/* Every pages/app/*.route.jsx exports `default` (the page) and `appPath` (its route); import.meta.glob avoids edits outside this block. */}
        {Object.entries(import.meta.glob('./pages/app/*.route.jsx', { eager: true })).map(([file, mod]) => {
          const AppPage = mod.default
          return <Route key={file} path={mod.appPath} element={<ProtectedRoute><AppPage /></ProtectedRoute>} />
        })}
        {/* [APP-ROUTES-END] */}
        <Route path="/hunt"               element={<ProtectedRoute><Hunt /></ProtectedRoute>} />
        <Route path="/prevention"         element={<ProtectedRoute><Prevention /></ProtectedRoute>} />
        <Route path="/insights"           element={<ProtectedRoute><Insights /></ProtectedRoute>} />
        <Route path="*"             element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
