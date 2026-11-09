import { useState, useEffect } from 'react'
import ErrorBoundary from './components/ErrorBoundary'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Navbar } from './components/Navbar'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Agents from './pages/Agents'
import Alerts from './pages/Alerts'
import ThreatIntel from './pages/ThreatIntel'
import AlertRules from './pages/AlertRules'
import Users from './pages/Users'
import AuditLog from './pages/AuditLog'
import ChangePassword from './pages/ChangePassword'
import Settings from './pages/Settings'
import Search from './pages/Search'
import Detections from './pages/Detections'
import ThreatGraph from './pages/ThreatGraph'
import Locations from './pages/Locations'
import CloudPage from './pages/Cloud'
import AgentBuilder from './pages/AgentBuilder'
import LiveResponse from './pages/LiveResponse'
import DevOps from './pages/DevOps'
import NetworkProbes from './pages/NetworkProbes'
import Setup from './pages/Setup'
import Insights from './pages/Insights'

function Layout({ user, children }) {
  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)' }}>
      <Navbar user={user} />
      <div id="app-shell">
        {children}
      </div>
    </div>
  )
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
        <Route path="/alert-rules"  element={<ProtectedRoute><AlertRules /></ProtectedRoute>} />
        <Route path="/threat-intel" element={<Navigate to="/agents" replace />} />
        <Route path="/users"        element={<ProtectedRoute adminOnly><Users /></ProtectedRoute>} />
        <Route path="/audit-log"    element={<ProtectedRoute><AuditLog /></ProtectedRoute>} />
        <Route path="/settings"      element={<ProtectedRoute adminOnly><Settings /></ProtectedRoute>} />
        <Route path="/search"        element={<ProtectedRoute><Search /></ProtectedRoute>} />
        <Route path="/threat-graph" element={<Navigate to="/agents" replace />} />
        <Route path="/locations"      element={<Navigate to="/agents" replace />} />
        <Route path="/cloud"           element={<ProtectedRoute><CloudPage /></ProtectedRoute>} />
          <Route path="/detections"    element={<ProtectedRoute><Detections /></ProtectedRoute>} />
        <Route path="/agent-builder"   element={<ProtectedRoute adminOnly><AgentBuilder /></ProtectedRoute>} />
        <Route path="/live-response"    element={<ProtectedRoute adminOnly><LiveResponse /></ProtectedRoute>} />
        <Route path="/devops"             element={<ProtectedRoute><DevOps /></ProtectedRoute>} />
        <Route path="/network"            element={<ProtectedRoute><NetworkProbes /></ProtectedRoute>} />
        <Route path="/insights"           element={<ProtectedRoute><Insights /></ProtectedRoute>} />
        <Route path="*"             element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
