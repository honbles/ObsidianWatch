import { useState, useEffect, useRef } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Bell, Activity, Zap, GitBranch, Cloud,
  Monitor, Server, Apple, Globe, Settings, Users, Key,
  ClipboardList, LogOut, Sun, Moon, ChevronDown, Radio,
  Network, BookOpen, Eye, Code2, Shield, Database, Boxes
} from 'lucide-react'
import { useTheme } from '../api/useTheme'
import api from '../api/client'

function getOSCategory(os) {
  if (!os) return 'other'
  const l = os.toLowerCase()
  if (l.includes('win')) return 'windows'
  if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') || l.includes('centos')) return 'linux'
  if (l.includes('mac') || l.includes('darwin')) return 'macos'
  if (l.includes('network-probe')) return 'network-probe'
  return 'other'
}

const OS_META = {
  windows: { label: 'Windows', icon: Monitor, color: '#60a5fa' },
  linux:   { label: 'Linux',   icon: Server,  color: '#fb923c' },
  macos:   { label: 'macOS',   icon: Apple,   color: '#a78bfa' },
  other:   { label: 'Other',   icon: Globe,   color: '#94a3b8' },
}

function OWLogo({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="nl-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#00c2e0" stopOpacity="0.4"/>
          <stop offset="100%" stopColor="#00c2e0" stopOpacity="0"/>
        </radialGradient>
        <radialGradient id="nl-lens" cx="38%" cy="35%" r="60%">
          <stop offset="0%" stopColor="#1a3a4a"/>
          <stop offset="60%" stopColor="#0a1a22"/>
          <stop offset="100%" stopColor="#040e14"/>
        </radialGradient>
        <radialGradient id="nl-pupil" cx="42%" cy="40%" r="55%">
          <stop offset="0%" stopColor="#00c2e0" stopOpacity="0.95"/>
          <stop offset="40%" stopColor="#007fa0"/>
          <stop offset="100%" stopColor="#002a38"/>
        </radialGradient>
      </defs>
      <circle cx="110" cy="110" r="95" fill="url(#nl-glow)"/>
      <polygon points="110,12 193,59 193,161 110,208 27,161 27,59" fill="#06111a" stroke="#1a3a4a" strokeWidth="1.5"/>
      <polygon points="110,22 183,65 183,155 110,198 37,155 37,65" fill="none" stroke="#00c2e0" strokeWidth="0.5" strokeOpacity="0.3"/>
      <circle cx="110" cy="108" r="62" fill="url(#nl-lens)"/>
      <circle cx="110" cy="108" r="62" fill="none" stroke="#00c2e0" strokeWidth="1.2" strokeOpacity="0.7"/>
      <circle cx="110" cy="108" r="42" fill="#0d3040"/>
      <circle cx="110" cy="108" r="22" fill="url(#nl-pupil)"/>
      <circle cx="110" cy="108" r="9" fill="#001822"/>
      <ellipse cx="96" cy="92" rx="9" ry="6" fill="white" fillOpacity="0.12" transform="rotate(-30 96 92)"/>
    </svg>
  )
}

// ── Dropdown wrapper ──────────────────────────────────────────────────────────
function NavDropdown({ label, icon: Icon, children, isActive }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div ref={ref} style={{ position: 'relative', height: '100%', display: 'flex', alignItems: 'stretch', overflow: 'visible' }}>
      <button
        className={`nav-item ${isActive ? 'active' : ''}`}
        onClick={() => setOpen(o => !o)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', height: '100%' }}
      >
        {Icon && <Icon size={13}/>}
        {label}
        <ChevronDown size={11} style={{
          transition: 'transform 0.2s',
          transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          opacity: 0.6, marginLeft: 2
        }}/>
      </button>
      {open && (
        <div className="dropdown">
          {children}
        </div>
      )}
    </div>
  )
}

// ── Dropdown item — receives navigate/closeAll as props ───────────────────────
function DDItem({ to, icon: Icon, label, color, dot, dotColor, onClick, badge, close }) {
  const navigate = useNavigate()
  const location = useLocation()
  const isActive = to ? location.pathname === to : false

  const handleClick = () => {
    if (close) close()
    if (onClick) onClick()
    else if (to) navigate(to)
  }

  return (
    <div className={`dropdown-item ${isActive ? 'active' : ''}`} onClick={handleClick}>
      {dot && (
        <span style={{
          width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
          background: dotColor || 'var(--text3)'
        }}/>
      )}
      {Icon && <Icon size={13} style={{ color: color || 'var(--text3)', flexShrink: 0 }}/>}
      <span style={{ flex: 1 }}>{label}</span>
      {badge != null && badge > 0 && (
        <span className="badge" style={{ fontSize: '8px' }}>
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </div>
  )
}

function DDSection({ label }) {
  return <div className="dropdown-section">{label}</div>
}
function DDDivider() {
  return <div className="dropdown-divider"/>
}

// ── Dropdown with close callback ──────────────────────────────────────────────
function NavDropdownWithClose({ label, icon: Icon, isActive, children }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const close = () => setOpen(false)

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div ref={ref} style={{ position: 'relative', height: '100%', display: 'flex', alignItems: 'stretch', overflow: 'visible' }}>
      <button
        className={`nav-item ${isActive ? 'active' : ''}`}
        onClick={() => setOpen(o => !o)}
        style={{ background: 'none', border: 'none', cursor: 'pointer', height: '100%' }}
      >
        {Icon && <Icon size={13}/>}
        {label}
        <ChevronDown size={11} style={{
          transition: 'transform 0.2s',
          transform: open ? 'rotate(180deg)' : 'rotate(0deg)',
          opacity: 0.6, marginLeft: 2
        }}/>
      </button>
      {open && (
        <div className="dropdown">
          {typeof children === 'function' ? children(close) : children}
        </div>
      )}
    </div>
  )
}

// ── Main Navbar ───────────────────────────────────────────────────────────────
export function Navbar({ user }) {
  const navigate = useNavigate()
  const location = useLocation()
  const { theme, toggle } = useTheme()
  const [agents, setAgents]         = useState([])
  const [connectors, setConnectors] = useState([])
  const [devopsConns, setDevopsConns] = useState([])
  const [alertCount, setAlertCount] = useState(0)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userMenuRef = useRef(null)

  useEffect(() => {
    const load = () => {
      api.get('/api/v1/agents').then(r => setAgents(r.data?.agents || [])).catch(() => {})
      api.get('/api/v1/cloud-connectors').then(r => setConnectors(r.data?.connectors || [])).catch(() => {})
      api.get('/api/v1/devops-connectors').then(r => setDevopsConns(r.data?.connectors || [])).catch(() => {})
      api.get('/api/v1/alerts', { params: { status: 'open', limit: 1 } })
        .then(r => setAlertCount(r.data?.counts?.open || 0)).catch(() => {})
    }
    load()
    const id = setInterval(load, 20000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    const handler = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) setUserMenuOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    localStorage.removeItem('require_password_change')
    navigate('/login')
  }

  const endpointAgents = agents.filter(a => getOSCategory(a.os) !== 'network-probe')
  const networkProbes  = agents.filter(a => getOSCategory(a.os) === 'network-probe')
  const byOS = endpointAgents.reduce((acc, a) => {
    const cat = getOSCategory(a.os)
    if (!acc[cat]) acc[cat] = []
    acc[cat].push(a)
    return acc
  }, {})

  const totalOnline = agents.filter(a => a.online).length
  const isPath = (...paths) => paths.some(p => location.pathname === p)

  return (
    <nav id="top-nav">
      {/* Logo */}
      <div
        onClick={() => navigate('/')}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '0 20px 0 16px', height: '100%', cursor: 'pointer',
          borderRight: '1px solid var(--border)', flexShrink: 0
        }}
      >
        <OWLogo size={26}/>
        <div style={{ lineHeight: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 13, letterSpacing: '0.01em', color: 'var(--text)' }}>
            ObsidianWatch
          </div>
          <div style={{ fontSize: 9, color: 'var(--text3)', letterSpacing: '0.12em',
                        fontFamily: 'DM Mono, monospace', textTransform: 'uppercase', marginTop: 2 }}>
            SIEM · v0.3.1
          </div>
        </div>
      </div>

      {/* Nav items */}
      <div style={{ display: 'flex', alignItems: 'stretch', flex: 1, height: '100%', overflow: 'visible' }}>

        {/* Dashboard */}
        <button
          className={`nav-item ${isPath('/') ? 'active' : ''}`}
          onClick={() => navigate('/')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', height: '100%' }}
        >
          <LayoutDashboard size={13}/>
          Dashboard
        </button>

        {/* Endpoints */}
        <NavDropdownWithClose label="Endpoints" icon={Monitor} isActive={isPath('/agents')}>
          {(close) => (
            <>
              {[
                { os: 'windows', meta: OS_META.windows },
                { os: 'linux',   meta: OS_META.linux   },
                { os: 'macos',   meta: OS_META.macos   },
              ].map(({ os, meta }) => {
                const Icon = meta.icon
                const count = byOS[os]?.length || 0
                const online = byOS[os]?.filter(a => a.online).length || 0
                return (
                  <div key={os} className="dropdown-item"
                    onClick={() => { close(); navigate(`/agents?os=${os}`) }}
                    style={{ opacity: count === 0 ? 0.45 : 1 }}>
                    <Icon size={13} style={{ color: meta.color, flexShrink: 0 }}/>
                    <span style={{ flex: 1 }}>{meta.label}</span>
                    <span style={{
                      fontFamily: 'DM Mono, monospace', fontSize: 10,
                      color: online > 0 ? 'var(--green)' : 'var(--text3)'
                    }}>
                      {count > 0 ? `${online}/${count}` : 'none'}
                    </span>
                  </div>
                )
              })}
            </>
          )}
        </NavDropdownWithClose>

        {/* Investigate */}
        <NavDropdownWithClose label="Investigate" icon={Eye} isActive={isPath('/alerts', '/events')}>
          {(close) => (
            <>
              <div className={`dropdown-item ${isPath('/alerts') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/alerts') }}>
                <Bell size={13} style={{ color: 'var(--red)' }}/>
                <span style={{ flex: 1 }}>Alerts</span>
                {alertCount > 0 && <span className="badge">{alertCount > 99 ? '99+' : alertCount}</span>}
              </div>
              <div className={`dropdown-item ${isPath('/events') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/events') }}>
                <Activity size={13} style={{ color: 'var(--accent)' }}/>
                <span style={{ flex: 1 }}>Events</span>
              </div>
            </>
          )}
        </NavDropdownWithClose>

        {/* Detection */}
        <NavDropdownWithClose label="Detection" icon={Shield} isActive={isPath('/detections', '/alert-rules')}>
          {(close) => (
            <>
              <div className={`dropdown-item ${isPath('/detections') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/detections') }}>
                <Zap size={13} style={{ color: 'var(--yellow)' }}/>
                <span>Rules</span>
              </div>
              <div className={`dropdown-item ${isPath('/alert-rules') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/alert-rules') }}>
                <BookOpen size={13} style={{ color: 'var(--text3)' }}/>
                <span>Alert Rules</span>
              </div>
            </>
          )}
        </NavDropdownWithClose>

        {/* Cloud */}
        <NavDropdownWithClose label="Cloud" icon={Cloud} isActive={isPath('/cloud')}>
          {(close) => (
            <>
              {connectors.length > 0 && (
                <>
                  <DDSection label="Accounts"/>
                  {connectors.map(conn => (
                    <div key={conn.id} className="dropdown-item"
                      onClick={() => { close(); navigate(`/cloud?provider=${conn.provider}`) }}>
                      <span style={{
                        width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                        background: conn.status === 'connected' ? 'var(--green)' : 'var(--red)'
                      }}/>
                      <span style={{ flex: 1 }}>
                        {conn.provider?.toUpperCase()} · {conn.account_label || conn.account_id || '—'}
                      </span>
                    </div>
                  ))}
                  <DDDivider/>
                </>
              )}
              <div className={`dropdown-item ${isPath('/cloud') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/cloud') }}>
                <Cloud size={13} style={{ color: 'var(--accent)' }}/>
                <span>Cloud Overview</span>
              </div>
            </>
          )}
        </NavDropdownWithClose>

        {/* Network */}
        <button
          className={`nav-item ${isPath('/network') ? 'active' : ''}`}
          onClick={() => navigate('/network')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', height: '100%' }}
        >
          <Network size={13}/>
          Network
        </button>

        {/* DevOps */}
        <NavDropdownWithClose label="DevOps" icon={GitBranch} isActive={isPath('/devops')}>
          {(close) => (
            <>
              {devopsConns.length > 0 && (
                <>
                  <DDSection label="Connectors"/>
                  {devopsConns.map(c => (
                    <div key={c.id} className="dropdown-item"
                      onClick={() => { close(); navigate('/devops') }}>
                      <span style={{
                        width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                        background: c.status === 'connected' ? 'var(--green)' : 'var(--text3)'
                      }}/>
                      <span style={{ flex: 1 }}>{c.provider} · {c.org || '—'}</span>
                    </div>
                  ))}
                  <DDDivider/>
                </>
              )}
              <div className={`dropdown-item ${isPath('/devops') ? 'active' : ''}`}
                onClick={() => { close(); navigate('/devops') }}>
                <GitBranch size={13} style={{ color: 'var(--accent)' }}/>
                <span>Connectors</span>
              </div>
              <div className="dropdown-item" onClick={() => { close(); navigate('/devops') }}>
                <Code2 size={13} style={{ color: 'var(--green)' }}/>
                <span>Code Scan</span>
              </div>
            </>
          )}
        </NavDropdownWithClose>

        {/* Application placeholder */}
        <div className="nav-item" style={{ opacity: 0.35, cursor: 'not-allowed' }} title="Coming soon">
          <Boxes size={13}/>
          Application
        </div>

        {/* Settings */}
        {user?.role === 'admin' && (
          <NavDropdownWithClose label="Settings" icon={Settings}
            isActive={isPath('/settings', '/users', '/audit-log', '/agent-builder')}>
            {(close) => (
              <>
                <div className={`dropdown-item ${isPath('/agent-builder') ? 'active' : ''}`}
                  onClick={() => { close(); navigate('/agent-builder') }}>
                  <Key size={13} style={{ color: 'var(--accent)' }}/>
                  <span>Agent Builder</span>
                </div>
                <DDDivider/>
                <div className={`dropdown-item ${isPath('/users') ? 'active' : ''}`}
                  onClick={() => { close(); navigate('/users') }}>
                  <Users size={13} style={{ color: 'var(--text2)' }}/>
                  <span>Users & Access</span>
                </div>
                <div className={`dropdown-item ${isPath('/audit-log') ? 'active' : ''}`}
                  onClick={() => { close(); navigate('/audit-log') }}>
                  <ClipboardList size={13} style={{ color: 'var(--text2)' }}/>
                  <span>Audit Log</span>
                </div>
                <div className={`dropdown-item ${isPath('/settings') ? 'active' : ''}`}
                  onClick={() => { close(); navigate('/settings') }}>
                  <Settings size={13} style={{ color: 'var(--text2)' }}/>
                  <span>Platform Settings</span>
                </div>
              </>
            )}
          </NavDropdownWithClose>
        )}
      </div>

      {/* Right side */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0 14px',
                    borderLeft: '1px solid var(--border)', flexShrink: 0, height: '100%' }}>

        {/* Online count */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, padding: '0 8px',
                      fontSize: 11, color: 'var(--text2)' }}>
          <span className="pulse" style={{
            width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
            background: totalOnline > 0 ? 'var(--green)' : 'var(--text3)'
          }}/>
          <span style={{ fontFamily: 'DM Mono, monospace' }}>{totalOnline}</span>
          <span style={{ color: 'var(--text3)' }}>online</span>
        </div>

        {/* Theme toggle */}
        <button onClick={toggle} style={{
          width: 32, height: 32, borderRadius: 8, border: '1px solid var(--border)',
          background: 'transparent', color: 'var(--text2)', cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center'
        }}>
          {theme === 'dark' ? <Sun size={13} style={{ color: '#fbbf24' }}/> : <Moon size={13}/>}
        </button>

        {/* Alert bell */}
        <button onClick={() => navigate('/alerts')} style={{
          width: 32, height: 32, borderRadius: 8, border: '1px solid var(--border)',
          background: 'transparent', cursor: 'pointer', position: 'relative',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: alertCount > 0 ? 'var(--red)' : 'var(--text2)'
        }}>
          <Bell size={13}/>
          {alertCount > 0 && (
            <span className="badge" style={{
              position: 'absolute', top: -4, right: -4,
              minWidth: 15, height: 15, fontSize: '8px', padding: '0 3px'
            }}>
              {alertCount > 9 ? '9+' : alertCount}
            </span>
          )}
        </button>

        {/* User menu */}
        <div ref={userMenuRef} style={{ position: 'relative' }}>
          <button onClick={() => setUserMenuOpen(o => !o)} style={{
            display: 'flex', alignItems: 'center', gap: 7, padding: '4px 8px 4px 4px',
            borderRadius: 8, border: '1px solid var(--border)', background: 'transparent',
            cursor: 'pointer', height: 32
          }}>
            <div style={{
              width: 22, height: 22, borderRadius: 6, flexShrink: 0,
              background: 'linear-gradient(135deg, var(--accent2), var(--accent))',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontWeight: 700, color: '#000'
            }}>
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            <span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text)' }}>
              {user?.username}
            </span>
            <ChevronDown size={10} style={{ opacity: 0.5 }}/>
          </button>
          {userMenuOpen && (
            <div className="dropdown" style={{ right: 0, left: 'auto', minWidth: 160 }}>
              <div style={{ padding: '8px 10px 6px', borderBottom: '1px solid var(--border)', marginBottom: 4 }}>
                <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text)' }}>{user?.username}</div>
                <div style={{ fontSize: 10, color: 'var(--text3)', textTransform: 'capitalize', marginTop: 2 }}>
                  {user?.role}
                </div>
              </div>
              <div className="dropdown-item" onClick={toggle}>
                {theme === 'dark' ? <><Sun size={12} style={{ color: '#fbbf24' }}/> Light Mode</> : <><Moon size={12}/> Dark Mode</>}
              </div>
              <DDDivider/>
              <div className="dropdown-item" onClick={logout} style={{ color: 'var(--red)' }}>
                <LogOut size={12}/> Sign out
              </div>
            </div>
          )}
        </div>
      </div>
    </nav>
  )
}
