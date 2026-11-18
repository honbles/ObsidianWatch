import { useState, useEffect, useRef, useMemo } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Bell, Activity, Zap, GitBranch, Cloud, Monitor, Network, BookOpen,
  Shield, Boxes, Crosshair, Search, Settings, Users, Key, ClipboardList, Terminal,
  LogOut, Sun, Moon, ChevronDown, ChevronRight, PanelLeftClose, PanelLeftOpen, Eye,
} from 'lucide-react'
import { useTheme } from '../api/useTheme'
import api from '../api/client'
import { useDragSize } from '../hooks/useDragSize'

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

function osCategory(os) {
  const l = (os || '').toLowerCase()
  if (l.includes('network-probe')) return 'probe'
  if (l.includes('win')) return 'windows'
  if (l.includes('mac') || l.includes('darwin')) return 'macos'
  if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') || l.includes('centos')) return 'linux'
  return 'other'
}

// One data-driven definition drives the sidebar, the active state and the breadcrumb.
// `to` may carry a query string; an item is active when its path matches (and its query, if it has one).
function buildNav({ counts, alertCount, isAdmin }) {
  const osLabel = (k) => counts[k] ? `${counts[k].online}/${counts[k].total}` : null
  const main = [
    { section: 'Overview' },
    { id: 'dash', label: 'Dashboard', icon: LayoutDashboard, to: '/' },
    { section: 'Monitor' },
    { id: 'alerts', label: 'Alerts', icon: Bell, to: '/alerts', badge: alertCount },
    { id: 'events', label: 'Events', icon: Activity, to: '/events' },
    { id: 'search', label: 'Search', icon: Search, to: '/search' },
    { id: 'endpoints', label: 'Endpoints', icon: Monitor, children: [
      { label: 'All endpoints', to: '/agents' },
      { label: 'Windows', to: '/agents?os=windows', meta: osLabel('windows') },
      { label: 'Linux',   to: '/agents?os=linux',   meta: osLabel('linux') },
      { label: 'macOS',   to: '/agents?os=macos',   meta: osLabel('macos') },
    ] },
    { id: 'network', label: 'Network', icon: Network, to: '/network' },
    { section: 'Detect and hunt' },
    { id: 'detect', label: 'Detection', icon: Shield, children: [
      { label: 'Rules', to: '/detections' },
      { label: 'Alert rules', to: '/alert-rules' },
    ] },
    { id: 'hunt', label: 'Threat hunting', icon: Crosshair, to: '/hunt' },
    { id: 'insights', label: 'Insights', icon: Eye, to: '/insights' },
    { section: 'Platforms' },
    { id: 'cloud', label: 'Cloud', icon: Cloud, to: '/cloud' },
    { id: 'apps', label: 'Applications', icon: Boxes, children: [
      { label: 'Overview', to: '/applications' },
      { label: 'Services', to: '/applications/services' },
      { label: 'Dependencies', to: '/applications/map' },
      { label: 'Coverage', to: '/applications/coverage' },
      { label: 'Settings', to: '/applications/settings' },
    ] },
    { id: 'devops', label: 'DevOps', icon: GitBranch, to: '/devops' },
  ]
  const admin = isAdmin ? [
    { id: 'builder', label: 'Agent builder', icon: Key, to: '/agent-builder' },
    { id: 'live', label: 'Live response', icon: Terminal, to: '/live-response' },
    { id: 'users', label: 'Users and access', icon: Users, to: '/users' },
    { id: 'audit', label: 'Audit log', icon: ClipboardList, to: '/audit-log' },
    { id: 'settings', label: 'Platform settings', icon: Settings, to: '/settings' },
  ] : []
  return { main, admin }
}

function splitTo(to) { const [p, q] = to.split('?'); return { path: p, query: q || '' } }

function matches(loc, to) {
  const { path, query } = splitTo(to)
  if (path === '/') return loc.pathname === '/'
  if (query) return loc.pathname === path && loc.search.replace(/^\?/, '').includes(query)
  // a plain item is active on its own path and on sub-paths, unless a sibling with a query owns the URL
  return loc.pathname === path || (path !== '/agents' && loc.pathname.startsWith(path + '/'))
}
function childActive(loc, c, siblings) {
  const { path, query } = splitTo(c.to)
  if (query) return matches(loc, c.to)
  if (loc.pathname !== path && !loc.pathname.startsWith(path + '/')) return false
  // "All endpoints" is active only when no sibling's query is selected
  return !siblings.some(s => s !== c && splitTo(s.to).query && matches(loc, s.to))
}

function Badge({ n }) {
  if (!n) return null
  return <span className="sb-badge">{n > 99 ? '99+' : n}</span>
}

function Item({ it, loc, nav, collapsed, openIds, toggle }) {
  const Icon = it.icon
  if (!it.children) {
    const active = matches(loc, it.to)
    return (
      <div className={`sb-item ${active ? 'active' : ''}`} onClick={() => nav(it.to)} title={collapsed ? it.label : undefined}>
        <Icon size={15}/>
        {!collapsed && <span className="sb-label">{it.label}</span>}
        {!collapsed && <Badge n={it.badge}/>}
        {collapsed && it.badge > 0 && <span className="sb-dot"/>}
      </div>
    )
  }
  const anyActive = it.children.some(c => childActive(loc, c, it.children))
  const open = openIds.has(it.id) || (anyActive && !collapsed)
  return (
    <div>
      <div className={`sb-item ${anyActive ? 'active-parent' : ''}`}
        onClick={() => collapsed ? nav(it.children[0].to) : toggle(it.id)}
        title={collapsed ? it.label : undefined}>
        <Icon size={15}/>
        {!collapsed && <span className="sb-label">{it.label}</span>}
        {!collapsed && (open ? <ChevronDown size={12} className="sb-chev"/> : <ChevronRight size={12} className="sb-chev"/>)}
      </div>
      {!collapsed && open && (
        <div className="sb-children">
          {it.children.map(c => (
            <div key={c.to} className={`sb-child ${childActive(loc, c, it.children) ? 'active' : ''}`} onClick={() => nav(c.to)}>
              <span className="sb-label">{c.label}</span>
              {c.meta && <span className="sb-meta">{c.meta}</span>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function Shell({ user, children }) {
  const navigate = useNavigate()
  const loc = useLocation()
  const { theme, toggle } = useTheme()
  const [agents, setAgents] = useState([])
  const [alertCount, setAlertCount] = useState(0)
  const [userMenu, setUserMenu] = useState(false)
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('ow_sb_collapsed') === '1' } catch { return false } })
  const [openIds, setOpenIds] = useState(() => new Set())
  const menuRef = useRef(null)
  const [sbw, sbHandle] = useDragSize('sidebar', 212, 160, 360, 'x')

  useEffect(() => {
    const load = () => {
      api.get('/api/v1/agents').then(r => setAgents(r.data?.agents || [])).catch(() => {})
      api.get('/api/v1/alerts', { params: { status: 'open', limit: 1 } })
        .then(r => setAlertCount(r.data?.counts?.open || 0)).catch(() => {})
    }
    load()
    const id = setInterval(load, 20000)
    return () => clearInterval(id)
  }, [])
  useEffect(() => {
    const h = (e) => { if (menuRef.current && !menuRef.current.contains(e.target)) setUserMenu(false) }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [])
  useEffect(() => { try { localStorage.setItem('ow_sb_collapsed', collapsed ? '1' : '0') } catch { /* */ } }, [collapsed])

  const counts = useMemo(() => {
    const c = {}
    for (const a of agents) {
      const k = osCategory(a.os); if (k === 'probe') continue
      c[k] = c[k] || { total: 0, online: 0 }
      c[k].total++; if (a.online) c[k].online++
    }
    return c
  }, [agents])
  const totalOnline = agents.filter(a => a.online).length
  const { main, admin } = useMemo(() => buildNav({ counts, alertCount, isAdmin: user?.role === 'admin' }), [counts, alertCount, user])

  // breadcrumb = section heading + the active item
  const crumb = useMemo(() => {
    let section = ''
    for (const it of [...main, ...admin.map(x => ({ ...x, _admin: true }))]) {
      if (it.section) { section = it.section; continue }
      const hit = it.children ? it.children.find(c => childActive(loc, c, it.children)) : (matches(loc, it.to) ? it : null)
      if (hit) return [it._admin ? 'Administration' : section, it.children ? `${it.label}` : null, it.children ? hit.label : it.label].filter(Boolean)
    }
    return []
  }, [loc, main, admin])

  const go = (to) => navigate(to)
  const toggleGroup = (id) => setOpenIds(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })
  const logout = () => {
    ['token', 'user', 'require_password_change'].forEach(k => localStorage.removeItem(k))
    navigate('/login')
  }

  return (
    <div className={`shell ${collapsed ? 'collapsed' : ''}`} style={{ '--sb-w': sbw + 'px' }}>
      <aside className="sidebar">
        <div className="sb-brand" onClick={() => go('/')}>
          <OWLogo size={26}/>
          {!collapsed && (
            <div style={{ lineHeight: 1 }}>
              <div style={{ fontWeight: 700, fontSize: 13, color: '#fff' }}>ObsidianWatch</div>
              <div style={{ fontSize: 9, letterSpacing: '0.12em', fontFamily: 'DM Mono, monospace', textTransform: 'uppercase', marginTop: 3, color: 'var(--nav-text)' }}>SIEM · v0.3.1</div>
            </div>
          )}
        </div>
        <div className="sb-scroll">
          {main.map((it, i) => it.section
            ? (collapsed ? <div key={i} className="sb-rule"/> : <div key={i} className="sb-section">{it.section}</div>)
            : <Item key={it.id} it={it} loc={loc} nav={go} collapsed={collapsed} openIds={openIds} toggle={toggleGroup}/>)}
        </div>
        {admin.length > 0 && (
          <div className="sb-foot">
            {collapsed ? <div className="sb-rule"/> : <div className="sb-section">Administration</div>}
            {admin.map(it => <Item key={it.id} it={it} loc={loc} nav={go} collapsed={collapsed} openIds={openIds} toggle={toggleGroup}/>)}
          </div>
        )}
        {!collapsed && <div {...sbHandle}/>}
      </aside>

      <div className="shell-main">
        <header className="topbar">
          <button className="tb-btn" onClick={() => setCollapsed(c => !c)} title={collapsed ? 'Expand menu' : 'Collapse menu'}>
            {collapsed ? <PanelLeftOpen size={15}/> : <PanelLeftClose size={15}/>}
          </button>
          <div className="crumb">
            {crumb.map((c, i) => (
              <span key={i} className={i === crumb.length - 1 ? 'crumb-last' : ''}>{i > 0 && <span className="crumb-sep">/</span>}{c}</span>
            ))}
          </div>
          <div style={{ flex: 1 }}/>
          <div className="tb-stat" title="Agents online">
            <span className="pulse" style={{ width: 6, height: 6, borderRadius: '50%', background: totalOnline > 0 ? 'var(--green)' : 'var(--text3)' }}/>
            <span style={{ fontFamily: 'DM Mono, monospace' }}>{totalOnline}</span><span style={{ color: 'var(--text3)' }}>online</span>
          </div>
          <button className="tb-btn" onClick={toggle} title="Toggle theme">
            {theme === 'dark' ? <Sun size={14} style={{ color: '#fbbf24' }}/> : <Moon size={14}/>}
          </button>
          <button className="tb-btn" onClick={() => go('/alerts')} title="Open alerts" style={{ position: 'relative', color: alertCount > 0 ? 'var(--red)' : undefined }}>
            <Bell size={14}/>
            {alertCount > 0 && <span className="badge" style={{ position: 'absolute', top: -5, right: -5, minWidth: 15, height: 15, fontSize: 8, padding: '0 3px' }}>{alertCount > 9 ? '9+' : alertCount}</span>}
          </button>
          <div ref={menuRef} style={{ position: 'relative' }}>
            <button className="tb-user" onClick={() => setUserMenu(o => !o)}>
              <span className="tb-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</span>
              <span style={{ fontSize: 12, fontWeight: 500 }}>{user?.username}</span>
              <ChevronDown size={10} style={{ opacity: 0.5 }}/>
            </button>
            {userMenu && (
              <div className="dropdown" style={{ right: 0, left: 'auto', top: 'calc(100% + 4px)', minWidth: 170 }}>
                <div style={{ padding: '6px 10px 6px', borderBottom: '1px solid var(--border)', marginBottom: 4 }}>
                  <div style={{ fontSize: 12, fontWeight: 600 }}>{user?.username}</div>
                  <div style={{ fontSize: 10, color: 'var(--text3)', textTransform: 'capitalize' }}>{user?.role}</div>
                </div>
                <div className="dropdown-item" onClick={logout} style={{ color: 'var(--red)' }}><LogOut size={12}/> Sign out</div>
              </div>
            )}
          </div>
        </header>
        <div id="app-shell">{children}</div>
      </div>
    </div>
  )
}
