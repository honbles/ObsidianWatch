import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  LayoutDashboard, Bell, Activity, GitBranch, Cloud, Monitor, Network, Shield, Boxes, Crosshair, Search,
  Settings, Users, Key, ClipboardList, Terminal, LogOut, Sun, Moon, ChevronDown, PanelLeftClose, PanelLeftOpen,
  Eye, Share2, Gauge, ShieldCheck, SlidersHorizontal, BellOff, ListChecks, CornerDownLeft, Server, FileSearch,
} from 'lucide-react'
import { useTheme } from '../api/useTheme'
import api from '../api/client'
import { appApi, appSplitKey } from '../api/app'
import { useDragSize } from '../hooks/useDragSize'
import { useTimeRange, RANGE_PRESETS } from './shared/useTimeRange'

export function OWMark({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 22 22" aria-hidden="true">
      <path d="M11 1.5 20 6.5v9L11 20.5 2 15.5v-9z" fill="none" stroke="var(--acc)" strokeWidth="1.8" strokeLinejoin="round"/>
      <circle cx="11" cy="11" r="3" fill="var(--acc)"/>
    </svg>
  )
}

// The rail is grouped by domain. Endpoint, Application, Code and Cloud are the four places.
// Hunt, prevention and response work on endpoints only today, so they sit under Endpoint;
// alerts, search and rules cut across all four and get their own group.
function buildNav({ alertCount, isAdmin }) {
  const main = [
    { id: 'dash', label: 'Overview', icon: LayoutDashboard, to: '/' },
    { section: 'Endpoint' },
    { id: 'fleet', label: 'Fleet', icon: Monitor, to: '/agents' },
    { id: 'hunt', label: 'Hunt', icon: Crosshair, to: '/hunt' },
    { id: 'prevention', label: 'Prevention', icon: ShieldCheck, to: '/prevention' },
    { id: 'response', label: 'Response', icon: Terminal, to: '/response' },
    { section: 'Application' },
    { id: 'app-overview', label: 'Overview', icon: Gauge, to: '/applications', exact: true },
    { id: 'app-services', label: 'Services', icon: Boxes, to: '/applications/services' },
    { id: 'app-map', label: 'Dependencies', icon: Share2, to: '/applications/map' },
    { id: 'app-coverage', label: 'Coverage', icon: ListChecks, to: '/applications/coverage' },
    { id: 'app-settings', label: 'Settings', icon: SlidersHorizontal, to: '/applications/settings' },
    { section: 'Code' },
    { id: 'repos', label: 'Repositories', icon: GitBranch, to: '/devops' },
    { section: 'Cloud' },
    { id: 'cloud', label: 'Posture', icon: Cloud, to: '/cloud' },
    { section: 'Detect' },
    { id: 'alerts', label: 'Alerts', icon: Bell, to: '/alerts', badge: alertCount },
    { id: 'search', label: 'Search', icon: FileSearch, to: '/search' },
    { id: 'events', label: 'Events', icon: Activity, to: '/events' },
    { id: 'insights', label: 'Insights', icon: Eye, to: '/insights' },
    { id: 'rules', label: 'Rules', icon: Shield, to: '/detections' },
    { id: 'alert-rules', label: 'Alert rules', icon: ListChecks, to: '/alert-rules' },
    { id: 'suppressions', label: 'Suppressions', icon: BellOff, to: '/suppressions' },
    { section: 'Network' },
    { id: 'network', label: 'Probes', icon: Network, to: '/network', tag: 'beta' },
  ]
  const admin = isAdmin ? [
    { section: 'Administration' },
    { id: 'builder', label: 'Agent builder', icon: Key, to: '/agent-builder' },
    { id: 'users', label: 'Users and access', icon: Users, to: '/users' },
    { id: 'audit', label: 'Audit log', icon: ClipboardList, to: '/audit-log' },
    { id: 'settings', label: 'Platform settings', icon: Settings, to: '/settings' },
  ] : []
  return { main, admin }
}

function isActive(loc, it) {
  if (it.to === '/' || it.exact) return loc.pathname === it.to
  return loc.pathname === it.to || loc.pathname.startsWith(it.to + '/')
}

// Pages that read the shared ?from=&to= range. The context-bar range control only appears on these,
// so it never looks as if it filters a page that ignores it.
const RANGE_AWARE = ['/applications']
const rangeAware = (path) => RANGE_AWARE.some(p => path === p || path.startsWith(p + '/'))

function NavItem({ it, loc, collapsed }) {
  const Icon = it.icon
  const active = isActive(loc, it)
  return (
    <Link to={it.to} className={`sb-item ${active ? 'active' : ''}`} title={collapsed ? it.label : undefined} aria-current={active ? 'page' : undefined}>
      <Icon size={15} strokeWidth={1.6}/>
      {!collapsed && <span className="sb-label">{it.label}</span>}
      {!collapsed && it.tag && <span className="sb-tag">{it.tag}</span>}
      {!collapsed && it.badge > 0 && <span className="sb-badge">{it.badge > 99 ? '99+' : it.badge}</span>}
      {collapsed && it.badge > 0 && <span className="sb-dot"/>}
    </Link>
  )
}

function NavList({ items, loc, collapsed }) {
  return items.map((it, i) => it.section
    ? (collapsed ? <div key={'s' + i} className="sb-rule"/> : <div key={'s' + i} className="sb-section">{it.section}</div>)
    : <NavItem key={it.id} it={it} loc={loc} collapsed={collapsed}/>)
}

function useClickAway(ref, onAway) {
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onAway() }
    document.addEventListener('mousedown', h)
    return () => document.removeEventListener('mousedown', h)
  }, [ref, onAway])
}

// ── Global search (Ctrl/⌘ K, or /) ───────────────────────────────────────────
// Jumps to pages, hosts and services by name; anything else becomes an event search or a hunt.
function CommandPalette({ open, onClose, pages, agents }) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [sel, setSel] = useState(0)
  const [services, setServices] = useState(null)
  const inputRef = useRef(null)

  useEffect(() => {
    if (!open) return
    setQ(''); setSel(0)
    setTimeout(() => inputRef.current?.focus(), 0)
    if (services === null) {
      const to = new Date(), from = new Date(to.getTime() - 7 * 86400e3)
      appApi.services({ from: from.toISOString(), to: to.toISOString() }, { limit: 500 })
        .then(d => setServices(d?.services || [])).catch(() => setServices([]))
    }
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  const results = useMemo(() => {
    const s = q.trim().toLowerCase()
    const hit = (txt) => !s || String(txt || '').toLowerCase().includes(s)
    const out = []
    pages.filter(p => hit(p.label) || hit(p.group)).slice(0, s ? 6 : 8)
      .forEach(p => out.push({ kind: 'Pages', label: p.label, hint: p.group, icon: p.icon, to: p.to }))
    if (s) {
      agents.filter(a => hit(a.hostname) || hit(a.last_ip)).slice(0, 6).forEach(a =>
        out.push({ kind: 'Hosts', label: a.hostname, hint: a.online ? 'online' : 'offline', icon: Server, mono: true, to: `/agents?host=${encodeURIComponent(a.hostname)}` }))
      ;(services || []).filter(v => hit(v.name)).slice(0, 6).forEach(v =>
        out.push({ kind: 'Services', label: v.name, hint: v.environment || '', icon: Boxes, mono: true, to: `/applications/services/${encodeURIComponent(v.id)}` }))
      out.push({ kind: 'Search', label: `Search events for "${q.trim()}"`, icon: FileSearch, to: `/events?search=${encodeURIComponent(q.trim())}` })
      out.push({ kind: 'Search', label: `Hunt stored events for "${q.trim()}"`, icon: Crosshair, to: `/hunt?q=${encodeURIComponent(q.trim())}` })
    }
    return out
  }, [q, pages, agents, services])

  useEffect(() => { setSel(0) }, [q])
  if (!open) return null
  const go = (r) => { onClose(); navigate(r.to) }
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); onClose() }
    else if (e.key === 'ArrowDown') { e.preventDefault(); setSel(i => Math.min(results.length - 1, i + 1)) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setSel(i => Math.max(0, i - 1)) }
    else if (e.key === 'Enter' && results[sel]) { e.preventDefault(); go(results[sel]) }
  }
  let lastKind = null
  return (
    <div className="ow-palette-back" onMouseDown={onClose}>
      <div className="ow-palette" role="dialog" aria-modal="true" aria-label="Search" onMouseDown={e => e.stopPropagation()}>
        <div className="ow-palette-in">
          <Search size={15}/>
          <input ref={inputRef} value={q} onChange={e => setQ(e.target.value)} onKeyDown={onKey}
            placeholder="Search hosts, services and pages, or type anything to search events" aria-label="Search"/>
          <span className="ow-kbd">esc</span>
        </div>
        <div className="ow-palette-list" role="listbox">
          {results.length === 0 && <div style={{ padding: '18px 12px', color: 'var(--t3)', fontSize: 12.5 }}>Nothing matches.</div>}
          {results.map((r, i) => {
            const head = r.kind !== lastKind ? <div className="dropdown-section">{r.kind}</div> : null
            lastKind = r.kind
            const Icon = r.icon
            return (
              <div key={r.kind + r.to}>
                {head}
                <div role="option" aria-selected={i === sel} className={`dropdown-item ${i === sel ? 'sel' : ''}`}
                  onMouseEnter={() => setSel(i)} onClick={() => go(r)}>
                  <Icon size={14} strokeWidth={1.6}/>
                  <span className={r.mono ? 'mono' : ''} style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', color: 'var(--t1)' }}>{r.label}</span>
                  {r.hint && <span style={{ fontSize: 11.5, color: 'var(--t3)' }}>{r.hint}</span>}
                  {i === sel && <CornerDownLeft size={12} style={{ color: 'var(--t3)' }}/>}
                </div>
              </div>
            )
          })}
        </div>
        <div className="ow-palette-foot"><span><span className="ow-kbd">↑</span> <span className="ow-kbd">↓</span> move</span><span><span className="ow-kbd">↵</span> open</span><span style={{ marginLeft: 'auto' }}>Press <span className="ow-kbd">/</span> anywhere to search</span></div>
      </div>
    </div>
  )
}

const RANGE_NAMES = { '1h': 'Last hour', '6h': 'Last 6 hours', '24h': 'Last 24 hours', '7d': 'Last 7 days', '30d': 'Last 30 days' }
function RangeControl() {
  const range = useTimeRange()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useClickAway(ref, useCallback(() => setOpen(false), []))
  const span = new Date(range.to) - new Date(range.from)
  const preset = RANGE_PRESETS.find(p => Math.abs(span - p.ms) < 60e3)
  const fmt = (d) => new Date(d).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  const label = preset ? RANGE_NAMES[preset.key] : `${fmt(range.from)} – ${fmt(range.to)}`
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button className="tb-ctl" onClick={() => setOpen(o => !o)} aria-haspopup="menu" aria-expanded={open}>{label}<span className="caret">▾</span></button>
      {open && (
        <div className="dropdown" role="menu" style={{ right: 0, left: 'auto', minWidth: 180 }}>
          {RANGE_PRESETS.map(p => (
            <div key={p.key} role="menuitem" className={`dropdown-item ${preset?.key === p.key ? 'active' : ''}`} onClick={() => { range.setPreset(p.ms); setOpen(false) }}>{RANGE_NAMES[p.key]}</div>
          ))}
          {range.absolute && <><div className="dropdown-divider"/><div className="dropdown-item" role="menuitem" onClick={() => { range.setRange(null, null); setOpen(false) }}>Rolling 24 hours</div></>}
        </div>
      )}
    </div>
  )
}

// Breadcrumb: domain / page, plus the entity when the URL names one.
function crumbsFor(loc, items, svcLabel) {
  let group = ''
  let found = null
  for (const it of items) {
    if (it.section) { group = it.section; continue }
    if (isActive(loc, it) && (!found || it.to.length > found.it.to.length)) found = { it, group }
  }
  if (!found) return []
  const out = []
  if (found.it.to !== '/') out.push({ label: found.group })
  out.push({ label: found.it.label, to: found.it.to })
  const host = new URLSearchParams(loc.search).get('host')
  if (found.it.id === 'fleet' && host) out.push({ label: host, mono: true })
  if (svcLabel) out.push({ label: svcLabel, mono: true })
  return out
}

export function Shell({ user, children }) {
  const navigate = useNavigate()
  const loc = useLocation()
  const { theme, toggle } = useTheme()
  const [agents, setAgents] = useState([])
  const [alertCount, setAlertCount] = useState(0)
  const [userMenu, setUserMenu] = useState(false)
  const [palette, setPalette] = useState(false)
  const [svcNames, setSvcNames] = useState({})
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('ow_sb_collapsed') === '1' } catch { return false } })
  const menuRef = useRef(null)
  const [sbw, sbHandle] = useDragSize('rail', 216, 180, 320, 'x')

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
  useClickAway(menuRef, useCallback(() => setUserMenu(false), []))
  useEffect(() => { try { localStorage.setItem('ow_sb_collapsed', collapsed ? '1' : '0') } catch { /* */ } }, [collapsed])
  useEffect(() => {
    const h = (e) => {
      const typing = /^(input|textarea|select)$/i.test(document.activeElement?.tagName || '') || document.activeElement?.isContentEditable
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(p => !p) }
      else if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) { e.preventDefault(); setPalette(true) }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const isAdmin = user?.role === 'admin'
  const { main, admin } = useMemo(() => buildNav({ alertCount, isAdmin }), [alertCount, isAdmin])
  const allItems = useMemo(() => [...main, ...admin], [main, admin])
  const pages = useMemo(() => {
    let g = 'Overview'
    const out = []
    for (const it of allItems) { if (it.section) { g = it.section; continue } out.push({ ...it, group: g }) }
    return out
  }, [allItems])

  // Service URLs carry an id or "name|environment"; the breadcrumb shows the name.
  const svcKey = loc.pathname.match(/^\/applications\/services\/([^/]+)/)?.[1]
  const svcParam = svcKey ? decodeURIComponent(svcKey) : null
  useEffect(() => {
    if (!svcParam || svcNames[svcParam] || !/^\d+$/.test(svcParam)) return
    appApi.service(svcParam).then(d => { if (d?.service?.name) setSvcNames(m => ({ ...m, [svcParam]: d.service.name })) }).catch(() => {})
  }, [svcParam]) // eslint-disable-line react-hooks/exhaustive-deps
  const svcLabel = svcParam ? (svcNames[svcParam] || (/^\d+$/.test(svcParam) ? '…' : appSplitKey(svcParam).name)) : null
  const crumb = useMemo(() => crumbsFor(loc, allItems, svcLabel), [loc, allItems, svcLabel])

  const hosts = useMemo(() => agents.filter(a => !(a.os || '').toLowerCase().includes('network-probe')), [agents])
  const online = hosts.filter(a => a.online).length
  const hostState = hosts.length === 0 ? 'none' : online === hosts.length ? 'ok' : online === 0 ? 'crit' : 'warn'

  const logout = () => {
    ['token', 'user', 'require_password_change'].forEach(k => localStorage.removeItem(k))
    navigate('/login')
  }

  return (
    <div className={`shell ${collapsed ? 'collapsed' : ''}`} style={{ '--sb-w': sbw + 'px' }}>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="sb-brand" onClick={() => navigate('/')} title="ObsidianWatch">
          <OWMark size={22}/>{!collapsed && <span>ObsidianWatch</span>}
        </div>
        <nav className="sb-scroll"><NavList items={[...main, ...admin]} loc={loc} collapsed={collapsed}/></nav>
        <div className="sb-foot">
          <div className="sb-status" title={`${online} of ${hosts.length} hosts online`}>
            <span className={`ow-dot ${hostState}`} style={{ color: `var(--${hostState === 'none' ? 't3' : hostState})` }}/>
            {!collapsed && <span>{hosts.length ? `${online} of ${hosts.length} hosts online` : 'No hosts enrolled yet'}</span>}
          </div>
        </div>
        {!collapsed && <div {...sbHandle}/>}
      </aside>

      <div className="shell-main">
        <header className="topbar">
          <button className="tb-ctl tb-icon" onClick={() => setCollapsed(c => !c)} title={collapsed ? 'Expand menu' : 'Collapse menu'} aria-label={collapsed ? 'Expand menu' : 'Collapse menu'}>
            {collapsed ? <PanelLeftOpen size={15}/> : <PanelLeftClose size={15}/>}
          </button>
          <nav className="crumb" aria-label="Breadcrumb">
            {crumb.map((c, i) => (
              <span key={i} className={i === crumb.length - 1 ? 'crumb-last' : ''} style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {i > 0 && <span className="crumb-sep">/</span>}
                {c.to && i < crumb.length - 1 ? <Link to={c.to}>{c.label}</Link> : <span className={c.mono ? 'mono' : ''}>{c.label}</span>}
              </span>
            ))}
          </nav>
          <div className="ow-field tb-search" role="button" tabIndex={0} onClick={() => setPalette(true)}
            onKeyDown={e => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), setPalette(true))} aria-label="Search">
            <Search size={13}/><span className="tb-search-text">Search hosts, services, pages and events</span>
            <span className="mono" style={{ marginLeft: 'auto', fontSize: 11 }}>{/Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K'}</span>
          </div>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
            {rangeAware(loc.pathname) && <RangeControl/>}
            <button className="tb-ctl tb-icon" onClick={toggle} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun size={14}/> : <Moon size={14}/>}
            </button>
            <button className="tb-ctl tb-icon" onClick={() => navigate('/alerts')} title={`${alertCount} open alerts`} aria-label={`${alertCount} open alerts`}>
              <Bell size={14}/>
              {alertCount > 0 && <span className="tb-count">{alertCount > 99 ? '99+' : alertCount}</span>}
            </button>
            <div ref={menuRef} style={{ position: 'relative' }}>
              <button className="tb-ctl" onClick={() => setUserMenu(o => !o)} style={{ paddingLeft: 5 }} aria-haspopup="menu" aria-expanded={userMenu}>
                <span className="tb-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</span>
                <span style={{ fontWeight: 500 }}>{user?.username}</span>
                <ChevronDown size={11} className="caret"/>
              </button>
              {userMenu && (
                <div className="dropdown" role="menu" style={{ right: 0, left: 'auto', minWidth: 180 }}>
                  <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)', marginBottom: 4 }}>
                    <div style={{ fontWeight: 600 }}>{user?.username}</div>
                    <div style={{ fontSize: 12, color: 'var(--t3)', textTransform: 'capitalize' }}>{user?.role}</div>
                  </div>
                  <div className="dropdown-item" role="menuitem" onClick={() => { setUserMenu(false); navigate('/change-password') }}><Key size={13}/> Change password</div>
                  <div className="dropdown-item" role="menuitem" onClick={logout} style={{ color: 'var(--crit)' }}><LogOut size={13}/> Sign out</div>
                </div>
              )}
            </div>
          </div>
        </header>
        <main id="app-shell">{children}</main>
      </div>
      <CommandPalette open={palette} onClose={() => setPalette(false)} pages={pages} agents={hosts}/>
    </div>
  )
}
