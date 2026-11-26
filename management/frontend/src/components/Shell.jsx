import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import {
  LayoutDashboard, Bell, Activity, GitBranch, Cloud, Monitor, Network, Shield, Boxes, Crosshair, Search,
  Settings, Users, Key, ClipboardList, Terminal, LogOut, Sun, Moon, ChevronDown, Menu, X,
  Eye, Share2, Gauge, ShieldCheck, SlidersHorizontal, BellOff, ListChecks, CornerDownLeft, Server, FileSearch,
  Check, Type, Fingerprint, UserX, Radar,
} from 'lucide-react'
import { useTheme } from '../api/useTheme'
import api from '../api/client'
import { appApi } from '../api/app'
import { useTimeRange, RANGE_PRESETS } from './shared/useTimeRange'
import { MARK_SHAPES } from '../utils/brand'
import { DISPLAY_SIZES, getDisplaySize, setDisplaySize } from '../utils/display'

// The brand mark (shapes in utils/brand.js). Brand colours, the same in both themes.
export function OWMark({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" style={{ flexShrink: 0 }}>
      {MARK_SHAPES.map((m, i) => <path key={i} d={m.d} fill={m.fill}/>)}
    </svg>
  )
}

export function OWWordmark() {
  return <span className="ow-wordmark"><b>Obsidian</b><span>Watch</span></span>
}

// Navigation is a header: one menu per product, Detect across all of them, and Settings for the platform.
// ITDR is announced before it is built: its menu says so and links nowhere.
function buildNav({ alertCount, isAdmin }) {
  const products = [
    { id: 'endpoint', label: 'Endpoint', items: [
      { id: 'fleet', label: 'Fleet', icon: Monitor, to: '/agents' },
      { id: 'hunt', label: 'Hunt', icon: Crosshair, to: '/hunt' },
      { id: 'prevention', label: 'Prevention', icon: ShieldCheck, to: '/prevention' },
      { id: 'response', label: 'Response', icon: Terminal, to: '/response' },
    ] },
    { id: 'application', label: 'Application', items: [
      { id: 'app-hosts', label: 'Hosts', icon: Server, to: '/applications', exact: true, also: '/applications/hosts' },
      { id: 'app-overview', label: 'Overview', icon: Gauge, to: '/applications/overview' },
      { id: 'app-services', label: 'Services', icon: Boxes, to: '/applications/services' },
      { id: 'app-map', label: 'Dependencies', icon: Share2, to: '/applications/map' },
      { id: 'app-coverage', label: 'Coverage', icon: ListChecks, to: '/applications/coverage' },
      { id: 'app-settings', label: 'Settings', icon: SlidersHorizontal, to: '/applications/settings' },
    ] },
    { id: 'code', label: 'Code', items: [
      { id: 'repos', label: 'Repositories', icon: GitBranch, to: '/devops' },
    ] },
    { id: 'cloud', label: 'Cloud', items: [
      { id: 'cloud', label: 'Posture', icon: Cloud, to: '/cloud' },
    ] },
    { id: 'network', label: 'Network', items: [
      { id: 'network', label: 'Probes', icon: Radar, to: '/network', tag: 'beta' },
    ] },
    { id: 'itdr', label: 'ITDR', soon: true, items: [
      { id: 'itdr-threats', label: 'Identity threats', icon: Fingerprint, soon: true },
      { id: 'itdr-accounts', label: 'Risky accounts', icon: UserX, soon: true },
    ] },
    { id: 'detect', label: 'Detect', items: [
      { id: 'alerts', label: 'Alerts', icon: Bell, to: '/alerts', badge: alertCount },
      { id: 'events', label: 'Events', icon: Activity, to: '/events' },
      { id: 'insights', label: 'Insights', icon: Eye, to: '/insights' },
      { id: 'rules', label: 'Rules', icon: Shield, to: '/detections' },
      { id: 'alert-rules', label: 'Alert rules', icon: ListChecks, to: '/alert-rules' },
      { id: 'suppressions', label: 'Suppressions', icon: BellOff, to: '/suppressions' },
    ] },
  ]
  const settings = isAdmin ? [
    { id: 'builder', label: 'Agent builder', icon: Key, to: '/agent-builder' },
    { id: 'users', label: 'Users and access', icon: Users, to: '/users' },
    { id: 'audit', label: 'Audit log', icon: ClipboardList, to: '/audit-log' },
    { id: 'settings', label: 'Platform settings', icon: Settings, to: '/settings' },
  ] : []
  return { products, settings }
}

function isActive(loc, it) {
  if (it.also && (loc.pathname === it.also || loc.pathname.startsWith(it.also + '/'))) return true
  if (it.to === '/' || it.exact) return loc.pathname === it.to
  return loc.pathname === it.to || loc.pathname.startsWith(it.to + '/')
}

// Pages that read the shared ?from=&to= range. The context-bar range control only appears on these,
// so it never looks as if it filters a page that ignores it.
const RANGE_AWARE = ['/applications']
const rangeAware = (path) => RANGE_AWARE.some(p => path === p || path.startsWith(p + '/'))


function MenuItem({ it, loc, onGo }) {
  const Icon = it.icon
  if (it.soon) return (
    <div className="dropdown-item tn-soon" aria-disabled="true"><Icon size={14} strokeWidth={1.6}/><span style={{ flex: 1 }}>{it.label}</span><span className="sb-tag">soon</span></div>
  )
  const active = isActive(loc, it)
  return (
    <Link to={it.to} className={`dropdown-item ${active ? 'active' : ''}`} onClick={onGo} aria-current={active ? 'page' : undefined}>
      <Icon size={14} strokeWidth={1.6}/><span style={{ flex: 1 }}>{it.label}</span>
      {it.tag && <span className="sb-tag">{it.tag}</span>}
      {it.badge > 0 && <span className="sb-badge">{it.badge > 99 ? '99+' : it.badge}</span>}
    </Link>
  )
}

const groupActive = (loc, g) => g.items.some(it => !it.soon && isActive(loc, it))

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

export function Shell({ user, children }) {
  const navigate = useNavigate()
  const loc = useLocation()
  const { theme, toggle } = useTheme()
  const [agents, setAgents] = useState([])
  const [alertCount, setAlertCount] = useState(0)
  const [open, setOpen] = useState(null)        // id of the open header menu
  const [palette, setPalette] = useState(false)
  const [display, setDisplay] = useState(getDisplaySize)
  const navRef = useRef(null)

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
  useClickAway(navRef, useCallback(() => setOpen(null), []))
  useEffect(() => { setOpen(null) }, [loc.pathname, loc.search])
  useEffect(() => { setDisplaySize(display) }, [display])
  useEffect(() => {
    const h = (e) => {
      const typing = /^(input|textarea|select)$/i.test(document.activeElement?.tagName || '') || document.activeElement?.isContentEditable
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette(p => !p) }
      else if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey) { e.preventDefault(); setPalette(true) }
      else if (e.key === 'Escape') setOpen(null)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [])

  const isAdmin = user?.role === 'admin'
  const { products, settings } = useMemo(() => buildNav({ alertCount, isAdmin }), [alertCount, isAdmin])
  const pages = useMemo(() => {
    const out = [{ id: 'dash', label: 'Overview', icon: LayoutDashboard, to: '/', group: 'Overview' }]
    for (const g of products) for (const it of g.items) if (!it.soon) out.push({ ...it, group: g.label })
    for (const it of settings) out.push({ ...it, group: 'Settings' })
    return out
  }, [products, settings])

  const hosts = useMemo(() => agents.filter(a => !(a.os || '').toLowerCase().includes('network-probe')), [agents])
  const online = hosts.filter(a => a.online).length
  const hostState = hosts.length === 0 ? 'none' : online === hosts.length ? 'ok' : online === 0 ? 'crit' : 'warn'

  const logout = () => {
    ['token', 'user', 'require_password_change'].forEach(k => localStorage.removeItem(k))
    navigate('/login')
  }
  // Click opens a menu; while one is open, hovering another product switches to it, like a menu bar.
  const menuProps = (id) => ({
    onClick: () => setOpen(o => o === id ? null : id),
    onMouseEnter: () => setOpen(o => (o && o !== id && o !== 'user' && o !== 'mobile') ? id : o),
    'aria-haspopup': 'menu', 'aria-expanded': open === id,
  })
  const go = () => setOpen(null)
  const overviewActive = loc.pathname === '/'

  return (
    <div className="shell">
      <div className="shell-main">
        <header className="topbar" ref={navRef}>
          <Link to="/" className="tn-brand" title="ObsidianWatch" aria-label="ObsidianWatch, Overview"><OWMark size={24}/><OWWordmark/></Link>

          <nav className="tn-products" aria-label="Products">
            <Link to="/" className={`tn-link ${overviewActive ? 'on' : ''}`} aria-current={overviewActive ? 'page' : undefined}>Overview</Link>
            {products.map(g => (
              <div key={g.id} className="tn-menu">
                <button className={`tn-link ${groupActive(loc, g) ? 'on' : ''} ${open === g.id ? 'open' : ''}`} {...menuProps(g.id)}>
                  {g.label}{g.soon && <span className="tn-soon-dot" title="Coming soon"/>}
                  {g.id === 'detect' && alertCount > 0 && <span className="tn-count">{alertCount > 99 ? '99+' : alertCount}</span>}
                  <ChevronDown size={12} className="caret"/>
                </button>
                {open === g.id && (
                  <div className="dropdown tn-drop" role="menu">
                    {g.soon && <div className="tn-drop-note">Coming soon</div>}
                    {g.items.map(it => <MenuItem key={it.id} it={it} loc={loc} onGo={go}/>)}
                    {g.id === 'endpoint' && <>
                      <div className="dropdown-divider"/>
                      <div className="tn-drop-foot"><span className={`ow-dot ${hostState}`} style={{ color: `var(--${hostState === 'none' ? 't3' : hostState})` }}/>
                        {hosts.length ? `${online} of ${hosts.length} hosts online` : 'No hosts enrolled yet'}</div>
                    </>}
                  </div>
                )}
              </div>
            ))}
          </nav>

          <div className="tn-menu tn-mobile">
            <button className={`tb-ctl tn-menu-btn ${open === 'mobile' ? 'open' : ''}`} onClick={() => setOpen(o => o === 'mobile' ? null : 'mobile')} aria-haspopup="menu" aria-expanded={open === 'mobile'} aria-label="Menu">
              {open === 'mobile' ? <X size={15}/> : <Menu size={15}/>}<span>Menu</span>
            </button>
            {open === 'mobile' && (
              <div className="dropdown tn-mega" role="menu">
                <Link to="/" className={`dropdown-item ${overviewActive ? 'active' : ''}`} onClick={go}><LayoutDashboard size={14} strokeWidth={1.6}/> Overview</Link>
                <div className="tn-mega-grid">
                  {products.map(g => (
                    <div key={g.id}>
                      <div className="dropdown-section">{g.label}{g.soon && ' · soon'}</div>
                      {g.items.map(it => <MenuItem key={it.id} it={it} loc={loc} onGo={go}/>)}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="tn-right">
            <button className="tb-ctl tn-search" onClick={() => setPalette(true)} aria-label="Search" title="Search hosts, services, pages and events">
              <Search size={14}/><span className="tn-search-text">Search</span>
              <span className="ow-kbd">{/Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K'}</span>
            </button>
            {rangeAware(loc.pathname) && <RangeControl/>}
            <button className="tb-ctl tb-icon" onClick={toggle} title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun size={14}/> : <Moon size={14}/>}
            </button>
            <button className="tb-ctl tb-icon" onClick={() => navigate('/alerts')} title={`${alertCount} open alerts`} aria-label={`${alertCount} open alerts`}>
              <Bell size={14}/>
              {alertCount > 0 && <span className="tb-count">{alertCount > 99 ? '99+' : alertCount}</span>}
            </button>
            {settings.length > 0 && (
              <div className="tn-menu">
                <button className={`tb-ctl tb-icon ${settings.some(it => isActive(loc, it)) ? 'on' : ''}`} {...menuProps('settings')} title="Settings" aria-label="Settings">
                  <Settings size={14}/>
                </button>
                {open === 'settings' && (
                  <div className="dropdown tn-drop" role="menu" style={{ right: 0, left: 'auto' }}>
                    <div className="dropdown-section">Settings</div>
                    {settings.map(it => <MenuItem key={it.id} it={it} loc={loc} onGo={go}/>)}
                  </div>
                )}
              </div>
            )}
            <div className="tn-menu">
              <button className="tb-ctl" onClick={() => setOpen(o => o === 'user' ? null : 'user')} style={{ paddingLeft: 5 }} aria-haspopup="menu" aria-expanded={open === 'user'}>
                <span className="tb-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</span>
                <span className="tn-user">{user?.username}</span>
                <ChevronDown size={11} className="caret"/>
              </button>
              {open === 'user' && (
                <div className="dropdown" role="menu" style={{ right: 0, left: 'auto', minWidth: 190 }}>
                  <div style={{ padding: '8px 10px', borderBottom: '1px solid var(--line)', marginBottom: 4 }}>
                    <div style={{ fontWeight: 600 }}>{user?.username}</div>
                    <div style={{ fontSize: 12, color: 'var(--t3)', textTransform: 'capitalize' }}>{user?.role}</div>
                  </div>
                  <div className="dropdown-section" style={{ display: 'flex', alignItems: 'center', gap: 6 }}><Type size={11}/> Display size</div>
                  {DISPLAY_SIZES.map(d => (
                    <div key={d.id} className={`dropdown-item ${display === d.id ? 'active' : ''}`} role="menuitemradio" aria-checked={display === d.id} onClick={() => setDisplay(d.id)}>
                      <span style={{ width: 13, display: 'inline-flex' }}>{display === d.id && <Check size={13}/>}</span>{d.label}
                    </div>
                  ))}
                  <div className="dropdown-divider"/>
                  <div className="dropdown-item" role="menuitem" onClick={() => { setOpen(null); navigate('/change-password') }}><Key size={13}/> Change password</div>
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
