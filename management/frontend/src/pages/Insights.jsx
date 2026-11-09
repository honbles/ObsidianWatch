import { useEffect, useState, useCallback } from 'react'
import { Activity, Grid3x3, Fingerprint, UserSearch, Clock, RefreshCw, Siren, Boxes, Bug } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

// Insights: operational views over the newer backend endpoints.
//   Log sources (P-10), ATT&CK coverage (P-05), Prevalence (P-02),
//   Identity timeline (P-13), Scheduled searches (P-07).

const TABS = [
  { id: 'inventory', label: 'Inventory search', icon: Boxes },
  { id: 'incidents', label: 'Incidents',        icon: Siren },
  { id: 'findings',  label: 'Code findings',    icon: Bug },
  { id: 'sources',  label: 'Log sources',        icon: Activity },
  { id: 'coverage', label: 'ATT&CK coverage',    icon: Grid3x3 },
  { id: 'prev',     label: 'Prevalence',         icon: Fingerprint },
  { id: 'identity', label: 'Identity timeline',  icon: UserSearch },
  { id: 'sched',    label: 'Scheduled searches', icon: Clock },
]

const card = 'bg-siem-surface border border-siem-border rounded-xl'
const inputCls = 'bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-sm text-siem-text'
const btnCls = 'text-xs border border-siem-border rounded-lg px-3 py-1.5 text-siem-muted hover:text-siem-text'
const fmt = (t) => { try { return format(new Date(t), 'MMM d HH:mm:ss') } catch { return '—' } }

function Incidents() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [filter, setFilter] = useState('')
  const load = useCallback(async () => {
    setErr('')
    try { setData((await api.get('/api/v1/incidents', { params: { incident_status: filter } })).data) } catch (e) { setErr('Failed to load incidents') }
  }, [filter])
  const patch = async (id, body) => {
    try { await api.patch('/api/v1/incidents/' + id, body); load() } catch (e) { setErr(e.response?.data?.error || 'Update failed') }
  }
  useEffect(() => { load() }, [load])
  const rows = data?.incidents || []
  const riskCls = (r) => r >= 60 ? 'text-red-400' : r >= 25 ? 'text-orange-400' : 'text-siem-muted'
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-xs text-siem-muted">
        <span>{rows.length} incidents from {data?.alerts_considered ?? 0} open alerts (grouped per host, 2h gap)</span>
        <select className={btnCls + ' ml-auto'} value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">Active</option><option value="investigating">Investigating</option>
          <option value="resolved">Resolved</option><option value="false_positive">False positive</option><option value="all">All</option>
        </select>
        <button className={btnCls} onClick={load}><RefreshCw size={12} className="inline mr-1" />Refresh</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      <div className={`${card} overflow-x-auto`}>
        <table className="w-full text-sm">
          <thead><tr className="border-b border-siem-border text-siem-muted text-xs">
            {['Risk', 'Host', 'Alerts', 'Max sev', 'Window', 'Top alerts', 'Status', 'Owner'].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}
          </tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} className="border-b border-siem-border/50">
                <td className={`px-4 py-2 font-semibold ${riskCls(r.risk_score)}`}>{r.risk_score}</td>
                <td className="px-4 py-2 font-mono text-xs">{r.host}</td>
                <td className="px-4 py-2">{r.alert_count}</td>
                <td className="px-4 py-2">{r.max_severity}</td>
                <td className="px-4 py-2 text-siem-muted text-xs">{fmt(r.start)} → {fmt(r.end)}</td>
                <td className="px-4 py-2 text-xs">{(r.top_titles || []).join(' · ')}</td>
                <td className="px-4 py-2">
                  <select className={btnCls} value={r.state?.status || 'open'} onChange={e => patch(r.id, { status: e.target.value })}>
                    <option value="open">Open</option><option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option><option value="false_positive">False positive</option>
                  </select>
                </td>
                <td className="px-4 py-2">
                  <input className={btnCls + ' w-28'} defaultValue={r.state?.owner || ''} placeholder="owner"
                    onBlur={e => { if (e.target.value !== (r.state?.owner || '')) patch(r.id, { owner: e.target.value }) }} />
                </td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={8} className="px-4 py-6 text-center text-siem-muted">No incidents</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CodeFindings() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [minSev, setMinSev] = useState('medium')
  const [source, setSource] = useState('')
  const load = useCallback(async () => {
    setErr('')
    try { setData((await api.get('/api/v1/findings', { params: { min_severity: minSev, source } })).data) } catch (e) { setErr('Failed to load findings') }
  }, [minSev, source])
  useEffect(() => { load() }, [load])
  const rows = data?.findings || []
  const sevCls = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-siem-muted', info: 'text-siem-muted' }
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-xs text-siem-muted flex-wrap">
        <span>{data?.total ?? 0} findings across SAST, code scan and DevOps posture (latest scan per repo, duplicates merged)</span>
        <select className={btnCls + ' ml-auto'} value={minSev} onChange={e => setMinSev(e.target.value)}>
          <option value="">All severities</option><option value="critical">Critical</option><option value="high">High+</option><option value="medium">Medium+</option><option value="low">Low+</option>
        </select>
        <select className={btnCls} value={source} onChange={e => setSource(e.target.value)}>
          <option value="">All scanners</option><option value="sast">SAST</option><option value="code_scan">Code scan</option><option value="posture">Posture</option>
        </select>
        <button className={btnCls} onClick={load}><RefreshCw size={12} className="inline mr-1" />Refresh</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      <div className={`${card} overflow-x-auto`}>
        <table className="w-full text-sm">
          <thead><tr className="border-b border-siem-border text-siem-muted text-xs">
            {['Severity', 'Finding', 'Repo', 'Location', 'Found by'].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}
          </tr></thead>
          <tbody>
            {rows.map(f => (
              <tr key={f.id} className="border-b border-siem-border/50 align-top">
                <td className={`px-4 py-2 font-semibold ${sevCls[f.severity] || ''}`}>{f.severity}</td>
                <td className="px-4 py-2"><div>{f.title}</div>{f.remediation && <div className="text-xs text-siem-muted mt-0.5">{f.remediation}</div>}</td>
                <td className="px-4 py-2 font-mono text-xs">{f.repo}</td>
                <td className="px-4 py-2 font-mono text-xs">{f.file}{f.line ? ':' + f.line : ''}</td>
                <td className="px-4 py-2 text-xs">{(f.sources || []).join(', ')}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-siem-muted">No findings</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Inventory() {
  const [q, setQ] = useState('')
  const [version, setVersion] = useState('')
  const [kind, setKind] = useState('')
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const editMeta = async (host) => {
    const cur = res?.host_meta?.[host]
    const crit = window.prompt(`Criticality for ${host} (low, normal, high, critical). Critical hosts raise alert severity by one.`, cur?.criticality || 'normal')
    if (crit === null) return
    const tags = window.prompt('Tags, comma separated (letters, digits, : _ . -):', (cur?.tags || []).join(', '))
    if (tags === null) return
    try {
      const { data } = await api.put(`/api/v1/hosts/${encodeURIComponent(host)}/meta`, { criticality: crit, tags: tags.split(',').map(t => t.trim()).filter(Boolean) })
      setRes(r => ({ ...r, host_meta: { ...(r.host_meta || {}), [host]: data } }))
    } catch (e) { window.alert(e.response?.data?.error || 'Could not save') }
  }
  const run = async () => {
    setErr(''); setRes(null)
    try { setRes((await api.get('/api/v1/inventory/search', { params: { q, version, kind } })).data) }
    catch (e) { setErr(e.response?.data?.error || 'Search failed') }
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <input className={inputCls} placeholder="package or service, e.g. openssl" value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()} />
        <input className={inputCls} placeholder="version prefix (optional)" value={version} onChange={e => setVersion(e.target.value)} />
        <select className={inputCls} value={kind} onChange={e => setKind(e.target.value)}>
          <option value="">Packages + services</option><option value="package">Packages</option><option value="service">Services</option>
        </select>
        <button className={btnCls} onClick={run} disabled={q.trim().length < 2}>Search</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      {res && (
        <div className={`${card} overflow-x-auto`}>
          <div className="px-4 py-2 text-xs text-siem-muted">{res.hits.length} matches on {res.host_count} hosts (latest scan per host){res.truncated ? ' — truncated' : ''}</div>
          <table className="w-full text-sm">
            <thead><tr className="border-b border-siem-border text-siem-muted text-xs">
              {['Host', 'OS', 'Type', 'Name', 'Version / state', 'Scanned'].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}
            </tr></thead>
            <tbody>
              {res.hits.map((h, i) => (
                <tr key={i} className="border-b border-siem-border/50">
                  <td className="px-4 py-1.5 font-mono text-xs">
                    {h.host}
                    {res.host_meta?.[h.host] && (
                      <span className="ml-2 text-[10px] text-siem-muted">
                        {res.host_meta[h.host].criticality !== 'normal' && <span className="text-yellow-400 mr-1">{res.host_meta[h.host].criticality}</span>}
                        {(res.host_meta[h.host].tags || []).join(' ')}
                      </span>
                    )}
                    <button className="ml-2 text-[10px] text-siem-accent hover:underline" onClick={() => editMeta(h.host)}>tag</button>
                  </td><td className="px-4 py-1.5">{h.os}</td>
                  <td className="px-4 py-1.5">{h.kind}</td><td className="px-4 py-1.5">{h.name}</td>
                  <td className="px-4 py-1.5 font-mono text-xs">{h.version || h.state}</td>
                  <td className="px-4 py-1.5 text-siem-muted text-xs">{fmt(h.scanned_at)}</td>
                </tr>
              ))}
              {res.hits.length === 0 && <tr><td colSpan={6} className="px-4 py-6 text-center text-siem-muted">No matches</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function LogSources() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [onlySilent, setOnlySilent] = useState(false)
  const load = useCallback(async () => {
    setErr('')
    try { setData((await api.get('/api/v1/log-sources')).data) } catch (e) { setErr('Failed to load log sources') }
  }, [])
  useEffect(() => { load() }, [load])
  const rows = (data?.sources || []).filter(r => !onlySilent || r.silent)
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 text-xs text-siem-muted">
        <span>{data?.total ?? 0} streams</span>
        <span className={data?.silent ? 'text-yellow-400' : ''}>{data?.silent ?? 0} silent (no events for {data?.silent_after_minutes ?? 30} min)</span>
        <label className="flex items-center gap-1 ml-auto"><input type="checkbox" checked={onlySilent} onChange={e => setOnlySilent(e.target.checked)} /> only silent</label>
        <button className={btnCls} onClick={load}><RefreshCw size={12} className="inline mr-1" />Refresh</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      <div className={`${card} overflow-x-auto`}>
        <table className="w-full text-sm">
          <thead><tr className="border-b border-siem-border text-siem-muted text-xs">
            {['Host', 'Event type', 'Source', 'Events 1h', 'Events 24h', 'EPS (1h)', 'Last event', ''].map(h => <th key={h} className="text-left px-4 py-3">{h}</th>)}
          </tr></thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className="border-b border-siem-border/50">
                <td className="px-4 py-2 font-mono text-xs">{r.host || r.agent_id}</td>
                <td className="px-4 py-2">{r.event_type}</td>
                <td className="px-4 py-2 text-siem-muted">{r.source}</td>
                <td className="px-4 py-2">{r.events_1h.toLocaleString()}</td>
                <td className="px-4 py-2">{r.events_24h.toLocaleString()}</td>
                <td className="px-4 py-2">{r.eps_1h.toFixed(2)}</td>
                <td className="px-4 py-2 text-siem-muted">{fmt(r.last_event)}</td>
                <td className="px-4 py-2">{r.silent && <span className="text-[10px] px-2 py-0.5 rounded-full bg-yellow-900/40 text-yellow-300">silent</span>}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={8} className="px-4 py-6 text-center text-siem-muted">No streams</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Coverage() {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState('')
  useEffect(() => { api.get('/api/v1/coverage/attack').then(r => setData(r.data)).catch(() => setData({ platforms: [] })) }, [])
  return (
    <div className="space-y-3">
      {(data?.platforms || []).map(p => (
        <div key={p.platform} className={`${card} p-4`}>
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setOpen(open === p.platform ? '' : p.platform)}>
            <span className="font-semibold uppercase text-sm">{p.platform}</span>
            <span className="text-xs text-siem-muted">{p.rules} rules · {(p.techniques || []).length} techniques · {p.rules_without_mitre} without ATT&CK mapping · {p.rules_disabled} disabled</span>
          </div>
          {(p.data_gaps || []).length > 0 && (
            <ul className="mt-2 text-xs text-yellow-300 list-disc pl-5">{p.data_gaps.map(g => <li key={g}>{g}</li>)}</ul>
          )}
          {open === p.platform && (
            <div className="mt-3 flex flex-wrap gap-2">
              {(p.techniques || []).map(t => (
                <span key={t.technique} title={t.rules.join(', ')} className="text-[11px] font-mono px-2 py-1 rounded border border-siem-border">
                  {t.technique} <span className="text-siem-muted">×{t.rules.length}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function Prevalence() {
  const [kind, setKind] = useState('hash')
  const [value, setValue] = useState('')
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const run = async () => {
    setErr(''); setRes(null)
    if (!value.trim()) return
    try { setRes((await api.get('/api/v1/prevalence', { params: { [kind]: value.trim() } })).data) }
    catch { setErr('Lookup failed') }
  }
  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <select className={inputCls} value={kind} onChange={e => setKind(e.target.value)}>
          <option value="hash">File hash</option><option value="image">Image path</option><option value="process">Process name</option>
        </select>
        <input className={`${inputCls} flex-1`} value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()} placeholder="sha256 / C:\path\app.exe / app.exe" />
        <button className={btnCls} onClick={run}>Look up</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      {res && (
        <div className={`${card} p-4 space-y-2`}>
          <div className="text-sm">Seen on <b>{res.host_count}</b> of {res.fleet_size} hosts{res.host_count === 1 && <span className="ml-2 text-yellow-300">rare: single host</span>}{res.host_count === 0 && <span className="ml-2 text-yellow-300">never seen</span>}</div>
          {res.first_seen && <div className="text-xs text-siem-muted">First seen {fmt(res.first_seen)} on {res.first_host}; last {fmt(res.last_seen)}</div>}
          <table className="w-full text-xs"><tbody>
            {(res.hosts || []).map(h => <tr key={h.host} className="border-t border-siem-border/50"><td className="py-1 font-mono">{h.host}</td><td>{fmt(h.first_seen)}</td><td>{fmt(h.last_seen)}</td><td>{h.seen_count.toLocaleString()}</td></tr>)}
          </tbody></table>
        </div>
      )}
    </div>
  )
}

function Identity() {
  const [user, setUser] = useState('')
  const [hours, setHours] = useState(72)
  const [res, setRes] = useState(null)
  const [err, setErr] = useState('')
  const [links, setLinks] = useState('')
  const [linkMsg, setLinkMsg] = useState('')
  const saveLink = async () => {
    const names = links.split(',').map(x => x.trim()).filter(Boolean)
    if (!user.trim() || names.length === 0) { setLinkMsg('Enter the searched user and at least one other account name'); return }
    try {
      const cur = (await api.get('/api/v1/identity/aliases')).data?.aliases || {}
      cur[user.trim()] = [...new Set([...(cur[user.trim()] || []), ...names])]
      await api.put('/api/v1/identity/aliases', { aliases: cur })
      setLinkMsg('Linked. Search again to see the combined timeline.'); setLinks('')
    } catch { setLinkMsg('Could not save the link') }
  }
  const run = async () => {
    setErr(''); setRes(null)
    if (!user.trim()) return
    try { setRes((await api.get('/api/v1/identity/timeline', { params: { user: user.trim(), hours } })).data) }
    catch { setErr('Lookup failed') }
  }
  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <input className={`${inputCls} flex-1`} value={user} onChange={e => setUser(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()} placeholder="username (DOMAIN\\user and user@domain are normalised)" />
        <select className={inputCls} value={hours} onChange={e => setHours(+e.target.value)}>
          <option value={24}>24h</option><option value={72}>3 days</option><option value={168}>7 days</option><option value={720}>30 days</option>
        </select>
        <button className={btnCls} onClick={run}>Search</button>
      </div>
      {err && <div className="text-red-400 text-sm">{err}</div>}
      <div className="flex gap-2 items-center text-xs text-siem-muted">
        <input className={`${inputCls} flex-1`} value={links} onChange={e => setLinks(e.target.value)} placeholder="Link other account names for this person, comma-separated (e.g. their GitHub handle, Entra UPN)" />
        <button className={btnCls} onClick={saveLink}>Link accounts</button>
        {linkMsg && <span>{linkMsg}</span>}
      </div>
      {res && (
        <>
          <div className={`${card} p-4`}>
            <div className="text-xs text-siem-muted mb-2">Hosts used by <b>{res.user}</b>{(res.linked_accounts || []).length > 1 && <span className="ml-2">(linked: {res.linked_accounts.join(', ')})</span>}</div>
            {(res.hosts || []).map(h => (
              <div key={h.host} className="text-sm flex gap-3 py-1 border-t border-siem-border/50">
                <span className="font-mono w-48 truncate">{h.host}</span><span className="text-siem-muted">{h.os}</span>
                <span>{h.events.toLocaleString()} events</span><span className="text-siem-muted">{fmt(h.first_seen)} → {fmt(h.last_seen)}</span>
                {h.max_severity >= 3 && <span className="text-yellow-300">max sev {h.max_severity}</span>}
              </div>
            ))}
          </div>
          <div className={`${card} p-4`}>
            <div className="text-xs text-siem-muted mb-2">Timeline (logons, notable endpoint activity, all cloud and repo activity)
              {res.surfaces && <span className="ml-3">{Object.entries(res.surfaces).map(([k, v]) => `${k}: ${v}`).join(' · ')}</span>}</div>
            {(res.timeline || []).map((e, i) => (
              <div key={i} className="text-xs flex gap-3 py-1 border-t border-siem-border/50">
                <span className="w-32 text-siem-muted">{fmt(e.time)}</span>
                <span className={`w-16 text-[10px] uppercase ${e.surface === 'cloud' ? 'text-sky-400' : e.surface === 'devops' ? 'text-violet-400' : 'text-siem-muted'}`}>{e.surface || 'endpoint'}</span>
                <span className="w-40 font-mono truncate">{e.host}</span>
                <span className="w-24">{e.event_type}</span><span className="w-10">sev {e.severity}</span>
                <span className="flex-1 truncate" title={e.summary}>{e.summary}</span>{e.src_ip && <span className="font-mono text-siem-muted">{e.src_ip}</span>}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function Scheduled() {
  const [queries, setQueries] = useState([])
  const [msg, setMsg] = useState('')
  const load = useCallback(async () => {
    try { setQueries((await api.get('/api/v1/events/saved-queries')).data.queries || []) } catch { setQueries([]) }
  }, [])
  useEffect(() => { load() }, [load])
  const [form, setForm] = useState({})
  const get = (q) => form[q.id] || { enabled: true, every_minutes: 15, window_minutes: 15, threshold: 1, severity: 3 }
  const set = (q, patch) => setForm(f => ({ ...f, [q.id]: { ...get(q), ...patch } }))
  const save = async (q, enabled) => {
    setMsg('')
    try {
      await api.put(`/api/v1/events/saved-queries/${q.id}/schedule`, { ...get(q), enabled })
      setMsg(enabled ? `Scheduled "${q.name}"` : `Disabled "${q.name}"`)
    } catch (e) { setMsg(e?.response?.data?.error || 'Failed (only the owner can schedule a query)') }
  }
  const num = (q, k, min, max) => (
    <input type="number" min={min} max={max} className={`${inputCls} w-20`} value={get(q)[k]} onChange={e => set(q, { [k]: +e.target.value })} />
  )
  return (
    <div className="space-y-3">
      <div className="text-xs text-siem-muted">Save a query on the Search page, then schedule it here. It alerts when matches in the window reach the threshold.</div>
      {msg && <div className="text-sm text-siem-accent">{msg}</div>}
      <div className={`${card} overflow-x-auto`}>
        <table className="w-full text-sm">
          <thead><tr className="border-b border-siem-border text-siem-muted text-xs">
            {['Name', 'Query', 'Every (min)', 'Window (min)', 'Threshold', 'Severity', ''].map(h => <th key={h} className="text-left px-3 py-3">{h}</th>)}
          </tr></thead>
          <tbody>
            {queries.map(q => (
              <tr key={q.id} className="border-b border-siem-border/50">
                <td className="px-3 py-2">{q.name}</td>
                <td className="px-3 py-2 font-mono text-xs max-w-xs truncate" title={q.query}>{q.query}</td>
                <td className="px-3 py-2">{num(q, 'every_minutes', 5, 1440)}</td>
                <td className="px-3 py-2">{num(q, 'window_minutes', 5, 1440)}</td>
                <td className="px-3 py-2">{num(q, 'threshold', 1, 1000000)}</td>
                <td className="px-3 py-2">{num(q, 'severity', 1, 5)}</td>
                <td className="px-3 py-2 whitespace-nowrap">
                  <button className={btnCls} onClick={() => save(q, true)}>Schedule</button>{' '}
                  <button className={btnCls} onClick={() => save(q, false)}>Disable</button>
                </td>
              </tr>
            ))}
            {queries.length === 0 && <tr><td colSpan={7} className="px-4 py-6 text-center text-siem-muted">No saved queries yet</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function Insights() {
  const [tab, setTab] = useState('incidents')
  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center gap-2"><Activity className="text-siem-accent" size={20} /><h1 className="text-xl font-bold text-siem-text">Insights</h1></div>
      <div className="flex gap-2 flex-wrap">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 text-xs rounded-lg px-3 py-1.5 border ${tab === t.id ? 'border-siem-accent text-siem-accent' : 'border-siem-border text-siem-muted hover:text-siem-text'}`}>
            <t.icon size={13} />{t.label}
          </button>
        ))}
      </div>
      {tab === 'inventory' && <Inventory />}
      {tab === 'incidents' && <Incidents />}
      {tab === 'findings' && <CodeFindings />}
      {tab === 'sources' && <LogSources />}
      {tab === 'coverage' && <Coverage />}
      {tab === 'prev' && <Prevalence />}
      {tab === 'identity' && <Identity />}
      {tab === 'sched' && <Scheduled />}
    </div>
  )
}
