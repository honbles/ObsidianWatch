// Alerts: incident review. Status tabs (Checkmk's unhandled / handled split), urgency, owner and SLA on every row,
// facets and a timeline above the list (Splunk "show charts"), commands on selected rows, details in a side panel.
import { useEffect, useMemo, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Plus, RefreshCw, Search, X, Download, BarChart3 } from 'lucide-react'
import api from '../api/client'
import AlertPanel from '../components/AlertPanel'
import {
  PageHeader, Num, Tabs, StatePill, SevPill, Facets, countBy, useFacetFilter, DenseTable, parseFilter, relTime, downloadCSV,
  Histogram, Drawer, SelectionBar, Dialog, Field, useSelection, SEV_STACKS, SEV_WORD, StateBar,
} from '../components/ui'

const SLA_MS = { 5: 3600e3, 4: 4 * 3600e3, 3: 24 * 3600e3, 2: 72 * 3600e3 }
const SLA_TEXT = 'Response targets: critical 1 h, high 4 h, medium 24 h, low 72 h, from creation until acknowledged.'
const STATUS = { open: ['none', 'New'], acknowledged: ['info', 'In progress'], closed: ['ok', 'Closed'] }
const TABS = [
  { id: 'open', label: 'Unhandled' }, { id: 'acknowledged', label: 'In progress' }, { id: 'closed', label: 'Closed' }, { id: '', label: 'All' },
]

function slaOf(a) {
  const t = SLA_MS[a.severity]
  if (!t || a.status !== 'open' || a.acknowledged_at) return { state: 'na' }
  const over = Date.now() - new Date(a.created_at).getTime() - t
  return over > 0 ? { state: 'breached', over } : { state: 'within', left: -over }
}
const dur = (ms) => ms < 3600e3 ? `${Math.max(1, Math.round(ms / 60e3))} min` : ms < 2 * 86400e3 ? `${Math.round(ms / 3600e3)} h` : `${Math.round(ms / 86400e3)} d`

const GETTERS = {
  severity: a => a.severity,
  status: a => a.status,
  owner: a => a.assigned_to || '(unassigned)',
  sla: a => slaOf(a).state,
  host: a => a.host || '(none)',
  type: a => a.event_type || '(none)',
}

function NewAlertDialog({ onClose, onCreated }) {
  const [f, setF] = useState({ title: '', description: '', severity: 3, host: '' })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    if (!f.title.trim()) { setErr('A title is required'); return }
    setBusy(true)
    try { await api.post('/api/v1/alerts', f); onCreated(); onClose() } catch (e) { setErr(e.response?.data?.error || 'Could not create the alert') } finally { setBusy(false) }
  }
  return (
    <Dialog title="New alert" onClose={onClose} footer={<>
      <button className="ow-btn quiet" onClick={onClose}>Cancel</button>
      <button className="ow-btn primary" onClick={submit} disabled={busy}>{busy ? 'Creating…' : 'Create alert'}</button></>}>
      <Field label="Title"><input className="input" autoFocus value={f.title} onChange={e => setF({ ...f, title: e.target.value })}/></Field>
      <Field label="Description"><textarea className="input" rows={3} value={f.description} onChange={e => setF({ ...f, description: e.target.value })}/></Field>
      <div style={{ display: 'flex', gap: 12 }}>
        <Field label="Severity"><select className="input" value={f.severity} onChange={e => setF({ ...f, severity: Number(e.target.value) })}>
          {[5, 4, 3, 2, 1].map(s => <option key={s} value={s}>{SEV_WORD[s]}</option>)}</select></Field>
        <Field label="Host (optional)"><input className="input mono" value={f.host} onChange={e => setF({ ...f, host: e.target.value })}/></Field>
      </div>
      {err && <div className="c-crit" style={{ fontSize: 12.5 }}>{err}</div>}
    </Dialog>
  )
}

// One dialog for the commands that need input. action: assign | close
function CommandDialog({ action, ids, users, onClose, onDone }) {
  const [owner, setOwner] = useState('')
  const [comment, setComment] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const run = async () => {
    if (action === 'assign' && !owner.trim()) { setErr('Choose an analyst'); return }
    if (action === 'close' && !comment.trim()) { setErr('Say what was found and done, so the closure can be reviewed'); return }
    setBusy(true)
    try {
      const { data } = await api.post('/api/v1/alerts/bulk', { ids, action, comment: comment || undefined, assigned_to: owner || undefined })
      const failed = Object.keys(data?.failed || {}).length
      if (failed) setErr(`${failed} of ${ids.length} could not be updated`)
      else { onDone(); onClose() }
      if (failed) onDone()
    } catch (e) { setErr(e.response?.data?.error || 'The command failed') } finally { setBusy(false) }
  }
  const n = ids.length
  return (
    <Dialog title={`${action === 'assign' ? 'Assign' : 'Close'} ${n} alert${n === 1 ? '' : 's'}`} onClose={onClose} footer={<>
      <button className="ow-btn quiet" onClick={onClose}>Cancel</button>
      <button className="ow-btn primary" onClick={run} disabled={busy}>{busy ? 'Working…' : action === 'assign' ? 'Assign' : 'Close alerts'}</button></>}>
      {action === 'assign' && (
        <Field label="Analyst" hint="Assigning also moves the alerts to In progress.">
          {users.length ? (
            <select className="input" autoFocus value={owner} onChange={e => setOwner(e.target.value)}>
              <option value="">Choose…</option>{users.map(u => <option key={u.id} value={u.username}>{u.username} ({u.role})</option>)}
            </select>) : <input className="input" autoFocus value={owner} onChange={e => setOwner(e.target.value)} placeholder="Username"/>}
        </Field>)}
      <Field label={action === 'close' ? 'Review comment' : 'Comment (optional)'} hint={action === 'close' ? 'Kept on every closed alert and in the audit log.' : undefined}>
        <textarea className="input" rows={4} autoFocus={action === 'close'} value={comment} onChange={e => setComment(e.target.value)} placeholder={action === 'close' ? 'What was found, what was done, and why it is resolved' : ''}/>
      </Field>
      {err && <div className="c-crit" style={{ fontSize: 12.5 }}>{err}</div>}
    </Dialog>
  )
}

function TopList({ title, rows, onPick }) {
  const max = Math.max(1, ...rows.map(r => r.n))
  return (
    <div style={{ flex: '1 1 220px', minWidth: 0 }}>
      <div className="ow-lbl" style={{ marginBottom: 8 }}>{title}</div>
      {rows.length === 0 && <div className="t3" style={{ fontSize: 12 }}>None</div>}
      {rows.slice(0, 5).map(r => (
        <button key={r.v} className="ow-fc" style={{ height: 24 }} onClick={() => onPick(r.v)} title={`Filter to ${r.label ?? r.v}`}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0 }}>
            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: '0 1 auto' }}>{r.label ?? r.v}</span>
            <span style={{ flex: 1, minWidth: 20, height: 4, borderRadius: 2, background: 'var(--s3)', overflow: 'hidden' }}><span style={{ display: 'block', height: '100%', width: `${(r.n / max) * 100}%`, background: 'var(--t3)' }}/></span>
          </span><b>{r.n}</b>
        </button>
      ))}
    </div>
  )
}

export default function Alerts() {
  const [params, setParams] = useSearchParams()
  const [tab, setTab] = useState('open')
  const [alerts, setAlerts] = useState([])
  const [counts, setCounts] = useState({})
  const [loading, setLoading] = useState(true)
  const [err, setErr] = useState('')
  const [users, setUsers] = useState([])
  const [q, setQ] = useState('')
  // Deep links from the overview: ?sev=5 (that severity), ?sla=breached
  const [facets, setFacets] = useState(() => {
    const p = new URLSearchParams(window.location.search), out = {}
    if (p.get('sev')) out.severity = new Set([Number(p.get('sev'))])
    if (p.get('sla')) out.sla = new Set([p.get('sla')])
    return out
  })
  const [charts, setCharts] = useState(() => { try { return localStorage.getItem('ow_alert_charts') !== '0' } catch { return true } })
  const [openId, setOpenId] = useState(null)
  const [cmd, setCmd] = useState(null)
  const [busy, setBusy] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [sort, setSort] = useState({ key: 'urgency', dir: 'desc' })
  const selection = useSelection()
  const host = params.get('host') || ''

  const load = useCallback(async () => {
    try {
      const p = { status: tab, limit: 2000 }
      if (host) p.host = host
      const { data } = await api.get('/api/v1/alerts', { params: p })
      let list = data.alerts || []
      if (host && tab) list = list.filter(a => a.status === tab) // the per-host query ignores status
      setAlerts(list)
      if (data.counts) setCounts(data.counts)
      setErr('')
    } catch (e) { setErr(e.response?.data?.error || e.message) } finally { setLoading(false) }
  }, [tab, host])
  useEffect(() => { setLoading(true); load() }, [load])
  useEffect(() => { const id = setInterval(load, 30000); return () => clearInterval(id) }, [load])
  useEffect(() => { api.get('/api/v1/users').then(r => setUsers(r.data.users || [])).catch(() => {}) }, [])
  useEffect(() => { selection.clear() }, [tab, host]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { try { localStorage.setItem('ow_alert_charts', charts ? '1' : '0') } catch { /* */ } }, [charts])

  const faceted = useFacetFilter(alerts, GETTERS, facets)
  const rows = useMemo(() => {
    const { fields, text } = parseFilter(q)
    const f = faceted.filter(a => {
      if (text && !`${a.title} ${a.description || ''} ${a.host || ''} ${a.assigned_to || ''} ${a.event_type || ''}`.toLowerCase().includes(text)) return false
      if (fields.host && !fields.host.some(v => (a.host || '').toLowerCase().includes(v))) return false
      if (fields.owner && !fields.owner.some(v => (a.assigned_to || 'unassigned').toLowerCase().includes(v))) return false
      if (fields.sev && !fields.sev.some(v => SEV_WORD[a.severity].toLowerCase().startsWith(v) || String(a.severity) === v)) return false
      return true
    })
    const d = sort.dir === 'asc' ? 1 : -1
    const by = {
      urgency: (a, b) => (b.severity - a.severity) || ((slaOf(b).over || 0) - (slaOf(a).over || 0)) || (new Date(b.created_at) - new Date(a.created_at)),
      time: (a, b) => new Date(a.last_seen || a.created_at) - new Date(b.last_seen || b.created_at),
      host: (a, b) => (a.host || '').localeCompare(b.host || ''),
      owner: (a, b) => (a.assigned_to || '~').localeCompare(b.assigned_to || '~'),
    }[sort.key]
    return f.sort((a, b) => sort.key === 'urgency' ? by(a, b) * (d === -1 ? 1 : -1) : by(a, b) * d)
  }, [faceted, q, sort])

  const toggleFacet = (k, v) => setFacets(s => { const n = { ...s }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
  const onSort = (k) => setSort(s => ({ key: k, dir: s.key === k && s.dir === 'desc' ? 'asc' : 'desc' }))

  const ids = [...selection.selected]
  const acknowledge = async (list) => {
    setBusy(true)
    try { await api.post('/api/v1/alerts/bulk', { ids: list, action: 'acknowledge' }); selection.clear(); await load() }
    catch (e) { window.alert(e.response?.data?.error || 'Acknowledge failed') } finally { setBusy(false) }
  }

  const open = alerts.filter(a => a.status === 'open')
  const breached = alerts.filter(a => slaOf(a).state === 'breached')
  const unassignedCrit = open.filter(a => a.severity >= 4 && !a.assigned_to).length
  const worst = open.reduce((m, a) => Math.max(m, a.severity), 0)
  const histFrom = useMemo(() => {
    const oldest = alerts.reduce((m, a) => Math.min(m, new Date(a.created_at).getTime()), Date.now())
    return new Date(Math.max(oldest, Date.now() - 30 * 86400e3) - 3600e3)
  }, [alerts])

  const facetGroups = [
    { key: 'severity', label: 'Severity', values: countBy(alerts, GETTERS.severity, [5, 4, 3, 2, 1], SEV_WORD) },
    ...(tab === '' ? [{ key: 'status', label: 'Status', values: countBy(alerts, GETTERS.status, ['open', 'acknowledged', 'closed'], { open: 'New', acknowledged: 'In progress', closed: 'Closed' }) }] : []),
    ...(tab !== 'closed' ? [{ key: 'sla', label: 'Response SLA', values: countBy(alerts, GETTERS.sla, ['breached', 'within', 'na'], { breached: 'Past target', within: 'Within target', na: 'Not applicable' }) }] : []),
    { key: 'owner', label: 'Owner', values: countBy(alerts, GETTERS.owner).slice(0, 10) },
    { key: 'host', label: 'Host', values: countBy(alerts, GETTERS.host).slice(0, 12) },
    { key: 'type', label: 'Source', values: countBy(alerts, GETTERS.type).slice(0, 10) },
  ]

  const cols = [
    { key: 'sev', label: 'Severity', width: '92px', sortKey: 'urgency', render: a => <SevPill sev={a.severity}/> },
    { key: 'title', label: 'Alert', width: 'minmax(220px, 2fr)', render: a => (
      <span style={{ display: 'flex', gap: 8, alignItems: 'center', minWidth: 0 }}>
        <span className="t1" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{a.title}</span>
        {a.occurrence_count > 1 && <span className="tag mono" title={`Seen ${a.occurrence_count} times. Repeats within 30 minutes fold into one alert.`}>×{a.occurrence_count}</span>}
      </span>), title: a => a.description || a.title },
    { key: 'host', label: 'Host', width: 'minmax(130px, 1fr)', sortKey: 'host', render: a => a.host ? <span className="mono t1">{a.host}</span> : <span className="t3">—</span> },
    { key: 'owner', label: 'Owner', width: '96px', sortKey: 'owner', render: a => a.assigned_to ? <span className="t1">{a.assigned_to}</span> : <span className="t3">Unassigned</span> },
    { key: 'status', label: 'Status', width: '100px', render: a => { const [s, l] = STATUS[a.status] || STATUS.open; return <StatePill state={s} dot={a.status !== 'open'}>{l}</StatePill> } },
    { key: 'sla', label: 'Age', width: '108px', render: a => {
      const s = slaOf(a)
      return <span style={{ color: s.state === 'breached' ? 'var(--crit)' : 'var(--t2)' }} title={SLA_TEXT}>
        {relTime(a.created_at).replace(' ago', '')}{s.state === 'breached' && <> · {dur(s.over)} over</>}</span>
    } },
    { key: 'seen', label: 'Last seen', width: '88px', sortKey: 'time', render: a => <span className="t2">{relTime(a.last_seen || a.created_at)}</span>, title: a => new Date(a.last_seen || a.created_at).toLocaleString() },
  ]

  const exportCSV = () => downloadCSV(`alerts-${tab || 'all'}-${new Date().toISOString().slice(0, 10)}.csv`,
    ['id', 'severity', 'status', 'title', 'host', 'owner', 'source', 'created_at', 'last_seen', 'occurrences', 'past_sla'],
    rows.map(a => [a.id, SEV_WORD[a.severity], a.status, a.title, a.host, a.assigned_to || '', a.event_type, a.created_at, a.last_seen, a.occurrence_count || 1, slaOf(a).state === 'breached']))

  const tabN = { open: counts.open, acknowledged: counts.acknowledged, closed: counts.closed }
  return (
    <div>
      {showNew && <NewAlertDialog onClose={() => setShowNew(false)} onCreated={load}/>}
      {cmd && <CommandDialog action={cmd.action} ids={cmd.ids} users={users} onClose={() => setCmd(null)} onDone={() => { selection.clear(); load() }}/>}
      <PageHeader
        title="Alerts"
        state={loading ? undefined : counts.open ? (worst >= 5 ? 'crit' : worst >= 4 ? 'warn' : 'info') : 'ok'}
        stateText={counts.open ? `${counts.open.toLocaleString()} unhandled` : 'Nothing unhandled'}
        sub={<>{host && <>Host <span className="mono t1">{host}</span> <button className="ow-btn quiet" style={{ height: 20, padding: '0 4px' }} onClick={() => setParams({})}>clear</button> · </>}
          {breached.length ? <span className="c-crit">{breached.length} past response target. </span> : 'Every unhandled alert is within its response target. '}
          <span title={SLA_TEXT} style={{ textDecoration: 'underline dotted', cursor: 'help' }}>Targets</span></>}
        actions={<>
          <button className="ow-btn" onClick={() => setCharts(c => !c)} aria-pressed={charts}><BarChart3 size={13}/>{charts ? 'Hide charts' : 'Show charts'}</button>
          <button className="ow-btn" onClick={exportCSV} disabled={!rows.length}><Download size={13}/>Export</button>
          <button className="ow-btn" onClick={load} title="Refresh (also every 30 s)"><RefreshCw size={13}/></button>
          <button className="ow-btn primary" onClick={() => setShowNew(true)}><Plus size={13}/>New alert</button>
        </>}
        nums={<>
          <Num k="Unhandled" v={(counts.open ?? 0).toLocaleString()} tone={counts.open ? 'crit' : undefined}/>
          <Num k="Past response target" v={breached.length} tone={breached.length ? 'crit' : undefined} title={SLA_TEXT}/>
          <Num k="High or critical, unassigned" v={unassignedCrit} tone={unassignedCrit ? 'warn' : undefined}/>
          <Num k="In progress" v={(counts.acknowledged ?? 0).toLocaleString()}/>
          <Num k="Closed" v={(counts.closed ?? 0).toLocaleString()}/>
          <Num k={tab === 'open' ? 'Unhandled by severity' : 'This view by severity'} grow={2}>
            <div style={{ marginTop: 6 }}><StateBar parts={[5, 4, 3, 2, 1].map(s => ({ n: alerts.filter(a => a.severity === s).length, state: { 5: 'crit', 4: 'warn', 3: 'acc', 2: 'none', 1: 'none' }[s], label: SEV_WORD[s].toLowerCase() }))}/></div>
          </Num>
        </>}
        tabs={<Tabs value={tab} onChange={(t) => { setTab(t); setFacets({}) }} tabs={TABS.map(t => ({ ...t, n: t.id ? tabN[t.id] : null }))}/>}
      />
      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {charts && alerts.length > 0 && (
          <div className="ow-card" style={{ padding: '14px 16px', display: 'flex', gap: 24, flexWrap: 'wrap' }}>
            <div style={{ flex: '3 1 420px', minWidth: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontWeight: 500 }}>Created over time</span>
                <span style={{ display: 'flex', gap: 12, fontSize: 11.5, color: 'var(--t3)' }}>{SEV_STACKS.slice().reverse().map(s => <span key={s.k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: s.color }}/>{s.label}</span>)}</span>
              </div>
              <Histogram items={alerts.map(a => ({ t: a.created_at, k: a.severity }))} stacks={SEV_STACKS} from={histFrom} label="alerts"/>
            </div>
            <TopList title="Top hosts" rows={countBy(alerts, GETTERS.host)} onPick={v => toggleFacet('host', v)}/>
            <TopList title="Top detections" rows={countBy(alerts, a => a.title)} onPick={v => setQ(v)}/>
          </div>
        )}
        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <Facets groups={facetGroups} selected={facets} onToggle={toggleFacet} onClear={() => setFacets({})}/>
          <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
            {selection.selected.size > 0 ? (
              <SelectionBar count={selection.selected.size} total={rows.length} allMatching={rows.every(a => selection.selected.has(a.id))}
                onSelectAllMatching={() => selection.setAll(rows.map(a => a.id))} onClear={selection.clear}>
                {tab !== 'acknowledged' && tab !== 'closed' && <button className="ow-btn" style={{ height: 26 }} disabled={busy} onClick={() => acknowledge(ids)}>Acknowledge</button>}
                {tab !== 'closed' && <button className="ow-btn" style={{ height: 26 }} onClick={() => setCmd({ action: 'assign', ids })}>Assign…</button>}
                {tab !== 'closed' && <button className="ow-btn" style={{ height: 26 }} onClick={() => setCmd({ action: 'close', ids })}>Close…</button>}
              </SelectionBar>
            ) : (
              <div className="ow-card-bar">
                <label className="ow-field" style={{ flex: 1, maxWidth: 420, height: 28 }}>
                  <Search size={13} style={{ color: 'var(--t3)' }}/>
                  <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter · text, host:web owner:unassigned sev:critical" aria-label="Filter alerts"/>
                  {q && <button onClick={() => setQ('')} aria-label="Clear filter" style={{ background: 'none', border: 0, color: 'var(--t3)', cursor: 'pointer' }}><X size={12}/></button>}
                </label>
                <span className="t2" style={{ fontSize: 12 }}>{rows.length.toLocaleString()} of {alerts.length.toLocaleString()}</span>
                <span className="t3" style={{ marginLeft: 'auto', fontSize: 12 }}>Sorted by {{ urgency: 'urgency', time: 'last seen', host: 'host', owner: 'owner' }[sort.key]}</span>
              </div>
            )}
            {err && <div className="c-crit" style={{ padding: '10px 14px' }}>Could not load alerts: {err}</div>}
            <DenseTable cols={cols} rows={loading ? [] : rows.slice(0, 500)} rowKey={a => a.id}
              rowState={a => a.status === 'closed' ? null : a.severity >= 5 ? 'crit' : a.severity >= 4 ? 'warn' : null}
              onRow={a => setOpenId(a.id)} current={openId}
              selected={selection.selected} onSelect={selection.onSelect}
              onSelectAll={v => v ? selection.setAll(rows.slice(0, 500).map(a => a.id)) : selection.clear()}
              sort={sort} onSort={onSort}
              empty={loading ? 'Loading…' : alerts.length ? 'No alerts match these filters.' : tab === 'open' ? 'Nothing unhandled. New alerts appear here as detections fire.' : 'No alerts in this view.'}/>
            {rows.length > 500 && <div className="ow-card-foot">Showing the 500 most urgent of {rows.length.toLocaleString()}. Narrow the filters, or select all matching to act on every one.</div>}
          </div>
        </div>
      </div>
      <Drawer open={!!openId} onClose={() => setOpenId(null)} label="Alert details">
        {openId && <AlertPanel alertId={openId} users={users} onClose={() => setOpenId(null)} onStatusChange={load} inline/>}
      </Drawer>
    </div>
  )
}
