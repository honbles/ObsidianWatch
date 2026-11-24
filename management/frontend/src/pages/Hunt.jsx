import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Crosshair, Play, Loader2, Download, ChevronDown, ChevronRight, History, Radar, WifiOff, Search } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { PageHeader, Tabs } from '../components/ui'
import { isAdminUser } from '../components/ResponseActions.jsx'

// Threat hunting at scale.
//  - Live query: ask every connected agent a fixed read-only question right now.
//  - History: run a KQL-style query over stored events, rolled up per host.

const KINDS = [
  ['processes', 'Running processes', 'e.g. powershell  or  name:curl cmdline:http'],
  ['connections', 'Network connections', 'e.g. 203.0.113.7  or  remote::4444'],
  ['listening', 'Listening ports', 'e.g. 3389  or  local::22'],
  ['persistence', 'Persistence (autoruns, tasks, cron...)', 'e.g. powershell  or  type:run_key'],
  ['software', 'Installed software', 'e.g. anydesk teamviewer (any of the words must match)'],
  ['users', 'Local users', 'e.g. admin:yes'],
  ['file_find', 'Find a file', 'file name text, or sha256:<64 hex>'],
]

function Table({ cols, rows }) {
  return (
    <div className="overflow-x-auto max-h-80 border border-siem-border/50 rounded">
      <table className="w-full text-[11px]">
        <thead><tr className="bg-siem-surface/60 sticky top-0">{cols.map(c => <th key={c} className="text-left px-2 py-1 text-[9px] uppercase text-siem-muted">{c}</th>)}</tr></thead>
        <tbody>{rows.map((r, i) => <tr key={i} className="border-t border-siem-border/30">{r.map((v, j) => <td key={j} className="px-2 py-1 font-mono break-all max-w-[420px]">{v}</td>)}</tr>)}</tbody>
      </table>
    </div>
  )
}

function HuntResults({ id }) {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState({})
  const timer = useRef(null)
  useEffect(() => {
    let stop = false
    const load = async () => {
      try {
        const { data } = await api.get(`/api/v1/hunt/live/${id}`)
        if (stop) return
        setData(data)
        if (!data.hunt.completed_at) timer.current = setTimeout(load, data.hunt.queued > 0 ? 15000 : 2500)
      } catch { /* ignore */ }
    }
    load()
    return () => { stop = true; clearTimeout(timer.current) }
  }, [id])
  if (!data) return <div className="p-4 text-xs text-siem-muted"><Loader2 size={14} className="animate-spin inline mr-2" />Loading…</div>
  const { hunt, results } = data
  const done = !!hunt.completed_at
  const download = async () => {
    const r = await api.get(`/api/v1/hunt/live/${id}/csv`, { responseType: 'blob' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(r.data); a.download = `hunt-${id}.csv`; a.click()
  }
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="text-sm font-semibold text-siem-text">{hunt.name}</div>
        <span className="text-[10px] text-siem-muted">{hunt.responded}/{hunt.agents_total} hosts answered</span>
        <span className="text-[10px] text-siem-muted">{hunt.hosts_with_hits} with hits · {hunt.total_rows} rows</span>
        {!done && <span className="text-[10px] text-amber-300 flex items-center gap-1"><Loader2 size={11} className="animate-spin" /> {hunt.queued > 0 ? `${hunt.queued} waiting for hosts to come online` : 'collecting…'}</span>}
        {hunt.expires_at && !done && <span className="text-[10px] text-siem-muted">window ends {formatDistanceToNow(new Date(hunt.expires_at), { addSuffix: true })}</span>}
        <button onClick={download} className="ml-auto text-[11px] text-siem-muted hover:text-siem-text flex items-center gap-1"><Download size={12} /> CSV</button>
      </div>
      <div className="rounded-xl border border-siem-border overflow-hidden">
        {results.map(r => {
          const cols = r.columns || [], rows = r.rows || []
          const isOpen = open[r.agent_id]
          const hit = r.row_count > 0
          return (
            <div key={r.agent_id} className="border-b border-siem-border/40 last:border-0">
              <div className={`flex items-center gap-2 px-3 py-2 ${hit ? 'cursor-pointer hover:bg-white/[0.03]' : ''}`} onClick={() => hit && setOpen(o => ({ ...o, [r.agent_id]: !o[r.agent_id] }))}>
                {hit ? (isOpen ? <ChevronDown size={12} /> : <ChevronRight size={12} />) : <span className="w-3" />}
                <span className="text-xs font-medium text-siem-text">{r.hostname}</span>
                <span className="text-[10px] text-siem-muted">{r.os}</span>
                <span className={`ml-auto text-[10px] ${r.status === 'ok' ? (hit ? 'text-orange-300' : 'text-siem-muted') : (r.status === 'pending' || r.status === 'queued') ? 'text-amber-300' : 'text-red-300'}`}>
                  {r.status === 'ok' ? `${r.row_count} row${r.row_count === 1 ? '' : 's'}${r.truncated ? '+' : ''}${r.was_queued ? ' · answered late' : ''}` : r.status === 'queued' ? 'offline, will run when it reconnects' : r.status === 'pending' ? 'waiting…' : `${r.status}: ${r.message}`}
                </span>
              </div>
              {isOpen && hit && <div className="px-3 pb-3"><Table cols={cols} rows={rows} /></div>}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function LiveTab({ library, initial }) {
  const admin = isAdminUser()
  const [kind, setKind] = useState(initial?.kind || 'processes')
  const [match, setMatch] = useState(initial?.match || '')
  const [path, setPath] = useState('')
  const [os, setOS] = useState('')
  const [offline, setOffline] = useState('skip')
  const [waitH, setWaitH] = useState(24)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [hunts, setHunts] = useState([])
  const [active, setActive] = useState(null)
  const loadHunts = async () => { try { setHunts((await api.get('/api/v1/hunt/live')).data.hunts || []) } catch { /* */ } }
  useEffect(() => { loadHunts() }, [])
  useEffect(() => { if (initial) { setKind(initial.kind); setMatch(initial.match || '') } }, [initial])
  const hint = KINDS.find(k => k[0] === kind)?.[2]
  const run = async () => {
    setBusy(true); setErr('')
    try {
      const { data } = await api.post('/api/v1/hunt/live', { kind, match, path, os, offline, wait_hours: waitH })
      setActive(data.id); loadHunts()
    } catch (e) { setErr(e.response?.data?.error || e.message) } finally { setBusy(false) }
  }
  return (
    <div className="grid lg:grid-cols-[340px_1fr] gap-5">
      <div className="space-y-4">
        <div className="rounded-xl border border-siem-border bg-siem-surface/40 p-4 space-y-2.5">
          <div className="text-xs font-semibold text-siem-text">Ask the fleet</div>
          <select value={kind} onChange={e => setKind(e.target.value)} className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text">
            {KINDS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          <input value={match} onChange={e => setMatch(e.target.value)} placeholder={hint} className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />
          {kind === 'file_find' && <input value={path} onChange={e => setPath(e.target.value)} placeholder="Folder to search (default: C:\Users or /)" className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />}
          <select value={os} onChange={e => setOS(e.target.value)} className="w-full bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text">
            <option value="">All operating systems</option><option value="windows">Windows</option><option value="linux">Linux</option><option value="darwin">macOS</option>
          </select>
          <div className="flex items-center gap-2 text-xs text-siem-text">
            <span className="text-siem-muted">Offline hosts</span>
            <select value={offline} onChange={e => setOffline(e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1 text-xs">
              <option value="skip">Skip</option><option value="wait">Wait for them</option>
            </select>
            {offline === 'wait' && (
              <select value={waitH} onChange={e => setWaitH(+e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1 text-xs">
                <option value={1}>1 hour</option><option value={24}>24 hours</option><option value={72}>3 days</option><option value={168}>7 days</option>
              </select>
            )}
          </div>
          {offline === 'wait' && <div className="text-[10px] text-siem-muted">Offline hosts get the question the moment they reconnect, until the window ends. Late answers are marked.</div>}
          <div className="text-[10px] text-siem-muted">Fixed, read-only questions: nothing is executed on the host. Several words must all match; <code>col:text</code> limits a word to one column. Hosts need a live tunnel to answer.</div>
          {admin ? (
            <button onClick={run} disabled={busy || (kind === 'file_find' && !match)} className="w-full px-3 py-2 rounded bg-siem-accent text-white text-xs font-semibold flex items-center justify-center gap-1.5 disabled:opacity-50">
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />} Run on fleet
            </button>
          ) : <div className="text-[11px] text-amber-300">Admin role required to run live queries.</div>}
          {err && <div className="text-[11px] text-red-300">{err}</div>}
        </div>
        <div className="rounded-xl border border-siem-border bg-siem-surface/40 p-3">
          <div className="text-[10px] uppercase tracking-wider text-siem-muted mb-1.5">Recent live hunts</div>
          {hunts.length === 0 && <div className="text-xs text-siem-muted">None yet.</div>}
          {hunts.map(h => (
            <button key={h.id} onClick={() => setActive(h.id)} className={`w-full text-left px-2 py-1.5 rounded text-xs hover:bg-white/[0.04] ${active === h.id ? 'bg-white/[0.06]' : ''}`}>
              <div className="text-siem-text truncate">{h.name}</div>
              <div className="text-[10px] text-siem-muted">{h.hosts_with_hits}/{h.agents_total} hosts with hits · {formatDistanceToNow(new Date(h.created_at), { addSuffix: true })} · {h.requested_by}</div>
            </button>
          ))}
        </div>
      </div>
      <div>{active ? <HuntResults id={active} key={active} /> : <div className="rounded-xl border border-dashed border-siem-border p-10 text-center text-xs text-siem-muted"><Radar size={22} className="mx-auto mb-2 opacity-60" />Pick a question and run it on the fleet, or open a recent hunt.</div>}</div>
    </div>
  )
}

function HistoryTab({ initial }) {
  const nav = useNavigate()
  const [q, setQ] = useState(initial?.query || '')
  const [since, setSince] = useState('7d')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [res, setRes] = useState(null)
  useEffect(() => { if (initial?.query) { setQ(initial.query); setRes(null) } }, [initial])
  const run = async (query = q) => {
    if (!query.trim()) return
    setBusy(true); setErr('')
    try { setRes((await api.get('/api/v1/hunt/history', { params: { q: query, since } })).data) }
    catch (e) { setErr(e.response?.data?.error || e.message); setRes(null) } finally { setBusy(false) }
  }
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-siem-border bg-siem-surface/40 p-4 space-y-2.5">
        <div className="text-xs font-semibold text-siem-text">Which hosts match this query in stored events?</div>
        <div className="flex gap-2 flex-wrap">
          <input value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === 'Enter' && run()} placeholder='type:process cmd:"-enc" and not user:SYSTEM' className="flex-1 min-w-[280px] bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text font-mono" />
          <select value={since} onChange={e => setSince(e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1.5 text-xs text-siem-text">
            {[['1h', 'Last hour'], ['6h', 'Last 6 hours'], ['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['90d', 'Last 90 days']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          <button onClick={() => run()} disabled={busy || !q.trim()} className="px-3 py-1.5 rounded bg-siem-accent text-white text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50">{busy ? <Loader2 size={13} className="animate-spin" /> : <Search size={13} />} Hunt</button>
        </div>
        <div className="text-[10px] text-siem-muted">Same query language as the Events page (fields: host, user, proc, cmd, image, file, hash, dst, port, type, sev, time; and / or / not; * wildcard).</div>
        {err && <div className="text-[11px] text-red-300">{err}</div>}
      </div>
      {res && (
        <div className="rounded-xl border border-siem-border overflow-hidden">
          <div className="px-3 py-2 bg-siem-surface/40 text-xs text-siem-text"><b>{res.total_hosts}</b> host{res.total_hosts === 1 ? '' : 's'} · <b>{res.total_events?.toLocaleString()}</b> events</div>
          {res.hosts.length === 0 ? <div className="p-4 text-xs text-siem-muted">No host matches in this window.</div> : (
            <table className="w-full text-xs">
              <thead><tr className="text-[9px] uppercase text-siem-muted"><th className="text-left px-3 py-1.5">Host</th><th className="text-right px-3 py-1.5">Events</th><th className="text-left px-3 py-1.5">First / last</th><th className="text-left px-3 py-1.5">Latest sample</th><th /></tr></thead>
              <tbody>
                {res.hosts.map(h => (
                  <tr key={h.agent_id + h.host} className="border-t border-siem-border/40 align-top">
                    <td className="px-3 py-2 font-medium text-siem-text">{h.host}<div className="text-[10px] text-siem-muted">{(h.event_types || []).join(', ')}</div></td>
                    <td className="px-3 py-2 text-right">{h.count.toLocaleString()}</td>
                    <td className="px-3 py-2 text-[10px] text-siem-muted whitespace-nowrap">{formatDistanceToNow(new Date(h.first), { addSuffix: true })}<br />{formatDistanceToNow(new Date(h.last), { addSuffix: true })}</td>
                    <td className="px-3 py-2 font-mono text-[10px] break-all max-w-[420px]">{h.sample}</td>
                    <td className="px-3 py-2 text-right whitespace-nowrap">
                      <button onClick={() => nav(`/events?host=${encodeURIComponent(h.host)}&search=${encodeURIComponent(q)}`)} className="text-siem-accent hover:underline text-[11px]">Open events</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  )
}

export default function Hunt() {
  const [tab, setTab] = useState('history')
  const [lib, setLib] = useState([])
  // ?q= seeds a history hunt (the global search hands queries over this way)
  const [params] = useSearchParams()
  const [pick, setPick] = useState(() => params.get('q') ? { mode: 'history', query: params.get('q'), n: Date.now() } : null)
  useEffect(() => { const q = params.get('q'); if (q) { setPick({ mode: 'history', query: q, n: Date.now() }); setTab('history') } }, [params])
  useEffect(() => { api.get('/api/v1/hunt/library').then(r => setLib(r.data.hunts || [])).catch(() => {}) }, [])
  const choose = h => { setPick({ ...h, n: Date.now() }); setTab(h.mode) }
  const groups = useMemo(() => ({ history: lib.filter(h => h.mode === 'history'), live: lib.filter(h => h.mode === 'live') }), [lib])
  return (
    <div>
      <PageHeader title="Hunt"
        sub="Ask a question of stored events across every host, or query the fleet live. Start from the library on the right, or write your own."
        tabs={<Tabs value={tab} onChange={setTab} tabs={[{ id: 'history', label: 'Stored events' }, { id: 'live', label: 'Live fleet query' }]}/>}/>
      <div className="ow-body">
      <div className="grid xl:grid-cols-[1fr_320px] gap-4 items-start">
        <div>{tab === 'history' ? <HistoryTab initial={pick?.mode === 'history' ? pick : null} /> : <LiveTab initial={pick?.mode === 'live' ? pick : null} />}</div>
        <div className="ow-card" style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontWeight: 600 }}>Hunt library</div>
          {[['history', 'On stored events'], ['live', 'Live on the fleet']].map(([m, l]) => (
            <div key={m}>
              <div className="ow-lbl" style={{ marginBottom: 4 }}>{l}</div>
              {groups[m].map(h => (
                <button key={h.id} onClick={() => choose(h)} className="ow-fc" style={{ height: 'auto', padding: '6px 8px', flexDirection: 'column', alignItems: 'flex-start', gap: 2 }}>
                  <span className="t1" style={{ whiteSpace: 'normal' }}>{h.title || h.name}{h.attack && <span className="mono t3" style={{ marginLeft: 6, fontSize: 11 }}>{h.attack}</span>}</span>
                  {h.desc && <span className="t3" style={{ fontSize: 11.5, whiteSpace: 'normal' }}>{h.desc}</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
    </div>
  )
}
