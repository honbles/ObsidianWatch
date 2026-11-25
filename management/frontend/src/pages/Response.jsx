// Response: one place to act on hosts. Pick hosts, pick an action, give a reason, review, run.
// Every action is recorded server-side with who asked, why and the outcome (History tab).
// Isolation and release queue for offline hosts; other actions need the host's live tunnel.
import { useEffect, useMemo, useState, useCallback } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { ShieldAlert, ShieldCheck, Skull, Ban, RotateCcw, FileX2, ArchiveRestore, ListChecks, RefreshCw, Terminal, Trash2, FileSearch, Download, Globe, UserX, UserCheck } from 'lucide-react'
import api from '../api/client'
import { runAction, isAdminUser } from '../components/ResponseActions.jsx'
import { ProcessPicker } from '../components/ProcessList.jsx'
import LiveResponse from './LiveResponse'
import { getOSCategory } from './agents/shared.jsx'
import { isProbe } from '../utils/states'
import {
  PageHeader, Num, Tabs, StatePill, Facets, countBy, useFacetFilter, DenseTable, relTime, useSelection, Dialog, Field,
} from '../components/ui'

// What each action does, what it needs, and whether it can reach an offline host.
export const ACTIONS = [
  // Network
  { id: 'isolate', group: 'Network', label: 'Isolate', icon: ShieldAlert, multi: true, queues: true, danger: true,
    help: 'Cuts the host off from every other machine and the internet. ObsidianWatch stays reachable, so you can keep investigating. The user gets a pop-up saying the computer is isolated, again whenever they try to reach a site.' },
  { id: 'release', group: 'Network', label: 'Release isolation', icon: ShieldCheck, multi: true, queues: true,
    help: 'Restores normal networking.' },
  { id: 'block_ip', group: 'Network', label: 'Block IP address', icon: Globe, multi: true, danger: true,
    help: 'Drops all traffic to and from one address (a C2 server, a scanner) without isolating the host. Survives restarts. The ObsidianWatch servers cannot be blocked.' },
  { id: 'unblock_ip', group: 'Network', label: 'Unblock IP address', icon: RotateCcw, multi: true,
    help: 'Lifts an address block.' },
  { id: 'list_blocked_ips', group: 'Network', label: 'Blocked IPs', icon: ListChecks, multi: true, readOnly: true,
    help: 'Shows the addresses blocked on each selected host.' },
  // Processes
  { id: 'kill_process', group: 'Processes', label: 'Kill process', icon: Skull, multi: false, danger: true,
    help: 'Ends one process (and optionally its children) on one host. Pick it from the live process list. The expected image guards against PID reuse.' },
  { id: 'block_process', group: 'Processes', label: 'Block program', icon: Ban, multi: true, danger: true,
    help: 'Makes the program non-executable and ends it every time it starts, until unblocked. System files and the agent itself cannot be blocked.' },
  { id: 'unblock_process', group: 'Processes', label: 'Unblock program', icon: RotateCcw, multi: true,
    help: 'Lets a blocked program run again.' },
  { id: 'list_blocked', group: 'Processes', label: 'Blocked programs', icon: ListChecks, multi: true, readOnly: true,
    help: 'Shows what is currently blocked on each selected host.' },
  // Files
  { id: 'quarantine_file', group: 'Files', label: 'Quarantine file', icon: FileX2, multi: true, danger: true,
    help: 'Moves the file into a locked vault on the host, recording its SHA-256. It can be restored or deleted from the vault later.' },
  { id: 'delete_file', group: 'Files', label: 'Delete file', icon: Trash2, multi: true, danger: true,
    help: 'Permanently deletes the file. Give its SHA-256 to delete it only if it is still the same file. Prefer quarantine when you may need it back. System files cannot be deleted.' },
  { id: 'restore_file', group: 'Files', label: 'Restore from vault', icon: ArchiveRestore, multi: false,
    help: 'Puts a quarantined file back where it was. Choose it from the host\'s vault.' },
  { id: 'delete_quarantined', group: 'Files', label: 'Delete from vault', icon: Trash2, multi: false, danger: true,
    help: 'Permanently destroys a quarantined file. Choose it from the host\'s vault. This cannot be undone.' },
  { id: 'file_info', group: 'Files', label: 'File details', icon: FileSearch, multi: true, readOnly: true,
    help: 'Size, permissions, modification time and SHA-256 of a file on each selected host. Changes nothing.' },
  { id: 'collect_file', group: 'Files', label: 'Collect file', icon: Download, multi: false,
    help: 'Brings a copy of a file (up to 2 MB) back for analysis. Only administrators can download it, and each download is audited.' },
  { id: 'list_quarantine', group: 'Files', label: 'Quarantine vault', icon: ListChecks, multi: true, readOnly: true,
    help: 'Shows the quarantined files on each selected host.' },
  // Accounts
  { id: 'disable_user', group: 'Accounts', label: 'Disable account', icon: UserX, multi: true, danger: true,
    help: 'Locks a local account and ends its running processes. On Linux the account is also expired, which stops SSH key logins. Domain accounts must be disabled in the directory.' },
  { id: 'enable_user', group: 'Accounts', label: 'Enable account', icon: UserCheck, multi: true,
    help: 'Unlocks a local account disabled here.' },
]
const GROUPS = ['Network', 'Processes', 'Files', 'Accounts']
const BY_ID = Object.fromEntries(ACTIONS.map(a => [a.id, a]))
const TTLS = [['Until released', 0], ['1 hour', 60], ['4 hours', 240], ['24 hours', 1440], ['7 days', 10080]]
const isAbs = (p) => /^([A-Za-z]:[\\/]|\/|\\\\)/.test(p || '')

const STATUS = { ok: ['ok', 'Done'], sent: ['info', 'Sent'], queued: ['info', 'Queued'], pending: ['info', 'Pending'], failed: ['crit', 'Failed'], timeout: ['crit', 'Timed out'], error: ['crit', 'Failed'] }
export function ActionStatus({ status }) {
  const [s, l] = STATUS[status] || ['none', status]
  return <StatePill state={s}>{l}</StatePill>
}
export function describeParams(a) {
  const p = typeof a.params === 'string' ? (() => { try { return JSON.parse(a.params) } catch { return {} } })() : (a.params || {})
  if (p.pid) return `PID ${p.pid}${p.image ? ' · ' + p.image : ''}${p.tree ? ' · with children' : ''}`
  if (p.path) return p.path + (p.sha256 ? ` · sha256 ${p.sha256.slice(0, 12)}…` : '')
  if (p.id) return `vault item ${p.id}`
  if (p.ip) return p.ip
  if (p.user) return `account ${p.user}`
  if (a.action === 'isolate') return (p.ttl_minutes ? `for ${p.ttl_minutes >= 1440 ? p.ttl_minutes / 1440 + ' d' : p.ttl_minutes / 60 + ' h'}` : 'until released') + (p.no_block_page ? ' · silent' : '')
  return ''
}

const PATH_ACTIONS = ['block_process', 'unblock_process', 'quarantine_file', 'delete_file', 'file_info', 'collect_file']
const VAULT_ACTIONS = ['restore_file', 'delete_quarantined']
const IP_ACTIONS = ['block_ip', 'unblock_ip']
const USER_ACTIONS = ['disable_user', 'enable_user']
const isIP = (s) => /^\s*(\d{1,3}(\.\d{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)\s*$/.test(s || '')

function FileFactsView({ f }) {
  return (
    <div className="mono t2" style={{ fontSize: 11.5, marginTop: 4, display: 'grid', gridTemplateColumns: '70px 1fr', gap: '2px 8px' }}>
      <span className="t3">sha256</span><span style={{ wordBreak: 'break-all' }}>{f.sha256}</span>
      <span className="t3">size</span><span>{f.size?.toLocaleString()} bytes</span>
      {f.mode && <><span className="t3">mode</span><span>{f.mode}</span></>}
      {f.modified && <><span className="t3">modified</span><span>{new Date(f.modified).toLocaleString()}</span></>}
      {f.deleted && <><span className="t3">state</span><span className="c-crit">deleted</span></>}
    </div>
  )
}

// Downloads go through the API client so the session token is sent.
export function CollectedDownload({ id, name }) {
  const [err, setErr] = useState('')
  const get = async () => {
    setErr('')
    try {
      const r = await api.get(`/api/v1/response/actions/${encodeURIComponent(id)}/file`, { responseType: 'blob' })
      const a = document.createElement('a'); a.href = URL.createObjectURL(r.data)
      a.download = ((name || 'collected').split(/[\\/]/).pop() || 'collected') + '.collected'; a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 5000)
    } catch { setErr('Download failed') }
  }
  return <div style={{ marginTop: 6 }}><button className="ow-btn" style={{ height: 26 }} onClick={get}><Download size={12}/>Download copy</button>{err && <span className="c-crit" style={{ marginLeft: 8, fontSize: 12 }}>{err}</span>}</div>
}

// ── Run action ────────────────────────────────────────────────────────────────
function RunAction({ hosts, preselect, onDone }) {
  const admin = isAdminUser()
  const sel = useSelection()
  const [facets, setFacets] = useState({})
  const [q, setQ] = useState('')
  const [action, setAction] = useState('isolate')
  const [params, setParams] = useState({ ttl_minutes: 0, block_page: true, pid: '', image: '', tree: true, path: '', id: '', sha256: '', ip: '', user: '' })
  const [reason, setReason] = useState('')
  const [review, setReview] = useState(false)
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState(null)
  const [vault, setVault] = useState(null)

  useEffect(() => { if (preselect.length) sel.setAll(preselect) }, [preselect.join(',')]) // eslint-disable-line react-hooks/exhaustive-deps

  const G = useMemo(() => ({
    conn: h => h.tunnel_online ? 'live' : h.online ? 'no_tunnel' : 'offline',
    os: h => getOSCategory(h.os),
    tags: h => h.tags.length ? h.tags : '(none)',
    iso: h => h.isolated ? 'isolated' : h.isolationPending ? 'pending' : 'normal',
  }), [])
  const faceted = useFacetFilter(hosts, G, facets)
  const shown = faceted.filter(h => !q || `${h.hostname} ${h.last_ip} ${h.tags.join(' ')}`.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => a.hostname.localeCompare(b.hostname))
  const chosen = hosts.filter(h => sel.selected.has(h.id))
  const def = BY_ID[action]
  const single = chosen.length === 1 ? chosen[0] : null

  // Who this action can actually reach right now.
  const reach = (h) => h.tunnel_online ? 'run' : def.queues ? 'queue' : 'skip'
  const runnable = chosen.filter(h => reach(h) !== 'skip')

  const paramErr = (() => {
    if (!chosen.length) return 'Select at least one host'
    if (!def.multi && chosen.length > 1) return `${def.label} works on one host at a time`
    if (action === 'kill_process' && !(+params.pid > 1)) return 'Pick a process or enter its PID'
    if (PATH_ACTIONS.includes(action) && !isAbs(params.path)) return 'Enter the full path'
    if (action === 'delete_file' && params.sha256 && !/^[0-9a-fA-F]{64}$/.test(params.sha256.trim())) return 'SHA-256 must be 64 hex characters'
    if (VAULT_ACTIONS.includes(action) && !/^[0-9a-f]{16}$/.test(params.id)) return 'Choose a file from the vault'
    if (IP_ACTIONS.includes(action) && !isIP(params.ip)) return 'Enter one IPv4 or IPv6 address'
    if (USER_ACTIONS.includes(action) && !/^[A-Za-z0-9_][A-Za-z0-9._@ -]{0,63}$/.test(params.user.trim())) return 'Enter the local account name'
    if (def.danger && !reason.trim()) return 'Give a reason. It is kept with the action and in the audit log'
    if (!runnable.length) return 'None of the selected hosts can be reached for this action'
    return ''
  })()

  const payload = () => {
    switch (action) {
      case 'isolate': return { ttl_minutes: +params.ttl_minutes, ...(params.block_page ? {} : { no_block_page: true }) }
      case 'kill_process': return { pid: +params.pid, image: params.image, tree: params.tree }
      case 'delete_file': return { path: params.path, ...(params.sha256.trim() ? { sha256: params.sha256.trim().toLowerCase() } : {}) }
      case 'restore_file': case 'delete_quarantined': return { id: params.id }
      case 'block_ip': case 'unblock_ip': return { ip: params.ip.trim() }
      case 'disable_user': case 'enable_user': return { user: params.user.trim() }
      default: return PATH_ACTIONS.includes(action) ? { path: params.path } : {}
    }
  }

  const run = async () => {
    setRunning(true)
    const out = []
    await Promise.all(chosen.map(async h => {
      if (reach(h) === 'skip') { out.push({ host: h, status: 'skipped', text: 'Host offline or its response tunnel is not connected' }); return }
      const r = await runAction(h.id, action, payload(), { reason: reason.trim() })
      out.push({ host: h, status: r.ok ? (r.data?.status || 'ok') : 'failed', text: r.data?.message || r.error || '', result: r.data?.result, actionId: r.data?.id })
    }))
    out.sort((a, b) => a.host.hostname.localeCompare(b.host.hostname))
    setResults(out); setRunning(false); setReview(false); onDone()
  }

  const loadVault = async () => {
    if (!single) return
    const r = await runAction(single.id, 'list_quarantine', {})
    setVault(r.ok ? (r.data?.result || []) : { error: r.error || r.data?.message || 'Could not read the vault' })
  }
  useEffect(() => { setVault(null) }, [single?.id, action])

  const toggle = (k, v) => setFacets(f => { const n = { ...f }; const s = new Set(n[k] || []); s.has(v) ? s.delete(v) : s.add(v); n[k] = s; return n })

  if (!admin) return <div className="ow-card" style={{ padding: 24 }}>Response actions are for administrators. You can still see every action in History.</div>

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(520px, 1.25fr) minmax(380px, 1fr)', gap: 16, alignItems: 'start' }}>
      {/* 1. Targets */}
      <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start', minWidth: 0 }}>
        <Facets selected={facets} onToggle={toggle} onClear={() => setFacets({})} groups={[
          { key: 'conn', label: 'Reachable', values: countBy(hosts, G.conn, ['live', 'no_tunnel', 'offline'], { live: 'Live tunnel', no_tunnel: 'Online, no tunnel', offline: 'Offline' }) },
          { key: 'iso', label: 'Isolation', values: countBy(hosts, G.iso, ['isolated', 'pending', 'normal'], { isolated: 'Isolated', pending: 'Pending', normal: 'Not isolated' }) },
          { key: 'os', label: 'OS', values: countBy(hosts, G.os, ['linux', 'windows', 'macos', 'other'], { linux: 'Linux', windows: 'Windows', macos: 'macOS', other: 'Other' }) },
          { key: 'tags', label: 'Tags', values: countBy(hosts, G.tags).slice(0, 12) },
        ]}/>
        <section className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <span style={{ fontWeight: 600 }}>1 · Hosts</span>
            <label className="ow-field" style={{ flex: 1, maxWidth: 260, height: 28 }}><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter hosts" aria-label="Filter hosts"/></label>
            <span className="t2" style={{ fontSize: 12, marginLeft: 'auto' }}>{chosen.length} selected</span>
          </div>
          <DenseTable rows={shown} rowKey={h => h.id} selected={sel.selected} onSelect={sel.onSelect}
            onSelectAll={v => v ? sel.setAll([...new Set([...sel.selected, ...shown.map(h => h.id)])]) : sel.clear()}
            onRow={h => sel.onSelect(h.id, !sel.selected.has(h.id))}
            empty="No hosts match."
            cols={[
              { key: 'h', label: 'Host', width: 'minmax(140px, 1.4fr)', render: h => <span className="mono t1">{h.hostname}</span> },
              { key: 'c', label: 'Reachable', width: '120px', render: h => h.tunnel_online ? <StatePill state="ok">Live</StatePill> : h.online ? <StatePill state="none" title="Agent online but live_response is not enabled or the tunnel is down">No tunnel</StatePill> : <StatePill state="none">Offline</StatePill> },
              { key: 'i', label: 'Isolation', width: '100px', render: h => h.isolated ? <StatePill state="crit">Isolated</StatePill> : h.isolationPending ? <StatePill state="warn">Pending</StatePill> : <span className="t3">—</span> },
              { key: 't', label: 'Tags', width: '1fr', render: h => <span className="t2">{h.tags.join(', ') || '—'}</span> },
            ]}/>
        </section>
      </div>

      {/* 2. Action, 3. Reason, run */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16, position: 'sticky', top: 'calc(var(--topbar-h) + 12px)' }}>
        <section className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>2 · Action</span></div>
          <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
            {GROUPS.map(g => (
              <div key={g}>
                <div className="t3" style={{ fontSize: 11, fontWeight: 600, letterSpacing: '.06em', textTransform: 'uppercase', marginBottom: 6 }}>{g}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 6 }}>
                  {ACTIONS.filter(a => a.group === g).map(a => {
                    const Icon = a.icon
                    const disabled = !a.multi && chosen.length > 1
                    return (
                      <button key={a.id} onClick={() => { setAction(a.id); setResults(null) }} disabled={disabled}
                        title={disabled ? 'One host at a time' : a.help}
                        className={`ow-fc ${action === a.id ? 'on' : ''}`} style={{ height: 32, justifyContent: 'flex-start', gap: 8, opacity: disabled ? 0.4 : 1, border: '1px solid var(--line)' }}>
                        <Icon size={13}/><span>{a.label}</span>
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
            <div className="t2" style={{ fontSize: 12.5, lineHeight: 1.5 }}>{def.help}{def.queues ? ' Offline hosts get it when they reconnect.' : def.readOnly ? '' : ' Needs a live response tunnel on each host.'}</div>

            {action === 'isolate' && (
              <>
                <Field label="Duration"><select className="input" value={params.ttl_minutes} onChange={e => setParams(p => ({ ...p, ttl_minutes: e.target.value }))}>
                  {TTLS.map(([l, v]) => <option key={v} value={v}>{l}</option>)}</select></Field>
                <label className="t2" style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 12.5 }}>
                  <input type="checkbox" className="ow-check" checked={params.block_page} onChange={e => setParams(p => ({ ...p, block_page: e.target.checked }))}/>
                  <span>Tell the user: a pop-up says the computer is isolated and to contact the administrator, at isolation and again (at most every 10 minutes) when they try to reach a site. Off: isolate silently.</span>
                </label>
              </>
            )}
            {IP_ACTIONS.includes(action) && (
              <Field label="IP address" hint="One IPv4 or IPv6 address."><input className="input mono" value={params.ip} onChange={e => setParams(p => ({ ...p, ip: e.target.value }))} placeholder="203.0.113.9"/></Field>
            )}
            {USER_ACTIONS.includes(action) && (
              <Field label="Local account" hint="The account name on the host. System accounts and uid 0 are refused."><input className="input mono" value={params.user} onChange={e => setParams(p => ({ ...p, user: e.target.value }))} placeholder="jdoe"/></Field>
            )}
            {action === 'kill_process' && (
              <>
                {single ? <ProcessPicker agentId={single.id} enabled={!!single.tunnel_online} onPick={p => setParams(x => ({ ...x, pid: String(p.pid), image: p.path || '' }))}/>
                  : <div className="t3" style={{ fontSize: 12 }}>Select one host to pick from its live process list.</div>}
                <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 8 }}>
                  <Field label="PID"><input className="input mono" value={params.pid} onChange={e => setParams(p => ({ ...p, pid: e.target.value.replace(/\D/g, '') }))}/></Field>
                  <Field label="Expected image"><input className="input mono" value={params.image} onChange={e => setParams(p => ({ ...p, image: e.target.value }))} placeholder="/usr/bin/x or C:\…\x.exe"/></Field>
                </div>
                <label className="t2" style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5 }}><input type="checkbox" className="ow-check" checked={params.tree} onChange={e => setParams(p => ({ ...p, tree: e.target.checked }))}/>Also kill its child processes</label>
              </>
            )}
            {PATH_ACTIONS.includes(action) && (
              <Field label={['block_process', 'unblock_process'].includes(action) ? 'Program path' : 'File path'} hint="Full path. On Windows, include the drive letter.">
                <input className="input mono" value={params.path} onChange={e => setParams(p => ({ ...p, path: e.target.value }))} placeholder="/tmp/payload or C:\Users\x\evil.exe"/>
              </Field>
            )}
            {action === 'delete_file' && (
              <Field label="Expected SHA-256 (optional)" hint="If given, the file is deleted only when its content still has this hash.">
                <input className="input mono" value={params.sha256} onChange={e => setParams(p => ({ ...p, sha256: e.target.value }))} placeholder="64 hex characters"/>
              </Field>
            )}
            {VAULT_ACTIONS.includes(action) && (
              single ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <button className="ow-btn" style={{ alignSelf: 'flex-start' }} disabled={!single.tunnel_online} onClick={loadVault}>Read {single.hostname}'s vault</button>
                  {vault?.error && <div className="c-crit" style={{ fontSize: 12.5 }}>{vault.error}</div>}
                  {Array.isArray(vault) && (vault.length === 0 ? <div className="t3">The vault is empty.</div> : vault.map(v => (
                    <button key={v.id} className={`ow-fc ${params.id === v.id ? 'on' : ''}`} style={{ height: 'auto', padding: '6px 8px' }} onClick={() => setParams(p => ({ ...p, id: v.id }))}>
                      <span className="mono" style={{ whiteSpace: 'normal', wordBreak: 'break-all' }}>{v.orig_path}</span><b>{v.sha256?.slice(0, 10)}</b>
                    </button>)))}
                </div>
              ) : <div className="t3" style={{ fontSize: 12 }}>Select one host to read its vault.</div>
            )}
            <Field label={def.danger ? 'Reason (required)' : 'Reason'}><input className="input" value={reason} maxLength={500} onChange={e => setReason(e.target.value)} placeholder="e.g. Alert #1042: reverse shell from nginx"/></Field>
          </div>
          <div className="ow-card-foot">
            <span>{paramErr || `${runnable.length} host${runnable.length === 1 ? '' : 's'} will get this${chosen.length > runnable.length ? `, ${chosen.length - runnable.length} skipped` : ''}`}</span>
            <button className={`ow-btn ${def.danger ? 'primary' : ''}`} disabled={!!paramErr || running} onClick={() => def.readOnly ? run() : setReview(true)}>
              {running ? 'Running…' : def.readOnly ? 'Run' : 'Review'}
            </button>
          </div>
        </section>

        {results && (
          <section className="ow-card" style={{ overflow: 'hidden' }}>
            <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Results · {def.label}</span><button className="ow-btn quiet" style={{ marginLeft: 'auto', height: 24 }} onClick={() => setResults(null)}>Clear</button></div>
            {results.map(r => (
              <div key={r.host.id} className="ow-grid" style={{ gridTemplateColumns: '1fr 100px', minHeight: 'auto', padding: '8px 14px', alignItems: 'start' }}>
                <div style={{ whiteSpace: 'normal' }}>
                  <Link to={`/agents?host=${encodeURIComponent(r.host.hostname)}`} className="mono t1">{r.host.hostname}</Link>
                  {r.text && <div className="t2" style={{ fontSize: 12 }}>{r.text}</div>}
                  {Array.isArray(r.result) && <div className="mono t2" style={{ fontSize: 11.5, marginTop: 4 }}>{r.result.length ? r.result.map(x => x.orig_path || x.ip || String(x)).join('\n') : 'Empty'}</div>}
                  {r.result?.rows && <div className="mono t2" style={{ fontSize: 11.5, marginTop: 4, whiteSpace: 'pre-wrap' }}>{r.result.rows.length ? r.result.rows.map(x => x[0]).join('\n') : 'Nothing blocked'}</div>}
                  {r.result?.sha256 && <FileFactsView f={r.result}/>}
                  {action === 'collect_file' && r.status === 'ok' && r.actionId && <CollectedDownload id={r.actionId} name={r.result?.path}/>}
                </div>
                <div>{r.status === 'skipped' ? <StatePill state="none">Skipped</StatePill> : <ActionStatus status={r.status}/>}</div>
              </div>
            ))}
          </section>
        )}
      </div>

      {review && (
        <Dialog title={`${def.label} on ${runnable.length} host${runnable.length === 1 ? '' : 's'}?`} onClose={() => setReview(false)} width={520}
          footer={<><button className="ow-btn quiet" onClick={() => setReview(false)}>Cancel</button>
            <button className="ow-btn primary" onClick={run} disabled={running}>{running ? 'Running…' : `${def.label} now`}</button></>}>
          <div className="t2">{def.help}</div>
          {describeParams({ action, params: payload() }) && <div><span className="t3">Target: </span><span className="mono t1">{describeParams({ action, params: payload() })}</span></div>}
          <div><span className="t3">Reason: </span>{reason || '—'}</div>
          <div style={{ maxHeight: 220, overflowY: 'auto', border: '1px solid var(--line)', borderRadius: 6 }}>
            {chosen.map(h => (
              <div key={h.id} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 10px', borderBottom: '1px solid var(--line)' }}>
                <span className="mono">{h.hostname}</span>
                <span className="t2" style={{ fontSize: 12 }}>{{ run: 'runs now', queue: 'queued until it reconnects', skip: 'skipped: not reachable' }[reach(h)]}</span>
              </div>
            ))}
          </div>
        </Dialog>
      )}
    </div>
  )
}

// ── History ──────────────────────────────────────────────────────────────────
function History({ actions, loading }) {
  const [facets, setFacets] = useState({})
  const G = useMemo(() => ({ action: a => a.action, status: a => a.status, by: a => a.requested_by, host: a => a.hostname }), [])
  const rows = useFacetFilter(actions, G, facets)
  const toggle = (k, v) => setFacets(f => { const n = { ...f }; const s = new Set(n[k] || []); s.has(v) ? s.delete(v) : s.add(v); n[k] = s; return n })
  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      <Facets selected={facets} onToggle={toggle} onClear={() => setFacets({})} groups={[
        { key: 'status', label: 'Outcome', values: countBy(actions, G.status) },
        { key: 'action', label: 'Action', values: countBy(actions, G.action, null, Object.fromEntries(ACTIONS.map(a => [a.id, a.label]))) },
        { key: 'by', label: 'Requested by', values: countBy(actions, G.by) },
        { key: 'host', label: 'Host', values: countBy(actions, G.host).slice(0, 12) },
      ]}/>
      <section className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
        <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Every response action</span><span className="t3" style={{ fontSize: 12 }}>Newest 100, fleet-wide. Also in the audit log.</span></div>
        <DenseTable rows={rows} rowKey={a => a.id} empty={loading ? 'Loading…' : 'No response actions yet.'}
          rowState={a => ['failed', 'timeout'].includes(a.status) ? 'crit' : null}
          cols={[
            { key: 'w', label: 'When', width: '110px', render: a => <span className="t2" title={new Date(a.requested_at).toLocaleString()}>{relTime(a.requested_at)}</span> },
            { key: 'h', label: 'Host', width: 'minmax(130px, 1fr)', render: a => <Link to={`/agents?host=${encodeURIComponent(a.hostname)}`} className="mono t1" onClick={e => e.stopPropagation()}>{a.hostname}</Link> },
            { key: 'a', label: 'Action', width: '150px', render: a => <span className="t1">{BY_ID[a.action]?.label || a.action}</span> },
            { key: 't', label: 'Target', width: 'minmax(160px, 1.4fr)', render: a => <span className="mono t2">{describeParams(a) || '—'}</span>, title: a => describeParams(a) },
            { key: 'b', label: 'By / reason', width: 'minmax(160px, 1.4fr)', render: a => <span><span className="t1">{a.requested_by}</span>{a.reason && <span className="t3"> · {a.reason}</span>}</span>, title: a => a.reason },
            { key: 's', label: 'Outcome', width: '104px', render: a => <ActionStatus status={a.status}/>, title: a => a.message },
          ]}/>
      </section>
    </div>
  )
}

export default function Response() {
  const [params, setParams] = useSearchParams()
  const tab = ['run', 'history', 'live'].includes(params.get('tab')) ? params.get('tab') : 'run'
  const [agents, setAgents] = useState([])
  const [lr, setLr] = useState({})
  const [meta, setMeta] = useState({})
  const [iso, setIso] = useState({})
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    const [a, l, m, i, h] = await Promise.all([
      api.get('/api/v1/agents').then(r => r.data?.agents || []).catch(() => []),
      api.get('/api/v1/live-response/agents').then(r => Array.isArray(r.data) ? r.data : []).catch(() => []),
      api.get('/api/v1/hosts/meta').then(r => r.data?.hosts || []).catch(() => []),
      api.get('/api/v1/response/isolated').then(r => r.data?.agents || []).catch(() => []),
      api.get('/api/v1/response/actions').then(r => r.data?.actions || []).catch(() => []),
    ])
    setAgents(a); setLr(Object.fromEntries(l.map(x => [x.id, x]))); setMeta(Object.fromEntries(m.map(x => [x.host, x])))
    setIso(Object.fromEntries(i.map(x => [x.agent_id, x]))); setActions(h); setLoading(false)
  }, [])
  useEffect(() => { load(); const t = setInterval(load, 15000); return () => clearInterval(t) }, [load])

  const hosts = useMemo(() => agents.filter(a => !isProbe(a)).map(a => ({
    ...a, tags: meta[a.hostname]?.tags || [], tunnel_online: !!lr[a.id]?.tunnel_online,
    isolated: !!iso[a.id]?.isolated, isolationPending: !!iso[a.id]?.desired_isolated && !iso[a.id]?.isolated,
  })), [agents, lr, meta, iso])
  const preselect = useMemo(() => {
    const want = params.getAll('host')
    return hosts.filter(h => want.includes(h.hostname) || want.includes(h.id)).map(h => h.id)
  }, [hosts, params])

  const live = hosts.filter(h => h.tunnel_online).length
  const isolated = hosts.filter(h => h.isolated).length
  const pending = hosts.filter(h => h.isolationPending).length
  const dayAgo = Date.now() - 86400e3
  const today = actions.filter(a => new Date(a.requested_at) > dayAgo)
  const failed = today.filter(a => ['failed', 'timeout'].includes(a.status)).length
  const setTab = (t) => { const n = new URLSearchParams(params); n.set('tab', t); setParams(n, { replace: true }) }

  return (
    <div>
      <PageHeader title="Response"
        state={isolated ? 'crit' : pending ? 'warn' : undefined} stateText={isolated ? `${isolated} host${isolated === 1 ? '' : 's'} isolated` : `${pending} isolation${pending === 1 ? '' : 's'} pending`}
        sub="Contain and clean up across the fleet. Every action records who asked, why and what happened."
        actions={<button className="ow-btn" onClick={load}><RefreshCw size={13}/>Refresh</button>}
        nums={<>
          <Num k="Reachable now" v={live} unit={`of ${hosts.length}`} title="Hosts with a connected live-response tunnel"/>
          <Num k="Isolated" v={isolated} tone={isolated ? 'crit' : undefined}/>
          <Num k="Isolation pending" v={pending} tone={pending ? 'warn' : undefined} title="Queued for hosts that are offline"/>
          <Num k="Actions, 24 h" v={today.length}/>
          <Num k="Failed, 24 h" v={failed} tone={failed ? 'crit' : undefined}/>
        </>}
        tabs={<Tabs value={tab} onChange={setTab} tabs={[{ id: 'run', label: 'Run action' }, { id: 'history', label: 'History', n: actions.length || null }, { id: 'live', label: 'Live response' }]}/>}/>
      {tab === 'live' ? <LiveResponse/> : (
        <div className="ow-body">
          {tab === 'run' ? <RunAction hosts={hosts} preselect={preselect} onDone={load}/> : <History actions={actions} loading={loading}/>}
        </div>
      )}
    </div>
  )
}

export function ResponseLink({ host, children = 'Take action', className = 'ow-btn primary' }) {
  return <Link to={`/response?host=${encodeURIComponent(host)}`} className={className} style={{ textDecoration: 'none' }}><Terminal size={13}/>{children}</Link>
}
