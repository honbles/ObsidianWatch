import { useEffect, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { ShieldCheck, ShieldAlert, ShieldOff, Shield, Play, ScanSearch, X, Check, Loader2 } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../../api/client'

// Protection on one host: is it protected, what it checked in the last 24 hours, and the proof (a test that
// plants a harmless file the agent must catch, and on-demand scans). GET /api/v1/agents/{id}/protection;
// scan and test_protection are response actions (admin).

const VERDICT = {
  protected: { label: 'Protected', tone: 'ok', icon: ShieldCheck },
  audit: { label: 'Audit only', tone: 'warn', icon: ShieldAlert },
  off: { label: 'Not protected', tone: 'crit', icon: ShieldOff },
  unknown: { label: 'Unknown', tone: 't3', icon: Shield },
}
const MODE_LABEL = { enforce: 'Stop', audit: 'Alert only', off: 'Off' }
const TYPES = [['hash', 'Files and programs'], ['ip', 'Connections'], ['domain', 'Domains']]
const COUNTERS = [['files_checked', 'Files checked'], ['programs_checked', 'Programs checked'], ['connections_checked', 'Connections checked'], ['dns_checked', 'DNS answers checked']]

const isAdmin = () => { try { return JSON.parse(localStorage.getItem('user') || '{}').role === 'admin' } catch { return false } }
const ago = (t) => t ? formatDistanceToNow(new Date(t), { addSuffix: true }) : ''
const n = (v) => (v ?? 0).toLocaleString()

export function useProtection(agentId) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const load = useCallback(() => api.get(`/api/v1/agents/${agentId}/protection`)
    .then(r => { setData(r.data); setErr('') })
    .catch(e => setErr(e.response?.data?.error || 'Could not load the protection state')), [agentId])
  const busy = data?.test?.status === 'pending' || data?.scan?.status === 'running' || data?.scan?.status === 'sent'
  useEffect(() => {
    load()
    const t = setInterval(load, busy ? 5000 : 30000)
    return () => clearInterval(t)
  }, [load, busy])
  return { data, err, reload: load }
}

export function ProtectionTile({ agentId }) {
  const { data } = useProtection(agentId)
  const v = VERDICT[data?.verdict] || VERDICT.unknown
  return (
    <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
      <div className="text-2xs text-siem-muted uppercase tracking-wider mb-1">Protection</div>
      <div className="text-base font-bold" style={{ color: `var(--${v.tone})` }}>{data ? v.label : '…'}</div>
    </div>
  )
}

function ScanDialog({ agent, onClose, onStarted }) {
  const [whole, setWhole] = useState(false)
  const [path, setPath] = useState(/win/i.test(agent.os || '') ? 'C:\\Users' : '/home')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const start = async () => {
    setBusy(true); setErr('')
    try {
      await api.post(`/api/v1/agents/${agent.id}/actions`, { action: 'scan', params: whole ? { kind: 'whole' } : { path: path.trim() }, reason: 'manual scan' })
      onStarted(); onClose()
    } catch (e) { setErr(e.response?.data?.error || e.response?.data?.message || 'The scan could not start') }
    finally { setBusy(false) }
  }
  return createPortal(
    <div className="fixed inset-0 z-[220] flex items-center justify-center bg-black/70" onClick={onClose}>
      <div className="ow-card" style={{ width: 460, padding: 20 }} onClick={e => e.stopPropagation()} role="dialog" aria-label="Scan host">
        <div className="flex items-center gap-2 mb-3">
          <ScanSearch size={16} className="c-acc"/><h3 style={{ margin: 0 }}>Scan {agent.hostname}</h3>
          <button className="ow-btn quiet ml-auto" onClick={onClose} aria-label="Close"><X size={14}/></button>
        </div>
        <label className="flex items-center gap-2 text-sm py-1"><input type="radio" checked={!whole} onChange={() => setWhole(false)}/> A folder</label>
        {!whole && <input className="input mono" style={{ marginLeft: 22, width: 'calc(100% - 22px)' }} value={path} onChange={e => setPath(e.target.value)} aria-label="Folder"/>}
        <label className="flex items-center gap-2 text-sm py-1 mt-1"><input type="radio" checked={whole} onChange={() => setWhole(true)}/> The whole disk</label>
        <p className="t3 text-xs mt-2">Every file is hashed and checked against the malicious list; matches are handled like any other (quarantined when files are set to stop). Executables are also sent for a reputation lookup. Operating-system folders are skipped, and the scan runs in the background at low priority.</p>
        {err && <div className="c-crit text-xs mt-2">{err}</div>}
        <div className="flex gap-2 mt-4">
          <button className="ow-btn primary" onClick={start} disabled={busy || (!whole && !path.trim())}>{busy ? 'Starting…' : 'Start scan'}</button>
          <button className="ow-btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>, document.body)
}

export function ProtectionPanel({ agent }) {
  const { data, err, reload } = useProtection(agent.id)
  const [scanOpen, setScanOpen] = useState(false)
  const [testErr, setTestErr] = useState('')
  const [testing, setTesting] = useState(false)
  const admin = isAdmin()
  const runTest = async () => {
    setTesting(true); setTestErr('')
    try { await api.post(`/api/v1/agents/${agent.id}/actions`, { action: 'test_protection', reason: 'protection test' }) }
    catch (e) { setTestErr(e.response?.data?.message || e.response?.data?.error || 'The test could not start') }
    finally { setTesting(false); reload() }
  }
  if (err) return <div className="ow-card p-4 c-crit text-sm">{err}</div>
  if (!data) return <div className="ow-card p-4 t3 text-sm">Loading protection…</div>
  const v = VERDICT[data.verdict] || VERDICT.unknown
  const VIcon = v.icon
  const rep = data.reported || {}
  const modes = rep.modes || {}
  const c = rep.counters_24h || {}
  const lists = rep.list_counts || {}
  const test = data.test
  const scan = data.scan
  const res = scan?.result
  return (
    <div className="ow-card" style={{ overflow: 'hidden' }} data-testid="protection-panel">
      <div className="ow-card-bar">
        <VIcon size={18} style={{ color: `var(--${v.tone})` }}/>
        <span style={{ fontWeight: 600 }}>Protection</span>
        <span className="ow-pill" style={{ color: `var(--${v.tone})`, background: 'var(--s2)' }}>{v.label}</span>
        <span className="t2 text-xs truncate">{data.verdict_detail}</span>
        {admin && <span className="ml-auto flex gap-2 flex-none">
          <button className="ow-btn" onClick={runTest} disabled={testing || test?.status === 'pending' || !data.tunnel_online}
            title={data.tunnel_online ? 'Plant a harmless test file the agent must catch' : 'The agent is not connected'}>
            {testing || test?.status === 'pending' ? <Loader2 size={13} className="animate-spin"/> : <Play size={13}/>} Test protection</button>
          <button className="ow-btn" onClick={() => setScanOpen(true)} disabled={!data.tunnel_online || scan?.status === 'running'}>
            <ScanSearch size={13}/> {scan?.status === 'running' ? 'Scanning…' : 'Scan'}</button>
        </span>}
      </div>
      <div className="grid gap-4 p-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))' }}>
        <div>
          <div className="ow-lbl mb-2">What it does</div>
          {TYPES.map(([k, label]) => {
            const got = modes[k] || (data.reported ? 'off' : '')
            const want = data.intended_modes?.[k]
            return (
              <div key={k} className="flex justify-between text-sm py-1">
                <span className="t2">{label}</span>
                <span style={{ color: got === 'enforce' ? 'var(--ok)' : got === 'audit' ? 'var(--warn)' : 'var(--t3)', fontWeight: 600 }}
                  title={want && got && want !== got ? `The server's policy is "${MODE_LABEL[want]}"; the agent has not applied it yet` : undefined}>
                  {MODE_LABEL[got] || '—'}{want && got && want !== got ? ' *' : ''}</span>
              </div>)
          })}
          <div className="t3 text-xs mt-2">
            {data.reported ? <>List: {n(lists.hashes)} files · {n(lists.ips)} addresses · {n(lists.domains)} domains{rep.list_received ? `, updated ${ago(rep.list_received)}` : ''}.
              {rep.kernel_block ? ' Connections are refused in the kernel.' : ''} {rep.watched_folders ? `${rep.watched_folders} folders watched for new files.` : ''}</> : 'No report from the agent yet.'}
          </div>
        </div>
        <div>
          <div className="ow-lbl mb-2">Last 24 hours</div>
          {COUNTERS.map(([k, label]) => (
            <div key={k} className="flex justify-between text-sm py-1"><span className="t2">{label}</span><span className="mono">{data.reported ? n(c[k]) : '—'}</span></div>))}
          <div className="flex justify-between text-sm py-1" style={{ borderTop: '1px solid var(--line)', marginTop: 4, paddingTop: 6 }}>
            <span className="t1" style={{ fontWeight: 600 }}>Threats stopped</span>
            <span className="mono" style={{ fontWeight: 600, color: data.threats_24h?.stopped ? 'var(--ok)' : undefined }}>
              {n(data.threats_24h?.stopped)}{data.threats_24h?.matched > data.threats_24h?.stopped ? <span className="c-warn"> · {n(data.threats_24h.matched - data.threats_24h.stopped)} not stopped</span> : ''}</span>
          </div>
        </div>
        <div>
          <div className="ow-lbl mb-2">Proof</div>
          <div className="text-sm py-1" data-testid="protection-test">
            {!test ? <span className="t3">Not tested yet.{admin ? ' Test protection plants a harmless file the agent has to catch.' : ''}</span> : (
              <div className="flex gap-2 items-start">
                {test.status === 'pass' ? <Check size={15} className="c-ok flex-none mt-0.5"/> : test.status === 'fail' ? <X size={15} className="c-crit flex-none mt-0.5"/> : <Loader2 size={15} className="animate-spin c-acc flex-none mt-0.5"/>}
                <span><b style={{ color: test.status === 'pass' ? 'var(--ok)' : test.status === 'fail' ? 'var(--crit)' : 'var(--acc)' }}>
                  {test.status === 'pass' ? 'Test passed' : test.status === 'fail' ? 'Test failed' : 'Testing…'}</b> <span className="t3 text-xs">{ago(test.started)}</span><br/>
                  <span className="t2 text-xs">{test.detail}</span></span>
              </div>)}
            {testErr && <div className="c-crit text-xs mt-1">{testErr}</div>}
          </div>
          <div className="text-sm py-1 mt-1" style={{ borderTop: '1px solid var(--line)', paddingTop: 6 }} data-testid="protection-scan">
            {!scan ? <span className="t3">No scan yet.</span> : scan.status === 'finished' && res ? (
              <span><b>Scan {ago(res.finished)}</b>: {n(res.files_scanned)} files in {res.whole_disk ? 'the whole disk' : (res.roots || []).join(', ')}, <b style={{ color: res.threats_found ? 'var(--crit)' : 'var(--ok)' }}>{res.threats_found ? `${res.threats_found} threats found` : 'no threats'}</b>
                <span className="t3 text-xs">{res.executables_checked ? ` · ${n(res.executables_checked)} executables sent for reputation` : ''}{res.stopped ? ` · ${res.stopped}` : ''}</span></span>
            ) : scan.status === 'failed' || scan.status === 'timeout' ? <span className="c-crit">Scan failed: {scan.message}</span>
              : <span className="flex items-center gap-2"><Loader2 size={13} className="animate-spin c-acc"/> Scan running, started {ago(scan.requested_at)}</span>}
          </div>
        </div>
      </div>
      {scanOpen && <ScanDialog agent={agent} onClose={() => setScanOpen(false)} onStarted={reload}/>}
    </div>
  )
}
