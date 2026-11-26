// Cloud posture across every connected account: one findings list with facets, one accounts table,
// and the per-account workspace (scans, compliance, blast radius, events) as the third tab.
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../../api/client'
import { PageHeader, Num, Tabs, StatePill, SevPill, Facets, countBy, useFacetFilter, DenseTable, parseFilter, relTime, downloadCSV, Meter } from '../../components/ui'
import { riskScore, CIS_MAPPING } from './shared.jsx'
import { Search, X, Download, RefreshCw } from 'lucide-react'

export const cloudFindingPath = (f) => `/cloud/findings/${f.connector}/${encodeURIComponent(f.id)}`
export { PROVIDER, CAT_LABEL }

const SEV_N = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const N_SEV = { 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info' }
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
const PROVIDER = { aws: 'AWS', azure: 'Azure', gcp: 'GCP' }
const CAT_LABEL = { iam: 'Identity and access', network: 'Network', storage: 'Storage', compute: 'Compute', logging: 'Logging', sql: 'Databases', kms: 'Keys and secrets', monitoring: 'Monitoring', database: 'Databases', keyvault: 'Keys and secrets', identity: 'Identity and access' }
const sevState = (n) => n >= 5 ? 'crit' : n >= 4 ? 'high' : n >= 3 ? 'med' : n >= 2 ? 'low' : 'none'
const acctName = (c) => c.account_label || c.account_id || `${PROVIDER[c.provider] || c.provider} ${c.id}`

export function usePosture() {
  const [s, setS] = useState({ loading: true, accounts: [], findings: [], error: '' })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    ;(async () => {
      try {
        const { data } = await api.get('/api/v1/cloud-connectors')
        const conns = Array.isArray(data?.connectors) ? data.connectors : []
        const res = await Promise.all(conns.map(c => api.get(`/api/v1/cloud-connectors/${c.id}/cspm`).then(r => r.data).catch(() => null)))
        const findings = []
        const accounts = conns.map((c, i) => {
          const r = res[i] || {}
          const list = Array.isArray(r.findings) ? r.findings : []
          for (const f of list) findings.push({
            ...f, sevN: SEV_N[f.severity] || 1, status: f.status || 'open', connector: c.id, provider: c.provider, account: acctName(c),
            scanned: f.scanned_at || r.scanned_at, cis: CIS_MAPPING[f.category] || '',
          })
          const open = list.filter(f => (f.status || 'open') === 'open')
          const cnt = (sev) => open.filter(f => f.severity === sev).length
          const counts = { critical: cnt('critical'), high: cnt('high'), medium: cnt('medium'), low: cnt('low'), total_findings: open.length, passed: r.passed || 0 }
          return { ...c, name: acctName(c), scanned: r.scanned_at && new Date(r.scanned_at).getFullYear() > 2000 ? r.scanned_at : null, counts, risk: riskScore(counts),
            notAssessed: (r.not_assessed || []).length, worst: open.reduce((m, f) => Math.max(m, SEV_N[f.severity] || 1), 0) }
        })
        if (live) setS({ loading: false, accounts, findings, error: '' })
      } catch (e) { if (live) setS({ loading: false, accounts: [], findings: [], error: e.response?.data?.error || e.message }) }
    })()
    return () => { live = false }
  }, [tick])
  return { ...s, reload: () => { setS(v => ({ ...v, loading: true })); setTick(t => t + 1) } }
}

function toggler(setSel) {
  return (k, v) => setSel(s => { const n = { ...s }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
}

const F_GET = { severity: f => N_SEV[f.sevN], status: f => f.status, provider: f => f.provider, account: f => f.account, category: f => f.category || 'other' }
function FindingsTab({ findings, multiProvider }) {
  const [sel, setSel] = useState({ status: new Set(['open']) })
  const [q, setQ] = useState('')
  const navigate = useNavigate()
  const faceted = useFacetFilter(findings, F_GET, sel)
  const rows = useMemo(() => {
    const { fields, text } = parseFilter(q)
    return faceted.filter(f => {
      if (text && !`${f.title} ${f.resource} ${f.account} ${f.description || ''}`.toLowerCase().includes(text)) return false
      if (fields.severity && !fields.severity.some(v => N_SEV[f.sevN].startsWith(v))) return false
      if (fields.status && !fields.status.some(v => f.status.startsWith(v))) return false
      return true
    }).sort((a, b) => b.sevN - a.sevN || new Date(b.scanned) - new Date(a.scanned))
  }, [faceted, q])
  const groups = [
    { key: 'severity', label: 'Severity', values: countBy(findings, F_GET.severity, ['critical', 'high', 'medium', 'low', 'info'], SEV_LABEL) },
    { key: 'status', label: 'Status', values: countBy(findings, F_GET.status, ['open', 'suppressed'], { open: 'Open', suppressed: 'Suppressed' }) },
    ...(multiProvider ? [{ key: 'provider', label: 'Provider', values: countBy(findings, F_GET.provider, ['aws', 'azure', 'gcp'], PROVIDER) }] : []),
    { key: 'account', label: 'Account', values: countBy(findings, F_GET.account).slice(0, 12) },
    { key: 'category', label: 'Area', values: countBy(findings, F_GET.category, null, CAT_LABEL) },
  ]
  const cols = [
    { key: 's', label: 'Severity', width: '96px', render: f => f.status === 'suppressed' ? <StatePill state="none">Suppressed</StatePill> : <SevPill sev={f.sevN}/> },
    { key: 't', label: 'Finding', width: '1.7fr', render: f => <span className="t1">{f.title}</span>, title: f => f.description || f.title },
    { key: 'a', label: 'Account', width: '1.1fr', render: f => <span className="t2">{PROVIDER[f.provider] || f.provider} · {f.account}</span> },
    { key: 'r', label: 'Resource', width: '1.5fr', render: f => <span className="mono t1">{f.resource || '—'}</span>, title: f => `${f.resource_type || ''} ${f.resource || ''}` },
    { key: 'c', label: 'Area', width: '120px', render: f => <span className="t2">{CAT_LABEL[f.category] || f.category || '—'}</span>, title: f => f.cis },
    { key: 'd', label: 'Detected', width: '96px', render: f => <span className="t2">{relTime(f.scanned)}</span> },
  ]
  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      <Facets groups={groups} selected={sel} onToggle={toggler(setSel)} onClear={() => setSel({})}/>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
              <Search size={13} style={{ color: 'var(--t3)' }}/>
              <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter · severity:critical,high or a resource name" aria-label="Filter findings"/>
              {q && <button onClick={() => setQ('')} aria-label="Clear filter" style={{ background: 'none', border: 0, color: 'var(--t3)', cursor: 'pointer' }}><X size={12}/></button>}
            </label>
            <span className="t2" style={{ fontSize: 12 }}>{rows.length.toLocaleString()} of {findings.length.toLocaleString()}</span>
          </div>
          <DenseTable cols={cols} rows={rows.slice(0, 500)} rowKey={f => `${f.connector}|${f.id}|${f.resource}`} rowState={f => f.status === 'suppressed' ? 'none' : sevState(f.sevN)}
            onRow={f => navigate(cloudFindingPath(f))}
            empty={findings.length ? 'No findings match these filters.' : 'No posture findings yet. Run a scan from the Accounts and scans tab.'}/>
          {rows.length > 500 && <div className="ow-card-foot">Showing the first 500 of {rows.length.toLocaleString()}. Narrow the filter to see the rest.</div>}
        </div>
      </div>
    </div>
  )
}

function AccountsTab({ accounts, onOpen }) {
  const st = a => a.status === 'error' ? 'crit' : !a.scanned ? 'none' : sevState(a.worst) === 'none' ? 'ok' : sevState(a.worst)
  const word = a => a.status === 'error' ? 'Error' : !a.scanned ? 'Not scanned' : { crit: 'Critical', warn: 'High', info: 'Medium', ok: 'OK' }[st(a)] || 'OK'
  const cols = [
    { key: 's', label: 'State', width: '110px', render: a => <StatePill state={st(a)} title={a.last_error || undefined}>{word(a)}</StatePill> },
    { key: 'n', label: 'Account', width: '1.4fr', render: a => <span className="mono t1">{a.name}</span>, title: a => a.account_id },
    { key: 'p', label: 'Provider', width: '80px', render: a => <span className="t2">{PROVIDER[a.provider] || a.provider}</span> },
    { key: 'c', label: 'Critical', width: '70px', render: a => <span className="mono" style={{ color: a.counts.critical ? 'var(--crit)' : 'var(--t3)' }}>{a.counts.critical}</span> },
    { key: 'h', label: 'High', width: '60px', render: a => <span className="mono" style={{ color: a.counts.high ? 'var(--warn)' : 'var(--t3)' }}>{a.counts.high}</span> },
    { key: 'o', label: 'Open', width: '60px', render: a => <span className="mono">{a.counts.total_findings}</span> },
    { key: 'r', label: 'Risk', width: '110px', render: a => <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span className="mono" style={{ width: 22 }}>{a.risk}</span><span style={{ flex: 1 }}><Meter pct={a.risk} state={a.risk >= 60 ? 'crit' : a.risk >= 40 ? 'warn' : 'ok'}/></span></span>, title: () => 'Risk score, 0 to 100, lower is better' },
    { key: 'd', label: 'Last scan', width: '100px', render: a => <span className="t2">{a.scanned ? relTime(a.scanned) : 'never'}</span> },
  ]
  return (
    <div className="ow-card" style={{ overflow: 'hidden' }}>
      <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Accounts</span><span className="t3" style={{ fontSize: 12 }}>Open the account to run scans, check compliance and see its events</span></div>
      <DenseTable cols={cols} rows={[...accounts].sort((a, b) => b.worst - a.worst || b.risk - a.risk)} rowKey={a => a.id} rowState={st} onRow={onOpen}
        empty="No cloud accounts connected yet."/>
    </div>
  )
}

export default function PostureOverview({ connectorsView, onOpenAccount }) {
  const d = usePosture()
  const [tab, setTab] = useState('findings')
  const open = d.findings.filter(f => f.status === 'open')
  const n = (sev) => open.filter(f => f.severity === sev).length
  const totals = { critical: n('critical'), high: n('high'), medium: n('medium'), low: n('low'), total_findings: open.length, passed: d.accounts.reduce((s, a) => s + a.counts.passed, 0) }
  const risk = riskScore(totals)
  const checks = totals.total_findings + totals.passed
  const passRate = checks ? Math.round((totals.passed / checks) * 100) : null
  const providers = [...new Set(d.accounts.map(a => PROVIDER[a.provider] || a.provider))]
  const lastScan = d.accounts.map(a => a.scanned).filter(Boolean).sort().pop()
  const resources = new Set(open.map(f => f.resource).filter(Boolean)).size
  const noData = !d.loading && d.accounts.length === 0
  const state = d.loading ? undefined : noData ? 'none' : totals.critical ? 'crit' : totals.high ? 'warn' : open.length ? 'info' : 'ok'
  const stateText = noData ? 'No accounts connected' : totals.critical ? `${totals.critical} critical finding${totals.critical === 1 ? '' : 's'}` : totals.high ? `${totals.high} high finding${totals.high === 1 ? '' : 's'}` : open.length ? 'No critical or high findings' : 'No open findings'
  const bars = [['Critical', totals.critical, 'crit'], ['High', totals.high, 'warn'], ['Medium', totals.medium, 'acc'], ['Low', totals.low, 'none']]
  const maxBar = Math.max(1, ...bars.map(b => b[1]))

  const exportCSV = () => downloadCSV(`cloud-findings-${new Date().toISOString().slice(0, 10)}.csv`,
    ['severity', 'status', 'title', 'provider', 'account', 'resource', 'resource_type', 'area', 'detected'],
    d.findings.map(f => [f.severity, f.status, f.title, f.provider, f.account, f.resource, f.resource_type, f.category, f.scanned]))

  return (
    <div>
      <PageHeader
        title="Posture" state={tab === 'connectors' ? undefined : state} stateText={stateText}
        sub={d.loading ? 'Loading posture…' : d.error ? `Could not load accounts: ${d.error}` : noData ? 'Connect an AWS, Azure or GCP account to assess its configuration.'
          : `${providers.length} provider${providers.length === 1 ? '' : 's'}, ${d.accounts.length} account${d.accounts.length === 1 ? '' : 's'}.${lastScan ? ` Last assessment ${relTime(lastScan)}.` : ' No assessments have run yet.'}`}
        actions={tab !== 'connectors' && <>
          <button className="ow-btn" onClick={d.reload}><RefreshCw size={13}/>Reload</button>
          <button className="ow-btn" onClick={exportCSV} disabled={!d.findings.length}><Download size={13}/>Export</button>
          <button className="ow-btn primary" onClick={() => setTab('connectors')}>Connect account</button>
        </>}
        nums={tab !== 'connectors' && !noData && <>
          <Num k="Risk score" v={risk} unit="/ 100" title="Weighted by severity across all accounts. Lower is better.">
            <div className="ow-num-d">lower is better</div>
          </Num>
          <Num k="Checks passing" v={passRate == null ? '–' : passRate} unit={passRate == null ? undefined : '%'} title={`${totals.passed.toLocaleString()} of ${checks.toLocaleString()} checks`}>
            {passRate != null && <div style={{ marginTop: 6, maxWidth: 160 }}><Meter pct={passRate} state={passRate >= 90 ? 'ok' : passRate >= 70 ? 'warn' : 'crit'}/></div>}
          </Num>
          <Num k="Open findings" v={open.length.toLocaleString()} tone={open.length ? (totals.critical ? 'crit' : 'warn') : undefined}/>
          <Num k="Resources affected" v={resources.toLocaleString()}/>
          <Num k="Accounts" v={d.accounts.length}/>
          <Num k="By severity" grow={1.5}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 4 }}>
              {bars.map(([l, v, c]) => (
                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div className="t2" style={{ width: 56, fontSize: 12 }}>{l}</div>
                  <div style={{ flex: 1 }}><Meter pct={(v / maxBar) * 100} state={c} height={8}/></div>
                  <span className="mono" style={{ width: 34, textAlign: 'right' }}>{v}</span>
                </div>
              ))}
            </div>
          </Num>
        </>}
        tabs={<Tabs value={tab} onChange={setTab} tabs={[
          { id: 'findings', label: 'Findings', n: open.length || null }, { id: 'accounts', label: 'Accounts', n: d.accounts.length || null }, { id: 'connectors', label: 'Accounts and scans' }]}/>}
      />
      {tab === 'connectors' ? connectorsView : (
        <div className="ow-body">
          {d.loading ? <div className="t3" style={{ padding: 32, textAlign: 'center' }}>Loading…</div>
            : tab === 'findings' ? <FindingsTab findings={d.findings} multiProvider={providers.length > 1}/>
              : <AccountsTab accounts={d.accounts} onOpen={a => { onOpenAccount?.(a.id); setTab('connectors') }}/>}
        </div>
      )}
    </div>
  )
}
