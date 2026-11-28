// Code: repositories and findings across every connected Git source.
// Each connector contributes its latest SAST scan per repository and its last posture check.
// They are joined on the short repository name, since posture reports "org/repo@branch" and scans "repo" or "org/repo".
import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../../api/client'
import { PageHeader, Num, Tabs, StatePill, SevPill, Facets, countBy, useFacetFilter, DenseTable, parseFilter, relTime, downloadCSV } from '../../components/ui'
import { Search, X, Download, RefreshCw } from 'lucide-react'
import ReachBadge, { REACH_ORDER, reachTitle } from './ReachBadge'

// Findings have no server id, so the page URL carries a short stable key built from what identifies one.
function hash32(str) { let h = 2166136261; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619) } return (h >>> 0).toString(36) }
export const findingId = (f) => `${f.connector}-${f.source}-${hash32([f.repo, f.where, f.title, f.type].join('|'))}`
export const repoPath = (connector, repo) => `/devops/repos/${connector}/${encodeURIComponent(repo)}`
export const findingPath = (f) => `/devops/findings/${findingId(f)}`
export { SOURCE_LABEL, TYPE_LABEL, PROVIDER_LABEL, N_SEV }

const SEV_N = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const N_SEV = { 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info' }
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', clean: 'Clean' }
const TYPE_LABEL = { secret: 'Secrets', dependency: 'Dependencies', dangerous_code: 'Dangerous code', sensitive_file: 'Sensitive files', config: 'Configuration', sast: 'Code weaknesses (SAST)', posture: 'Branch and access rules' }
const SOURCE_LABEL = { sast: 'SAST', posture: 'Posture check' }
const PROVIDER_LABEL = { github: 'GitHub', gitlab: 'GitLab', azuredevops: 'Azure DevOps' }

const repoKey = (s) => (s || '').split('@')[0].split('/').filter(Boolean).pop()?.toLowerCase() || ''
const branchOf = (s) => (s || '').includes('@') ? s.split('@').pop() : ''
const parseJSON = (v) => { if (!v) return []; if (Array.isArray(v)) return v; try { const x = JSON.parse(v); return Array.isArray(x) ? x : [] } catch { return [] } }

async function loadConnector(c) {
  const get = (u) => api.get(u).then(r => r.data).catch(e => ({ _err: e.response?.status || 'error' }))
  const [sast, posture] = await Promise.all([
    get(`/api/v1/devops-connectors/${c.id}/sast`),
    get(`/api/v1/devops-connectors/${c.id}/posture`),
  ])
  const findings = []
  const base = { connector: c.id, org: c.org, provider: c.provider }
  // Latest result per repository (older servers only send the single latest scan).
  const sastScans = Array.isArray(sast?.scans) && sast.scans.length ? sast.scans : (sast?.scan ? [sast.scan] : [])
  for (const sc of sastScans) for (const f of parseJSON(sc.findings)) findings.push({
    ...base, source: 'sast', type: 'sast', sev: SEV_N[f.severity] || 1, title: f.title, detail: f.detail, branch: sc.branch,
    repo: repoKey(f.repo || sc.repo) || '(unknown)', where: f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : '', at: sc.scanned_at, fix: f.fix, rule: f.rule_id, testCode: !!f.test_code, reach: f.reachability?.level, reachInfo: f.reachability, triage: f.triage?.status || (f.triage_hint ? 'hint_' + f.triage_hint.suggestion : 'open'),
  })
  const pf = posture && !posture._err ? posture : null
  if (pf) for (const f of (pf.findings || [])) {
    const repoLevel = (f.resource || '').includes('/')
    findings.push({
      ...base, source: 'posture', type: 'posture', sev: SEV_N[f.severity] || 1, title: f.title, detail: f.detail,
      repo: repoLevel ? repoKey(f.resource) : `(${c.org})`, orgLevel: !repoLevel, branch: branchOf(f.resource), where: f.resource, at: pf.scanned_at, fix: f.fix,
    })
  }
  const lastScan = [sast?.scan?.scanned_at, pf?.scanned_at].filter(Boolean).sort().pop()
  return { findings, lastScan, scanned: { sast: !!sast?.scan, posture: !!pf }, reposChecked: pf?.repos_checked || 0 }
}

export function useCodeData({ coverage = false } = {}) {
  const [state, setState] = useState({ loading: true, connectors: [], findings: [], repos: [], lastScan: null, error: '' })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    ;(async () => {
      try {
        const { data } = await api.get('/api/v1/devops-connectors')
        const conns = Array.isArray(data?.connectors) ? data.connectors : []
        const per = await Promise.all(conns.map(loadConnector))
        const findings = per.flatMap(p => p.findings)
        const lastScan = per.map(p => p.lastScan).filter(Boolean).sort().pop() || null
        if (!live) return
        setState({ loading: false, connectors: conns.map((c, i) => ({ ...c, ...per[i] })), findings, repoList: null, coverage: null, lastScan, error: '' })
        // The full repository list comes from the provider API (slow, may be rate limited), so it arrives second.
        const lists = await Promise.all(conns.map(c => api.get(`/api/v1/devops-connectors/${c.id}/sast/repos`)
          .then(r => (r.data?.repos || []).map(x => ({ name: repoKey(x.repo || x.name), branch: x.branch || x.default_branch || '', connector: c.id, org: c.org, provider: c.provider })))
          .catch(() => [])))
        if (live) setState(s => ({ ...s, repoList: lists.flat() }))
        // Scan coverage (repositories and branches scanned against what the provider reports) needs one branch
        // list per repository, so it arrives last.
        if (!coverage) return
        const covs = await Promise.all(conns.map(c => api.get(`/api/v1/devops-connectors/${c.id}/sast/coverage`)
          .then(r => ({ connector: c.id, ...r.data })).catch(() => null)))
        if (live) setState(s => ({ ...s, coverage: covs }))
      } catch (e) {
        if (live) setState(s => ({ ...s, loading: false, error: e.response?.data?.error || e.message }))
      }
    })()
    return () => { live = false }
  }, [tick])
  return { ...state, reload: () => { setState(s => ({ ...s, loading: true })); setTick(t => t + 1) } }
}

// summariseCoverage adds up the connectors' coverage. null while it loads; failed connectors are left out.
export function summariseCoverage(coverage) {
  if (!coverage) return null
  const ok = coverage.filter(Boolean)
  const byRepo = new Map()
  const list = []
  for (const c of ok) for (const r of c.repos || []) {
    byRepo.set(c.connector + '|' + repoKey(r.repo), r)
    list.push({ name: repoKey(r.repo), branch: r.default_branch === 'HEAD' ? '' : r.default_branch, connector: c.connector })
  }
  const sum = (k) => ok.reduce((n, c) => n + (c[k] || 0), 0)
  return {
    reposTotal: sum('repos_total'), reposScanned: sum('repos_scanned'),
    branchesTotal: sum('branches_total'), branchesScanned: sum('branches_scanned'),
    partial: ok.length < coverage.length || ok.some(c => c.branches_partial),
    reposPartial: ok.length < coverage.length || ok.some(c => c.repos_partial), byRepo, list,
  }
}

export function buildRepos(findings, repoList, connectors, cov) {
  const m = new Map()
  const conn = Object.fromEntries(connectors.map(c => [c.id, c]))
  const touch = (key, c, extra = {}) => {
    const k = c + '|' + key
    if (!m.has(k)) m.set(k, { key: k, name: key, connector: c, org: conn[c]?.org, provider: conn[c]?.provider, branch: '', findings: [], types: new Set(), sev: 0, lastScan: conn[c]?.lastScan })
    const r = m.get(k)
    if (extra.branch && !r.branch) r.branch = extra.branch
    return r
  }
  for (const x of repoList || []) if (x.name) touch(x.name, x.connector, { branch: x.branch })
  for (const x of cov?.list || []) if (x.name) touch(x.name, x.connector, { branch: x.branch }) // scanned repositories without findings
  for (const f of findings) {
    const r = touch(f.repo, f.connector, { branch: f.branch })
    r.findings.push(f); r.types.add(f.type); r.sev = Math.max(r.sev, f.sev)
  }
  return [...m.values()].map(r => {
    const top = [...r.findings].sort((a, b) => b.sev - a.sev || (a.type === 'secret' ? -1 : 1))[0]
    const c = cov?.byRepo.get(r.key)
    return { ...r, top, types: [...r.types], sevName: r.sev ? N_SEV[r.sev] : 'clean', orgLevel: r.name.startsWith('('), cov: c,
      scanState: !c ? 'unknown' : c.scanned ? 'scanned' : 'not_scanned' }
  })
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'clean']
const sevState = (n) => n >= 5 ? 'crit' : n >= 4 ? 'high' : n >= 3 ? 'med' : n >= 2 ? 'low' : n >= 1 ? 'none' : 'ok'

export function FilterBar({ value, onChange, placeholder, count, total, children }) {
  return (
    <div className="ow-card-bar">
      <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
        <Search size={13} style={{ color: 'var(--t3)' }}/>
        <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} aria-label="Filter"/>
        {value && <button onClick={() => onChange('')} aria-label="Clear filter" style={{ background: 'none', border: 0, color: 'var(--t3)', cursor: 'pointer' }}><X size={12}/></button>}
      </label>
      <span className="t2" style={{ fontSize: 13.5 }}>{count.toLocaleString()} of {total.toLocaleString()}</span>
      {children}
    </div>
  )
}

export function toggler(setSel) {
  return (k, v) => setSel(s => { const n = { ...s }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
}

const SCAN_LABEL = { scanned: 'Scanned', not_scanned: 'Not scanned', unknown: 'Unknown' }
const R_GET = { severity: r => r.sevName, type: r => r.types.length ? r.types : '(none)', provider: r => r.provider, org: r => r.org, scan: r => r.scanState }
function RepositoriesTab({ repos, multiOrg }) {
  const navigate = useNavigate()
  const onOpen = (r) => navigate(repoPath(r.connector, r.name))
  const [sel, setSel] = useState({})
  const [q, setQ] = useState('')
  const faceted = useFacetFilter(repos, R_GET, sel)
  const rows = useMemo(() => {
    const { fields, text } = parseFilter(q)
    return faceted.filter(r => {
      if (text && !`${r.name} ${r.org} ${r.top?.title || ''}`.toLowerCase().includes(text)) return false
      if (fields.severity && !fields.severity.some(v => r.sevName.startsWith(v))) return false
      if (fields.type && !fields.type.some(v => r.types.some(t => t.startsWith(v)))) return false
      return true
    }).sort((a, b) => b.sev - a.sev || b.findings.length - a.findings.length || a.name.localeCompare(b.name))
  }, [faceted, q])
  const groups = [
    { key: 'severity', label: 'Severity', values: countBy(repos, R_GET.severity, SEV_ORDER, SEV_LABEL) },
    { key: 'type', label: 'Finding type', values: countBy(repos, r => r.types, Object.keys(TYPE_LABEL), TYPE_LABEL) },
    { key: 'provider', label: 'Provider', values: countBy(repos, R_GET.provider, null, PROVIDER_LABEL) },
    ...(multiOrg ? [{ key: 'org', label: 'Organisation', values: countBy(repos, R_GET.org) }] : []),
    ...(repos.some(r => r.cov) ? [{ key: 'scan', label: 'Scan status', values: countBy(repos, R_GET.scan, ['scanned', 'not_scanned', 'unknown'], SCAN_LABEL) }] : []),
  ]
  const cols = [
    { key: 's', label: 'Severity', width: '96px', render: r => r.sev ? <SevPill sev={r.sev}/> : <StatePill state="ok">Clean</StatePill> },
    { key: 'n', label: 'Repository', width: '1.2fr', render: r => <span className="mono t1">{r.orgLevel ? r.org + ' (organisation)' : <>{multiOrg && <span className="t3">{r.org}/</span>}{r.name}</>}</span>, title: r => `${r.org}/${r.name}` },
    { key: 't', label: 'Top finding', width: '1.8fr', render: r => <span className="t2">{r.top ? r.top.title : 'No findings'}</span>, title: r => r.top ? `${SOURCE_LABEL[r.top.source]}: ${r.top.title}` : '' },
    { key: 'c', label: 'Count', width: '64px', render: r => <span className="mono" style={{ color: r.sev >= 5 ? 'var(--crit)' : r.sev >= 4 ? 'var(--warn)' : 'var(--t3)' }}>{r.findings.length}</span> },
    { key: 'b', label: 'Branch', width: '100px', render: r => <span className="mono t1">{r.branch || '—'}</span> },
    { key: 'bs', label: 'Branches scanned', width: '120px', render: r => r.cov?.branches_known
        ? <span className="mono" style={{ color: r.cov.branches_scanned ? 'var(--t1)' : 'var(--t3)' }}>{r.cov.branches_scanned} / {r.cov.branches_total}</span>
        : <span className="t3">{r.cov ? '—' : ''}</span>,
      title: r => r.cov?.branches_known ? `${r.cov.branches_scanned} of ${r.cov.branches_total} branches have a stored SAST result` : '' },
    { key: 'd', label: 'Scanned', width: '100px', render: r => r.scanState === 'not_scanned'
        ? <span className="t3">Not scanned</span>
        : <span className="t2">{relTime(r.cov?.last_scan || r.top?.at || r.lastScan)}</span> },
  ]
  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      <Facets groups={groups} selected={sel} onToggle={toggler(setSel)} onClear={() => setSel({})}/>
      <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
        <FilterBar value={q} onChange={setQ} placeholder="Filter · severity:critical,high type:secret" count={rows.length} total={repos.length}/>
        <DenseTable cols={cols} rows={rows.slice(0, 300)} rowKey={r => r.key} rowState={r => sevState(r.sev)} onRow={onOpen}
          empty={repos.length ? 'No repositories match these filters.' : 'No repositories yet. Connect a source and run a scan from the Connectors tab.'}/>
        {rows.length > 300 && <div className="ow-card-foot">Showing the first 300 of {rows.length.toLocaleString()}. Narrow the filter to see the rest.</div>}
      </div>
    </div>
  )
}

const REACH_LABEL = { loaded: 'Running (loaded)', deployed: 'Deployed', not_running: 'Not running', unknown: 'Runtime unknown' }
const TRIAGE_LABEL = { open: 'Open', confirmed: 'Confirmed', false_positive: 'False positive', accepted_risk: 'Accepted risk', hint_likely_false_positive: 'Likely false positive', hint_likely_true_positive: 'Likely real' }
const CODE_LABEL = { production: 'Production code', test: 'Test and example code' }
const F_GET = { severity: f => N_SEV[f.sev], type: f => f.type, source: f => f.source, repo: f => f.repo, runtime: f => f.reach, triage: f => f.triage, code: f => f.testCode ? 'test' : 'production' }
function FindingsTab({ findings, initialRepo }) {
  const [sel, setSel] = useState(() => initialRepo ? { repo: new Set([initialRepo]) } : {})
  useEffect(() => { if (initialRepo) setSel({ repo: new Set([initialRepo]) }) }, [initialRepo])
  const [q, setQ] = useState('')
  const navigate = useNavigate()
  const faceted = useFacetFilter(findings, F_GET, sel)
  const rows = useMemo(() => {
    const { text } = parseFilter(q)
    return faceted.filter(f => !text || `${f.title} ${f.repo} ${f.where} ${f.detail || ''}`.toLowerCase().includes(text)).sort((a, b) => b.sev - a.sev || (REACH_ORDER[a.reach] ?? 2) - (REACH_ORDER[b.reach] ?? 2) || a.repo.localeCompare(b.repo))
  }, [faceted, q])
  const groups = [
    { key: 'severity', label: 'Severity', values: countBy(findings, F_GET.severity, SEV_ORDER, SEV_LABEL) },
    { key: 'type', label: 'Finding type', values: countBy(findings, F_GET.type, Object.keys(TYPE_LABEL), TYPE_LABEL) },
    { key: 'source', label: 'Source', values: countBy(findings, F_GET.source, ['sast', 'posture'], SOURCE_LABEL) },
    { key: 'triage', label: 'Triage', values: countBy(findings.filter(f => f.triage), F_GET.triage, Object.keys(TRIAGE_LABEL), TRIAGE_LABEL) },
    ...(findings.some(f => f.testCode) ? [{ key: 'code', label: 'Code', values: countBy(findings.filter(f => f.source === 'sast'), F_GET.code, ['production', 'test'], CODE_LABEL) }] : []),
    { key: 'runtime', label: 'Runtime (dependencies)', values: countBy(findings.filter(f => f.reach), F_GET.runtime, Object.keys(REACH_LABEL), REACH_LABEL) },
    { key: 'repo', label: 'Repository', values: countBy(findings, F_GET.repo).slice(0, 15) },
  ]
  const cols = [
    { key: 's', label: 'Severity', width: '96px', render: f => <SevPill sev={f.sev}/> },
    { key: 't', label: 'Finding', width: '1.7fr', render: f => <span className="t1">{f.title} {f.testCode && <span className="ow-pill" title="In test, fixture or example code: severity lowered one level" style={{ marginLeft: 4 }}>test code</span>} {f.reach && <ReachBadge reach={f.reachInfo}/>}</span>, title: f => f.reachInfo ? `${f.detail || f.title}\n${reachTitle(f.reachInfo)}` : (f.detail || f.title) },
    { key: 'r', label: 'Repository', width: '1fr', render: f => <span className="mono">{f.orgLevel ? f.org : f.repo}</span> },
    { key: 'w', label: 'Where', width: '1.4fr', render: f => <span className="mono t2">{f.where || '—'}</span>, title: f => f.where },
    { key: 'o', label: 'Source', width: '120px', render: f => <span className="t2">{SOURCE_LABEL[f.source]}</span> },
    { key: 'd', label: 'Scanned', width: '96px', render: f => <span className="t2">{relTime(f.at)}</span> },
  ]
  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      <Facets groups={groups} selected={sel} onToggle={toggler(setSel)} onClear={() => setSel({})}/>
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <FilterBar value={q} onChange={setQ} placeholder="Filter findings by title, repository or file" count={rows.length} total={findings.length}/>
          <DenseTable cols={cols} rows={rows.slice(0, 500)} rowKey={f => [f.connector, f.source, f.repo, f.where, f.title].join('|')} rowState={f => sevState(f.sev)}
            onRow={f => navigate(findingPath(f))} empty={findings.length ? 'No findings match these filters.' : 'No findings. Scans run from the Connectors tab.'}/>
          {rows.length > 500 && <div className="ow-card-foot">Showing the first 500 of {rows.length.toLocaleString()}.</div>}
        </div>
      </div>
    </div>
  )
}

export default function CodeOverview({ connectorsView }) {
  const d = useCodeData({ coverage: true })
  const [tab, setTab] = useState('repos')
  const [repoFocus, setRepoFocus] = useState(null)
  const cov = useMemo(() => summariseCoverage(d.coverage), [d.coverage])
  const repos = useMemo(() => buildRepos(d.findings, d.repoList, d.connectors, cov), [d.findings, d.repoList, d.connectors, cov])
  const realRepos = repos.filter(r => !r.orgLevel)
  const n = (pred) => d.findings.filter(pred).length
  const crit = realRepos.filter(r => r.sev >= 5).length
  const high = realRepos.filter(r => r.sev === 4).length
  const secrets = n(f => f.type === 'secret')
  const providers = [...new Set(d.connectors.map(c => PROVIDER_LABEL[c.provider] || c.provider))]
  const noData = !d.loading && d.connectors.length === 0
  const state = d.loading ? undefined : noData ? 'none' : crit ? 'crit' : high ? 'warn' : d.findings.length ? 'info' : 'ok'
  const stateText = noData ? 'No sources connected' : crit ? `${crit} repositor${crit === 1 ? 'y' : 'ies'} with critical findings` : high ? `${high} repositor${high === 1 ? 'y' : 'ies'} with high findings` : d.findings.length ? 'No critical or high findings' : 'No open findings'

  const exportCSV = () => downloadCSV(`code-findings-${new Date().toISOString().slice(0, 10)}.csv`,
    ['severity', 'title', 'organisation', 'repository', 'where', 'type', 'source', 'scanned_at'],
    d.findings.map(f => [N_SEV[f.sev], f.title, f.org, f.repo, f.where, TYPE_LABEL[f.type] || f.type, SOURCE_LABEL[f.source], f.at]))

  return (
    <div>
      <PageHeader
        title="Repositories" state={tab === 'connectors' ? undefined : state} stateText={stateText}
        sub={d.loading ? 'Loading scan results…' : d.error ? `Could not load sources: ${d.error}` : noData
          ? 'Connect GitHub, GitLab or Azure DevOps to watch commits, secrets, pipelines and branch rules.'
          : `${realRepos.length.toLocaleString()} repositor${realRepos.length === 1 ? 'y' : 'ies'} across ${providers.join(' and ')} (${d.connectors.length} source${d.connectors.length === 1 ? '' : 's'}).${d.lastScan ? ` Last scan ${relTime(d.lastScan)}.` : ' No scans have run yet.'}${d.repoList === null ? ' Fetching the full repository list…' : ''}`}
        actions={tab !== 'connectors' && <>
          <button className="ow-btn" onClick={d.reload} title="Reload scan results"><RefreshCw size={13}/>Reload</button>
          <button className="ow-btn" onClick={exportCSV} disabled={!d.findings.length}><Download size={13}/>Export</button>
          <button className="ow-btn primary" onClick={() => setTab('connectors')}>Connect source</button>
        </>}
        nums={tab !== 'connectors' && <>
          <Num k="Repositories scanned" title={cov?.reposPartial ? 'A source\u2019s repository list could not be read; its scanned repositories are counted' : 'Repositories with a stored SAST result, of the repositories the connected sources report now'}
            v={cov ? `${cov.reposScanned.toLocaleString()} / ${cov.reposTotal.toLocaleString()}` : `… / ${realRepos.length.toLocaleString()}`}
            unit={cov?.reposPartial ? 'partial' : undefined} tone={cov && cov.reposTotal && cov.reposScanned < cov.reposTotal ? 'warn' : undefined}/>
          <Num k="Branches scanned" title={cov?.partial ? 'Some repositories\u2019 branch lists could not be read or were beyond the first 300; the totals cover the rest' : 'Branches with a stored SAST result, of all branches of those repositories'}
            v={cov ? `${cov.branchesScanned.toLocaleString()} / ${cov.branchesTotal.toLocaleString()}` : '…'} unit={cov?.partial ? 'partial' : undefined}/>
          <Num k="Open findings" v={d.findings.length.toLocaleString()} tone={crit ? 'crit' : d.findings.length ? 'warn' : undefined}/>
          <Num k="Secrets exposed" v={secrets.toLocaleString()} tone={secrets ? 'crit' : undefined}/>
          <Num k="Critical findings" v={n(f => f.sev >= 5).toLocaleString()} tone={n(f => f.sev >= 5) ? 'crit' : undefined}/>
          <Num k="Branch and access issues" v={n(f => f.source === 'posture').toLocaleString()} tone={n(f => f.source === 'posture') ? 'warn' : undefined}/>
        </>}
        tabs={<Tabs value={tab} onChange={(t) => { setTab(t); if (t !== 'findings') setRepoFocus(null) }} tabs={[
          { id: 'repos', label: 'Repositories' }, { id: 'findings', label: 'Findings', n: d.findings.length || null }, { id: 'connectors', label: 'Connectors and scans', n: d.connectors.length || null }]}/>}
      />
      {tab === 'connectors' ? connectorsView : (
        <div className="ow-body">
          {d.loading ? <div className="t3" style={{ padding: 32, textAlign: 'center' }}>Loading…</div>
            : tab === 'repos' ? <RepositoriesTab repos={repos} multiOrg={d.connectors.length > 1}/>
              : <FindingsTab findings={d.findings} initialRepo={repoFocus}/>}
        </div>
      )}
    </div>
  )
}
