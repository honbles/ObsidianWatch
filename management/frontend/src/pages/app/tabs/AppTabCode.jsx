import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../../../api/client'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { StateBlock } from '../../../components/shared'
import { DenseTable, Dialog, Field, relTime } from '../../../components/ui'
import { SevWord, Counts } from '../../../components/app/AppRisk'
import { appIsAdmin } from '../../../components/app/appFormat'

const REACH = {
  loaded: ['Loaded here', 'c-crit', 'This service\'s process has the vulnerable package version in memory'],
  deployed: ['On disk here', 'c-warn', 'The vulnerable version is in this service\'s files but was not seen loaded'],
  not_in_service: ['Not in this service', 't3', 'This service\'s processes do not run this package version'],
  unknown: ['Not known', 't3', 'No runtime package inventory for this service yet'],
}
const COVERAGE = {
  reported: null,
  not_running: 'No live instance of this service in the last 24 hours, so findings cannot be checked against what runs.',
  no_packages: 'The host reports a runtime inventory, but no packages were attributed to this service\'s processes. Runtime matching covers Go, Java, Python, Node.js and .NET processes on Linux.',
  none: 'No runtime package inventory from this service\'s hosts. It comes from the Linux agent built with the app-server profile; until then findings show the scanner severity only.',
}

function LinkDialog({ service, onClose, onSaved }) {
  const [conns, setConns] = useState([])
  const [conn, setConn] = useState('')
  const [repos, setRepos] = useState(null)
  const [repo, setRepo] = useState('')
  const [branches, setBranches] = useState(null)
  const [branch, setBranch] = useState('')
  const [state, setState] = useState({ busy: false, err: '' })
  useEffect(() => { api.get('/api/v1/devops-connectors').then(r => setConns(Array.isArray(r.data?.connectors) ? r.data.connectors : [])).catch(() => setConns([])) }, [])
  useEffect(() => {
    setRepos(null); setRepo(''); setBranches(null); setBranch('')
    if (!conn) return
    api.get(`/api/v1/devops-connectors/${conn}/sast/repos`).then(r => setRepos(r.data?.repos || [])).catch(e => { setRepos([]); setState({ busy: false, err: e.response?.data?.error || 'Could not list repositories' }) })
  }, [conn])
  const def = repos?.find(r => r.repo === repo)?.branch || ''
  useEffect(() => {
    setBranches(null); setBranch('')
    if (!conn || !repo) return
    const p = new URLSearchParams({ repo }); if (def) p.set('default', def)
    api.get(`/api/v1/devops-connectors/${conn}/sast/branches?${p}`).then(r => { setBranches(r.data?.branches || []); setBranch(def) }).catch(() => { setBranches([]); setBranch(def) })
  }, [conn, repo]) // eslint-disable-line react-hooks/exhaustive-deps
  const save = async () => {
    setState({ busy: true, err: '' })
    try {
      await appApi.addCodeLink(service.id, { connector_id: Number(conn), repo, branch, is_default: !branch || branch === def })
      onSaved()
    } catch (e) { setState({ busy: false, err: e.response?.data?.error || e.message }) }
  }
  const sel = 'input'
  return (
    <Dialog title={`Link code to ${service.name}`} onClose={onClose} width={520}
      footer={<>
        <button className="ow-btn" onClick={onClose}>Cancel</button>
        <button className="ow-btn primary" disabled={!conn || !repo || state.busy} onClick={save}>{state.busy ? 'Linking…' : 'Link'}</button>
      </>}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div className="t2" style={{ fontSize: 13.5 }}>The repository and branch this service is built from.</div>
        <Field label="Code connector">
          <select className={sel} value={conn} onChange={e => setConn(e.target.value)}>
            <option value="">Choose…</option>
            {conns.map(c => <option key={c.id} value={c.id}>{c.label || c.org} ({c.provider})</option>)}
          </select>
        </Field>
        <Field label="Repository" hint={conn && repos === null ? 'Loading repositories…' : undefined}>
          <select className={sel} value={repo} onChange={e => setRepo(e.target.value)} disabled={!repos}>
            <option value="">Choose…</option>
            {(repos || []).map(r => <option key={r.repo} value={r.repo}>{r.repo}</option>)}
          </select>
        </Field>
        <Field label="Branch" hint="The branch that is deployed for this environment.">
          <select className={sel} value={branch} onChange={e => setBranch(e.target.value)} disabled={!repo || branches === null}>
            {def && !(branches || []).some(b => b.name === def) && <option value={def}>{def} (default)</option>}
            {(branches || []).map(b => <option key={b.name} value={b.name}>{b.name}{b.default ? ' (default)' : ''}{b.scanned_at ? ` · scanned ${relTime(b.scanned_at)}` : ''}</option>)}
          </select>
        </Field>
        {state.err && <div className="c-crit" style={{ fontSize: 13.5 }}>{state.err}</div>}
        {conns.length === 0 && <div className="t3" style={{ fontSize: 13.5 }}>No code connectors yet. Add one under Code → DevOps first.</div>}
      </div>
    </Dialog>
  )
}

function weighText(w = {}) {
  const ups = []
  if ((w.exposure === 'unknown' ? w.exposure_effective : w.exposure) === 'internet') ups.push('internet-facing')
  if (w.criticality === 'high' || w.criticality === 'critical') ups.push(`${w.criticality} criticality`)
  return (ups.length ? `priority is raised one level each for ${ups.join(' and ')} when loaded` : 'priority is the scanner severity when loaded')
    + ', and lowered one level when not in this service'
}

const SRC = { otel: 'OpenTelemetry vcs attributes', oci: 'container image label', git: 'git checkout on the host' }
const SCAN_STATE = {
  scanned: ['scanned', 'c-ok'], queued: ['scan queued', 'c-warn'], running: ['scanning…', 'c-warn'], failed: ['scan failed', 'c-crit'],
  short_id: ['short commit id, cannot fetch', 't3'], repo_mismatch: ['different repository', 'c-crit'], none: ['not scanned yet', 't3'],
}

// What runs: the commits the instances report and the scan of each.
function Deployments({ link }) {
  const deps = link.deployments || []
  if (!deps.length) {
    return <div className="t3" style={{ padding: '8px 14px', fontSize: 13.5 }}>
      Commit not reported yet: findings are from the latest scan of <span className="mono">{link.branch || 'the default branch'}</span>.
    </div>
  }
  return (
    <div style={{ padding: '8px 14px', display: 'flex', flexDirection: 'column', gap: 4, fontSize: 13.5 }}>
      {deps.map(d => {
        const [label, cls] = SCAN_STATE[d.scan.status] || SCAN_STATE.none
        return (
          <div key={d.revision}>
            <span className="t2">{d.primary ? 'Running' : 'Also running'}</span> <span className="mono t1" title={d.revision}>{d.short}</span>
            {d.branch && <span className="t3"> ({d.branch})</span>}
            <span className="t2"> · {d.instances} instance{d.instances === 1 ? '' : 's'} on {d.hosts.join(', ')}</span>
            <span className="t3"> · from {SRC[d.source] || d.source}</span>
            <span className={cls}> · {label}{d.scan.scanned_at ? ' ' + relTime(d.scan.scanned_at) : ''}</span>
            {d.scan.counts && <span style={{ marginLeft: 8 }}><Counts parts={[[d.scan.counts.critical, 'crit', 'var(--crit)'], [d.scan.counts.high, 'high', 'var(--warn)'], [d.scan.counts.medium, 'med']]}/></span>}
            {d.repo_mismatch && <div className="c-crit" style={{ fontSize: 13.5 }}>This instance reports <span className="mono">{d.repo}</span>, not <span className="mono">{link.repo}</span>. Check the link.</div>}
            {d.scan.error && <div className="c-crit" style={{ fontSize: 13.5 }}>{d.scan.error}</div>}
          </div>
        )
      })}
      <div className="t3" style={{ fontSize: 13.5 }}>
        {link.showing === 'commit'
          ? <>Findings below are from the scan of the running commit <span className="mono">{link.showing_revision.slice(0, 12)}</span>.</>
          : <>Findings below are from the latest scan of <span className="mono">{link.branch || 'the default branch'}</span> until the running commit is scanned.</>}
      </div>
    </div>
  )
}

// Code: the repositories linked to this service and their findings, each
// dependency finding labelled against what this service's processes run.
export default function AppTabCode({ service }) {
  const admin = appIsAdmin()
  const { data, loading, error, reload } = useAppLoad(() => appApi.code(service.id), [service.id])
  const [open, setOpen] = useState(false)
  const [filter, setFilter] = useState('running')
  const links = data?.links || []
  const findings = data?.findings || []
  const scanning = links.some(l => l.scanning || (l.deployments || []).some(d => d.scan.status === 'queued' || d.scan.status === 'running'))
  useEffect(() => {
    if (!scanning) return
    const t = setTimeout(reload, 10000)
    return () => clearTimeout(t)
  }, [scanning, data]) // eslint-disable-line react-hooks/exhaustive-deps
  const shown = useMemo(() => findings.filter(f =>
    filter === 'all' ? true :
    filter === 'running' ? (f.service_reach === 'loaded' || f.service_reach === 'deployed' || !f.service_reach || f.service_reach === 'unknown') :
    filter === 'deps' ? !!f.package : !f.package), [findings, filter])
  const nLoaded = findings.filter(f => f.service_reach === 'loaded').length
  const remove = async (l) => {
    if (!window.confirm(`Unlink ${l.repo} from ${service.name}?`)) return
    await appApi.removeCodeLink(service.id, l.id).catch(() => {})
    reload()
  }
  const cols = [
    { key: 'p', label: 'Priority', width: '92px', render: f => <SevWord sev={f.priority} title={f.priority !== f.severity ? `Scanner severity ${f.severity}; adjusted for this service` : undefined}/> },
    { key: 'r', label: 'Running here', width: '130px', render: f => {
      if (!f.package) return <span className="t3">code</span>
      const [l, c, t] = REACH[f.service_reach] || REACH.unknown
      return <span className={c} title={t}>{l}</span>
    } },
    { key: 't', label: 'Finding', width: 'minmax(220px, 2fr)', title: f => f.detail, render: f => <span className="t1">{f.title}{f.package && <span className="mono t3" style={{ fontSize: 13 }}> · {f.package} {f.version}</span>}</span> },
    { key: 'f', label: 'Where', width: 'minmax(150px, 1fr)', render: f => <span className="mono t2" style={{ fontSize: 13 }}>{f.repo} · {f.file}{f.line ? `:${f.line}` : ''}</span> },
    { key: 'i', label: '', width: '70px', render: f => f.issue_url ? <a href={f.issue_url} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()}>issue</a> : null },
  ]
  return (
    <StateBlock loading={loading && !data} error={error}>
      {data && (<div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <span style={{ fontWeight: 600 }}>Linked code</span>
            <span className="t3" style={{ fontSize: 13.5 }}>Repositories this service is built from</span>
            {admin && <button className="ow-btn primary" style={{ marginLeft: 'auto' }} onClick={() => setOpen(true)}>Link repository</button>}
          </div>
          <DenseTable rowKey={l => l.id} rows={links}
            empty={admin ? 'No repository linked.' : 'No repository linked. An admin can link one.'}
            cols={[
              { key: 'r', label: 'Repository', width: 'minmax(180px, 1.4fr)', render: l => <Link className="mono t1" to={`/devops/repos/${l.connector_id}/${encodeURIComponent(l.repo)}`}>{l.repo}</Link> },
              { key: 'b', label: 'Branch', width: '130px', render: l => <span className="mono t2">{l.branch || 'default'}{l.is_default && l.branch ? <span className="t3"> (default)</span> : null}</span> },
              { key: 'c', label: 'Connector', width: '140px', render: l => <span className="t2">{l.connector || '—'} <span className="t3">{l.provider}</span></span> },
              { key: 's', label: 'Findings from', width: '150px', render: l => l.scanning && !l.scanned_at ? <span className="c-warn">scanning…</span> : l.scanned_at ? <span className="t2">{l.showing === 'commit' ? <>commit <span className="mono">{l.showing_revision.slice(0, 7)}</span></> : 'branch head'} · {relTime(l.scanned_at)}</span> : <span className="t3">not scanned</span> },
              { key: 'n', label: 'Findings', width: 'minmax(170px, 1fr)', render: l => <Counts parts={[[l.counts.critical, 'crit', 'var(--crit)'], [l.counts.high, 'high', 'var(--warn)'], [l.counts.medium, 'med'], [l.counts.low, 'low'], [l.dismissed, 'dismissed']]}/> },
              ...(admin ? [{ key: 'x', label: '', width: '70px', render: l => <button className="ow-btn quiet" onClick={e => { e.stopPropagation(); remove(l) }}>Unlink</button> }] : []),
            ]}/>
          {links.map(l => <div key={l.id} style={{ borderTop: '1px solid var(--line)' }}><Deployments link={l}/></div>)}
        </div>

        {links.length > 0 && <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar" style={{ gap: 10 }}>
            <span style={{ fontWeight: 600 }}>Findings</span>
            <select className="input" style={{ height: 26, width: 230 }} value={filter} onChange={e => setFilter(e.target.value)}>
              <option value="running">Running here or not known ({findings.filter(f => f.service_reach !== 'not_in_service').length})</option>
              <option value="deps">Dependencies ({findings.filter(f => f.package).length})</option>
              <option value="code">Code and secrets ({findings.filter(f => !f.package).length})</option>
              <option value="all">All ({findings.length})</option>
            </select>
            <span className="t3" style={{ fontSize: 13.5 }}>{nLoaded} vulnerable package{nLoaded === 1 ? '' : 's'} loaded by this service · {weighText(data.weighting)}</span>
          </div>
          {COVERAGE[data.inventory] && <div className="t3" style={{ padding: '8px 14px', fontSize: 13.5 }}>{COVERAGE[data.inventory]}</div>}
          <DenseTable rowKey={f => `${f.connector_id}-${f.repo}-${f.rule_id}-${f.file}-${f.line}-${f.package || ''}`} rows={shown}
            rowState={f => (f.priority === 'critical' ? 'crit' : f.priority === 'high' ? 'warn' : null)}
            cols={cols} empty="No findings in this view."/>
        </div>}

        {(data.platform || []).some(p => p.os_package || p.port_risks.length || p.cves.length) && (
          <div className="ow-card" style={{ overflow: 'hidden' }}>
            <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>From the host scan</span>
              <span className="t3" style={{ fontSize: 13.5 }}>The installed package this service runs from, and scan findings on its ports</span></div>
            <DenseTable rowKey={p => p.agent_id} rows={data.platform}
              cols={[
                { key: 'h', label: 'Host', width: '160px', render: p => <Link className="mono t1" to={`/applications/hosts/${encodeURIComponent(p.agent_id)}`}>{p.host}</Link> },
                { key: 'p', label: 'Installed package', width: '200px', render: p => p.os_package ? <span className="mono t2">{p.os_package} {p.os_package_version}</span> : <span className="t3">—</span> },
                { key: 'r', label: 'Port findings', width: 'minmax(200px, 1.5fr)', render: p => p.port_risks.length ? p.port_risks.map(r => <div key={r.port} className="t2" style={{ fontSize: 13.5 }}><span className="mono">{r.port}</span> {r.risk_label} <span className="t3">{r.risk_detail}</span></div>) : <span className="t3">none</span> },
                { key: 'c', label: 'CVEs', width: 'minmax(160px, 1fr)', render: p => p.cves.length ? <span className="c-crit">{p.cves.slice(0, 3).map(c => c.cve_id).join(', ')}{p.cves.length > 3 ? ` +${p.cves.length - 3}` : ''}</span> : <span className="t3">{p.scanned_at ? 'none known' : 'no scan'}</span> },
              ]}/>
          </div>)}

        {(data.unlinked_running || []).length > 0 && (
          <div className="ow-card" style={{ overflow: 'hidden' }}>
            <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Also loaded by this service</span>
              <span className="t3" style={{ fontSize: 13.5 }}>Vulnerable package versions this service runs, found in repositories not linked to it</span></div>
            <DenseTable rowKey={u => `${u.connector_id}-${u.repo}-${u.vuln}-${u.package}`} rows={data.unlinked_running}
              cols={[
                { key: 's', label: 'Severity', width: '92px', render: u => <SevWord sev={u.severity}/> },
                { key: 'v', label: 'Vulnerability', width: 'minmax(200px, 1.5fr)', render: u => <span className="t1">{u.vuln} <span className="mono t3">{u.package} {u.version}</span></span> },
                { key: 'e', label: 'Here', width: '110px', render: u => <span className={u.evidence === 'loaded' ? 'c-crit' : 'c-warn'}>{u.evidence === 'loaded' ? 'loaded' : 'on disk'}</span> },
                { key: 'r', label: 'Found in', width: 'minmax(160px, 1fr)', render: u => <Link className="mono t2" to={`/devops/repos/${u.connector_id}/${encodeURIComponent(u.repo)}`}>{u.repo}</Link> },
              ]}/>
          </div>)}
        {open && <LinkDialog service={service} onClose={() => setOpen(false)} onSaved={() => { setOpen(false); reload() }}/>}
      </div>)}
    </StateBlock>
  )
}
