// Code: the software bill of materials of one repository, in the app.
// Route: /devops/sbom/:connector?repo=<full name>&branch=<branch>
import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import api from '../../api/client'
import { PageHeader, Num, Facets, DenseTable, countBy, useFacetFilter, relTime, Section, downloadCSV } from '../../components/ui'
import { FilterBar, toggler } from './CodeOverview'
import ReachBadge from './ReachBadge'

const RUNTIME_LABEL = { loaded: 'Running (loaded)', deployed: 'Deployed', not_running: 'Not running', unknown: 'Runtime unknown' }
const VULN_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'No known vulnerability' }
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 }
const worst = c => (c.vulns || []).reduce((w, v) => (SEV_RANK[v.severity] || 0) > (SEV_RANK[w] || 0) ? v.severity : w, c.vulns?.length ? 'low' : 'none')

const G = {
  ecosystem: c => c.ecosystem || 'other',
  vuln: c => worst(c),
  runtime: c => c.runtime,
  dep: c => c.transitive ? 'transitive' : 'direct',
  license: c => c.licenses?.length ? c.licenses : ['(none declared)'],
  file: c => c.file || '(unknown)',
}

function VulnCell({ c }) {
  if (!c.vulns?.length) return <span className="t3">—</span>
  const w = worst(c)
  const color = w === 'critical' ? 'var(--crit)' : w === 'high' ? 'var(--warn)' : 'var(--t2)'
  return <span className="mono" style={{ color }} title={c.vulns.map(v => `${v.id} (${v.severity})`).join('\n')}>{c.vulns.length} · {w}</span>
}

export default function SBOMPage() {
  const { connector } = useParams()
  const [params] = useSearchParams()
  const repo = params.get('repo') || ''
  const branch = params.get('branch') || ''
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [sel, setSel] = useState({})
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(null)

  useEffect(() => {
    const p = new URLSearchParams({ repo, view: '1' })
    if (branch) p.set('branch', branch)
    api.get(`/api/v1/devops-connectors/${connector}/sast/sbom?${p}`).then(r => setData(r.data))
      .catch(e => setErr(e.response?.data?.error || 'Could not load the SBOM'))
  }, [connector, repo, branch])

  const comps = data?.components || []
  const faceted = useFacetFilter(comps, G, sel)
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase()
    return faceted.filter(c => !t || `${c.name} ${c.version} ${c.purl || ''} ${(c.licenses || []).join(' ')} ${(c.vulns || []).map(v => v.id).join(' ')}`.toLowerCase().includes(t))
      .sort((a, b) => (SEV_RANK[worst(b)] || 0) - (SEV_RANK[worst(a)] || 0) || ({ loaded: 0, deployed: 1 }[a.runtime] ?? 2) - ({ loaded: 0, deployed: 1 }[b.runtime] ?? 2) || a.name.localeCompare(b.name))
  }, [faceted, q])

  const download = async () => {
    const p = new URLSearchParams({ repo }); if (branch) p.set('branch', branch)
    const res = await api.get(`/api/v1/devops-connectors/${connector}/sast/sbom?${p}`, { responseType: 'blob' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(res.data); a.download = `${repo.replace(/\//g, '_')}.cdx.json`; a.click(); URL.revokeObjectURL(a.href)
  }
  const exportCSV = () => downloadCSV(`${repo.replace(/\//g, '_')}-components.csv`,
    ['name', 'version', 'ecosystem', 'purl', 'licenses', 'dependency', 'vulnerabilities', 'runtime', 'file'],
    rows.map(c => [c.name, c.version, c.ecosystem, c.purl || '', (c.licenses || []).join(' '), c.transitive ? 'transitive' : 'direct',
      (c.vulns || []).map(v => v.id).join(' '), c.runtime, c.file || '']))

  const s = data?.summary || {}
  const groups = [
    { key: 'vuln', label: 'Vulnerabilities', values: countBy(comps, G.vuln, ['critical', 'high', 'medium', 'low', 'none'], VULN_LABEL) },
    { key: 'runtime', label: 'Runtime', values: countBy(comps, G.runtime, Object.keys(RUNTIME_LABEL), RUNTIME_LABEL) },
    { key: 'dep', label: 'Dependency', values: countBy(comps, G.dep, ['direct', 'transitive'], { direct: 'Direct', transitive: 'Transitive' }) },
    { key: 'ecosystem', label: 'Ecosystem', values: countBy(comps, G.ecosystem) },
    { key: 'license', label: 'Licence', values: countBy(comps, G.license).slice(0, 15) },
    { key: 'file', label: 'Manifest', values: countBy(comps, G.file).slice(0, 10) },
  ]
  const cols = [
    { key: 'n', label: 'Component', width: '1.6fr', render: c => <span className="mono t1">{c.name}</span>, title: c => c.purl || c.name },
    { key: 'v', label: 'Version', width: '110px', render: c => <span className="mono t2">{c.version}</span> },
    { key: 'e', label: 'Ecosystem', width: '96px', render: c => <span className="t2">{c.ecosystem || '—'}</span> },
    { key: 'd', label: 'Dependency', width: '96px', render: c => <span className="t2">{c.transitive ? 'transitive' : 'direct'}</span> },
    { key: 'l', label: 'Licence', width: '1fr', render: c => <span className="t2">{(c.licenses || []).join(', ') || '—'}</span>, title: c => (c.licenses || []).join(', ') },
    { key: 'x', label: 'Vulnerabilities', width: '120px', render: c => <VulnCell c={c}/> },
    { key: 'r', label: 'Runtime', width: '130px', render: c => <ReachBadge reach={{ level: c.runtime, hosts: c.hosts, services: c.services }}/> },
  ]
  const key = c => `${c.ecosystem}|${c.name}|${c.version}|${c.file}`

  return (
    <div>
      <PageHeader title={`SBOM · ${repo}`} mono
        sub={data ? <>CycloneDX 1.5 · branch <span className="mono">{data.branch || 'default'}</span> · from the SAST scan {relTime(data.scanned_at)}</> : (err || 'Loading…')}
        actions={<>
          <button className="ow-btn" onClick={() => navigate(-1)}>Back</button>
          <button className="ow-btn" onClick={exportCSV} disabled={!rows.length}>Export CSV</button>
          <button className="ow-btn primary" onClick={download} disabled={!data}>Download CycloneDX</button>
        </>}
        nums={data && <>
          <Num k="Components" v={s.components || 0}/>
          <Num k="Transitive" v={s.transitive || 0}/>
          <Num k="Vulnerable" v={s.vulnerable || 0} tone={s.vulnerable ? 'warn' : undefined}/>
          <Num k="Running (loaded)" v={s.runtime_loaded || 0} tone={s.runtime_loaded ? 'crit' : undefined}/>
          <Num k="Deployed" v={s.runtime_deployed || 0}/>
        </>}/>
      {data && (
        <div className="ow-body" style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <Facets groups={groups} selected={sel} onToggle={toggler(setSel)} onClear={() => setSel({})}/>
          <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="ow-card" style={{ overflow: 'hidden' }}>
              <FilterBar value={q} onChange={setQ} placeholder="Filter by package, version, licence or vulnerability ID" count={rows.length} total={comps.length}/>
              <DenseTable cols={cols} rows={rows.slice(0, 1000)} rowKey={key} current={open && key(open)}
                rowState={c => worst(c) === 'critical' ? 'crit' : worst(c) === 'high' ? 'warn' : null}
                onRow={c => setOpen(open && key(open) === key(c) ? null : c)}
                empty={comps.length ? 'No components match these filters.' : 'The SBOM has no components.'}/>
              {rows.length > 1000 && <div className="ow-card-foot">Showing the first 1,000 of {rows.length.toLocaleString()}. Narrow the filter or export.</div>}
            </div>
            {open && (
              <Section title={`${open.name} ${open.version}`} sub={open.purl}>
                <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: '6px 12px' }}>
                  <span className="t3">Ecosystem</span><span>{open.ecosystem || '—'}</span>
                  <span className="t3">Dependency</span><span>{open.transitive ? 'Transitive (pulled in by another package)' : 'Direct'}</span>
                  <span className="t3">Declared in</span><span className="mono">{open.file || '—'}</span>
                  <span className="t3">Licences</span><span>{(open.licenses || []).join(', ') || 'None declared'}</span>
                  <span className="t3">Runtime</span><span>{RUNTIME_LABEL[open.runtime]}{open.services?.length ? ` · ${open.services.join(', ')}` : ''}{open.hosts?.length ? ` · hosts ${open.hosts.join(', ')}` : ''}</span>
                </div>
                {open.vulns?.length > 0 && (
                  <div style={{ marginTop: 12 }}>
                    <div className="ow-lbl" style={{ marginBottom: 6 }}>Vulnerabilities</div>
                    {open.vulns.map(v => (
                      <div key={v.id} style={{ padding: '6px 0', borderTop: '1px solid var(--line)' }}>
                        <span className="mono t1">{v.id}</span> <span className="t3">· {v.severity}</span>
                        {v.detail && <div className="t2" style={{ marginTop: 2 }}>{v.detail}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </Section>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
