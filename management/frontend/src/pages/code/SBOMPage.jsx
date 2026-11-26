// Code: the software bill of materials of one repository, in the app.
// Route: /devops/sbom/:connector?repo=<full name>&branch=<branch>
import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams, useSearchParams } from 'react-router-dom'
import api from '../../api/client'
import { PageHeader, Num, Facets, DenseTable, countBy, useFacetFilter, relTime, downloadCSV, Drawer } from '../../components/ui'
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

const SEV_COLOR = { critical: 'var(--crit)', high: 'var(--warn)', medium: 'var(--acc)', low: 'var(--t3)' }
const TRIAGE_LABEL = { false_positive: 'false positive', accepted_risk: 'accepted risk', confirmed: 'confirmed' }

// CVE tags: the worst two IDs, then "+N". A tag opens that vulnerability.
function VulnCell({ c, onOpen }) {
  if (!c.vulns?.length) return <span className="t3">—</span>
  const shown = c.vulns.slice(0, 2)
  return (
    <span style={{ display: 'inline-flex', gap: 4, alignItems: 'center', flexWrap: 'nowrap', overflow: 'hidden' }}>
      {shown.map(v => (
        <button key={v.id} className="mono" title={`${v.id} (${v.severity})${v.title ? ' · ' + v.title : ''}`}
          onClick={e => { e.stopPropagation(); onOpen(c, v.id) }}
          style={{ fontSize: 13, padding: '1px 6px', borderRadius: 5, border: `1px solid ${SEV_COLOR[v.severity] || 'var(--line2)'}`, color: SEV_COLOR[v.severity] || 'var(--t2)', background: 'transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
          {v.id}
        </button>
      ))}
      {c.vulns.length > 2 && <button className="t2" onClick={e => { e.stopPropagation(); onOpen(c) }} style={{ fontSize: 13, background: 'transparent', border: 0, cursor: 'pointer', whiteSpace: 'nowrap' }}>+{c.vulns.length - 2}</button>}
    </span>
  )
}

function VulnCounts({ vulns }) {
  const n = {}
  vulns.forEach(v => { n[v.severity] = (n[v.severity] || 0) + 1 })
  return <span className="mono" style={{ display: 'inline-flex', gap: 10 }}>
    {['critical', 'high', 'medium', 'low'].filter(k => n[k]).map(k => <span key={k} style={{ color: SEV_COLOR[k] }}>{n[k]} {k}</span>)}
  </span>
}

// Drawer: one component and every vulnerability in it, with links and fixes.
function ComponentDrawer({ c, focus, onClose }) {
  const [vq, setVq] = useState('')
  useEffect(() => {
    if (!focus) return
    const t = setTimeout(() => document.getElementById(`vuln-${focus}`)?.scrollIntoView({ block: 'center' }), 50)
    return () => clearTimeout(t)
  }, [focus, c])
  if (!c) return null
  const vulns = (c.vulns || []).filter(v => !vq || `${v.id} ${v.title || ''} ${v.detail || ''}`.toLowerCase().includes(vq.toLowerCase()))
  const fixes = [...new Set((c.vulns || []).map(v => v.fix).filter(Boolean))]
  const files = c.files?.length ? c.files : (c.file ? [c.file] : [])
  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14, overflowY: 'auto', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="mono" style={{ fontSize: 16, fontWeight: 600, wordBreak: 'break-all' }}>{c.name} <span className="t2">{c.version}</span></div>
          <div className="t3 mono" style={{ fontSize: 13, wordBreak: 'break-all' }}>{c.purl}</div>
        </div>
        <button className="ow-btn quiet" onClick={onClose} aria-label="Close">Esc</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '134px 1fr', gap: '6px 12px', fontSize: 14 }}>
        <span className="t3">Ecosystem</span><span>{c.ecosystem || '—'}</span>
        <span className="t3">Dependency</span><span>{c.transitive ? 'Transitive (pulled in by another package)' : 'Direct'}</span>
        <span className="t3">Declared in</span><span className="mono" style={{ fontSize: 13.5 }}>{files.length ? files.map(f => <div key={f}>{f}</div>) : '—'}</span>
        <span className="t3">Licences</span><span>{(c.licenses || []).join(', ') || 'None declared'}</span>
        <span className="t3">Runtime</span><span>{RUNTIME_LABEL[c.runtime]}{c.services?.length ? ` · ${c.services.join(', ')}` : ''}{c.hosts?.length ? ` · hosts ${c.hosts.join(', ')}` : ''}</span>
        {c.vulns?.length > 0 && <><span className="t3">Vulnerabilities</span><span><VulnCounts vulns={c.vulns}/></span></>}
      </div>
      {fixes.length > 0 && (
        <div className="ow-card" style={{ padding: '10px 12px', background: 'var(--s2)', fontSize: 14 }}>
          <div className="ow-lbl" style={{ marginBottom: 4 }}>Fix</div>
          {fixes.map(f => <div key={f}>{f}</div>)}
        </div>
      )}
      {c.vulns?.length > 0 && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <div className="ow-lbl">Vulnerabilities ({c.vulns.length})</div>
            {c.vulns.length > 6 && <label className="ow-field" style={{ height: 26, flex: 1, maxWidth: 260 }}><input value={vq} onChange={e => setVq(e.target.value)} placeholder="Filter by ID or text"/></label>}
          </div>
          {vulns.map(v => (
            <div key={v.id} id={`vuln-${v.id}`} style={{ padding: '10px 10px', borderTop: '1px solid var(--line)', background: v.id === focus ? 'var(--s2)' : undefined, borderRadius: v.id === focus ? 6 : 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span className="mono t1" style={{ fontWeight: 600 }}>{v.id}</span>
                <span style={{ color: SEV_COLOR[v.severity], fontSize: 13.5 }}>{v.severity}</span>
                {v.triage && <span className="t3" style={{ fontSize: 13.5 }}>· {TRIAGE_LABEL[v.triage] || v.triage}</span>}
                <span style={{ marginLeft: 'auto', display: 'inline-flex', gap: 10, fontSize: 13.5 }}>
                  {v.db_url && <a href={v.db_url} target="_blank" rel="noreferrer">{v.id.startsWith('CVE-') ? 'NVD' : v.id.startsWith('GHSA-') ? 'GitHub advisory' : 'OSV'}</a>}
                  {v.url && v.url !== v.db_url && <a href={v.url} target="_blank" rel="noreferrer">Advisory</a>}
                  {v.issue_url && <a href={v.issue_url} target="_blank" rel="noreferrer">Issue</a>}
                </span>
              </div>
              {(v.title || v.detail) && <div className="t2" style={{ marginTop: 4, fontSize: 14 }}>{v.title || v.detail}</div>}
              {v.fix && fixes.length > 1 && <div className="t3" style={{ marginTop: 3, fontSize: 13.5 }}>Fix: {v.fix}</div>}
              {v.files?.length > 1 && <div className="t3" style={{ marginTop: 3, fontSize: 13.5 }}>In {v.files.length} manifests</div>}
            </div>
          ))}
          {vulns.length === 0 && <div className="t3" style={{ fontSize: 13.5 }}>No vulnerability matches the filter.</div>}
        </div>
      )}
    </div>
  )
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
  const [focus, setFocus] = useState(null)
  const openComp = (c, vid) => { setOpen(c); setFocus(vid || null) }

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
    return faceted.filter(c => !t || `${c.name} ${c.version} ${c.purl || ''} ${(c.licenses || []).join(' ')} ${(c.vulns || []).map(v => `${v.id} ${v.title || ''}`).join(' ')}`.toLowerCase().includes(t))
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
      (c.vulns || []).map(v => v.id).join(' '), c.runtime, (c.files?.length ? c.files : [c.file || '']).join(' ')]))

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
    { key: 'n', label: 'Component', width: 'minmax(180px, 1.6fr)', render: c => <span className="mono t1">{c.name}</span>, title: c => c.purl || c.name },
    { key: 'v', label: 'Version', width: '110px', render: c => <span className="mono t2">{c.version}</span> },
    { key: 'e', label: 'Ecosystem', width: '96px', render: c => <span className="t2">{c.ecosystem || '—'}</span> },
    { key: 'd', label: 'Dependency', width: '96px', render: c => <span className="t2">{c.transitive ? 'transitive' : 'direct'}</span> },
    { key: 'l', label: 'Licence', width: '1fr', render: c => <span className="t2">{(c.licenses || []).join(', ') || '—'}</span>, title: c => (c.licenses || []).join(', ') },
    { key: 'x', label: 'Vulnerabilities', width: '260px', render: c => <VulnCell c={c} onOpen={openComp}/>, title: c => (c.vulns || []).length ? `${c.vulns.length} vulnerabilities` : undefined },
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
                onRow={c => (open && key(open) === key(c) ? setOpen(null) : openComp(c))}
                empty={comps.length ? 'No components match these filters.' : 'The SBOM has no components.'}/>
              {rows.length > 1000 && <div className="ow-card-foot">Showing the first 1,000 of {rows.length.toLocaleString()}. Narrow the filter or export.</div>}
            </div>
          </div>
        </div>
      )}
      <Drawer open={!!open} onClose={() => setOpen(null)} label="Component details" width={640}>
        <ComponentDrawer c={open} focus={focus} onClose={() => setOpen(null)}/>
      </Drawer>
    </div>
  )
}
