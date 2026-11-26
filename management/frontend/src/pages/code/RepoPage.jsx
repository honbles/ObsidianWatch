// One repository: every finding against it from every scan source, with its branch rules, on its own page.
import { useMemo } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { PageHeader, Num, SevPill, StatePill, DenseTable, relTime } from '../../components/ui'
import { useCodeData, buildRepos, findingPath, SOURCE_LABEL, TYPE_LABEL, PROVIDER_LABEL } from './CodeOverview'

export default function RepoPage() {
  const { connector, repo } = useParams()
  const navigate = useNavigate()
  const d = useCodeData()
  const r = useMemo(() => buildRepos(d.findings, d.repoList, d.connectors).find(x => String(x.connector) === connector && x.name === repo), [d, connector, repo])
  const conn = d.connectors.find(c => String(c.id) === connector)
  const fs = (r?.findings || []).slice().sort((a, b) => b.sev - a.sev)
  const n = (p) => fs.filter(p).length
  const posture = fs.filter(f => f.source === 'posture')
  return (
    <div>
      <PageHeader title={<>{conn && <span className="t3">{conn.org}/</span>}{repo}</>} mono
        state={d.loading ? undefined : r?.sev ? { 5: 'crit', 4: 'warn', 3: 'info' }[r.sev] || 'none' : 'ok'}
        stateText={r?.sev ? `Worst finding: ${{ 5: 'critical', 4: 'high', 3: 'medium', 2: 'low', 1: 'info' }[r.sev]}` : 'No findings'}
        sub={d.loading ? 'Loading…' : conn ? <>{PROVIDER_LABEL[conn.provider] || conn.provider} · {r?.branch ? <>branch <span className="mono t1">{r.branch}</span> · </> : ''}last scan {relTime(r?.lastScan || conn.lastScan)}</> : 'Repository not found in any connected source.'}
        actions={<>
          <button className="ow-btn" onClick={() => navigate(-1)}>Back</button>
          <Link className="ow-btn" style={{ textDecoration: 'none' }} to="/devops">All repositories</Link>
        </>}
        nums={!d.loading && <>
          <Num k="Open findings" v={fs.length}/>
          <Num k="Critical" v={n(f => f.sev >= 5)} tone={n(f => f.sev >= 5) ? 'crit' : undefined}/>
          <Num k="High" v={n(f => f.sev === 4)} tone={n(f => f.sev === 4) ? 'warn' : undefined}/>
          <Num k="Secrets" v={n(f => f.type === 'secret')} tone={n(f => f.type === 'secret') ? 'crit' : undefined}/>
          <Num k="Branch and access issues" v={posture.length} tone={posture.length ? 'warn' : undefined}/>
        </>}/>
      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <section className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Findings</span><span className="t3" style={{ fontSize: 13.5 }}>From the secret and code scan, SAST and the posture check</span></div>
          <DenseTable rows={fs} rowKey={f => findingPath(f)} onRow={f => navigate(findingPath(f))} rowState={f => f.sev >= 5 ? 'crit' : f.sev >= 4 ? 'warn' : null}
            empty={d.loading ? 'Loading…' : 'No findings in the latest scans.'}
            cols={[
              { key: 's', label: 'Severity', width: '92px', render: f => <SevPill sev={f.sev}/> },
              { key: 't', label: 'Finding', width: 'minmax(220px, 2fr)', render: f => <span className="t1">{f.title}</span> },
              { key: 'w', label: 'Where', width: 'minmax(160px, 1.4fr)', render: f => <span className="mono t2">{f.where || '—'}</span>, title: f => f.where },
              { key: 'y', label: 'Type', width: '150px', render: f => <span className="t2">{TYPE_LABEL[f.type] || f.type}</span> },
              { key: 'o', label: 'Source', width: '140px', render: f => <span className="t2">{SOURCE_LABEL[f.source]}</span> },
              { key: 'd', label: 'Scanned', width: '96px', render: f => <span className="t2">{relTime(f.at)}</span> },
            ]}/>
        </section>
        {!d.loading && !fs.length && <div className="t3"><StatePill state="ok">Clean</StatePill> Nothing open against this repository.</div>}
      </div>
    </div>
  )
}
