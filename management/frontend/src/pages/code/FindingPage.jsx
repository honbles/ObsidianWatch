// One code finding on its own page: what, where, how it was found, how to fix it.
import { useMemo } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { PageHeader, SevPill, Section, relTime } from '../../components/ui'
import { useCodeData, findingId, findingPath, repoPath, SOURCE_LABEL, TYPE_LABEL } from './CodeOverview'

function Row({ k, children }) {
  return <div style={{ display: 'grid', gridTemplateColumns: '179px 1fr', gap: 12, padding: '6px 0', borderBottom: '1px solid var(--line)' }}><span className="t3">{k}</span><span>{children}</span></div>
}

export default function FindingPage() {
  const { fid } = useParams()
  const navigate = useNavigate()
  const d = useCodeData()
  const f = useMemo(() => d.findings.find(x => findingId(x) === fid), [d.findings, fid])
  const siblings = f ? d.findings.filter(x => x.repo === f.repo && x.connector === f.connector && x !== f).sort((a, b) => b.sev - a.sev).slice(0, 8) : []
  if (!d.loading && !f) return (
    <div><PageHeader title="Finding not found" sub="It may have been fixed and dropped from the latest scan." actions={<Link className="ow-btn" style={{ textDecoration: 'none' }} to="/devops">All repositories</Link>}/></div>
  )
  return (
    <div>
      <PageHeader title={f?.title || 'Loading…'}
        sub={f && <><Link className="mono c-acc" to={repoPath(f.connector, f.repo)}>{f.org}/{f.repo}</Link>{f.where && <> · <span className="mono">{f.where}</span></>} · {SOURCE_LABEL[f.source]} · scanned {relTime(f.at)}</>}
        actions={<button className="ow-btn" onClick={() => navigate(-1)}>Back</button>}>
        {f && <div style={{ marginTop: 10 }}><SevPill sev={f.sev}/></div>}
      </PageHeader>
      {f && (
        <div className="ow-body" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(314px, 1fr)', gap: 16, alignItems: 'start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <Section title="Details">
              <Row k="Type">{TYPE_LABEL[f.type] || f.type}</Row>
              <Row k="Repository"><Link className="mono c-acc" to={repoPath(f.connector, f.repo)}>{f.org}/{f.repo}</Link></Row>
              {f.branch && <Row k="Branch"><span className="mono">{f.branch}</span></Row>}
              <Row k="Location"><span className="mono">{f.where || '—'}</span></Row>
              {f.rule && <Row k="Rule"><span className="mono">{f.rule}</span></Row>}
              {f.commit && <Row k="Commit"><span className="mono">{f.commit.slice(0, 12)}</span>{f.author && <> by {f.author}</>}</Row>}
              <Row k="Found by">{SOURCE_LABEL[f.source]}, {relTime(f.at)}</Row>
              {f.detail && <div style={{ paddingTop: 12, whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>{f.detail}</div>}
            </Section>
            {f.fix && <Section title="How to fix"><div className="t2" style={{ whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>{f.fix}</div>
              {f.type === 'secret' && <div style={{ marginTop: 10 }} className="c-warn">Rotate the secret first: deleting it from the code does not remove it from git history.</div>}</Section>}
          </div>
          <Section title="Other findings in this repository" pad={false}>
            {siblings.length === 0 ? <div className="t3" style={{ padding: 14 }}>None.</div> : siblings.map(x => (
              <Link key={findingId(x)} to={findingPath(x)} className="ow-grid click" style={{ gridTemplateColumns: '94px 1fr', textDecoration: 'none', color: 'inherit' }}>
                <SevPill sev={x.sev}/><span className="t1" title={x.title}>{x.title}</span>
              </Link>))}
          </Section>
        </div>
      )}
    </div>
  )
}
