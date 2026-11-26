// One cloud posture finding on its own page.
import { useMemo } from 'react'
import { Link, useParams, useNavigate } from 'react-router-dom'
import { PageHeader, SevPill, StatePill, Section, relTime } from '../../components/ui'
import { usePosture, cloudFindingPath, PROVIDER, CAT_LABEL } from './PostureOverview'

function Row({ k, children }) {
  return <div style={{ display: 'grid', gridTemplateColumns: '179px 1fr', gap: 12, padding: '6px 0', borderBottom: '1px solid var(--line)' }}><span className="t3">{k}</span><span>{children}</span></div>
}

export default function CloudFindingPage() {
  const { connector, id } = useParams()
  const navigate = useNavigate()
  const d = usePosture()
  const f = useMemo(() => d.findings.find(x => String(x.connector) === connector && String(x.id) === id), [d.findings, connector, id])
  const sameResource = f ? d.findings.filter(x => x !== f && x.connector === f.connector && x.resource && x.resource === f.resource) : []
  const sameRule = f ? d.findings.filter(x => x !== f && x.title === f.title) : []
  if (!d.loading && !f) return <div><PageHeader title="Finding not found" sub="It may have been fixed and dropped from the latest assessment." actions={<Link className="ow-btn" style={{ textDecoration: 'none' }} to="/cloud">All findings</Link>}/></div>
  const list = (items, empty) => items.length === 0 ? <div className="t3" style={{ padding: 14 }}>{empty}</div> : items.slice(0, 10).map(x => (
    <Link key={x.connector + x.id} to={cloudFindingPath(x)} className="ow-grid click" style={{ gridTemplateColumns: '94px 1fr', textDecoration: 'none', color: 'inherit' }}>
      <SevPill sev={x.sevN}/><span className="t1" title={x.title}>{x.title} <span className="t3">· {x.account}{x.resource && x.resource !== f.resource ? ` · ${x.resource}` : ''}</span></span>
    </Link>))
  return (
    <div>
      <PageHeader title={f?.title || 'Loading…'}
        sub={f && <>{PROVIDER[f.provider] || f.provider} · {f.account} · <span className="mono t1">{f.resource || 'account-wide'}</span> · detected {relTime(f.scanned)}</>}
        actions={<button className="ow-btn" onClick={() => navigate(-1)}>Back</button>}>
        {f && <div style={{ marginTop: 10, display: 'flex', gap: 8 }}><SevPill sev={f.sevN}/>{f.status === 'suppressed' && <StatePill state="none">Suppressed</StatePill>}</div>}
      </PageHeader>
      {f && (
        <div className="ow-body" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(336px, 1fr)', gap: 16, alignItems: 'start' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <Section title="Details">
              <Row k="Account">{PROVIDER[f.provider]} · {f.account}</Row>
              <Row k="Resource"><span className="mono">{f.resource || '—'}</span>{f.resource_type && <span className="t3"> ({f.resource_type})</span>}</Row>
              <Row k="Area">{CAT_LABEL[f.category] || f.category || '—'}</Row>
              {f.cis && <Row k="Benchmark">{f.cis}</Row>}
              {f.mitre && <Row k="MITRE ATT&CK"><span className="mono">{f.mitre}</span></Row>}
              <Row k="Check">{f.id}</Row>
              {f.description && <div style={{ paddingTop: 12, whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>{f.description}</div>}
            </Section>
            {f.remediation && <Section title="Remediation"><div className="t2" style={{ whiteSpace: 'pre-wrap', lineHeight: 1.55 }}>{f.remediation}</div></Section>}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <Section title="Same resource" pad={false}>{list(sameResource, 'No other findings on this resource.')}</Section>
            <Section title="Same check elsewhere" pad={false}>{list(sameRule, 'Only here.')}</Section>
          </div>
        </div>
      )}
    </div>
  )
}
