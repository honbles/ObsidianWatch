import { useParams, useNavigate } from 'react-router-dom'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import { StateBlock } from '../../components/shared'
import { PageHeader, Num, DenseTable, relTime } from '../../components/ui'
import { AppTierBadge } from '../../components/app/AppBadges'
import { SevWord, Counts, RiskTable } from '../../components/app/AppRisk'

export const appPath = '/applications/hosts/:agent'

const ROLE = { database: 'Database', cache: 'Cache', web: 'Web / proxy', runtime: 'App server', queue: 'Broker', search: 'Search', app: 'Application', other: 'Other' }

// One host: its services (instrumented first, then the platform software that
// matters), then every open risk on it - host alerts, service alerts, the host
// scan and vulnerable code its services load - worst first.
export default function AppHostDetail() {
  const { agent } = useParams()
  const navigate = useNavigate()
  const { data: h, loading, error } = useAppLoad(() => appApi.host(agent), [agent])
  const svcs = h?.service_list || []
  const risks = h?.risks || []
  const cols = [
    { key: 's', label: 'Top risk', width: '100px', render: s => <SevWord sev={s.top_severity}/> },
    { key: 't', label: 'Tier', width: '52px', render: s => <AppTierBadge tier={s.tier}/> },
    { key: 'n', label: 'Service', width: 'minmax(150px, 1.2fr)', render: s => <span><span className="mono t1">{s.name}</span>{s.environment !== 'default' && <span className="t3"> · {s.environment}</span>}</span> },
    { key: 'r', label: 'What it is', width: 'minmax(120px, 0.9fr)', render: s => <span className="t2">{s.role_label || ROLE[s.role] || '—'}{s.os_package && <span className="t3 mono" style={{ fontSize: 13 }}> · {s.os_package} {s.os_package_version}</span>}</span> },
    { key: 'p', label: 'Ports', width: '110px', render: s => <span className="mono t2">{(s.ports || []).slice(0, 4).join(', ') || '—'}{s.ports?.length > 4 ? ' …' : ''}</span> },
    { key: 'x', label: 'Exposure', width: '84px', render: s => <span className={s.exposure === 'internet' ? 'c-warn' : 't2'}>{s.exposure}</span> },
    { key: 'a', label: 'Risks', width: '170px', render: s => <Counts parts={[[s.open_alerts, 'alerts', 'var(--warn)'], [s.code_vulns, 'code', 'var(--crit)'], [s.host_risks, 'host']]}/> },
    { key: 'c', label: 'Code', width: 'minmax(120px, 1fr)', render: s => s.code_links?.length
      ? <span className="mono t2" title={s.code_links.join(', ')}>{s.code_links[0]}{s.code_links.length > 1 ? ` +${s.code_links.length - 1}` : ''}</span>
      : <span className="t3">not linked</span> },
  ]
  return (
    <div>
      <PageHeader title={h?.host || agent} mono
        state={h ? (h.top_severity === 'critical' ? 'crit' : h.top_severity === 'high' ? 'warn' : 'ok') : undefined}
        stateText={h ? (h.top_severity ? `Top risk: ${h.top_severity}` : 'No open risk') : undefined}
        sub={h && <>{[h.os, h.ip, h.online ? 'agent online' : h.last_seen ? `agent last seen ${relTime(h.last_seen)}` : null].filter(Boolean).join(' · ')}
          {!h.runtime_inventory && <span className="t3"> · no runtime package inventory from this host, so vulnerable code cannot be matched to its services</span>}</>}
        actions={h && <button className="ow-btn" onClick={() => navigate(`/agents?host=${encodeURIComponent(h.host)}`)}>Open in Fleet</button>}
        nums={h && <>
          <Num k="Services" v={h.services}/>
          <Num k="Service alerts" v={h.service_alerts} tone={h.service_alerts ? 'warn' : undefined}/>
          <Num k="Host alerts" v={h.host_alerts} tone={h.host_alerts ? 'warn' : undefined}/>
          <Num k="Host scan crit / high" v={h.vuln?.scanned_at ? `${h.vuln.critical} / ${h.vuln.high}` : '—'} tone={h.vuln?.critical ? 'crit' : undefined}/>
          <Num k="Vulnerable code running" v={h.code_vulns} tone={h.code_critical ? 'crit' : h.code_vulns ? 'warn' : undefined}/>
        </>}/>
      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <StateBlock loading={loading && !h} error={error} empty={!loading && !h} emptyText="No monitored services on this host in the last 24 hours.">
          {h && <>
            <div className="ow-card" style={{ overflow: 'hidden' }}>
              <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Services on this host</span>
                <span className="t3" style={{ fontSize: 13.5 }}>Instrumented first, then databases, caches, web servers and runtimes, then the rest</span></div>
              <DenseTable cols={cols} rows={svcs} rowKey={s => s.id}
                rowState={s => (s.top_severity === 'critical' ? 'crit' : s.top_severity === 'high' ? 'warn' : null)}
                onRow={s => navigate(`/applications/services/${encodeURIComponent(s.key)}`)} empty="No services."/>
            </div>
            <div className="ow-card" style={{ overflow: 'hidden' }}>
              <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Open risks</span>
                <span className="t3" style={{ fontSize: 13.5 }}>Severity is raised for internet-facing and high-criticality services, and lowered for vulnerable code that is on disk but not loaded</span></div>
              <RiskTable risks={risks} host={h.host} empty="No open alerts, scan findings or running vulnerable code on this host."/>
            </div>
          </>}
        </StateBlock>
      </div>
    </div>
  )
}
