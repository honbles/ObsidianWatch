import { Link } from 'react-router-dom'
import { StatTile, DenseTable, relTime, SEV_WORD } from '../../../components/ui'
import AppSetupHint from '../../../components/app/AppSetupHint'

const HOST_RULES = [
  ['APP-H01', 'Shell started by the service (Critical if it then connects out or writes files)'],
  ['APP-H02', 'Download tool run by the service (curl, wget, nc…)'],
  ['APP-H03', 'Executable written to a web or upload directory'],
  ['APP-H04', 'New outbound destination after learning'],
  ['APP-H05', 'Connection to a known-bad or no-DNS public address'],
  ['APP-H06', 'Cloud metadata endpoint accessed'],
  ['APP-H07', 'Secret or credential file read'],
  ['APP-H08', 'Privilege change'],
  ['APP-H11', 'Container escape signal'],
]

function ports(listen) {
  try {
    const v = typeof listen === 'string' ? JSON.parse(listen) : listen
    return (v || []).map(x => (typeof x === 'number' ? x : String(x).split(':').pop()))
  } catch { return [] }
}

// Overview for a service seen only by the host agent (Tier 0): where it runs,
// what is watched, open alerts and linked code. No request data exists, so no
// request charts are shown.
export default function AppT0Overview({ service, detail, alerts, edges, go }) {
  const inst = (detail?.instances || []).filter(i => !i.stopped_at)
  const hosts = [...new Set(inst.map(i => i.host))]
  const allPorts = [...new Set(inst.flatMap(i => ports(i.listen)))]
  const outbound = edges.filter(e => e.dst_kind !== 'service').length
  return (
    <>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        <StatTile k="Running instances" v={inst.length} note={hosts.length ? `on ${hosts.length} host${hosts.length === 1 ? '' : 's'}` : 'none live'}/>
        <StatTile k="Listening ports" v={allPorts.length ? allPorts.slice(0, 5).join(', ') : '—'} note={allPorts.length > 5 ? `+${allPorts.length - 5} more` : null}/>
        <StatTile k="Open alerts" v={alerts.length} tone={alerts.some(a => a.severity >= 4) ? 'crit' : alerts.length ? 'warn' : undefined} note={alerts.length ? null : 'host rules are watching'}/>
        <StatTile k="Linked code" v={service.code_links || 0} note={service.code_links ? 'see the Code tab' : 'link a repository on the Code tab'}/>
        <StatTile k="Destinations" v={outbound} note="outbound, from the host sensor"/>
      </div>

      <div className="ow-card" style={{ overflow: 'hidden' }}>
        <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Where it runs</span>
          <button className="ow-btn quiet" style={{ marginLeft: 'auto' }} onClick={() => go('instances')}>All instances</button></div>
        <DenseTable rowKey={i => i.id} rows={inst.slice(0, 8)} empty="No live instance."
          cols={[
            { key: 'h', label: 'Host', width: 'minmax(140px, 1fr)', render: i => <Link className="mono t1" to={`/applications/hosts/${encodeURIComponent(i.agent_id)}`}>{i.host}</Link> },
            { key: 'p', label: 'Process', width: '110px', render: i => <span className="mono t2">{i.pid || '—'}</span> },
            { key: 'c', label: 'Container', width: '130px', render: i => <span className="mono t2">{i.container_id ? i.container_id.slice(0, 12) : '—'}</span> },
            { key: 'l', label: 'Ports', width: '130px', render: i => <span className="mono t2">{ports(i.listen).join(', ') || '—'}</span> },
            { key: 'v', label: 'Commit', width: '110px', render: i => { const a = typeof i.attrs === 'string' ? JSON.parse(i.attrs || '{}') : (i.attrs || {}); return a.vcs_revision ? <span className="mono t2" title={`${a.vcs_revision} from ${a.vcs_source}${a.vcs_repo ? ' · ' + a.vcs_repo : ''}`}>{a.vcs_revision.slice(0, 7)}</span> : <span className="t3">—</span> } },
            { key: 's', label: 'Started', width: '110px', render: i => <span className="t2">{relTime(i.proc_start)}</span> },
          ]}/>
      </div>

      {alerts.length > 0 && <div className="ow-card" style={{ overflow: 'hidden' }}>
        <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Open alerts</span>
          <button className="ow-btn quiet" style={{ marginLeft: 'auto' }} onClick={() => go('alerts')}>All alerts</button></div>
        <DenseTable rowKey={a => a.id} rows={alerts.slice(0, 6)}
          cols={[
            { key: 's', label: 'Severity', width: '90px', render: a => <span className={a.severity >= 5 ? 'c-crit' : a.severity >= 4 ? 'c-warn' : 't2'}>{SEV_WORD[a.severity] || a.severity}</span> },
            { key: 't', label: 'Alert', width: 'minmax(220px, 2fr)', render: a => <Link className="t1" to={`/alerts/${a.id}`}>{a.title}</Link> },
            { key: 'r', label: 'Raised', width: '110px', render: a => <span className="t2">{relTime(a.created_at)}</span> },
          ]}/>
      </div>}

      <div className="ow-card" style={{ padding: '12px 14px' }}>
        <div style={{ fontWeight: 600, marginBottom: 6 }}>Watched without instrumentation</div>
        <div className="t2" style={{ fontSize: 12.5, marginBottom: 8 }}>Host detections run now. Requests, errors and traces need OpenTelemetry.</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 4, fontSize: 12.5 }}>
          {HOST_RULES.map(([id, t]) => <div key={id}><span className="mono t3">{id}</span> <span className="t2">{t}</span></div>)}
        </div>
      </div>
      <AppSetupHint tier={service.tier} name={service.name} environment={service.environment} />
    </>
  )
}
