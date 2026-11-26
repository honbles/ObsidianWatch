import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import { PageHeader, Num, DenseTable, relTime } from '../../components/ui'
import { SevWord, Counts } from '../../components/app/AppRisk'

export const appPath = '/applications'

// Hosts: the servers that run monitored services, worst first. Only hosts with
// an application-monitoring agent and a live service appear here.
export default function AppHosts() {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const { data, loading, error } = useAppLoad(() => appApi.hosts(), [])
  const all = data?.hosts || []
  const rows = useMemo(() => {
    const t = q.trim().toLowerCase()
    return all.filter(h => !t || `${h.host} ${h.ip} ${h.os}`.toLowerCase().includes(t))
  }, [all, q])
  const n = (f) => all.filter(f).length
  const cols = [
    { key: 's', label: 'Top risk', width: '100px', render: h => <SevWord sev={h.top_severity}/> },
    { key: 'h', label: 'Host', width: 'minmax(170px, 1.3fr)', render: h => <span><span className="mono t1">{h.host || h.agent_id}</span> <span className="t3" style={{ fontSize: 13 }}>{h.os}</span></span> },
    { key: 'svc', label: 'Services', width: '150px', render: h => <Counts parts={[[h.by_tier[2], 'T2'], [h.by_tier[1], 'T1'], [h.by_tier[0], 'T0']]}/> },
    { key: 'al', label: 'Open alerts', width: '150px', render: h => <Counts parts={[[h.service_alerts, 'service', 'var(--warn)'], [h.host_alerts, 'host']]}/> },
    { key: 'v', label: 'Host scan', width: 'minmax(150px, 1fr)', render: h => h.vuln?.scanned_at
      ? <Counts parts={[[h.vuln.critical, 'crit', 'var(--crit)'], [h.vuln.high, 'high', 'var(--warn)'], [h.vuln.medium, 'med'], [h.vuln.cves, 'CVE', 'var(--crit)']]}/>
      : <span className="t3">no scan yet</span> },
    { key: 'c', label: 'Vulnerable code running', width: '170px', render: h => !h.runtime_inventory ? <span className="t3" title="This host has not reported a runtime package inventory (Linux agent with the app-server profile)">no inventory</span>
      : <Counts parts={[[h.code_critical, 'critical', 'var(--crit)'], [h.code_vulns - h.code_critical, 'other']]}/> },
    { key: 'o', label: 'Agent', width: '100px', render: h => <span className={h.online ? 'c-ok' : 't3'}>{h.online ? 'online' : h.last_seen ? relTime(h.last_seen) : '—'}</span> },
  ]
  return (
    <div>
      <PageHeader title="Hosts"
        state={loading ? undefined : n(h => h.top_severity === 'critical') ? 'crit' : n(h => h.top_severity === 'high') ? 'warn' : all.length ? 'ok' : 'none'}
        stateText={all.length ? `${n(h => h.top_severity === 'critical')} with critical risk` : 'No monitored hosts yet'}
        sub="Hosts with a monitored service in the last 24 hours."
        nums={<>
          <Num k="Hosts" v={all.length}/>
          <Num k="Services" v={all.reduce((a, h) => a + h.services, 0)}/>
          <Num k="Critical" v={n(h => h.top_severity === 'critical')} tone={n(h => h.top_severity === 'critical') ? 'crit' : undefined}/>
          <Num k="Running vulnerable code" v={n(h => h.code_vulns > 0)} tone={n(h => h.code_vulns > 0) ? 'warn' : undefined}/>
          <Num k="Offline" v={n(h => !h.online)}/>
        </>}/>
      <div className="ow-body">
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
              <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by host, address or OS" aria-label="Filter hosts"/>
            </label>
            <span className="t2" style={{ fontSize: 13.5 }}>{rows.length} of {all.length}</span>
          </div>
          {error && <div className="c-crit" style={{ padding: '10px 14px' }}>{String(error)}</div>}
          <DenseTable cols={cols} rows={loading ? [] : rows} rowKey={h => h.agent_id}
            rowState={h => (h.top_severity === 'critical' ? 'crit' : h.top_severity === 'high' ? 'warn' : null)}
            onRow={h => navigate(`/applications/hosts/${encodeURIComponent(h.agent_id)}`)}
            empty={loading ? 'Loading…' : 'No hosts with monitored services.'}/>
        </div>
      </div>
    </div>
  )
}
