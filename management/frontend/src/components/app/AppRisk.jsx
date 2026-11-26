// Shared pieces for host and service risk views. Owned by the Application build.
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { DenseTable, StatePill, relTime } from '../ui'

export const SEV_STATE = { critical: 'crit', high: 'warn', medium: 'info', low: 'none', info: 'none' }
export const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }

export function SevWord({ sev, title }) {
  if (!sev) return <StatePill state="ok">No open risk</StatePill>
  return <StatePill state={SEV_STATE[sev] || 'none'} title={title}>{SEV_LABEL[sev] || sev}</StatePill>
}

export function Counts({ parts }) {
  const shown = parts.filter(([n]) => n > 0)
  if (!shown.length) return <span className="t3">—</span>
  return <span className="mono" style={{ display: 'inline-flex', gap: 8 }}>
    {shown.map(([n, label, color]) => <span key={label} title={label} style={{ color }}>{n} <span className="t3" style={{ fontSize: 13 }}>{label}</span></span>)}
  </span>
}

export const RISK_KIND = {
  service_alert: 'Service alert', host_alert: 'Host alert', code_vuln: 'Vulnerable code', host_port: 'Exposed port',
  host_cve: 'Host CVE', host_finding: 'Host config',
}

// Where a risk row leads: the alert, the repository, or the host in Fleet.
export function riskLink(r, host) {
  if (r.alert_id) return `/alerts/${r.alert_id}`
  if (r.kind === 'code_vuln' && r.connector_id) return `/devops/repos/${r.connector_id}/${encodeURIComponent(r.repo)}`
  if (host) return `/agents?host=${encodeURIComponent(host)}`
  return null
}

const EVIDENCE = { loaded: 'loaded in memory', deployed: 'on disk, not loaded' }

// RiskTable lists risk items with kind and service filters.
export function RiskTable({ risks, host, showService = true, empty = 'No open risks.' }) {
  const [kind, setKind] = useState('')
  const [svc, setSvc] = useState('')
  const kinds = useMemo(() => [...new Set(risks.map(r => r.kind))], [risks])
  const svcs = useMemo(() => [...new Set(risks.map(r => r.service).filter(Boolean))].sort(), [risks])
  const keyed = useMemo(() => risks.map((r, i) => ({ ...r, _k: i })), [risks])
  const rows = keyed.filter(r => (!kind || r.kind === kind) && (!svc || (svc === '-' ? !r.service : r.service === svc)))
  const cols = [
    { key: 's', label: 'Severity', width: '92px', render: r => <SevWord sev={r.severity} title={r.base_severity && r.base_severity !== r.severity ? `Base ${r.base_severity}; weighted by the service's exposure, criticality and whether the code is loaded` : undefined}/> },
    { key: 'k', label: 'Type', width: '120px', render: r => <span className="t2">{RISK_KIND[r.kind] || r.kind}</span> },
    { key: 't', label: 'Risk', width: 'minmax(220px, 2fr)', title: r => r.detail, render: r => {
      const to = riskLink(r, host)
      const label = <span className="t1">{r.title}</span>
      return to ? <Link to={to} onClick={e => e.stopPropagation()}>{label}</Link> : label
    } },
    ...(showService ? [{ key: 'svc', label: 'Service', width: 'minmax(110px, 0.8fr)', render: r => r.service
      ? <Link className="mono" to={`/applications/services/${encodeURIComponent(r.service_key)}`} onClick={e => e.stopPropagation()}>{r.service}</Link>
      : <span className="t3">host</span> }] : []),
    { key: 'e', label: 'Evidence', width: 'minmax(140px, 1fr)', render: r => <span className="t2" style={{ fontSize: 13.5 }}>
      {r.kind === 'code_vuln' ? <>{EVIDENCE[r.evidence] || r.evidence} · <span className="mono">{r.repo}</span>{r.linked ? <span className="c-ok"> · linked</span> : r.service ? <span className="t3"> · not linked</span> : null}</> : r.time ? relTime(r.time) : r.evidence}
    </span> },
  ]
  return (
    <>
      <div className="ow-card-bar" style={{ gap: 8 }}>
        <select className="input" style={{ height: 26, width: 170 }} value={kind} onChange={e => setKind(e.target.value)} aria-label="Risk type">
          <option value="">All types ({risks.length})</option>
          {kinds.map(k => <option key={k} value={k}>{RISK_KIND[k] || k} ({risks.filter(r => r.kind === k).length})</option>)}
        </select>
        {showService && svcs.length > 0 && <select className="input" style={{ height: 26, width: 170 }} value={svc} onChange={e => setSvc(e.target.value)} aria-label="Service">
          <option value="">All services</option><option value="-">Host only</option>
          {svcs.map(s => <option key={s}>{s}</option>)}
        </select>}
        <span className="t3" style={{ fontSize: 13.5 }}>{rows.length} shown · worst first</span>
      </div>
      <DenseTable cols={cols} rows={rows} rowKey={r => r._k}
        rowState={r => (r.severity === 'critical' ? 'crit' : r.severity === 'high' ? 'warn' : null)} empty={empty}/>
    </>
  )
}
