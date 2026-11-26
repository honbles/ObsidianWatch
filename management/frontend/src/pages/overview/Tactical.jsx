// Tactical overview: one table of every monitored domain (Checkmk's tactical overview), every count a link
// into the matching filtered view, and one list of unhandled problems across all domains, worst first.
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import api from '../../api/client'
import { appApi } from '../../api/app'
import { StatePill, SevPill, Histogram, SEV_STACKS, relTime, DenseTable } from '../../components/ui'
import { isProbe, serviceListState } from '../../utils/states'
import { useCodeData, buildRepos, findingPath } from '../code/CodeOverview'
import { usePosture, cloudFindingPath } from '../cloud/PostureOverview'

const SLA_MS = { 5: 3600e3, 4: 4 * 3600e3, 3: 24 * 3600e3, 2: 72 * 3600e3 }
const pastSLA = (a) => SLA_MS[a.severity] && a.status === 'open' && !a.acknowledged_at && Date.now() - new Date(a.created_at) > SLA_MS[a.severity]

function useOverviewData() {
  const [d, setD] = useState({ loading: true })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    let live = true
    const to = new Date(), from = new Date(to.getTime() - 24 * 3600e3)
    Promise.all([
      api.get('/api/v1/agents').then(r => r.data?.agents || []).catch(() => null),
      api.get('/api/v1/alerts', { params: { status: '', limit: 2000 } }).then(r => r.data).catch(() => null),
      appApi.services({ from: from.toISOString(), to: to.toISOString() }, { limit: 1000 }).then(r => r.services || []).catch(() => null),
    ]).then(([agents, alerts, services]) => { if (live) setD({ loading: false, agents, alerts: alerts?.alerts || null, counts: alerts?.counts || {}, services }) })
    return () => { live = false }
  }, [tick])
  useEffect(() => { const id = setInterval(() => setTick(t => t + 1), 60000); return () => clearInterval(id) }, [])
  return d
}

function Cell({ n, to, tone, title }) {
  if (n === null || n === undefined) return <span className="t3">—</span>
  const style = { color: n > 0 && tone ? `var(--${tone})` : n > 0 ? 'var(--t1)' : 'var(--t3)', fontWeight: n > 0 && tone ? 600 : 400 }
  return to && n > 0 ? <Link to={to} className="mono ow-cell-link" style={style} title={title}>{n.toLocaleString()}</Link> : <span className="mono" style={style} title={title}>{n.toLocaleString()}</span>
}

export default function Tactical() {
  const navigate = useNavigate()
  const d = useOverviewData()
  const code = useCodeData()
  const cloud = usePosture()

  const open = (d.alerts || []).filter(a => a.status === 'open')
  const active = (d.alerts || []).filter(a => a.status !== 'closed')
  // Hosts are online or offline; alerts are counted on their own row, not folded into the host.
  const hosts = useMemo(() => d.agents ? d.agents.filter(a => !isProbe(a)).map(a => ({ ...a, state: a.online ? 'ok' : 'none' })) : null, [d.agents])
  const svcs = useMemo(() => d.services ? d.services.map(s => ({ ...s, ...serviceListState(s) })) : null, [d.services])
  const repos = useMemo(() => code.loading ? null : buildRepos(code.findings, code.repoList, code.connectors).filter(r => !r.orgLevel), [code])
  const accts = cloud.loading ? null : cloud.accounts
  const cnt = (list, pred) => list ? list.filter(pred).length : null

  const rows = [
    { k: 'Hosts', to: '/agents', total: hosts?.length,
      problems: cnt(hosts, h => !h.online), crit: null, stale: null,
      links: { problems: '/agents?status=offline' }, problemsLabel: 'offline' },
    { k: 'Alerts', to: '/alerts', total: d.alerts ? active.length : null,
      problems: d.alerts ? open.length : null, crit: cnt(d.alerts && open, a => a.severity >= 5), stale: cnt(d.alerts && open, pastSLA),
      links: { problems: '/alerts', crit: '/alerts?sev=5', stale: '/alerts?sla=breached' }, problemsLabel: 'unhandled', staleLabel: 'past response target' },
    { k: 'Services', to: '/applications/services', total: svcs?.length,
      problems: cnt(svcs, s => s.state === 'crit' || s.state === 'warn'), crit: cnt(svcs, s => s.state === 'crit'), stale: cnt(svcs, s => s.state === 'none'),
      links: { problems: '/applications/services', crit: '/applications/services', stale: '/applications/services' }, staleLabel: 'no traffic in 24 h' },
    { k: 'Repositories', to: '/devops', total: repos?.length,
      problems: cnt(repos, r => r.sev >= 4), crit: cnt(repos, r => r.sev >= 5), stale: repos ? code.connectors.filter(c => !c.lastScan).length : null,
      links: { problems: '/devops', crit: '/devops', stale: '/devops' }, problemsLabel: 'high or critical findings', staleLabel: 'sources never scanned' },
    { k: 'Cloud accounts', to: '/cloud', total: accts?.length,
      problems: cnt(accts, a => a.worst >= 4), crit: cnt(accts, a => a.worst >= 5), stale: cnt(accts, a => !a.scanned || a.status === 'error'),
      links: { problems: '/cloud', crit: '/cloud', stale: '/cloud' }, problemsLabel: 'high or critical findings', staleLabel: 'not scanned or erroring' },
  ]
  const rowState = (r) => r.crit > 0 ? 'crit' : r.problems > 0 ? 'warn' : r.total === 0 || r.total == null ? 'none' : r.stale > 0 ? 'warn' : 'ok'

  // Unhandled problems across every domain, worst first (Checkmk "unhandled problems").
  const problems = useMemo(() => {
    const out = []
    for (const a of open) out.push({ key: 'a' + a.id, sev: a.severity, domain: 'Alert', what: a.title, where: a.host || '—', since: a.created_at, to: `/alerts/${a.id}`, extra: pastSLA(a) ? 'past target' : '' })
    for (const h of hosts || []) if (h.state === 'none') out.push({ key: 'h' + h.id, sev: 4, domain: 'Host', what: 'Agent offline', where: h.hostname, since: h.last_seen, to: `/agents?host=${encodeURIComponent(h.hostname)}` })
    for (const s of svcs || []) if (s.state === 'crit' || s.state === 'warn') out.push({ key: 's' + s.id, sev: s.state === 'crit' ? 5 : 4, domain: 'Service', what: s.why, where: s.name, since: s.last_seen, to: `/applications/services/${s.id}` })
    for (const r of repos || []) if (r.sev >= 4 && r.top) out.push({ key: 'r' + r.key, sev: r.sev, domain: 'Code', what: r.top.title, where: r.name, since: r.top.at, to: findingPath(r.top) })
    for (const f of cloud.findings || []) if (f.status === 'open' && f.sevN >= 4) out.push({ key: 'c' + f.connector + f.id, sev: f.sevN, domain: 'Cloud', what: f.title, where: f.resource || f.account, since: f.scanned, to: cloudFindingPath(f) })
    return out.sort((a, b) => b.sev - a.sev || new Date(a.since) - new Date(b.since))
  }, [open, hosts, svcs, repos, cloud.findings]) // eslint-disable-line react-hooks/exhaustive-deps

  const weekAgo = Date.now() - 7 * 86400e3
  const recent = (d.alerts || []).filter(a => new Date(a.created_at).getTime() > weekAgo)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(582px, 1.1fr) minmax(470px, 1fr)', gap: 16, alignItems: 'stretch' }}>
        <section className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar"><span style={{ fontWeight: 600 }}>Tactical overview</span><span className="t3" style={{ fontSize: 13.5 }}>Every number opens the matching list</span></div>
          <div role="table">
            <div className="ow-grid h" style={{ gridTemplateColumns: 'minmax(120px, 1.5fr) 112px 70px 88px 76px 64px' }}><div>Domain</div><div>State</div><div style={{ textAlign: 'right' }}>Total</div><div style={{ textAlign: 'right' }}>Problems</div><div style={{ textAlign: 'right' }}>Critical</div><div style={{ textAlign: 'right' }}>Stale</div></div>
            {rows.map(r => {
              const st = rowState(r)
              return (
                <div key={r.k} className={`ow-grid click ${st !== 'ok' && st !== 'none' ? 's-' + st : ''}`} style={{ gridTemplateColumns: 'minmax(120px, 1.5fr) 112px 70px 88px 76px 64px', minHeight: 44 }} onClick={() => navigate(r.to)} role="row">
                  <span className="t1" style={{ fontWeight: 500 }}>{r.k}</span>
                  <span>{r.total == null ? <span className="t3" style={{ fontSize: 13.5 }}>Loading…</span> : <StatePill state={st}>{{ ok: 'OK', warn: 'Attention', crit: 'Critical', none: r.total === 0 ? 'None set up' : 'Unknown' }[st]}</StatePill>}</span>
                  <span style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}><Cell n={r.total} to={r.to}/></span>
                  <span style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}><Cell n={r.problems} to={r.links.problems} tone="warn" title={r.problemsLabel || 'not OK'}/></span>
                  <span style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}><Cell n={r.crit} to={r.links.crit} tone="crit" title="critical"/></span>
                  <span style={{ textAlign: 'right' }} onClick={e => e.stopPropagation()}><Cell n={r.stale} to={r.links.stale} tone="warn" title={r.staleLabel}/></span>
                </div>
              )
            })}
          </div>
          <div className="ow-card-foot"><span>Stale: offline hosts, alerts past their response target, services with no traffic, sources or accounts not scanned.</span></div>
        </section>

        <section className="ow-card" style={{ padding: '14px 16px' }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 10 }}>
            <span style={{ fontWeight: 600 }}>Alerts, last 7 days</span>
            <span className="t3" style={{ fontSize: 13.5 }}>{recent.length.toLocaleString()} created · {open.length.toLocaleString()} still unhandled</span>
            <Link to="/alerts" className="c-acc" style={{ marginLeft: 'auto', fontSize: 13.5 }}>Open alerts</Link>
          </div>
          <Histogram items={recent.map(a => ({ t: a.created_at, k: a.severity }))} stacks={SEV_STACKS} from={weekAgo} buckets={42} height={190} label="alerts"/>
          <div style={{ display: 'flex', gap: 12, fontSize: 13, color: 'var(--t3)', marginTop: 10 }}>
            {SEV_STACKS.slice().reverse().map(x => <span key={x.k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: x.color }}/>{x.label}</span>)}
          </div>
        </section>
      </div>

      <section className="ow-card" style={{ overflow: 'hidden' }}>
        <div className="ow-card-bar">
          <span style={{ fontWeight: 600 }}>Unhandled problems</span>
          <span className="t3" style={{ fontSize: 13.5 }}>Alerts, offline hosts, failing services and high or critical findings, worst and oldest first</span>
          <span className="t2" style={{ marginLeft: 'auto', fontSize: 13.5 }}>{problems.length.toLocaleString()}</span>
        </div>
        <DenseTable rows={problems.slice(0, 25)} rowKey={p => p.key} onRow={p => navigate(p.to)}
          rowState={p => p.sev >= 5 ? 'crit' : p.sev >= 4 ? 'warn' : null}
          empty={d.loading ? 'Loading…' : 'No unhandled problems.'}
          cols={[
            { key: 's', label: 'Severity', width: '92px', render: p => <SevPill sev={p.sev}/> },
            { key: 'd', label: 'Domain', width: '84px', render: p => <span className="t2">{p.domain}</span> },
            { key: 'w', label: 'Problem', width: 'minmax(240px, 2.2fr)', render: p => <span className="t1">{p.what}</span>, title: p => p.what },
            { key: 'o', label: 'Object', width: 'minmax(140px, 1fr)', render: p => <span className="mono">{p.where}</span>, title: p => p.where },
            { key: 'x', label: '', width: '110px', render: p => p.extra ? <StatePill state="crit" dot={false}>{p.extra}</StatePill> : null },
            { key: 't', label: 'Since', width: '96px', render: p => <span className="t2">{relTime(p.since)}</span> },
          ]}/>
        {problems.length > 25 && <div className="ow-card-foot"><span>Showing the 25 worst of {problems.length.toLocaleString()}.</span><Link to="/alerts" className="c-acc">All alerts</Link></div>}
      </section>
    </div>
  )
}
