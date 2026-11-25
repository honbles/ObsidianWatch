import { Link } from 'react-router-dom'
import { useTimeRange, StateBlock } from '../../components/shared'
import { appApi } from '../../api/app'
import useAppLoad from '../../components/app/useAppLoad'
import AppPageHeader from '../../components/app/AppPageHeader'
import AppStatCard from '../../components/app/AppStatCard'
import { SeverityBadge } from '../../components/SeverityBadge'
import { appRel, appPct } from '../../components/app/appFormat'

export const appPath = '/applications/overview'

const svcLink = (s) => `/applications/services/${encodeURIComponent(s.key)}`
const REASONS = {
  asserted_identity: 'Telemetry from a process the agent could not bind to the service',
  route_overflow: 'Too many distinct routes; some are counted as "other"',
  trace_drops: 'Trace buffer overflowed; some traces were dropped',
  not_reporting: 'Instrumented but no instance reported in the last 24 h',
}

function Section({ title, children, empty }) {
  return (
    <div className="card">
      <div className="card-head"><span className="text-sm font-medium text-siem-text">{title}</span></div>
      {empty ? <div className="p-4 text-xs text-siem-muted">{empty}</div> : children}
    </div>
  )
}

// Overview: how exposed and how well covered are we? (spec 11.3)
export default function AppOverview() {
  const range = useTimeRange(7 * 24 * 3600e3)
  const { data: d, loading, error } = useAppLoad(() => appApi.overview(range), [range.from, range.to])
  const empty = d && d.services === 0
  return (
    <div className="p-6 space-y-5">
      <AppPageHeader title="Applications" range={range}
        subtitle="What we run, how exposed it is, what changed and where we are blind. Services are discovered from the host; OpenTelemetry adds routes and dependencies." />
      <StateBlock loading={loading} error={error} empty={empty}
        emptyText="No services yet. Build an agent with the app-server profile (Agent Builder) and services appear as they run.">
        {d && (<>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <AppStatCard label="Services" value={d.services} hint={`${d.tiers['0']} host-only · ${d.tiers['1']} OTel · ${d.tiers['2']} helper`} />
            <AppStatCard label="Coverage" value={appPct(d.coverage, 0)} hint="services sending OpenTelemetry" tone={d.coverage < 0.5 ? 'warn' : undefined} />
            <AppStatCard label="Internet-facing" value={d.exposure.internet} hint={d.exposure.unknown ? `${d.exposure.unknown} not classified yet` : 'all classified'} tone={d.exposure.unknown ? 'warn' : undefined} />
            <AppStatCard label="Open alerts" value={d.open_alerts_total} tone={d.open_alerts_total ? 'bad' : undefined} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Section title="Open alerts by service" empty={d.open_alerts.length === 0 && 'No open application alerts. New detections start in observe mode.'}>
              <ul className="divide-y divide-siem-border/50">
                {d.open_alerts.map(a => (
                  <li key={a.service.key} className="px-3 py-2 flex items-center justify-between text-sm">
                    <Link to={`${svcLink(a.service)}?tab=alerts`} className="text-siem-text hover:underline">{a.service.name} <span className="text-xs text-siem-muted">{a.service.environment}</span></Link>
                    <span className="flex items-center gap-2 text-xs"><SeverityBadge severity={a.max_severity} /><span className="text-siem-muted">{a.open} open</span></span>
                  </li>))}
              </ul>
            </Section>

            <Section title="Exposure and criticality">
              <div className="p-3 grid grid-cols-2 gap-4 text-xs">
                <div><div className="text-siem-muted mb-1">Exposure</div>
                  {Object.entries(d.exposure).map(([k, v]) => <div key={k} className="flex justify-between"><span>{k}</span><b className="text-siem-text">{v}</b></div>)}</div>
                <div><div className="text-siem-muted mb-1">Criticality</div>
                  {Object.entries(d.criticality).map(([k, v]) => <div key={k} className="flex justify-between"><span>{k}</span><b className="text-siem-text">{v}</b></div>)}</div>
              </div>
            </Section>

            <Section title="What changed in this range">
              <div className="p-3 space-y-3 text-xs">
                <div className="flex gap-5 text-siem-muted">
                  <span><b className="text-siem-text">{d.changes.new_services.length}</b> new services</span>
                  <span><b className="text-siem-text">{d.changes.new_dependencies.length}</b> new dependencies</span>
                  <span><b className="text-siem-text">{d.changes.new_routes}</b> new routes</span>
                  <span><b className="text-siem-text">{d.changes.deploys.length}</b> deploys</span>
                </div>
                {d.changes.new_services.map(s => <div key={s.key}>New service <Link className="text-siem-accent hover:underline" to={svcLink(s)}>{s.name}</Link> <span className="text-siem-muted">{s.environment}</span></div>)}
                {d.changes.new_dependencies.map((e, i) => (
                  <div key={i}><Link className="text-siem-accent hover:underline" to={`${svcLink(e.service)}?tab=dependencies`}>{e.service.name}</Link> now talks to <span className="font-mono">{e.dst_name}</span> <span className="text-siem-muted">({e.dst_kind}, {appRel(e.first_seen)})</span></div>))}
              </div>
            </Section>

            <Section title="Recent deploys" empty={d.changes.deploys.length === 0 && 'No new versions in this range.'}>
              <ul className="divide-y divide-siem-border/50">
                {d.changes.deploys.map((x, i) => (
                  <li key={i} className="px-3 py-2 text-xs flex justify-between">
                    <Link className="text-siem-text hover:underline" to={svcLink(x.service)}>{x.service.name} <span className="text-siem-muted">{x.service.environment}</span></Link>
                    <span className="text-siem-muted">{x.version} · {appRel(x.first_seen)}</span>
                  </li>))}
              </ul>
            </Section>
          </div>

          <Section title="Needs attention" empty={d.degraded.length === 0 && 'Every reporting service is healthy.'}>
            <ul className="divide-y divide-siem-border/50">
              {d.degraded.map(x => (
                <li key={x.service.key} className="px-3 py-2 text-xs">
                  <Link className="text-siem-text hover:underline" to={svcLink(x.service)}>{x.service.name}</Link> <span className="text-siem-muted">{x.service.environment}</span>
                  <ul className="mt-1 text-siem-muted list-disc ml-5">{x.reasons.map(r => <li key={r}>{REASONS[r] || r}</li>)}</ul>
                </li>))}
            </ul>
          </Section>
        </>)}
      </StateBlock>
    </div>
  )
}
