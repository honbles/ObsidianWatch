import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { appApi } from '../../api/app'
import { StateBlock } from '../shared'
import { AppTierBadge, AppExposureBadge } from './AppBadges'
import { appRel } from './appFormat'

// "Applications" panel for the host page. The integration owner mounts it:
//   <AppHostApplications agentId={agent.id} />
// It lists the services that have an instance on this host's agent.
export default function AppHostApplications({ agentId }) {
  const [state, setState] = useState({ loading: true, error: null, rows: [] })
  useEffect(() => {
    if (!agentId) return
    let live = true
    const to = new Date(), from = new Date(to.getTime() - 7 * 86400e3)
    appApi.services({ from: from.toISOString(), to: to.toISOString() }, { agent_id: agentId, limit: 100 })
      .then(d => live && setState({ loading: false, error: null, rows: d.services || [] }))
      .catch(e => live && setState({ loading: false, error: e.response?.data?.error || e.message, rows: [] }))
    return () => { live = false }
  }, [agentId])
  return (
    <div className="card">
      <div className="card-head"><span className="text-sm font-medium text-siem-text">Applications on this host</span></div>
      <StateBlock loading={state.loading} error={state.error} empty={state.rows.length === 0}
        emptyText="No applications seen on this host in the last 7 days.">
        <ul className="divide-y divide-siem-border/50">
          {state.rows.map(s => (
            <li key={s.id} className="px-3 py-2 flex items-center justify-between gap-3 text-sm">
              <Link to={`/applications/services/${encodeURIComponent(s.key)}`} className="text-siem-text hover:underline">
                {s.name} <span className="text-siem-muted text-xs">{s.environment}</span>
              </Link>
              <span className="flex items-center gap-2 text-xs text-siem-muted">
                <AppTierBadge tier={s.tier} /><AppExposureBadge exposure={s.settings.exposure} settings={s.settings} />
                <span>{s.instances} inst.</span><span>{appRel(s.last_seen)}</span>
              </span>
            </li>
          ))}
        </ul>
      </StateBlock>
    </div>
  )
}
