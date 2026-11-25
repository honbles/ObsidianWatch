// Code step 4: runtime reachability of a dependency finding.
const STYLE = {
  loaded:      ['Running (loaded)', 'bg-red-950/40 text-red-300 border-red-800/50'],
  deployed:    ['Deployed', 'bg-amber-950/30 text-amber-300 border-amber-800/40'],
  not_running: ['Not running', 'bg-siem-surface text-siem-muted border-siem-border'],
  unknown:     ['Runtime unknown', 'bg-siem-surface text-siem-muted/60 border-siem-border/60'],
}

export const REACH_ORDER = { loaded: 0, deployed: 1, unknown: 2, not_running: 3 }

export function reachTitle(r) {
  if (!r) return ''
  if (r.level === 'unknown') return 'No host reports a runtime inventory, so it is not known whether this version runs.'
  if (r.level === 'not_running') return 'Hosts report runtime inventories and none runs this version (last 24 h).'
  const where = [...(r.services || []), ...(r.hosts || []).map(h => `host ${h}`)].join(', ')
  return `${r.level === 'loaded' ? 'Loaded by' : 'Installed for'} ${where || 'a running process'}${r.last_seen ? `; last seen ${new Date(r.last_seen).toLocaleString()}` : ''}`
}

export default function ReachBadge({ reach }) {
  if (!reach) return null
  const [label, cls] = STYLE[reach.level] || STYLE.unknown
  return <span title={reachTitle(reach)} className={`text-[9px] px-1.5 py-0.5 rounded border shrink-0 ${cls}`}>{label}</span>
}
