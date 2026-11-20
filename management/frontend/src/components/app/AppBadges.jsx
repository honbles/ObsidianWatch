// Small status badges for the Applications section. Owned by the Application build.
const base = 'inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium'

const TIER = {
  0: ['T0', 'border-slate-500/40 text-slate-300', 'Discovered from the host only'],
  1: ['T1', 'border-sky-500/40 text-sky-300', 'OpenTelemetry received'],
  2: ['T2', 'border-emerald-500/40 text-emerald-300', 'Security helper events received'],
}
export function AppTierBadge({ tier }) {
  const [label, cls, title] = TIER[tier] || TIER[0]
  return <span className={`${base} ${cls}`} title={title}>{label}</span>
}

const EXPOSURE = { internet: 'border-red-500/40 text-red-300', internal: 'border-slate-500/40 text-slate-300', unknown: 'border-amber-500/40 text-amber-300' }
// settings is the service's settings object: the analyst's value wins, otherwise the inferred one is shown (marked "auto").
export function AppExposureBadge({ exposure, settings }) {
  const inferred = settings && (!exposure || exposure === 'unknown') && settings.exposure_inferred && settings.exposure_inferred !== 'unknown'
  const v = inferred ? settings.exposure_inferred : exposure
  return <span title={inferred ? `Inferred: ${settings.exposure_reason}. Set it in the service settings to override.` : undefined}
    className={`${base} ${EXPOSURE[v] || EXPOSURE.unknown}`}>{v || 'unknown'}{inferred ? ' (auto)' : ''}</span>
}

const CRIT = { low: 'text-slate-400 border-slate-500/30', normal: 'text-slate-300 border-slate-500/40', high: 'text-orange-300 border-orange-500/40', critical: 'text-red-300 border-red-500/40' }
export function AppCriticalityBadge({ criticality }) {
  return <span className={`${base} ${CRIT[criticality] || CRIT.normal}`}>{criticality || 'normal'}</span>
}

export function AppIdentityBadge({ identity }) {
  const ok = identity === 'verified'
  return (
    <span className={`${base} ${ok ? 'border-emerald-500/40 text-emerald-300' : 'border-amber-500/40 text-amber-300'}`}
      title={ok ? 'Telemetry came from the process bound to this service' : 'Telemetry came from a process the agent could not bind to this service; it cannot raise high-severity alerts alone'}>
      {ok ? 'verified' : 'asserted'}
    </span>
  )
}
