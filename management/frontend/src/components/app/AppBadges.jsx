// Small status badges for the Applications section. Owned by the Application build.
const base = 'ow-pill'

const TIER = {
  0: ['T0', 'none', 'Discovered from the host only'],
  1: ['T1', 'info', 'OpenTelemetry received'],
  2: ['T2', 'info', 'Security helper events received'],
}
export function AppTierBadge({ tier, instrumentation }) {
  const [label, cls, title] = TIER[tier] || TIER[0]
  if (tier >= 1 && instrumentation === 'ebpf') {
    return <span className={`${base} ${cls}`} title="Request data from the agent's eBPF instrumentation (no code change)">{label}·eBPF</span>
  }
  return <span className={`${base} ${cls}`} title={title}>{label}</span>
}

const EXPOSURE = { internet: 'warn', internal: 'none', unknown: 'none' }
// settings is the service's settings object: the analyst's value wins, otherwise the inferred one is shown (marked "auto").
export function AppExposureBadge({ exposure, settings }) {
  const inferred = settings && (!exposure || exposure === 'unknown') && settings.exposure_inferred && settings.exposure_inferred !== 'unknown'
  const v = inferred ? settings.exposure_inferred : exposure
  return <span title={inferred ? `Inferred: ${settings.exposure_reason}. Set it in the service settings to override.` : undefined}
    className={`${base} ${EXPOSURE[v] || EXPOSURE.unknown}`}>{v || 'unknown'}{inferred ? ' (auto)' : ''}</span>
}

const CRIT = { low: 'none', normal: 'none', high: 'warn', critical: 'crit' }
export function AppCriticalityBadge({ criticality }) {
  return <span className={`${base} ${CRIT[criticality] || CRIT.normal}`}>{criticality || 'normal'}</span>
}

export function AppIdentityBadge({ identity }) {
  const ok = identity === 'verified'
  return (
    <span className={`${base} ${ok ? 'ok' : 'warn'}`}
      title={ok ? 'Telemetry came from the process bound to this service' : 'Telemetry came from a process the agent could not bind to this service; it cannot raise high-severity alerts alone'}>
      {ok ? 'verified' : 'asserted'}
    </span>
  )
}
