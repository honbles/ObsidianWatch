// What the agent did about a prevention alert (Endpoint → Prevention): stopped (quarantined, killed,
// blocked) or not stopped (audit mode, or the action failed). Other alerts have no outcome.
const LABEL = {
  quarantined: 'Quarantined', killed: 'Killed', 'killed+quarantined': 'Killed and quarantined',
  blocked: 'Blocked', ip_blocked: 'Blocked', audit: 'Not stopped', failed: 'Not stopped',
}

export function alertOutcome(a) {
  let ev = a?.evidence
  if (typeof ev === 'string') { try { ev = JSON.parse(ev) } catch { ev = null } }
  const o = ev?.outcome
  if (o && LABEL[o]) {
    return { stopped: o !== 'audit' && o !== 'failed', label: LABEL[o], why: o === 'audit' ? 'audit mode: reported, not stopped' : o === 'failed' ? 'the agent could not act' : '' }
  }
  // prevention alerts raised before outcomes were recorded: the rule says it
  const rule = a?.rule_id || ''
  const t = a?.title || ''
  if (/^PREV-[A-Z]+-1$/.test(rule) || /\b(Stopped|Blocked)\b/.test(t) && /Known Malicious/i.test(t)) return { stopped: true, label: 'Stopped', why: '' }
  if (/^PREV-[A-Z]+-0$/.test(rule) || /Known Malicious (File Present|Address\b(?!.*Blocked)|Domain\b(?!.*Blocked))/i.test(t)) return { stopped: false, label: 'Not stopped', why: '' }
  return null
}

export function OutcomeBadge({ alert, size = 'sm' }) {
  const o = alertOutcome(alert)
  if (!o) return null
  return (
    <span className="ow-pill" title={o.why || (o.stopped ? 'The agent stopped this threat' : 'The agent reported this threat but did not stop it')}
      style={{ flex: 'none', color: o.stopped ? 'var(--ok)' : 'var(--crit)', background: o.stopped ? 'var(--okbg, var(--s2))' : 'var(--cbg)', fontSize: size === 'lg' ? 12 : 11 }}>
      {o.stopped ? '✓ ' : '! '}{o.label}
    </span>
  )
}
