export function SeverityBadge({ severity }) {
  const labels = { 1:'INFO', 2:'LOW', 3:'MED', 4:'HIGH', 5:'CRIT' }
  return (
    <span className={`sev sev-${severity || 1}`}>
      {labels[severity] || 'INFO'}
    </span>
  )
}
