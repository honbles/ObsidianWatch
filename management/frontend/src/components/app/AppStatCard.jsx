import { Sparkline } from '../shared'

// A number with a caption and an optional trend line.
export default function AppStatCard({ label, value, hint, values, color = 'var(--accent)', tone }) {
  const toneCls = tone === 'bad' ? 'text-red-300' : tone === 'warn' ? 'text-amber-300' : 'text-siem-text'
  return (
    <div className="card p-3 min-w-[150px]">
      <div className="text-2xs uppercase tracking-wide text-siem-muted">{label}</div>
      <div className="flex items-end justify-between gap-2 mt-1">
        <div className={`text-xl font-semibold ${toneCls}`}>{value}</div>
        {values && values.length > 1 && <Sparkline values={values} color={color} width={80} height={24} />}
      </div>
      {hint && <div className="text-mini text-siem-muted mt-1">{hint}</div>}
    </div>
  )
}
