import { RANGE_PRESETS } from './useTimeRange'

export default function TimeRangePicker({ range }) {
  const span = new Date(range.to) - new Date(range.from)
  return (
    <div className="inline-flex rounded-lg border border-siem-border overflow-hidden text-xs">
      {RANGE_PRESETS.map(p => {
        const active = Math.abs(span - p.ms) < 60e3
        return (
          <button key={p.key} onClick={() => range.setPreset(p.ms)}
            className={`px-2.5 py-1 transition-colors ${active ? 'bg-siem-accent/20 text-siem-text' : 'text-siem-muted hover:text-siem-text'}`}>
            {p.label}
          </button>
        )
      })}
    </div>
  )
}
