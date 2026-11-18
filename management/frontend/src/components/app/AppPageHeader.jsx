import { Link, useLocation, useSearchParams } from 'react-router-dom'
import { Boxes } from 'lucide-react'
import { TimeRangePicker } from '../shared'

const TABS = [
  ['Overview', '/applications'],
  ['Services', '/applications/services'],
  ['Dependencies', '/applications/map'],
  ['Coverage', '/applications/coverage'],
  ['Settings', '/applications/settings'],
]

// Page title, section sub-navigation and (optionally) the shared time-range picker.
export default function AppPageHeader({ title, subtitle, range, children }) {
  const { pathname } = useLocation()
  const [params] = useSearchParams()
  const qs = params.toString() ? `?${params.toString()}` : ''
  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-siem-text tracking-tight flex items-center gap-2.5">
            <Boxes size={18} className="text-siem-accent" />{title}
          </h1>
          {subtitle && <p className="text-[11px] text-siem-muted mt-1 max-w-3xl">{subtitle}</p>}
        </div>
        <div className="flex items-center gap-2">
          {children}
          {range && <TimeRangePicker range={range} />}
        </div>
      </div>
      <div className="flex gap-1 border-b border-siem-border">
        {TABS.map(([label, to]) => {
          const active = to === '/applications' ? pathname === to : pathname.startsWith(to)
          return (
            <Link key={to} to={`${to}${qs}`}
              className={`px-3 py-1.5 text-xs border-b-2 -mb-px transition-colors ${active ? 'border-siem-accent text-siem-text' : 'border-transparent text-siem-muted hover:text-siem-text'}`}>
              {label}
            </Link>
          )
        })}
      </div>
    </div>
  )
}
