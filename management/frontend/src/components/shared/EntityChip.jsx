import { Link } from 'react-router-dom'
import { entityHref } from './entityRoutes'

export default function EntityChip({ kind, value }) {
  const href = entityHref(kind, value)
  const body = (<><span className="text-siem-muted">{kind}</span> <span className="text-siem-text">{value}</span></>)
  const cls = 'inline-flex items-center gap-1 rounded border border-siem-border px-1.5 py-0.5 text-xs'
  return href ? <Link to={href} className={`${cls} hover:bg-white/5`}>{body}</Link> : <span className={cls}>{body}</span>
}
