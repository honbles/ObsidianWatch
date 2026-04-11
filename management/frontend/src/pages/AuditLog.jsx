import { useEffect, useState } from 'react'
import { ClipboardList, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

const ACTION_COLORS = {
  login:              'text-siem-green',
  change_password:    'text-siem-accent',
  create_user:        'text-siem-accent',
  delete_user:        'text-siem-red',
  create_alert:       'text-yellow-400',
  ack_alert:          'text-yellow-400',
  close_alert:        'text-siem-muted',
  create_alert_rule:  'text-siem-accent',
  update_alert_rule:  'text-siem-muted',
  delete_alert_rule:  'text-siem-red',
  assign_alert:       'text-yellow-400',
  close_alert_review: 'text-siem-muted',
}

export default function AuditLog() {
  const [entries, setEntries] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(0)
  const limit = 100

  const load = async (p = 0) => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/audit-log', { params: { limit, offset: p * limit } })
      setEntries(data.entries || [])
      setTotal(data.total || 0)
    } finally { setLoading(false) }
  }

  useEffect(() => { load(0) }, [])

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ClipboardList className="text-siem-accent" size={20} />
          <h1 className="text-xl font-bold text-siem-text">Audit Log</h1>
          <span className="text-xs text-siem-muted">{total.toLocaleString()} entries</span>
        </div>
        <button onClick={() => load(page)}
          className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5">
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-siem-border text-siem-muted text-xs">
              <th className="text-left px-4 py-3">Time</th>
              <th className="text-left px-4 py-3">User</th>
              <th className="text-left px-4 py-3">Action</th>
              <th className="text-left px-4 py-3">Target</th>
              <th className="text-left px-4 py-3">Detail</th>
              <th className="text-left px-4 py-3">IP</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-12 text-siem-muted">Loading...</td></tr>
            ) : entries.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-12 text-siem-muted">No audit entries</td></tr>
            ) : entries.map(e => (
              <tr key={e.id} className="border-b border-siem-border/40">
                <td className="px-4 py-2.5 text-siem-muted text-xs whitespace-nowrap">
                  {format(new Date(e.created_at), 'MM/dd HH:mm:ss')}
                </td>
                <td className="px-4 py-2.5 text-siem-text font-medium">{e.username}</td>
                <td className={`px-4 py-2.5 text-xs font-mono ${ACTION_COLORS[e.action] || 'text-siem-muted'}`}>{e.action}</td>
                <td className="px-4 py-2.5 text-siem-muted text-xs">{e.target || '—'}</td>
                <td className="px-4 py-2.5 text-siem-muted text-xs truncate max-w-[200px]">{e.detail || '—'}</td>
                <td className="px-4 py-2.5 text-siem-muted text-xs font-mono">{e.ip_address || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {total > limit && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-siem-border">
            <span className="text-xs text-siem-muted">Page {page + 1} of {Math.ceil(total / limit)}</span>
            <div className="flex gap-2">
              <button disabled={page === 0} onClick={() => { const p = page - 1; setPage(p); load(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Previous</button>
              <button disabled={(page + 1) * limit >= total} onClick={() => { const p = page + 1; setPage(p); load(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
