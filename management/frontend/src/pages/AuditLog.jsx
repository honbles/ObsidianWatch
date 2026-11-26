import { useEffect, useState } from 'react'
import { ClipboardList, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'
import { Download } from 'lucide-react'
import { PageHeader, Facets, countBy, useFacetFilter, DenseTable, downloadCSV } from '../components/ui'

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
  create_suppression: 'text-yellow-400',
  update_suppression: 'text-yellow-400',
  delete_suppression: 'text-siem-red',
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

  const [q, setQ] = useState('')
  const [facets, setFacets] = useState({})
  const G = { user: e => e.username, action: e => e.action }
  const faceted = useFacetFilter(entries, G, facets)
  const rows = faceted.filter(e => !q || `${e.username} ${e.action} ${e.target || ''} ${e.detail || ''} ${e.ip_address || ''}`.toLowerCase().includes(q.toLowerCase()))
  const toggle = (k, v) => setFacets(f => { const n = { ...f }; const set = new Set(n[k] || []); set.has(v) ? set.delete(v) : set.add(v); n[k] = set; return n })
  const tone = (a) => /^(delete|remove|bulk_close|disable)/.test(a) ? 'var(--crit)' : /^(create|add|enable)/.test(a) ? 'var(--ok)' : /^(update|edit|set|assign|bulk)/.test(a) ? 'var(--warn)' : 'var(--t2)'
  return (
    <div>
      <PageHeader title="Audit log" sub={`${total.toLocaleString()} actions. Filters apply to the ${entries.length} on this page.`}
        actions={<>
          <button className="ow-btn" disabled={!rows.length} onClick={() => downloadCSV(`audit-${new Date().toISOString().slice(0, 10)}.csv`, ['time', 'user', 'action', 'target', 'detail', 'ip'], rows.map(e => [e.created_at, e.username, e.action, e.target, e.detail, e.ip_address]))}><Download size={13}/>Export page</button>
          <button className="ow-btn" onClick={() => load(page)}><RefreshCw size={13}/>Refresh</button>
        </>}/>
      <div className="ow-body" style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
        <Facets selected={facets} onToggle={toggle} onClear={() => setFacets({})} groups={[
          { key: 'user', label: 'User', values: countBy(entries, G.user) },
          { key: 'action', label: 'Action', values: countBy(entries, G.action).slice(0, 15) },
        ]}/>
        <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by user, action, target or IP" aria-label="Filter audit log"/></label>
            <span className="t2" style={{ fontSize: 13.5 }}>{rows.length} of {entries.length} on this page</span>
          </div>
          <DenseTable rows={loading ? [] : rows} rowKey={e => e.id} empty={loading ? 'Loading…' : 'No audit entries.'} cols={[
            { key: 't', label: 'Time', width: '150px', render: e => <span className="mono t2" style={{ fontSize: 13.5 }} title={new Date(e.created_at).toISOString()}>{format(new Date(e.created_at), 'MMM dd HH:mm:ss')}</span> },
            { key: 'u', label: 'User', width: '120px', render: e => <span className="t1">{e.username}</span> },
            { key: 'a', label: 'Action', width: 'minmax(160px, 1fr)', render: e => <span className="mono" style={{ color: tone(e.action) }}>{e.action}</span> },
            { key: 'g', label: 'Target', width: 'minmax(140px, 1fr)', render: e => <span className="mono t2">{e.target || '—'}</span>, title: e => e.target },
            { key: 'd', label: 'Detail', width: 'minmax(200px, 2fr)', render: e => <span className="t2">{e.detail || '—'}</span>, title: e => e.detail },
            { key: 'i', label: 'Source IP', width: '120px', render: e => <span className="mono t3">{e.ip_address || '—'}</span> },
          ]}/>
          {total > limit && (
            <div className="ow-card-foot"><span>Page {page + 1} of {Math.ceil(total / limit)}</span>
              <span style={{ display: 'flex', gap: 4 }}>
                <button className="ow-btn quiet" style={{ height: 24 }} disabled={page === 0} onClick={() => { const p = page - 1; setPage(p); load(p) }}>‹ Newer</button>
                <button className="ow-btn quiet" style={{ height: 24 }} disabled={(page + 1) * limit >= total} onClick={() => { const p = page + 1; setPage(p); load(p) }}>Older ›</button>
              </span></div>)}
        </div>
      </div>
    </div>
  )
}
