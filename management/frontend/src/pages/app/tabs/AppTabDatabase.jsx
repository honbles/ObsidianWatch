import { useState } from 'react'
import { DataTable } from '../../../components/shared'
import { appApi } from '../../../api/app'
import useAppLoad from '../../../components/app/useAppLoad'
import { appInt, appMs } from '../../../components/app/appFormat'

// What the service asks its databases: calls, time and errors by operation and table, and the statement
// itself (values removed on the host) when the service is set to send fingerprints.
export default function AppTabDatabase({ service, range }) {
  const [sort, setSort] = useState('total_ms')
  const { data, loading, error } = useAppLoad(() => appApi.queries(service.id, range, { sort }), [service.id, range.from, range.to, sort])
  const rows = data?.queries || []
  const fp = service.settings?.db_statement_mode === 'fingerprint'
  const cols = [
    { key: 'system', label: 'Database', width: 100, render: q => <span className="font-mono text-xs">{q.system}</span> },
    { key: 'op', label: 'Operation', width: 90, render: q => q.operation || '-' },
    { key: 'table', label: 'Table', render: q => <span className="font-mono text-xs">{q.table || '-'}</span> },
    { key: 'text', label: 'Statement', render: q => q.text
      ? <span className="font-mono text-xs break-all" title={`fingerprint ${q.fingerprint}`}>{q.text}</span>
      : <span className="text-siem-muted text-xs">{fp ? 'no statement reported' : 'names only'}</span> },
    { key: 'calls', label: 'Calls', align: 'right', render: q => appInt(q.calls) },
    { key: 'err', label: 'Errors', align: 'right', render: q => <span className={q.errors > 0 ? 'text-red-300' : ''}>{appInt(q.errors)}</span> },
    { key: 'avg', label: 'Avg', align: 'right', render: q => appMs(q.avg_ms) },
    { key: 'p95', label: 'p95', align: 'right', render: q => appMs(q.p95_ms, q.over_range) },
    { key: 'total', label: 'Total time', align: 'right', render: q => appMs(q.total_ms) },
  ]
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs text-siem-muted">
        Sort by
        <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={sort} onChange={e => setSort(e.target.value)}>
          <option value="total_ms">Total time</option><option value="p95">p95</option><option value="calls">Calls</option><option value="errors">Errors</option>
        </select>
      </div>
      <div className="card"><DataTable columns={cols} rows={rows} loading={loading} error={error}
        rowKey={q => [q.system, q.operation, q.table, q.fingerprint].join('|')}
        emptyText="No database calls in this range." /></div>
      <div className="text-xs text-siem-muted">
        Operation and table names only, unless statement fingerprints are on in Settings.
      </div>
    </div>
  )
}
