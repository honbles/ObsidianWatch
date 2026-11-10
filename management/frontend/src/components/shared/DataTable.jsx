import { useMemo, useState } from 'react'
import StateBlock from './StateBlock'

// columns: [{ key, label, render?(row), sort?(row)=>comparable, align?, width? }]
export default function DataTable({ columns, rows, onRowClick, loading, error, emptyText, rowKey = (r, i) => i, initialSort }) {
  const [sort, setSort] = useState(initialSort || null) // {key, dir}
  const sorted = useMemo(() => {
    if (!sort || !rows) return rows || []
    const col = columns.find(c => c.key === sort.key)
    const val = col?.sort || (r => r[sort.key])
    return [...rows].sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * (sort.dir === 'asc' ? 1 : -1))
  }, [rows, sort, columns])
  return (
    <StateBlock loading={loading} error={error} empty={!rows || rows.length === 0} emptyText={emptyText}>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-siem-muted border-b border-siem-border">
              {columns.map(c => (
                <th key={c.key} style={{ width: c.width, textAlign: c.align }}
                  className={`px-3 py-2 font-medium ${c.sort || !c.render ? 'cursor-pointer select-none' : ''}`}
                  onClick={() => setSort(s => ({ key: c.key, dir: s?.key === c.key && s.dir === 'desc' ? 'asc' : 'desc' }))}>
                  {c.label}{sort?.key === c.key ? (sort.dir === 'asc' ? ' ▲' : ' ▼') : ''}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((r, i) => (
              <tr key={rowKey(r, i)} onClick={onRowClick ? () => onRowClick(r) : undefined}
                className={`border-b border-siem-border/50 ${onRowClick ? 'cursor-pointer hover:bg-white/5' : ''}`}>
                {columns.map(c => (
                  <td key={c.key} style={{ textAlign: c.align }} className="px-3 py-2 text-siem-text">
                    {c.render ? c.render(r) : String(r[c.key] ?? '')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </StateBlock>
  )
}
