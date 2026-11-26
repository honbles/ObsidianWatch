import { useEffect, useMemo, useState } from 'react'
import StateBlock from './StateBlock'

// columns: [{ key, label, render?(row), sort?(row)=>comparable, align?, width? }]
// pageSize: show that many rows at a time, after sorting, with a pager (off when unset).
export default function DataTable({ columns, rows, onRowClick, loading, error, emptyText, rowKey = (r, i) => i, initialSort, pageSize }) {
  const [page, setPage] = useState(0)
  const [sort, setSort] = useState(initialSort || null) // {key, dir}
  const sorted = useMemo(() => {
    if (!sort || !rows) return rows || []
    const col = columns.find(c => c.key === sort.key)
    const val = col?.sort || (r => r[sort.key])
    return [...rows].sort((a, b) => (val(a) > val(b) ? 1 : val(a) < val(b) ? -1 : 0) * (sort.dir === 'asc' ? 1 : -1))
  }, [rows, sort, columns])
  const pages = pageSize ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1
  useEffect(() => { setPage(0) }, [rows, sort, pageSize]) // a new filter or sort starts at the first page
  const shown = pageSize ? sorted.slice(page * pageSize, (page + 1) * pageSize) : sorted
  const pager = pageSize && sorted.length > pageSize && (
    <div className="flex items-center gap-2 px-3 py-2 text-xs text-siem-muted border-t border-siem-border">
      <span>{page * pageSize + 1}–{Math.min(sorted.length, (page + 1) * pageSize)} of {sorted.length}</span>
      <button className="ow-btn quiet" disabled={page === 0} onClick={() => setPage(0)}>First</button>
      <button className="ow-btn quiet" disabled={page === 0} onClick={() => setPage(x => x - 1)}>Previous</button>
      <span>page {page + 1} of {pages}</span>
      <button className="ow-btn quiet" disabled={page >= pages - 1} onClick={() => setPage(x => x + 1)}>Next</button>
      <button className="ow-btn quiet" disabled={page >= pages - 1} onClick={() => setPage(pages - 1)}>Last</button>
    </div>)
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
            {shown.map((r, i) => (
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
      {pager}
    </StateBlock>
  )
}
