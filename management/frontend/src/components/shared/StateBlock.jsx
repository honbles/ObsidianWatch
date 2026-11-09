// One consistent loading / empty / error block. Usage:
//   <StateBlock loading={l} error={e} empty={!rows.length} emptyText="No services yet">{children}</StateBlock>
export default function StateBlock({ loading, error, empty, emptyText = 'Nothing to show', children }) {
  if (loading) return <div className="p-8 text-center text-sm text-siem-muted">Loading…</div>
  if (error) return <div className="p-8 text-center text-sm text-red-400">{typeof error === 'string' ? error : (error.message || 'Something went wrong')}</div>
  if (empty) return <div className="p-8 text-center text-sm text-siem-muted">{emptyText}</div>
  return children
}
