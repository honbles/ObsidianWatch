// Page header for the Applications pages. The rail carries the section's pages and the context bar
// carries the time range, so this is only title, description and actions. `range` is accepted for
// callers written before the redesign and is no longer drawn here.
// The pages wrap it in a padded container, so it bleeds out to the edges with negative margins.
export default function AppPageHeader({ title, subtitle, children }) {
  return (
    <header className="ow-head notabs" style={{ margin: 'var(--app-bleed, -24px -24px 0)' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
        <div style={{ minWidth: 0, maxWidth: 900 }}>
          <h1>{title}</h1>
          {subtitle && <div className="ow-sub">{subtitle}</div>}
        </div>
        {children && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>{children}</div>}
      </div>
    </header>
  )
}
