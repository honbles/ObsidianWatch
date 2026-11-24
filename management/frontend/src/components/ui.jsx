// Design-system parts. One set of parts on every page, so a cloud finding reads like an endpoint alert
// reads like a failing service. Styles live in index.css under the ow-* classes.
import { useMemo, useState, useEffect } from 'react'

// ── State ─────────────────────────────────────────────────────────────────────
// Five states. Colour is never the only signal: each has a shape (circle, diamond, square) and a word.
export const STATE_LABEL = { ok: 'OK', warn: 'Warning', crit: 'Critical', none: 'Unknown', info: 'Info' }

export function StateDot({ state = 'none' }) {
  return <span className={`ow-dot ${state}`} aria-hidden="true"/>
}

export function StatePill({ state = 'none', children, dot = true, title }) {
  return (
    <span className={`ow-pill ${state}`} title={title}>
      {dot && <StateDot state={state}/>}{children ?? STATE_LABEL[state]}
    </span>
  )
}

// Severity 1..5 (platform scale) → state + word.
export const SEV_WORD = { 5: 'Critical', 4: 'High', 3: 'Medium', 2: 'Low', 1: 'Info' }
export const sevState = (s) => s >= 5 ? 'crit' : s >= 4 ? 'warn' : s >= 3 ? 'info' : 'none'
export function SevPill({ sev }) {
  return <StatePill state={sevState(sev)}>{SEV_WORD[sev] || 'Info'}</StatePill>
}

// ── Page header: what this is, its state in one pill, the numbers that matter, then tabs ──
export function PageHeader({ title, mono, state, stateText, stateTitle, sub, actions, nums, tabs, children }) {
  return (
    <header className={`ow-head ${tabs ? '' : 'notabs'}`}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
        <div style={{ minWidth: 0, flex: '1 1 auto', maxWidth: 960 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h1 className={mono ? 'mono' : ''}>{title}</h1>
            {state && <StatePill state={state} title={stateTitle}>{stateText}</StatePill>}
          </div>
          {sub && <div className="ow-sub">{sub}</div>}
        </div>
        {actions && <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>{actions}</div>}
      </div>
      {nums && <div className="ow-nums">{nums}</div>}
      {children}
      {tabs}
    </header>
  )
}

// A headline number inside the page header.
export function Num({ k, v, unit, tone, delta, deltaTone, grow, children, title }) {
  return (
    <div className="ow-num" style={grow ? { flex: `${grow} 1 260px` } : undefined} title={title}>
      <div className="ow-num-k">{k}</div>
      {v !== undefined && (
        <div className="ow-num-v" style={tone ? { color: `var(--${tone})` } : undefined}>
          {v}{unit && <span className="ow-num-u"> {unit}</span>}
          {delta && <span className="ow-num-u" style={{ color: deltaTone ? `var(--${deltaTone})` : undefined }}> {delta}</span>}
        </div>
      )}
      {children}
    </div>
  )
}

// A stat tile (card) for pages whose numbers need room for a trend or a meter.
export function StatTile({ k, v, unit, note, noteTone, tone, children, style }) {
  return (
    <div className="ow-stat" style={style}>
      <div style={{ fontSize: 12, color: 'var(--t2)' }}>{k}</div>
      <div className="ow-stat-v" style={tone ? { color: `var(--${tone})` } : undefined}>
        {v}{unit && <span style={{ fontSize: 13, color: 'var(--t2)', fontWeight: 500 }}> {unit}</span>}
      </div>
      {children}
      {note && <div style={{ fontSize: 12, color: noteTone ? `var(--${noteTone})` : 'var(--t2)' }}>{note}</div>}
    </div>
  )
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <nav className="ow-tabs" role="tablist">
      {tabs.map(t => {
        const id = t.id ?? t
        const label = t.label ?? t
        return (
          <button key={id} role="tab" aria-selected={value === id} className={`ow-tab ${value === id ? 'on' : ''}`} onClick={() => onChange(id)}>
            {label}{t.n !== undefined && t.n !== null && <span className="ow-tab-n">{t.n}</span>}
          </button>
        )
      })}
    </nav>
  )
}

// Proportional bar of states, e.g. fleet health. parts: [{ n, state, label }]
export function StateBar({ parts, height = 10 }) {
  const total = parts.reduce((s, p) => s + p.n, 0)
  return (
    <div>
      <div className="ow-stack" style={{ height }} role="img" aria-label={parts.map(p => `${p.n} ${p.label}`).join(', ')}>
        {total === 0 ? null : parts.filter(p => p.n > 0).map(p => (
          <div key={p.label} style={{ flex: p.n, background: p.state === 'none' ? 'var(--t3)' : `var(--${p.state})` }} title={`${p.n} ${p.label}`}/>
        ))}
      </div>
      <div style={{ fontSize: 11.5, color: 'var(--t3)', marginTop: 4 }}>{parts.map(p => `${p.n.toLocaleString()} ${p.label}`).join(' · ')}</div>
    </div>
  )
}

export function Meter({ pct, state = 'acc', height = 6 }) {
  const c = state === 'none' ? 'var(--t3)' : `var(--${state})`
  return <div className="ow-meter" style={{ height }}><div style={{ width: `${Math.max(0, Math.min(100, pct))}%`, background: c }}/></div>
}

// ── Facets: counts per value, one click to filter ─────────────────────────────
// groups: [{ key, label, values: [{ v, label, n }] }]; selected: { [key]: Set }
export function Facets({ groups, selected, onToggle, onClear }) {
  const any = Object.values(selected).some(s => s && s.size)
  return (
    <aside className="ow-facets" aria-label="Filters">
      {groups.filter(g => g.values.length).map(g => (
        <div key={g.key}>
          <div className="ow-lbl" style={{ marginBottom: 6 }}>{g.label}</div>
          {g.values.map(x => {
            const on = selected[g.key]?.has(x.v)
            return (
              <button key={x.v} className={`ow-fc ${on ? 'on' : ''}`} onClick={() => onToggle(g.key, x.v)} aria-pressed={!!on}>
                <span>{x.label ?? x.v}</span><b>{x.n.toLocaleString()}</b>
              </button>
            )
          })}
        </div>
      ))}
      {any && <button className="ow-btn quiet" style={{ alignSelf: 'flex-start', paddingLeft: 8 }} onClick={onClear}>Clear filters</button>}
    </aside>
  )
}

// Count values for a facet from rows. getter returns a value or an array of values.
export function countBy(rows, getter, order, labels = {}) {
  const m = new Map()
  for (const r of rows) {
    const v = getter(r)
    for (const x of (Array.isArray(v) ? v : [v])) if (x !== undefined && x !== null && x !== '') m.set(x, (m.get(x) || 0) + 1)
  }
  let vals = [...m.entries()].map(([v, n]) => ({ v, n, label: labels[v] }))
  if (order) vals.sort((a, b) => (order.indexOf(a.v) + 1 || 99) - (order.indexOf(b.v) + 1 || 99))
  else vals.sort((a, b) => b.n - a.n)
  return vals
}

// Rows pass when, for every facet with a selection, the row's value(s) hit the selection.
export function useFacetFilter(rows, getters, selected) {
  return useMemo(() => rows.filter(r => Object.entries(selected).every(([k, set]) => {
    if (!set || !set.size || !getters[k]) return true
    const v = getters[k](r)
    return (Array.isArray(v) ? v : [v]).some(x => set.has(x))
  })), [rows, getters, selected])
}

// ── Dense table ───────────────────────────────────────────────────────────────
// cols: [{ key, label, width, render(row), title?, align? }]; rowState(row) → stripe.
// Selection (optional): selected: Set of keys, onSelect(key, checked), onSelectAll(checked). current: key of the open row.
export function DenseTable({ cols, rows, rowKey, rowState, onRow, empty = 'Nothing to show', head, selected, onSelect, onSelectAll, current, sort, onSort }) {
  const sel = !!onSelect
  const tpl = (sel ? '28px ' : '') + cols.map(c => c.width || '1fr').join(' ')
  const all = sel && rows.length > 0 && rows.every(r => selected.has(rowKey(r)))
  const some = sel && rows.some(r => selected.has(rowKey(r)))
  return (
    <div role="table">
      {head}
      <div className="ow-grid h" role="row" style={{ gridTemplateColumns: tpl }}>
        {sel && <div><Check checked={all} indeterminate={!all && some} onChange={onSelectAll} label="Select all rows"/></div>}
        {cols.map(c => (
          <div key={c.key} role="columnheader" style={{ textAlign: c.align, cursor: c.sortKey && onSort ? 'pointer' : undefined }}
            aria-sort={sort && c.sortKey && sort.key === c.sortKey ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}
            onClick={c.sortKey && onSort ? () => onSort(c.sortKey) : undefined}>
            {c.label}{sort && c.sortKey && sort.key === c.sortKey ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ''}
          </div>))}
      </div>
      {rows.length === 0 && <div style={{ padding: '28px 14px', color: 'var(--t3)', textAlign: 'center' }}>{empty}</div>}
      {rows.map(r => {
        const k = rowKey(r)
        const st = rowState ? rowState(r) : null
        const isSel = sel && selected.has(k)
        return (
          <div key={k} role="row" tabIndex={onRow ? 0 : undefined} aria-selected={isSel || undefined}
            className={`ow-grid ${st && st !== 'ok' ? 's-' + st : ''} ${onRow ? 'click' : ''} ${isSel ? 'sel' : ''} ${current === k ? 'cur' : ''}`}
            style={{ gridTemplateColumns: tpl }}
            onClick={onRow ? () => onRow(r) : undefined}
            onKeyDown={onRow ? (e) => { if (e.key === 'Enter') onRow(r) } : undefined}>
            {sel && <div><Check checked={isSel} onChange={v => onSelect(k, v)} label="Select row"/></div>}
            {cols.map(c => <div key={c.key} role="cell" title={c.title ? c.title(r) : undefined} style={c.align ? { textAlign: c.align } : undefined}>{c.render(r)}</div>)}
          </div>
        )
      })}
    </div>
  )
}

// Selection state for a list: keys in a Set, plus helpers.
export function useSelection() {
  const [selected, setSelected] = useState(() => new Set())
  return {
    selected,
    onSelect: (k, v) => setSelected(s => { const n = new Set(s); v ? n.add(k) : n.delete(k); return n }),
    setAll: (keys) => setSelected(new Set(keys)),
    clear: () => setSelected(new Set()),
  }
}

// Parse "os:linux state:warning free text" into { fields: {os:[..]}, text }
export function parseFilter(s) {
  const fields = {}
  const text = []
  for (const tok of (s || '').match(/(\S+:"[^"]*"|\S+)/g) || []) {
    const m = tok.match(/^([a-z_]+):(.+)$/i)
    if (m) (fields[m[1].toLowerCase()] ||= []).push(...m[2].replace(/"/g, '').toLowerCase().split(','))
    else text.push(tok.toLowerCase())
  }
  return { fields, text: text.join(' ') }
}

export function relTime(t) {
  if (!t) return '—'
  const d = (Date.now() - new Date(t).getTime()) / 1000
  if (!isFinite(d)) return '—'
  if (d < -45) {
    const f = -d
    if (f < 3600) return `in ${Math.round(f / 60)} min`
    if (f < 86400) return `in ${Math.round(f / 3600)} h`
    if (f < 2 * 86400) return 'tomorrow'
    return `in ${Math.round(f / 86400)} days`
  }
  if (d < 45) return 'just now'
  if (d < 3600) return `${Math.round(d / 60)} min ago`
  if (d < 86400) return `${Math.round(d / 3600)} h ago`
  if (d < 2 * 86400) return 'yesterday'
  return `${Math.round(d / 86400)} days ago`
}

export const fmtInt = (n) => (n ?? 0).toLocaleString()
export function fmtCompact(n) {
  if (n == null) return '—'
  if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B'
  if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M'
  if (n >= 1e4) return Math.round(n / 1e3) + 'k'
  return n.toLocaleString()
}

export function downloadCSV(name, header, rows) {
  const esc = (v) => { const s = String(v ?? ''); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s }
  const csv = [header, ...rows].map(r => r.map(esc).join(',')).join('\n')
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}

// Small inline SVG trend for a stat tile.
export function Trend({ values, state = 'acc', width = 140, height = 44, label }) {
  if (!values || values.length < 2) return null
  const max = Math.max(...values), min = Math.min(...values)
  const span = max - min || 1
  const pts = values.map((v, i) => `${(i / (values.length - 1)) * width},${height - 4 - ((v - min) / span) * (height - 8)}`).join(' ')
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      <polyline points={pts} fill="none" stroke={`var(--${state})`} strokeWidth="2" strokeLinejoin="round"/>
    </svg>
  )
}

// ── Explorer parts ────────────────────────────────────────────────────────────
// Count-over-time bars, stacked by a key (e.g. severity), like the timeline above a log or notable list.
// items: [{ t: Date|iso, k: stackKey, n?: weight (default 1) }]; stacks: [{ k, color, label }] bottom → top.
export function Histogram({ items, stacks, from, to, buckets = 60, height = 72, onRange, label = 'events' }) {
  const lo = from ? new Date(from).getTime() : Math.min(...items.map(i => new Date(i.t).getTime()))
  const hi = to ? new Date(to).getTime() : Date.now()
  const span = Math.max(1, hi - lo)
  const bins = Array.from({ length: buckets }, () => ({}))
  for (const it of items) {
    const t = new Date(it.t).getTime()
    if (!(t >= lo && t <= hi)) continue
    const b = Math.min(buckets - 1, Math.floor(((t - lo) / span) * buckets))
    bins[b][it.k] = (bins[b][it.k] || 0) + (it.n || 1)
  }
  const tot = bins.map(b => Object.values(b).reduce((s, n) => s + n, 0))
  const max = Math.max(1, ...tot)
  const fmt = (ms) => new Date(ms).toLocaleString([], span > 2 * 86400e3 ? { month: 'short', day: 'numeric' } : { hour: '2-digit', minute: '2-digit' })
  const w = 100 / buckets
  return (
    <div>
      <svg width="100%" height={height} viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" role="img" aria-label={`${tot.reduce((a, b) => a + b, 0)} ${label} over time`} style={{ display: 'block' }}>
        <line x1="0" x2="100" y1={height - 0.5} y2={height - 0.5} stroke="var(--line)" vectorEffect="non-scaling-stroke"/>
        {bins.map((b, i) => {
          let y = height
          return (
            <g key={i} style={{ cursor: onRange ? 'pointer' : undefined }} onClick={onRange ? () => onRange(new Date(lo + (span / buckets) * i), new Date(lo + (span / buckets) * (i + 1))) : undefined}>
              <title>{`${fmt(lo + (span / buckets) * i)} · ${tot[i]} ${label}`}</title>
              <rect x={i * w} y={0} width={w} height={height} fill="transparent"/>
              {stacks.map(s => {
                const n = b[s.k] || 0
                if (!n) return null
                const h = (n / max) * (height - 4)
                y -= h
                return <rect key={s.k} x={i * w + w * 0.12} y={y} width={w * 0.76} height={h} fill={s.color} rx="0.3"/>
              })}
            </g>
          )
        })}
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--t3)', marginTop: 4 }}>
        <span>{fmt(lo)}</span><span>{fmt(lo + span / 2)}</span><span>{fmt(hi)}</span>
      </div>
    </div>
  )
}

// Right-hand detail panel over the page, resizable, closes on Escape.
export function Drawer({ open, onClose, width = 620, children, label = 'Details' }) {
  const [w, setW] = useState(() => { try { return parseInt(localStorage.getItem('ow_drawer_w'), 10) || width } catch { return width } })
  useEffect(() => {
    if (!open) return
    const h = (e) => { if (e.key === 'Escape' && !/input|textarea|select/i.test(document.activeElement?.tagName || '')) onClose() }
    window.addEventListener('keydown', h); return () => window.removeEventListener('keydown', h)
  }, [open, onClose])
  useEffect(() => { try { localStorage.setItem('ow_drawer_w', String(w)) } catch { /* */ } }, [w])
  if (!open) return null
  const startDrag = (e) => {
    e.preventDefault()
    const x0 = e.clientX, w0 = w
    const mv = (ev) => setW(Math.max(420, Math.min(window.innerWidth - 320, w0 - (ev.clientX - x0))))
    const up = () => { window.removeEventListener('mousemove', mv); window.removeEventListener('mouseup', up); document.body.style.userSelect = '' }
    document.body.style.userSelect = 'none'
    window.addEventListener('mousemove', mv); window.addEventListener('mouseup', up)
  }
  return (
    <aside className="ow-drawer" role="dialog" aria-label={label} style={{ width: w }}>
      <div className="ow-drawer-grip" onMouseDown={startDrag} aria-hidden="true"/>
      {children}
    </aside>
  )
}

// Command bar shown over a list while rows are selected (Checkmk "commands", Splunk "edit selected").
export function SelectionBar({ count, total, allMatching, onSelectAllMatching, onClear, children }) {
  if (!count) return null
  return (
    <div className="ow-selbar" role="toolbar" aria-label="Actions on selected rows">
      <span style={{ fontWeight: 600 }}>{count.toLocaleString()} selected</span>
      {onSelectAllMatching && !allMatching && total > count && <button className="ow-btn quiet" style={{ height: 26, color: 'var(--acc)' }} onClick={onSelectAllMatching}>Select all {total.toLocaleString()} matching</button>}
      <span style={{ display: 'flex', gap: 6, marginLeft: 8 }}>{children}</span>
      <button className="ow-btn quiet" style={{ marginLeft: 'auto', height: 26 }} onClick={onClear}>Clear selection</button>
    </div>
  )
}

export function Section({ title, sub, actions, children, pad = true, style }) {
  return (
    <section className="ow-card" style={{ overflow: 'hidden', ...style }}>
      {(title || actions) && (
        <div className="ow-card-bar">
          {title && <span style={{ fontWeight: 600 }}>{title}</span>}
          {sub && <span className="t3" style={{ fontSize: 12 }}>{sub}</span>}
          {actions && <span style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>{actions}</span>}
        </div>
      )}
      <div style={pad ? { padding: 14 } : undefined}>{children}</div>
    </section>
  )
}

export function Check({ checked, indeterminate, onChange, label }) {
  return (
    <input type="checkbox" className="ow-check" aria-label={label} checked={!!checked}
      ref={el => { if (el) el.indeterminate = !!indeterminate }}
      onClick={e => e.stopPropagation()} onChange={e => onChange(e.target.checked)}/>
  )
}

export const SEV_COLORS = { 5: 'var(--crit)', 4: 'var(--warn)', 3: 'var(--acc)', 2: 'var(--t3)', 1: 'var(--line2)' }
export const SEV_STACKS = [1, 2, 3, 4, 5].map(k => ({ k, color: SEV_COLORS[k], label: SEV_WORD[k] }))

// A modal for commands that need input (assign, close with comment).
export function Dialog({ title, onClose, children, footer, width = 460 }) {
  useEffect(() => {
    const h = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h); return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="ow-palette-back" style={{ paddingTop: '14vh' }} onMouseDown={onClose}>
      <div className="ow-palette" role="dialog" aria-modal="true" aria-label={title} style={{ width: `min(${width}px, 92vw)` }} onMouseDown={e => e.stopPropagation()}>
        <div className="ow-card-bar" style={{ minHeight: 48 }}><span style={{ fontWeight: 600, fontSize: 14 }}>{title}</span>
          <button className="ow-btn quiet" style={{ marginLeft: 'auto', height: 26 }} onClick={onClose} aria-label="Close">Esc</button></div>
        <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>{children}</div>
        {footer && <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', padding: '12px 16px', borderTop: '1px solid var(--line)' }}>{footer}</div>}
      </div>
    </div>
  )
}

export function Field({ label, children, hint }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <span style={{ fontSize: 12, color: 'var(--t2)', fontWeight: 500 }}>{label}</span>
      {children}
      {hint && <span style={{ fontSize: 11.5, color: 'var(--t3)' }}>{hint}</span>}
    </label>
  )
}
