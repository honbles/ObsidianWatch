// Display size. The console is drawn at a scale (--ui-zoom in index.css): Compact 1, Default 1.08, Large 1.16.
// public/theme-init.js applies the saved size before the first paint.
export const DISPLAY_SIZES = [
  { id: 'compact', label: 'Compact' },
  { id: 'default', label: 'Default' },
  { id: 'large', label: 'Large' },
]

export function getDisplaySize() {
  try { const v = localStorage.getItem('ow-display'); return DISPLAY_SIZES.some(d => d.id === v) ? v : 'default' } catch { return 'default' }
}

export function setDisplaySize(id) {
  const el = document.documentElement
  el.classList.remove('ds-compact', 'ds-large')
  if (id === 'compact' || id === 'large') el.classList.add('ds-' + id)
  try { localStorage.setItem('ow-display', id) } catch { /* storage unavailable */ }
}

// The current scale. Pointer positions (clientX, getBoundingClientRect) are in window pixels; divide by this
// to get the console's own pixels, for example when dragging a resize handle or hit-testing a canvas.
export function uiZoom() {
  const z = parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--ui-zoom'))
  return z > 0 ? z : 1
}
