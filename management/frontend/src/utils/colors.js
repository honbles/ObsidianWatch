// Colour helpers for components. Colours are theme tokens (var(--crit), var(--cat3)…), never hex.

// A see-through tint of any colour, hex or token: tint('var(--crit)', 15) for a 15% wash.
export const tint = (color, pct) => `color-mix(in srgb, ${color} ${pct}%, transparent)`

// Canvas cannot read CSS variables. Resolve a token (or any CSS colour) to a concrete value for the
// current theme; call it at draw time so a theme switch is picked up on the next draw.
let probe = null
const cache = new Map()
export function resolveColor(color) {
  if (typeof document === 'undefined' || !color || !String(color).includes('(')) return color
  const key = document.documentElement.className + '|' + color
  if (cache.has(key)) return cache.get(key)
  if (!probe) { probe = document.createElement('span'); probe.style.display = 'none'; document.body.appendChild(probe) }
  probe.style.color = ''
  probe.style.color = color
  const v = getComputedStyle(probe).color || color
  if (cache.size > 500) cache.clear()
  cache.set(key, v)
  return v
}

// Severity on the platform scale 5..1.
export const SEV_VAR = { 5: 'var(--sev5)', 4: 'var(--sev4)', 3: 'var(--sev3)', 2: 'var(--sev2)', 1: 'var(--sev1)' }

// Categorical series, in order of use. Charts take colours from here rather than inventing their own.
export const CAT = ['var(--cat1)', 'var(--cat2)', 'var(--cat3)', 'var(--cat4)', 'var(--cat5)', 'var(--cat6)', 'var(--cat7)', 'var(--cat8)']
