// Fails the build when a component hard-codes a colour. Colours come from the theme tokens in
// src/index.css (var(--crit), var(--t2), the Tailwind palette mapped onto them) or, for the few fixed
// brand colours, from src/utils/brand.js. See docs/development/design-language.md.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const root = new URL('../src/', import.meta.url).pathname
const allowed = new Set(['utils/brand.js', 'index.css'])
const rules = [
  [/#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|#[0-9a-fA-F]{3}\b(?![-\w])/g, 'hex colour'],
  [/\brgba?\(\s*(?!0\s*,\s*0\s*,\s*0\s*[,)])(?!255\s*,\s*255\s*,\s*255\s*[,)])\d+\s*,/g, 'rgb() colour'],
  [/\bhsla?\(\s*\d/g, 'hsl() colour'],
]

const walk = (d) => readdirSync(d).flatMap(f => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p] })
const bad = []
for (const file of walk(root)) {
  const rel = relative(root, file)
  if (!/\.(jsx?|tsx?)$/.test(rel) || allowed.has(rel)) continue
  readFileSync(file, 'utf8').split('\n').forEach((line, i) => {
    if (/^\s*(\/\/|\*)/.test(line)) return
    for (const [re, what] of rules) for (const m of line.matchAll(re)) bad.push(`${rel}:${i + 1}: ${what} ${m[0]}`)
  })
}
if (bad.length) {
  console.error('Hard-coded colours (use a token from src/index.css, or src/utils/brand.js for fixed brand colours):\n  ' + bad.join('\n  '))
  process.exit(1)
}
console.log('check-colours: no hard-coded colours')
