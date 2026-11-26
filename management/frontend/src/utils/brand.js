// Fixed brand colours: the only hex values allowed in components (scripts/check-colours.mjs skips this file).
// Everything that follows the theme uses tokens from index.css instead.

// The mark: the shard eye. Two obsidian blades form the eyelids; the pupil is a cut gem.
// Drawn on a 24-unit grid; the same shapes are in public/favicon.svg and src/assets/logo.svg.
export const MARK = { shard: '#5b3df5', facet: '#8f76ff', crown: '#a896ff', eye: '#13101f', pupil: '#d9d0ff', deep: '#3b22c4' }
export const MARK_SHAPES = [
  { d: 'M1 12C6 4.2 18 4.2 23 12C17 8.4 7 8.4 1 12Z', fill: MARK.facet },        // upper blade
  { d: 'M1 12C6 4.2 12 4.6 12 4.6C12 6.6 7 8.4 1 12Z', fill: MARK.shard },       // upper blade, shaded facet
  { d: 'M1 12C6 19.8 18 19.8 23 12C17 15.6 7 15.6 1 12Z', fill: MARK.shard },     // lower blade
  { d: 'M23 12C18 19.8 12 19.4 12 19.4C12 17.4 17 15.6 23 12Z', fill: MARK.deep }, // lower blade, shaded facet
  { d: 'M12 8.7 15.2 12 12 15.3 8.8 12Z', fill: MARK.pupil },                     // gem pupil
  { d: 'M12 8.7 15.2 12 12 15.3Z', fill: MARK.crown },                            // gem, lit facet
]

// Chrome: rail and context bar, identical in both themes (mirrors --ch-* in index.css).
export const CHROME = { bg: '#13101f', deep: '#0d0b18', line: '#2b2643', t1: '#f3f0fd', t2: '#b6afd3', t3: '#8b85a9', acc: '#a896ff' }

// Terminals stay dark in both themes, like any shell.
export const TERMINAL_THEME = {
  background: '#0d0b16', foreground: '#e7e4f2', cursor: '#a896ff', cursorAccent: '#0d0b16',
  selectionBackground: 'rgba(168,150,255,0.30)',
  black: '#1d1a2b', red: '#ff6369', green: '#3dd68c', yellow: '#f5bd45', blue: '#5ca8ff', magenta: '#a896ff', cyan: '#3cc8dc', white: '#e7e4f2',
  brightBlack: '#6f6a86', brightRed: '#ff8a8f', brightGreen: '#6ee7ab', brightYellow: '#ffd27a', brightBlue: '#8cc2ff', brightMagenta: '#c4b8ff', brightCyan: '#7fdcea', brightWhite: '#ffffff',
}
export const TERMINAL_FONT = '"JetBrains Mono", ui-monospace, Menlo, monospace'

// Sign-in stage: the animated network behind the sign-in form (always on the obsidian background).
export const STAGE = {
  bg: '#0b0915',
  endpoint: [168, 150, 255],   // violet
  server: [47, 199, 174],      // teal
  threat: [255, 99, 105],      // red
  packet: [243, 240, 253],
}
