/** @type {import('tailwindcss').Config} */
// The console has one palette: the tokens in src/index.css. Tailwind's colour names are rebuilt on top of
// them, so `text-red-400` is the critical colour and `bg-emerald-950/30` a tint of the OK colour, in both
// themes. Shades keep their intent: 50–600 the colour itself, 700–800 a border tone, 900–950 the base for
// tinted backgrounds (use them with an /alpha). Hues that are not in the brand fold onto the nearest token.
const tok = (v) => `rgb(var(${v}) / <alpha-value>)`

function hue(name) {
  const c = tok(`--${name}-c`), e = tok(`--${name}-e`), d = tok(`--${name}-d`)
  return { DEFAULT: c, 50: c, 100: c, 200: c, 300: c, 400: c, 500: c, 600: c, 700: e, 800: e, 900: d, 950: d }
}

const neutral = {
  DEFAULT: tok('--t2-c'),
  50: tok('--t1-c'), 100: tok('--t1-c'), 200: tok('--t1-c'), 300: tok('--t1-c'),
  400: tok('--t2-c'), 500: tok('--t3-c'), 600: tok('--t3-c'),
  700: tok('--line2-c'), 800: tok('--line-c'), 900: tok('--s2-c'), 950: tok('--bg-c'),
}

const crit = hue('crit'), high = hue('high'), warn = hue('warn'), ok = hue('ok'), info = hue('info')
const teal = hue('teal'), violet = hue('violet'), magenta = hue('magenta')

export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  darkMode: 'class',
  theme: {
    colors: {
      transparent: 'transparent', current: 'currentColor', inherit: 'inherit',
      white: '#ffffff', black: '#000000',
      gray: neutral, slate: neutral, zinc: neutral, neutral, stone: neutral,
      red: crit, rose: crit, orange: high, amber: warn, yellow: warn,
      green: ok, emerald: ok, lime: ok, teal, sky: info, blue: info,
      // cyan was the console's accent before the rebrand; it now means the brand accent
      cyan: violet,
      indigo: violet, violet, purple: violet, fuchsia: magenta, pink: magenta,
      // design-system names (see src/index.css)
      ow: {
        bg: tok('--bg-c'), s1: tok('--s1-c'), s2: tok('--s2-c'), s3: tok('--s3-c'),
        line: tok('--line-c'), line2: tok('--line2-c'),
        t1: tok('--t1-c'), t2: tok('--t2-c'), t3: tok('--t3-c'),
        acc: tok('--acc-c'), accf: tok('--accf-c'), brand: tok('--brand-c'),
        ok: tok('--ok-c'), warn: tok('--warn-c'), crit: tok('--crit-c'), high: tok('--high-c'), info: tok('--info-c'),
      },
      // older names, kept as aliases
      siem: {
        bg: tok('--bg-c'), surface: tok('--s1-c'), surface2: tok('--s2-c'), surface3: tok('--s3-c'),
        border: tok('--line-c'), border2: tok('--line2-c'),
        text: tok('--t1-c'), muted: tok('--t2-c'), muted2: tok('--t3-c'),
        accent: tok('--acc-c'), accent2: tok('--acc-c'),
        green: tok('--ok-c'), yellow: tok('--warn-c'), orange: tok('--high-c'), red: tok('--crit-c'),
      },
    },
    extend: {
      // Tailwind's defaults point at gray-200 / blue-500; pin them to the line and accent tokens.
      borderColor: { DEFAULT: tok('--line-c') },
      divideColor: { DEFAULT: tok('--line-c') },
      ringColor: { DEFAULT: tok('--acc-c') },
      fontFamily: {
        sans: ['IBM Plex Sans', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['IBM Plex Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
