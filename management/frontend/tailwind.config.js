/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        siem: {
          bg:      'var(--bg)',
          surface: 'var(--surface)',
          surface2:'var(--surface2)',
          surface3:'var(--surface3)',
          border:  'var(--border)',
          border2: 'var(--border2)',
          text:    'var(--text)',
          muted:   'var(--text2)',
          muted2:  'var(--text3)',
          accent:  'var(--accent)',
          accent2: 'var(--accent2)',
          green:   'var(--green)',
          yellow:  'var(--yellow)',
          orange:  'var(--orange)',
          red:     'var(--red)',
        },
        // design-system tokens (see src/index.css)
        ow: {
          bg: 'var(--bg)', s1: 'var(--s1)', s2: 'var(--s2)', s3: 'var(--s3)',
          line: 'var(--line)', line2: 'var(--line2)',
          t1: 'var(--t1)', t2: 'var(--t2)', t3: 'var(--t3)',
          acc: 'var(--acc)', ok: 'var(--ok)', warn: 'var(--warn)', crit: 'var(--crit)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
}
