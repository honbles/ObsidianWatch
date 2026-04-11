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
      },
      fontFamily: {
        sans: ['Sora', 'system-ui', 'sans-serif'],
        mono: ['DM Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
