import { useState, useEffect, createContext, useContext, createElement } from 'react'

const ThemeCtx = createContext(null)

// Saved choice first; on a first visit, the operating system's preference (public/theme-init.js applies the
// same rule before the first paint).
function initialTheme() {
  try {
    const t = localStorage.getItem('ow-theme')
    if (t === 'light' || t === 'dark') return t
    return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  } catch { return 'dark' }
}

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(initialTheme)

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light')
    try { localStorage.setItem('ow-theme', theme) } catch { /* storage unavailable */ }
  }, [theme])

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  return createElement(ThemeCtx.Provider, { value: { theme, toggle } }, children)
}

export const useTheme = () => useContext(ThemeCtx)
