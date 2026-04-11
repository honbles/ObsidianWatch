import { useState, useEffect, createContext, useContext, createElement } from 'react'

const ThemeCtx = createContext(null)

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(() => localStorage.getItem('ow-theme') || 'dark')

  useEffect(() => {
    document.documentElement.classList.toggle('light', theme === 'light')
    localStorage.setItem('ow-theme', theme)
  }, [theme])

  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  return createElement(ThemeCtx.Provider, { value: { theme, toggle } }, children)
}

export const useTheme = () => useContext(ThemeCtx)
