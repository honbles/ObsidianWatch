import React from 'react'
import { useLocation } from 'react-router-dom'

// Catches render errors in a page so one broken view does not blank the whole
// app (navigation and layout stay usable). Resets when the route changes.
class Boundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(error) { return { error } }
  componentDidCatch(error, info) { console.error('Page crashed:', error, info?.componentStack) }
  render() {
    if (!this.state.error) return this.props.children
    return (
      <div className="p-8 max-w-xl">
        <div className="text-lg font-semibold text-siem-text mb-2">This page hit an error</div>
        <div className="text-sm text-siem-muted mb-4">
          The rest of the console still works. Try again, or open another page.
        </div>
        <pre className="text-xs text-red-400 bg-siem-surface border border-siem-border rounded-lg p-3 overflow-auto max-h-40 mb-4">
          {String(this.state.error?.message || this.state.error)}
        </pre>
        <button className="text-xs border border-siem-border rounded-lg px-3 py-1.5 text-siem-muted hover:text-siem-text"
          onClick={() => this.setState({ error: null })}>Try again</button>
      </div>
    )
  }
}

export default function ErrorBoundary({ children }) {
  const { pathname } = useLocation()
  return <Boundary key={pathname}>{children}</Boundary>
}
