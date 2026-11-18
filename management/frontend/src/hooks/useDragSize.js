import { useState, useRef, useCallback, useEffect } from 'react'

// Drag-to-resize state, persisted per key. axis 'x' measures from the left edge of the
// element the handle belongs to (or the right edge when `reverse`); axis 'y' from the bottom.
// Returns [size, handleProps]. Spread handleProps on a thin element placed on the divider.
export function useDragSize(key, initial, min, max, axis = 'x', reverse = false) {
  const [size, setSize] = useState(() => {
    try { const v = parseInt(localStorage.getItem('ow_size_' + key), 10); if (v >= min && v <= max) return v } catch { /* */ }
    return initial
  })
  const drag = useRef(null)
  const onMove = useCallback((e) => {
    const d = drag.current; if (!d) return
    const delta = (axis === 'x' ? e.clientX - d.x : e.clientY - d.y) * (reverse ? -1 : 1)
    setSize(Math.max(min, Math.min(max, d.start + delta)))
  }, [axis, reverse, min, max])
  const stop = useCallback(() => {
    if (!drag.current) return
    drag.current = null
    document.body.style.userSelect = ''; document.body.style.cursor = ''
  }, [])
  useEffect(() => {
    window.addEventListener('mousemove', onMove); window.addEventListener('mouseup', stop)
    return () => { window.removeEventListener('mousemove', onMove); window.removeEventListener('mouseup', stop) }
  }, [onMove, stop])
  useEffect(() => { try { localStorage.setItem('ow_size_' + key, String(size)) } catch { /* */ } }, [key, size])
  const handleProps = {
    className: `ow-resizer ow-resizer-${axis}`,
    onMouseDown: (e) => {
      e.preventDefault()
      drag.current = { x: e.clientX, y: e.clientY, start: size }
      document.body.style.userSelect = 'none'; document.body.style.cursor = axis === 'x' ? 'col-resize' : 'row-resize'
    },
    onDoubleClick: () => setSize(initial),
    title: 'Drag to resize, double-click to reset',
  }
  return [size, handleProps]
}
