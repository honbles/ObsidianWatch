// Shared time-range hook. Both builds read/write the same URL shape:
//   ?from=<ISO>&to=<ISO>   (absent => last 24h, rolling)
import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'

export const RANGE_PRESETS = [
  { key: '1h', label: '1h', ms: 3600e3 },
  { key: '6h', label: '6h', ms: 6 * 3600e3 },
  { key: '24h', label: '24h', ms: 24 * 3600e3 },
  { key: '7d', label: '7d', ms: 7 * 86400e3 },
  { key: '30d', label: '30d', ms: 30 * 86400e3 },
]

export function useTimeRange(defaultMs = 24 * 3600e3) {
  const [params, setParams] = useSearchParams()
  const fromQ = params.get('from')
  const toQ = params.get('to')
  const range = useMemo(() => {
    const to = toQ ? new Date(toQ) : new Date()
    const from = fromQ ? new Date(fromQ) : new Date(to.getTime() - defaultMs)
    return { from: from.toISOString(), to: to.toISOString(), absolute: !!(fromQ || toQ) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fromQ, toQ, defaultMs])
  const setRange = useCallback((from, to) => {
    const next = new URLSearchParams(params)
    if (from) next.set('from', from); else next.delete('from')
    if (to) next.set('to', to); else next.delete('to')
    setParams(next, { replace: true })
  }, [params, setParams])
  const setPreset = useCallback((ms) => {
    const to = new Date()
    setRange(new Date(to.getTime() - ms).toISOString(), to.toISOString())
  }, [setRange])
  return { ...range, setRange, setPreset }
}

// Query-string helper for API calls: {from,to} -> {from,to}
export const rangeParams = (r) => ({ from: r.from, to: r.to })
