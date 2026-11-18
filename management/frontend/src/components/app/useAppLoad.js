import { useEffect, useState } from 'react'

// Run an async loader whenever deps change; ignores results from stale runs.
// Returns { data, loading, error, reload }.
export default function useAppLoad(fn, deps, enabled = true) {
  const [s, setS] = useState({ data: null, loading: enabled, error: null })
  const [tick, setTick] = useState(0)
  useEffect(() => {
    if (!enabled) { setS({ data: null, loading: false, error: null }); return }
    let live = true
    setS(v => ({ ...v, loading: true, error: null }))
    Promise.resolve().then(fn)
      .then(d => live && setS({ data: d, loading: false, error: null }))
      .catch(e => live && setS({ data: null, loading: false, error: e.response?.data?.error || e.message || 'Request failed' }))
    return () => { live = false }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled, tick])
  return { ...s, reload: () => setTick(t => t + 1) }
}
