// Formatting helpers for the Applications section. Owned by the Application build.
import { formatDistanceToNow } from 'date-fns'

export const appInt = (n) => (n == null ? '-' : Number(n).toLocaleString())
export const appPct = (x, digits = 1) => (x == null ? '-' : `${(x * 100).toFixed(x > 0 && x < 0.001 ? 2 : digits)}%`)
export const appMs = (ms, over) => {
  if (ms == null || ms === 0) return '-'
  const t = ms >= 1000 ? `${(ms / 1000).toFixed(ms >= 10000 ? 0 : 1)} s` : `${Math.round(ms)} ms`
  return over ? `>${t}` : t
}
export const appRel = (iso) => {
  if (!iso) return '-'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) || d.getFullYear() < 1980 ? '-' : formatDistanceToNow(d, { addSuffix: true })
}
export const appTime = (iso) => (iso ? new Date(iso).toLocaleString() : '-')

// Learning: a first-seen rule leaves learning after both >= 7 days and >= 1000 requests (spec 10.1, defaults).
export const APP_LEARN_DAYS = 7
export const APP_LEARN_REQUESTS = 1000
export function appLearning(firstSeenIso, learningStartedIso, requests) {
  const start = new Date(learningStartedIso || firstSeenIso)
  const days = Math.max(0, Math.floor((Date.now() - start.getTime()) / 86400e3))
  const reqs = requests || 0
  const daysOk = days >= APP_LEARN_DAYS, reqOk = reqs >= APP_LEARN_REQUESTS
  let state = 'learning'
  if (daysOk && reqOk) state = 'ready'
  else if (daysOk && !reqOk) state = 'low_traffic'
  return { days, requests: reqs, state, daysOk, reqOk }
}
export const appLearningText = (l) =>
  l.state === 'ready' ? 'Baseline ready'
    : l.state === 'low_traffic' ? `Learning, low traffic (${appInt(l.requests)} of ${appInt(APP_LEARN_REQUESTS)} requests)`
      : `Learning: day ${Math.min(l.days + 1, APP_LEARN_DAYS)} of ${APP_LEARN_DAYS}, ${appInt(l.requests)} of ${appInt(APP_LEARN_REQUESTS)} requests`

export const appIsAdmin = () => {
  try { return JSON.parse(localStorage.getItem('user'))?.role === 'admin' } catch { return false }
}
