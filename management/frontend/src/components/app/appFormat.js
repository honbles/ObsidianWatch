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
export const appLearningText = (l, tier) =>
  tier === 0 ? 'Host only: no request telemetry, so no request baseline. Host rules learn from connections.'
    : l.state === 'ready' ? 'Baseline ready'
    : l.state === 'low_traffic' ? `Learning, low traffic (${appInt(l.requests)} of ${appInt(APP_LEARN_REQUESTS)} requests)`
      : `Learning: day ${Math.min(l.days + 1, APP_LEARN_DAYS)} of ${APP_LEARN_DAYS}, ${appInt(l.requests)} of ${appInt(APP_LEARN_REQUESTS)} requests`

export const appIsAdmin = () => {
  try { return JSON.parse(localStorage.getItem('user'))?.role === 'admin' } catch { return false }
}

// Per-route review page: /applications/services/<name|env>/routes/<METHOD>/<route without the leading slash>
export const appReviewPath = (service, method, route) =>
  `/applications/services/${encodeURIComponent(`${service.name}|${service.environment}`)}/routes/${encodeURIComponent(method)}/${String(route).replace(/^\//, '').split('/').map(encodeURIComponent).join('/')}`
// Route key of an alert or entity ("name|env|METHOD /route") to the review page of that route
export const appReviewPathFromKey = (key) => {
  const first = String(key || '').indexOf('|'), second = String(key || '').indexOf('|', first + 1)
  if (first < 0 || second < 0) return null
  const m = String(key).slice(second + 1).match(/^([A-Z*]+) (\/.*)$/)
  if (!m || m[1] === '*') return null
  return appReviewPath({ name: key.slice(0, first), environment: key.slice(first + 1, second) }, m[1], m[2])
}
// "GET /rest/products/search" (a trace's root request) to {method, route}
export const appSplitRequest = (s) => {
  const m = String(s || '').match(/^([A-Z]+) (\/\S*)/)
  return m ? { method: m[1], route: m[2] } : null
}
