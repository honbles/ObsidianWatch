// Application Monitoring API client. Owned by the Application build.
import api from './client'

const r = (range) => ({ from: range.from, to: range.to })
const get = (url, params) => api.get(url, { params }).then(x => x.data)

// "name|environment" is the alert-entity key of a service.
export const appKey = (name, env) => `${name}|${env}`
export const appSplitKey = (key) => {
  const i = key.lastIndexOf('|')
  return i < 0 ? { name: key, environment: 'default' } : { name: key.slice(0, i), environment: key.slice(i + 1) }
}

export const appApi = {
  overview: (range) => get('/api/v1/app/overview', r(range)),
  map: (range) => get('/api/v1/app/map', r(range)),
  services: (range, extra = {}) => get('/api/v1/app/services', { ...r(range), ...extra }),
  service: (id) => get(`/api/v1/app/services/${id}`),
  red: (id, range, extra = {}) => get(`/api/v1/app/services/${id}/red`, { ...r(range), ...extra }),
  routes: (id, range) => get(`/api/v1/app/services/${id}/routes`, r(range)),
  edges: (id, range) => get(`/api/v1/app/services/${id}/edges`, r(range)),
  timeline: (id, range, extra = {}) => get(`/api/v1/app/services/${id}/timeline`, { ...r(range), ...extra }),
  runtime: (id, range, extra = {}) => get(`/api/v1/app/services/${id}/runtime`, { ...r(range), ...extra }),
  alerts: (id, state = 'open') => get(`/api/v1/app/services/${id}/alerts`, { state }),
  events: (id, range, extra = {}) => get(`/api/v1/app/services/${id}/events`, { ...r(range), ...extra }),
  traces: (range, extra = {}) => get('/api/v1/app/traces', { ...r(range), ...extra }),
  trace: (traceId) => get(`/api/v1/app/traces/${encodeURIComponent(traceId)}`),
  instance: (id) => get(`/api/v1/app/instances/${id}`),
  saveSettings: (id, body) => api.put(`/api/v1/app/services/${id}/settings`, body).then(x => x.data),
  savePayloadPolicy: (id, body) => api.put(`/api/v1/app/services/${id}/payload-policy`, body).then(x => x.data),
  revokePayloadPolicy: (id, route, method) => api.delete(`/api/v1/app/services/${id}/payload-policy`, { params: { route, method } }).then(x => x.data),
  openapi: (id) => get(`/api/v1/app/services/${id}/openapi`),
  loadOpenapi: (id, body) => api.post(`/api/v1/app/services/${id}/openapi`, body).then(x => x.data),
  removeOpenapi: (id) => api.delete(`/api/v1/app/services/${id}/openapi`).then(x => x.data),
  payloads: (id, range, extra = {}) => get(`/api/v1/app/services/${id}/payloads`, { ...r(range), ...extra }),
  ruleMeta: () => get('/api/v1/rules/meta'),
  ruleStatus: () => get('/api/v1/app/rules/status'),
}

// Resolve a route param (numeric id or "name|environment") to a service row.
export async function appResolveService(param) {
  if (/^\d+$/.test(param)) return (await appApi.service(param)).service
  const { name, environment } = appSplitKey(param)
  const to = new Date(), from = new Date(to.getTime() - 90 * 86400e3)
  const { services } = await appApi.services({ from: from.toISOString(), to: to.toISOString() }, { q: name, environment, limit: 50 })
  return (services || []).find(s => s.name === name && s.environment === environment) || null
}
