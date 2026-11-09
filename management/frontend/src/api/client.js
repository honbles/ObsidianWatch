import axios from 'axios'

const api = axios.create({ baseURL: '' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      // Don't logout for non-critical endpoints
      const url = err.config?.url || ''
      const skipLogout = ['/api/v1/ai/'].some(p => url.includes(p))
      if (!skipLogout) {
        localStorage.removeItem('token')
        localStorage.removeItem('user')
        window.location.href = '/login'
      }
    }
    return Promise.reject(err)
  }
)

export default api

// Short-lived single-use ticket for opening a WebSocket (browsers cannot set an
// Authorization header, and the JWT must not be placed in the URL).
export async function getWSTicket() {
  const r = await api.post('/auth/ws-ticket')
  return r.data.ticket
}

// G-45: run a long scan as a background job and poll until it finishes, so
// no HTTP request is held open for minutes. Resolves like api.post would
// ({ data }), and rejects with the scan's error.
export async function runScan(url, { intervalMs = 2000, maxWaitMs = 12 * 60 * 1000 } = {}) {
  const start = await api.post(url + (url.includes('?') ? '&' : '?') + 'async=1')
  const jobId = start.data?.job_id
  if (!jobId) return start // older server: synchronous result
  const deadline = Date.now() + maxWaitMs
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, intervalMs))
    const { data } = await api.get(`/api/v1/jobs/${jobId}`)
    if (data.status === 'done') return { data: data.result }
    if (data.status === 'failed') {
      let msg = data.error
      try { msg = JSON.parse(data.error).error || msg } catch { /* keep raw */ }
      const err = new Error(msg || 'scan failed')
      err.response = { data: { error: msg } }
      throw err
    }
  }
  throw new Error('scan timed out')
}
