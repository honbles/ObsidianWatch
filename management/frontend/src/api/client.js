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
