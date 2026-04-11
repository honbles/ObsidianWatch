import { useEffect, useState } from 'react'
import { Users as UsersIcon, Plus, Trash2, ShieldCheck, User } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

export default function Users() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'analyst' })
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/users')
      setUsers(data.users || [])
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const create = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.post('/api/v1/users', form)
      setShowCreate(false)
      setForm({ username: '', password: '', role: 'analyst' })
      load()
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create user')
    }
  }

  const del = async (id, username) => {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return
    await api.delete(`/api/v1/users/${id}`)
    load()
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <UsersIcon className="text-siem-accent" size={20} />
          <h1 className="text-xl font-bold text-siem-text">User Management</h1>
        </div>
        <button onClick={() => setShowCreate(s => !s)}
          className="flex items-center gap-1.5 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-2 rounded-lg">
          <Plus size={13} /> New user
        </button>
      </div>

      {showCreate && (
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="text-sm font-medium text-siem-text mb-3">Create user</div>
          <form onSubmit={create} className="grid grid-cols-3 gap-3">
            <input className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
              placeholder="Username" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required />
            <input type="password" className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
              placeholder="Password (min 8 chars)" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required minLength={8} />
            <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
              value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
              <option value="analyst">Analyst</option>
              <option value="admin">Admin</option>
            </select>
            {error && <div className="col-span-3 text-siem-red text-xs">{error}</div>}
            <div className="col-span-3 flex gap-2">
              <button type="submit" className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-4 py-2 rounded-lg">Create</button>
              <button type="button" onClick={() => setShowCreate(false)} className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-4 py-2">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-siem-border text-siem-muted text-xs">
              <th className="text-left px-4 py-3">User</th>
              <th className="text-left px-4 py-3">Role</th>
              <th className="text-left px-4 py-3">Created</th>
              <th className="text-left px-4 py-3">Last login</th>
              <th className="text-left px-4 py-3">Password</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-10 text-siem-muted">Loading...</td></tr>
            ) : users.map(u => (
              <tr key={u.id} className="border-b border-siem-border/40">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="bg-siem-accent/10 rounded-full p-1.5">
                      {u.role === 'admin' ? <ShieldCheck size={12} className="text-siem-accent" /> : <User size={12} className="text-siem-muted" />}
                    </div>
                    <span className="text-siem-text font-medium">{u.username}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${
                    u.role === 'admin' ? 'bg-siem-accent/10 border-siem-accent/30 text-siem-accent' : 'bg-siem-border/30 border-siem-border text-siem-muted'
                  }`}>{u.role}</span>
                </td>
                <td className="px-4 py-3 text-siem-muted text-xs">{format(new Date(u.created_at), 'dd MMM yyyy')}</td>
                <td className="px-4 py-3 text-siem-muted text-xs">{u.last_login ? format(new Date(u.last_login), 'dd MMM yyyy HH:mm') : 'Never'}</td>
                <td className="px-4 py-3">
                  {u.password_changed
                    ? <span className="text-xs text-siem-green">Changed</span>
                    : <span className="text-xs text-yellow-400">Default</span>}
                </td>
                <td className="px-4 py-3">
                  {u.username !== 'admin' && (
                    <button onClick={() => del(u.id, u.username)} className="text-siem-muted hover:text-siem-red transition-colors">
                      <Trash2 size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
