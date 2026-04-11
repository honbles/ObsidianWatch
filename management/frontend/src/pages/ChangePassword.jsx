import { useState } from 'react'
import { KeyRound, ShieldAlert } from 'lucide-react'
import api from '../api/client'

export default function ChangePassword({ onChanged }) {
  const isForced = localStorage.getItem('require_password_change') === 'true'
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (next !== confirm) { setError('Passwords do not match'); return }
    if (next.length < 8) { setError('Password must be at least 8 characters'); return }
    setLoading(true)
    try {
      await api.patch('/auth/password', { current_password: current, new_password: next })
      setDone(true)
      setTimeout(() => onChanged && onChanged(), 1500)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to change password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-md">
      {isForced && (
        <div className="flex items-start gap-3 bg-yellow-900/20 border border-yellow-700/40 rounded-xl p-4 mb-6">
          <ShieldAlert className="text-yellow-400 shrink-0 mt-0.5" size={18} />
          <div>
            <div className="text-yellow-400 text-sm font-medium">Password change required</div>
            <div className="text-yellow-400/70 text-xs mt-0.5">You are using the default password. Please set a new password before continuing.</div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2 mb-6">
        <KeyRound className="text-siem-accent" size={20} />
        <h1 className="text-xl font-bold text-siem-text">Change Password</h1>
      </div>

      <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
        {done ? (
          <div className="text-center py-4">
            <div className="text-siem-green text-sm font-medium mb-1">Password changed successfully</div>
            <div className="text-siem-muted text-xs">Redirecting...</div>
          </div>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs text-siem-muted mb-1.5">Current password</label>
              <input type="password"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                value={current} onChange={e => setCurrent(e.target.value)} required
              />
            </div>
            <div>
              <label className="block text-xs text-siem-muted mb-1.5">New password</label>
              <input type="password"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                value={next} onChange={e => setNext(e.target.value)} required minLength={8}
              />
              <div className="text-xs text-siem-muted/60 mt-1">Minimum 8 characters</div>
            </div>
            <div>
              <label className="block text-xs text-siem-muted mb-1.5">Confirm new password</label>
              <input type="password"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2.5 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                value={confirm} onChange={e => setConfirm(e.target.value)} required
              />
            </div>
            {error && <div className="text-siem-red text-xs">{error}</div>}
            <button
              type="submit" disabled={loading}
              className="w-full bg-siem-accent hover:bg-siem-accent/90 text-white text-sm font-medium py-2.5 rounded-lg transition-colors disabled:opacity-50"
            >
              {loading ? 'Updating...' : 'Update password'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
