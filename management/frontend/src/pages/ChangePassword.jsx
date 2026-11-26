import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldAlert, CheckCircle2, AlertCircle } from 'lucide-react'
import { PageHeader } from '../components/ui'
import api from '../api/client'

export default function ChangePassword({ onChanged }) {
  const navigate = useNavigate()
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
    if (next.length < 10) { setError('Password must be at least 10 characters'); return }
    setLoading(true)
    try {
      const res = await api.patch('/auth/password', { current_password: current, new_password: next })
      // Server ends all other sessions on a password change and returns a fresh token for this one.
      if (res.data?.token) { try { localStorage.setItem('token', res.data.token) } catch { /* storage unavailable */ } }
      setDone(true)
      setTimeout(() => { onChanged && onChanged(); navigate('/') }, 1500)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to change password')
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <PageHeader title="Change password" sub="Changing your password signs out your other sessions."/>
      <div className="ow-body" style={{ maxWidth: 480 }}>
        {isForced && (
          <div className="pw-forced">
            <ShieldAlert size={18}/>
            <div><b>Password change required</b><span>You are using the default password. Set a new one before you continue.</span></div>
          </div>
        )}
        <div className="ow-card" style={{ padding: '18px 20px 20px' }}>
          {done ? (
            <div className="pw-done"><CheckCircle2 size={18}/><div><b>Password changed</b><span>Taking you back…</span></div></div>
          ) : (
            <form onSubmit={submit} className="auth-form" style={{ marginTop: 0 }}>
              <label className="auth-label" htmlFor="pw-cur">Current password</label>
              <input id="pw-cur" type="password" className="input auth-input" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="current-password" required/>
              <label className="auth-label" htmlFor="pw-new">New password</label>
              <input id="pw-new" type="password" className="input auth-input" value={next} onChange={e => setNext(e.target.value)} autoComplete="new-password" required minLength={10}/>
              <div className="setup-note" style={{ marginTop: 6 }}>At least 10 characters.</div>
              <label className="auth-label" htmlFor="pw-conf">Confirm new password</label>
              <input id="pw-conf" type="password" className="input auth-input" value={confirm} onChange={e => setConfirm(e.target.value)} autoComplete="new-password" required/>
              {error && <div className="auth-error" role="alert"><AlertCircle size={15}/><span>{error}</span></div>}
              <button type="submit" disabled={loading} className="ow-btn primary auth-submit">
                {loading ? <><span className="ow-spin" aria-hidden="true"/>Updating…</> : 'Update password'}
              </button>
            </form>
          )}
        </div>
      </div>
    </>
  )
}
