import { useEffect, useState } from 'react'
import { Trash2, Plus } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

// Analyst-supplied indicators (IP, domain, hash). They are matched exactly like
// feed indicators, and the platform also hunts the retained event history for
// each new one, so you can add a hash or IP after the fact and still get the alert.
export default function ManualIOCs() {
  const [rows, setRows] = useState([])
  const [type, setType] = useState('ip')
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [severity, setSeverity] = useState(4)
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => api.get('/api/v1/iocs/manual').then(r => setRows(r.data.indicators || [])).catch(() => setRows([]))
  useEffect(() => { load() }, [])

  const add = async e => {
    e.preventDefault()
    setBusy(true); setMsg('')
    try {
      await api.post('/api/v1/iocs/manual', { type, value, label, severity })
      setValue(''); setLabel('')
      setMsg('Added. Past events are being checked now; new matches raise alerts within a minute.')
      load()
    } catch (err) {
      setMsg(err.response?.data?.error || 'Could not add (admin access required)')
    } finally { setBusy(false) }
  }
  const del = async id => { try { await api.delete(`/api/v1/iocs/manual/${id}`); load() } catch { /* ignore */ } }

  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl p-5 space-y-3">
      <div>
        <div className="text-sm font-semibold text-siem-text">Manual indicators</div>
        <div className="text-xs text-siem-muted">Add your own IP, domain or file hash (MD5, SHA-1 or SHA-256). Useful for incident response, partner intel and testing. They survive feed syncs.</div>
      </div>
      <form onSubmit={add} className="flex flex-wrap items-end gap-2 text-xs">
        <select value={type} onChange={e => setType(e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1.5">
          <option value="ip">IP</option><option value="domain">Domain</option><option value="hash">Hash</option>
        </select>
        <input value={value} onChange={e => setValue(e.target.value)} placeholder={type === 'hash' ? 'sha256…' : type === 'ip' ? '203.0.113.7' : 'bad.example.com'}
          className="flex-1 min-w-[220px] bg-siem-bg border border-siem-border rounded px-2 py-1.5 font-mono" required />
        <input value={label} onChange={e => setLabel(e.target.value)} placeholder="label (e.g. EICAR test)" className="w-48 bg-siem-bg border border-siem-border rounded px-2 py-1.5" />
        <select value={severity} onChange={e => setSeverity(+e.target.value)} className="bg-siem-bg border border-siem-border rounded px-2 py-1.5">
          {[5, 4, 3, 2].map(s => <option key={s} value={s}>Severity {s}</option>)}
        </select>
        <button disabled={busy} className="flex items-center gap-1 border border-siem-accent text-siem-accent rounded px-3 py-1.5 hover:bg-siem-accent/10 disabled:opacity-50"><Plus size={12} /> Add</button>
      </form>
      {msg && <div className="text-[11px] text-siem-muted">{msg}</div>}
      {rows.length > 0 && (
        <div className="divide-y divide-siem-border border border-siem-border rounded-lg">
          {rows.map(r => (
            <div key={r.id} className="flex items-center gap-3 px-3 py-1.5 text-xs">
              <span className="uppercase text-[10px] text-siem-muted w-12">{r.type}</span>
              <span className="font-mono flex-1 truncate" title={r.value}>{r.value}</span>
              <span className="text-siem-muted truncate max-w-[160px]">{r.label}</span>
              <span className="text-siem-muted">sev {r.severity}</span>
              <span className="text-siem-muted hidden md:inline">{(() => { try { return format(new Date(r.created_at), 'MMM d HH:mm') } catch { return '' } })()}</span>
              <button onClick={() => del(r.id)} className="text-siem-muted hover:text-red-400" title="Remove"><Trash2 size={12} /></button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
