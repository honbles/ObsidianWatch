// Confirmation for actions that publish security findings on a public
// repository: the user must type "proceed".
import { useState } from 'react'
import { AlertTriangle, X } from 'lucide-react'

export function ProceedInput({ value, onChange }) {
  return (
    <label className="block text-xs text-siem-text">
      Type <span className="font-mono font-semibold">proceed</span> to continue
      <input autoFocus value={value} onChange={e => onChange(e.target.value)} placeholder="proceed"
        className="mt-1 w-full bg-siem-bg border border-red-800/60 rounded-lg px-2 py-1.5 text-xs text-siem-text font-mono" />
    </label>
  )
}

export const proceedTyped = (v) => v.trim().toLowerCase() === 'proceed'

export default function ConfirmPublic({ repo, what, onConfirm, onClose }) {
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const go = async () => {
    setBusy(true); setErr('')
    try { await onConfirm(text.trim()) } catch (e) { setErr(e.response?.data?.error || 'Failed') } finally { setBusy(false) }
  }
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-siem-surface border border-red-800/50 rounded-2xl w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border">
          <div className="flex items-center gap-2 text-sm font-semibold text-red-300"><AlertTriangle size={15}/>Public repository</div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={16}/></button>
        </div>
        <div className="px-5 py-4 space-y-3 text-xs text-siem-text">
          <p><span className="font-mono">{repo}</span> is public. {what} Anyone can read them, so attackers can learn about these vulnerabilities before the fixes are merged and deployed.</p>
          <p className="text-siem-muted">Prefer private disclosure where you can: fix privately, or use the platform's private security advisories.</p>
          <ProceedInput value={text} onChange={setText} />
          {err && <div className="text-red-400">{err}</div>}
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-siem-border">
          <button onClick={onClose} className="px-4 py-2 text-xs rounded-xl border border-siem-border text-siem-muted">Cancel</button>
          <button onClick={go} disabled={!proceedTyped(text) || busy}
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-red-700 hover:bg-red-600 text-white disabled:opacity-40">{busy ? 'Working…' : 'Proceed'}</button>
        </div>
      </div>
    </div>
  )
}
