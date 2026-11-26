// Code step 5: per-finding triage and fix suggestions (SAST tab).
import { useState } from 'react'
import { Wand2, Check, Ban, ShieldCheck, Undo2, Lightbulb } from 'lucide-react'
import api from '../../api/client'

const STATUS = {
  false_positive: ['False positive', 'text-siem-muted border-siem-border'],
  accepted_risk:  ['Accepted risk', 'text-amber-300 border-amber-800/50'],
  confirmed:      ['Confirmed', 'text-red-300 border-red-800/50'],
}

export function TriageBadge({ f }) {
  if (f.triage) {
    const [label, cls] = STATUS[f.triage.status] || [f.triage.status, '']
    return <span title={[f.triage.reason, f.triage.by && `by ${f.triage.by}`, f.triage.triage_rule_id && 'via triage rule'].filter(Boolean).join(' · ')}
      className={`text-2xs px-1.5 py-0.5 rounded border shrink-0 ${cls}`}>{label}</span>
  }
  if (f.triage_hint) {
    const fp = f.triage_hint.suggestion === 'likely_false_positive'
    return <span title={f.triage_hint.basis} className={`text-2xs px-1.5 py-0.5 rounded border shrink-0 border-dashed ${fp ? 'text-siem-muted border-siem-border' : 'text-red-300 border-red-800/50'}`}>
      {fp ? 'Likely false positive' : 'Likely real'}</span>
  }
  return null
}

export default function FindingActions({ conn, f, repo, branch, onChanged }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState('')
  const [fix, setFix] = useState(null)
  const [err, setErr] = useState('')

  const triage = async (status) => {
    if ((status === 'false_positive' || status === 'accepted_risk') && !reason.trim()) { setErr('Give a reason first.'); return }
    setBusy(status); setErr('')
    try {
      await api.post(`/api/v1/devops-connectors/${conn.id}/findings/triage`, { repo: repo || f.repo, finding: f, status, reason })
      onChanged && onChanged()
    } catch (e) { setErr(e.response?.data?.error || 'Could not save the decision') }
    finally { setBusy('') }
  }

  const createRule = async () => {
    const r = f.triage_hint?.suggested_rule
    if (!r) return
    if (!reason.trim()) { setErr('Give a reason for the rule first.'); return }
    setBusy('rule'); setErr('')
    try {
      await api.post(`/api/v1/devops-connectors/${conn.id}/triage-rules`, { ...r, status: 'false_positive', reason })
      onChanged && onChanged()
    } catch (e) { setErr(e.response?.data?.error || 'Could not create the rule (admins only)') }
    finally { setBusy('') }
  }

  const suggest = async () => {
    setBusy('fix'); setErr(''); setFix(null)
    try {
      const { data } = await api.post(`/api/v1/devops-connectors/${conn.id}/sast/fix`, { repo: repo || f.repo, branch, finding: f }, { timeout: 90000 })
      setFix(data)
    } catch (e) { setErr(e.response?.data?.error || 'Fix suggestion failed') }
    finally { setBusy('') }
  }

  const btn = 'flex items-center gap-1 text-mini px-2 py-1 rounded-lg border border-siem-border text-siem-muted hover:text-siem-text disabled:opacity-40'
  return (
    <div className="space-y-2 border-t border-siem-border/30 pt-3">
      {f.triage_hint && !f.triage && (
        <div className="flex items-start gap-2 text-xs text-siem-muted">
          <Lightbulb size={12} className="mt-0.5 text-amber-300/80 shrink-0"/>
          <span>{f.triage_hint.basis}.</span>
          {f.triage_hint.suggested_rule && (
            <button onClick={createRule} disabled={!!busy} className={btn + ' ml-auto shrink-0'}>
              Dismiss rule {f.triage_hint.suggested_rule.rule_id}{f.triage_hint.suggested_rule.path_prefix ? ` under ${f.triage_hint.suggested_rule.path_prefix}` : ''}{f.triage_hint.suggested_rule.repo ? ' here' : ' everywhere'}
            </button>
          )}
        </div>
      )}
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={suggest} disabled={!!busy} className={btn}><Wand2 size={11}/>{busy === 'fix' ? 'Thinking…' : f.package ? 'Show fix' : 'Suggest fix (AI)'}</button>
        {f.triage ? (
          <button onClick={() => triage('')} disabled={!!busy} className={btn}><Undo2 size={11}/>Clear decision</button>
        ) : (<>
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="Reason (required to dismiss)"
            className="flex-1 min-w-[160px] bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text"/>
          <button onClick={() => triage('false_positive')} disabled={!!busy} className={btn}><Ban size={11}/>False positive</button>
          <button onClick={() => triage('accepted_risk')} disabled={!!busy} className={btn}><ShieldCheck size={11}/>Accept risk</button>
          <button onClick={() => triage('confirmed')} disabled={!!busy} className={btn}><Check size={11}/>Confirm</button>
        </>)}
      </div>
      {err && <div className="text-xs text-red-400">{err}</div>}
      {fix && (
        <div className="bg-siem-bg border border-siem-border rounded-lg p-3 space-y-2 text-xs">
          {fix.likely_false_positive && <div className="text-amber-300">AI review: this may be a false positive. {fix.false_positive_reason}</div>}
          {fix.explanation && <p className="text-siem-muted">{fix.explanation}</p>}
          {fix.command && <code className="block font-mono text-emerald-300 bg-black/30 rounded px-2 py-1">{fix.command}</code>}
          {fix.diff && (
            <pre className="font-mono text-xs bg-black/30 rounded px-2 py-2 overflow-x-auto">{fix.diff.split('\n').map((l, i) => (
              <div key={i} className={l.startsWith('+') && !l.startsWith('+++') ? 'text-emerald-300' : l.startsWith('-') && !l.startsWith('---') ? 'text-red-300' : 'text-siem-muted'}>{l || ' '}</div>
            ))}</pre>
          )}
          {fix.kind === 'code' && <div className="text-siem-muted/60">AI suggestion{fix.confidence ? `, confidence ${fix.confidence}%` : ''}{fix.cached ? ' (cached)' : ''}. Review before applying; nothing is changed in the repository.</div>}
        </div>
      )}
    </div>
  )
}
