import { useEffect, useState } from 'react'
import { appApi } from '../../api/app'
import { appIsAdmin } from './appFormat'
import { appTime } from './appFormat'

const STATE_LABEL = {
  always_masked: ['always masked', 'border-red-500/40 text-red-300', 'Names like password, token or card are never forwarded'],
  pending: ['not reviewed', 'border-amber-500/40 text-amber-300', 'Nothing is forwarded until this route is reviewed'],
  new: ['new field', 'border-orange-500/40 text-orange-300', 'Appeared after the last review; withheld until reviewed'],
  masked: ['masked', 'border-slate-500/40 text-slate-300', 'Never leaves the host'],
  captured: ['captured', 'border-emerald-500/40 text-emerald-300', 'Forwarded with its value'],
}

// Review of one route's parameters: tick what to mask, save, and the agent starts forwarding the rest.
// Until a review is saved the agent forwards no parameter values for the route.
export default function AppRoutePolicyPanel({ service, route, onSaved }) {
  const admin = appIsAdmin()
  const params = route.params || []
  const [masked, setMasked] = useState({})
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  useEffect(() => {
    const m = {}
    for (const p of params) {
      m[p.name] = p.state === 'always_masked' || p.state === 'masked'
    }
    setMasked(m)
    setErr('')
  }, [route.route, route.method, route.policy?.reviewed_at, params.length]) // eslint-disable-line react-hooks/exhaustive-deps
  const reviewed = route.payload_review === 'reviewed' || route.payload_review === 'new_fields'

  const save = async () => {
    setBusy(true); setErr('')
    try {
      await appApi.savePayloadPolicy(service.id, {
        route: route.route, method: route.method,
        reviewed_names: params.map(p => p.name),
        masked: params.filter(p => masked[p.name]).map(p => p.name),
      })
      onSaved && onSaved()
    } catch (e) { setErr(e?.response?.data?.error || 'Could not save the review') } finally { setBusy(false) }
  }
  const revoke = async () => {
    setBusy(true); setErr('')
    try { await appApi.revokePayloadPolicy(service.id, route.route, route.method); onSaved && onSaved() }
    catch (e) { setErr(e?.response?.data?.error || 'Could not revoke the review') } finally { setBusy(false) }
  }

  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-sm font-medium text-siem-text"><span className="font-mono">{route.method} {route.route}</span></div>
          <div className="text-xs text-siem-muted mt-0.5">
            {reviewed
              ? `Reviewed by ${route.policy?.reviewed_by || 'an admin'} ${route.policy?.reviewed_at ? appTime(route.policy.reviewed_at) : ''}. Unmasked parameters are forwarded with their values.`
              : 'Not reviewed. The agent forwards no parameter values for this route until you save a review.'}
          </div>
        </div>
      </div>
      {!admin && <div className="text-xs text-amber-300">Read-only: reviewing parameters needs the admin role.</div>}
      <table className="w-full text-xs">
        <thead><tr className="text-left text-siem-muted"><th className="py-1 pr-3 font-normal">Parameter</th><th className="font-normal">Requests</th><th className="font-normal">Where</th><th className="font-normal">Status</th><th className="font-normal text-right">Mask</th></tr></thead>
        <tbody>
          {params.map(p => {
            const [label, cls, title] = STATE_LABEL[p.state] || STATE_LABEL.pending
            const locked = p.state === 'always_masked'
            return (
              <tr key={p.name} className="border-t border-siem-border">
                <td className="py-1.5 pr-3 font-mono">{p.name}</td>
                <td>{p.requests}</td>
                <td className="text-xs">{p.location || '-'}{p.source === 'declared' && <span className="ml-1 rounded border border-dashed border-siem-border px-1 text-siem-muted" title="In the API spec, not seen in traffic yet">spec only</span>}{p.undocumented && <span className="ml-1 rounded border border-amber-500/60 px-1 text-amber-300" title="Seen in traffic but not in the API spec">undocumented</span>}</td>
                <td><span title={title} className={`rounded border px-1 text-mini ${cls}`}>{label}</span></td>
                <td className="text-right">
                  <input type="checkbox" checked={!!masked[p.name] || locked} disabled={!admin || locked || busy}
                    onChange={e => setMasked(m => ({ ...m, [p.name]: e.target.checked }))} />
                </td>
              </tr>)
          })}
        </tbody>
      </table>
      {err && <div className="text-xs text-red-300">{err}</div>}
      {admin && (
        <div className="flex items-center gap-2">
          <button className="btn-primary text-xs" disabled={busy} onClick={save}>{reviewed ? 'Save review' : 'Save review and start capture'}</button>
          {reviewed && <button className="text-xs text-red-300 hover:underline" disabled={busy} onClick={revoke}>Revoke review (stop capture)</button>}
          <span className="text-xs text-siem-muted">Saving marks every parameter listed here as reviewed. Parameters that appear later stay withheld until reviewed.</span>
        </div>
      )}
    </div>
  )
}
