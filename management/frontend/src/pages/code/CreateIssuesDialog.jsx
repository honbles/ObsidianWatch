// Create issues on the platform from a repository's SAST findings:
// preview first, then create. One issue per problem, not per finding.
import { useEffect, useState } from 'react'
import { X, ExternalLink } from 'lucide-react'
import api from '../../api/client'

const SEV = ['critical', 'high', 'medium', 'low']
const TRACKER = { github: 'GitHub issues', gitlab: 'GitLab issues (confidential)', azuredevops: 'Azure DevOps work items (Bug)' }

export default function CreateIssuesDialog({ conn, repo, branch, onClose, onDone }) {
  const [minSev, setMinSev] = useState('high')
  const [plan, setPlan] = useState(null)
  const [result, setResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  useEffect(() => {
    setPlan(null); setErr('')
    api.post(`/api/v1/devops-connectors/${conn.id}/sast/issues`, { repo, branch, min_severity: minSev, dry_run: true })
      .then(r => setPlan(r.data)).catch(e => setErr(e.response?.data?.error || 'Could not prepare the issues'))
  }, [conn.id, repo, branch, minSev])

  const create = async () => {
    setBusy(true); setErr('')
    try {
      const { data } = await api.post(`/api/v1/devops-connectors/${conn.id}/sast/issues`, { repo, branch, min_severity: minSev }, { timeout: 180000 })
      setResult(data); onDone && onDone()
    } catch (e) { setErr(e.response?.data?.error || 'Creating issues failed') }
    finally { setBusy(false) }
  }

  const work = plan ? plan.new_issues + plan.comments : 0
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border">
          <div>
            <div className="text-sm font-semibold text-siem-text">Create issues · <span className="font-mono">{repo}</span></div>
            <div className="text-[11px] text-siem-muted">{TRACKER[conn.provider]} · one issue per problem, listing every location</div>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={16}/></button>
        </div>
        <div className="px-5 py-4 space-y-3 overflow-y-auto">
          {!result && (
            <div className="flex items-center gap-2 text-xs">
              <span className="text-siem-muted">Include findings of</span>
              <select value={minSev} onChange={e => setMinSev(e.target.value)} className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-siem-text">
                {SEV.map(s => <option key={s} value={s}>{s} or above</option>)}
              </select>
              <span className="text-siem-muted">· dismissed findings are left out</span>
            </div>
          )}
          {err && <div className="text-xs text-red-400">{err}</div>}
          {!plan && !err && <div className="text-xs text-siem-muted">Preparing…</div>}
          {plan?.blocked && <div className="text-xs text-amber-300 bg-amber-950/30 border border-amber-800/40 rounded-lg p-3">Not created: {plan.blocked}.</div>}
          {plan && !result && !plan.blocked && (
            <>
              <div className="text-xs text-siem-text">
                {work === 0 ? 'Every finding at this level already has an issue. Nothing to do.'
                  : <>{plan.new_issues > 0 && <b>{Math.min(plan.new_issues, plan.limit)} new issue(s)</b>}{plan.new_issues > 0 && plan.comments > 0 && ' and '}{plan.comments > 0 && <b>{plan.comments} comment(s) on existing issues</b>} for new locations.</>}
                {plan.new_issues > plan.limit && <span className="text-siem-muted"> At most {plan.limit} per click; click again for the rest.</span>}
              </div>
              <div className="border border-siem-border rounded-lg divide-y divide-siem-border/50">
                {(plan.groups || []).map(g => (
                  <div key={g.key} className="flex items-center gap-2 px-3 py-2 text-[11px]">
                    <span className="uppercase w-16 text-siem-muted">{g.severity}</span>
                    <span className="flex-1 text-siem-text truncate" title={g.title}>{g.title}</span>
                    <span className="text-siem-muted">{g.findings} finding(s)</span>
                    {g.existing_issue
                      ? <a href={g.existing_issue} target="_blank" rel="noreferrer" className="text-siem-accent flex items-center gap-1">{g.new_findings ? `+${g.new_findings} new` : 'exists'}<ExternalLink size={10}/></a>
                      : <span className="text-emerald-400">new issue</span>}
                  </div>
                ))}
                {(plan.groups || []).length === 0 && <div className="px-3 py-3 text-[11px] text-siem-muted">No findings at this level.</div>}
              </div>
              <p className="text-[11px] text-siem-muted">ObsidianWatch remembers which findings each issue covers, so clicking again only adds what is new. It does not follow whether issues are open or closed; the findings here stay the source of truth. Secret values are never written.</p>
            </>
          )}
          {result && (
            <div className="space-y-2 text-xs">
              <div className="text-siem-text">{(result.created || []).length} issue(s) created, {(result.updated || []).length} updated.</div>
              {[...(result.created || []), ...(result.updated || [])].map(x => (
                <a key={x.url} href={x.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-siem-accent"><ExternalLink size={10}/>{x.title}</a>
              ))}
              {(result.failed || []).length > 0 && <div className="text-red-400">Failed: {result.failed.join(' · ')}. The token needs permission to create issues.</div>}
              {result.note && <div className="text-siem-muted">{result.note}</div>}
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 px-5 py-3 border-t border-siem-border">
          <button onClick={onClose} className="px-4 py-2 text-xs rounded-xl border border-siem-border text-siem-muted">{result ? 'Close' : 'Cancel'}</button>
          {!result && <button onClick={create} disabled={!plan || plan.blocked || work === 0 || busy}
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-siem-accent text-white disabled:opacity-40">{busy ? 'Creating…' : 'Create'}</button>}
        </div>
      </div>
    </div>
  )
}
