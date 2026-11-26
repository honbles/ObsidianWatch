// Code step 3: per-connector scan automation (on push, schedule, PR checks)
// and the list of automated scan jobs.
import { Fragment, useEffect, useState, useCallback } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { Play, RefreshCw, CheckCircle, XCircle, Clock, ShieldAlert } from 'lucide-react'
import api from '../../api/client'

const STATUS_NAME = {
  github: 'ObsidianWatch / code scan',
  gitlab: 'ObsidianWatch code scan',
  azuredevops: 'genre obsidianwatch, name code-scan',
}

const BLOCK_HELP = {
  github: 'Settings → Branches → branch protection rule → "Require status checks to pass" → add the status below.',
  gitlab: 'Settings → Merge requests → "Pipelines must succeed". The scan reports as an external commit status, which is part of the pipeline.',
  azuredevops: 'Project settings → Repositories → Policies → branch → "Status checks" → add the status below as required.',
}

const SEV = ['none', 'critical', 'high', 'medium', 'low']

function Toggle({ label, help, checked, onChange }) {
  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <input type="checkbox" checked={!!checked} onChange={e => onChange(e.target.checked)} className="mt-0.5 accent-siem-accent" />
      <span>
        <span className="text-xs text-siem-text">{label}</span>
        {help && <span className="block text-xs text-siem-muted mt-0.5">{help}</span>}
      </span>
    </label>
  )
}

function JobStatus({ job }) {
  if (job.status === 'queued') return <span className="flex items-center gap-1 text-siem-muted"><Clock size={11}/>queued</span>
  if (job.status === 'running') return <span className="flex items-center gap-1 text-siem-accent"><RefreshCw size={11} className="animate-spin"/>running</span>
  if (job.status === 'failed') return <span className="flex items-center gap-1 text-red-400" title={job.error || ''}><XCircle size={11}/>failed</span>
  if (job.blocked) return <span className="flex items-center gap-1 text-orange-400"><ShieldAlert size={11}/>blocking</span>
  return <span className="flex items-center gap-1 text-emerald-400"><CheckCircle size={11}/>passed</span>
}

function TriageRules({ conn }) {
  const [rules, setRules] = useState([])
  const load = useCallback(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/triage-rules`).then(r => setRules(r.data.rules || [])).catch(() => {})
  }, [conn.id])
  useEffect(() => { load() }, [load])
  const remove = async (id) => { try { await api.delete(`/api/v1/devops-connectors/${conn.id}/triage-rules/${id}`); load() } catch { /* admin only */ } }
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="px-4 py-2 text-2xs uppercase tracking-wider text-siem-muted font-semibold border-b border-siem-border">Triage rules</div>
      {rules.length === 0 ? <div className="p-4 text-xs text-siem-muted">No triage rules. Create one from a finding's "likely false positive" hint in the SAST tab.</div> : (
        <table className="w-full text-xs">
          <tbody>
            {rules.map(r => (
              <tr key={r.id} className="border-t border-siem-border/50 first:border-0">
                <td className="px-4 py-2 font-mono">{r.rule_id}</td>
                <td className="font-mono text-siem-muted">{r.repo || 'all repositories'}{r.path_prefix ? ` · ${r.path_prefix}` : ''}</td>
                <td>{r.status.replace('_', ' ')}</td>
                <td className="text-siem-muted">{r.reason}</td>
                <td className="text-siem-muted">{r.created_by}{r.expires_at ? ` · until ${new Date(r.expires_at).toLocaleDateString()}` : ''}</td>
                <td className="text-right px-4"><button onClick={() => remove(r.id)} className="text-red-400 hover:underline">delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default function AutomationPanel({ conn }) {
  const [policy, setPolicy] = useState(null)
  const [saved, setSaved] = useState(null)
  const [jobs, setJobs] = useState([])
  const [open, setOpen] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const loadJobs = useCallback(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/scan-jobs`).then(r => setJobs(r.data.jobs || [])).catch(() => {})
  }, [conn.id])

  useEffect(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/scan-policy`).then(r => { setPolicy(r.data); setSaved(r.data) })
      .catch(e => setError(e.response?.data?.error || 'Could not load the policy'))
    loadJobs()
    const t = setInterval(loadJobs, 10000)
    return () => clearInterval(t)
  }, [conn.id, loadJobs])

  const set = (k, v) => setPolicy(p => ({ ...p, [k]: v }))
  const dirty = policy && saved && JSON.stringify(policy) !== JSON.stringify(saved)

  const save = async () => {
    setSaving(true); setError('')
    try {
      const body = { ...policy, repos: (policy.repos || []).filter(Boolean) }
      const { data } = await api.put(`/api/v1/devops-connectors/${conn.id}/scan-policy`, body)
      setPolicy(data); setSaved(data)
    } catch (e) { setError(e.response?.data?.error || 'Save failed') }
    finally { setSaving(false) }
  }

  const scanNow = async () => {
    setError('')
    try { await api.post(`/api/v1/devops-connectors/${conn.id}/scan-jobs`, {}); loadJobs() }
    catch (e) { setError(e.response?.data?.error || 'Could not queue the scan') }
  }

  const openJob = async (id) => {
    if (open?.id === id) { setOpen(null); return }
    try { const { data } = await api.get(`/api/v1/scan-jobs/${id}`); setOpen(data) } catch { /* ignore */ }
  }

  if (!policy) return <div className="p-5 text-xs text-siem-muted">{error || 'Loading…'}</div>

  return (
    <div className="p-5 space-y-5">
      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
          <div className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Pull / merge requests</div>
          <Toggle label="Scan every pull request" checked={policy.pr_checks} onChange={v => set('pr_checks', v)}
            help="Needs this connector's webhook with pull or merge request events." />
          <Toggle label="Post comments on the pull request" checked={policy.pr_comments} onChange={v => set('pr_comments', v)}
            help="A summary, and inline comments on the changed lines. Each finding is commented once." />
          <Toggle label="Run CodeQL on pull requests" checked={policy.pr_codeql} onChange={v => set('pr_codeql', v)}
            help="Deeper data-flow analysis; adds minutes per update." />
          <Toggle label="AI fix suggestions in comments" checked={policy.pr_ai_fixes} onChange={v => set('pr_ai_fixes', v)}
            help="Up to 5 per update. Needs an AI provider and source snippets allowed in Settings." />
          <div className="flex items-center gap-2">
            <span className="text-xs text-siem-text">Fail the check on</span>
            <select value={policy.block_on} onChange={e => set('block_on', e.target.value)}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              {SEV.map(s => <option key={s} value={s}>{s === 'none' ? 'never (report only)' : `${s} or above`}</option>)}
            </select>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-siem-text">Inline comments per update</span>
            <input type="number" min={1} max={100} value={policy.max_comments} onChange={e => set('max_comments', Number(e.target.value))}
              className="w-16 bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text" />
          </div>
          <p className="text-xs text-siem-muted border-t border-siem-border pt-2">
            Only issues on changed lines are reported. To block merging, make the status <span className="font-mono text-siem-text">{STATUS_NAME[conn.provider]}</span> required: {BLOCK_HELP[conn.provider]}
            {' '}The token needs write access to commit statuses and pull request comments.
          </p>
        </div>

        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">
          <div className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Pushes and schedule</div>
          <Toggle label="Scan on every push to the default branch" checked={policy.scan_on_push} onChange={v => set('scan_on_push', v)}
            help="Needs the push webhook. The result replaces the repository's stored SAST result." />
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-siem-text">Scheduled scan</span>
            <select value={policy.schedule} onChange={e => set('schedule', e.target.value)}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              <option value="off">off</option><option value="every5d">every 5 days (default)</option><option value="daily">daily</option><option value="weekly">weekly (Monday)</option>
            </select>
            <span className="text-xs text-siem-muted">of</span>
            <select value={policy.schedule_branches || 'all'} onChange={e => set('schedule_branches', e.target.value)}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              <option value="all">all branches</option><option value="default">the default branch</option>
            </select>
            <span className="text-xs text-siem-muted">at</span>
            <select value={policy.schedule_hour} onChange={e => set('schedule_hour', Number(e.target.value))}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00 UTC</option>)}
            </select>
          </div>
          <div>
            <span className="text-xs text-siem-text">Repositories for scheduled scans</span>
            <textarea rows={3} value={(policy.repos || []).join('\n')} onChange={e => set('repos', e.target.value.split('\n').map(s => s.trim()))}
              placeholder="One per line. Empty: every repository seen for this connector."
              className="mt-1 w-full bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text font-mono" />
            <p className="text-xs text-siem-muted mt-1">Each rescan replaces the branch's previous result, so fixed findings drop out. All branches: up to 2,000 per repository.</p>
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button onClick={save} disabled={!dirty || saving}
          className="px-4 py-2 text-xs font-semibold bg-siem-accent text-white rounded-xl disabled:opacity-40">{saving ? 'Saving…' : 'Save'}</button>
        <button onClick={scanNow} className="flex items-center gap-1.5 px-3 py-2 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-xl">
          <Play size={11}/> Scan all repositories now
        </button>
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>

      <TriageRules conn={conn} />

      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <div className="px-4 py-2 text-2xs uppercase tracking-wider text-siem-muted font-semibold border-b border-siem-border">Automated scans</div>
        {jobs.length === 0 ? <div className="p-4 text-xs text-siem-muted">No automated scans yet.</div> : (
          <table className="w-full text-xs">
            <thead><tr className="text-siem-muted text-2xs uppercase">
              <th className="text-left px-4 py-2">When</th><th className="text-left">Trigger</th><th className="text-left">Repository</th>
              <th className="text-left">Target</th><th className="text-left">Result</th><th className="text-right px-4">Findings</th>
            </tr></thead>
            <tbody>
              {jobs.map(j => (
                <Fragment key={j.id}>
                  <tr onClick={() => openJob(j.id)} className="border-t border-siem-border/50 hover:bg-siem-bg/50 cursor-pointer">
                    <td className="px-4 py-2 text-siem-muted">{formatDistanceToNow(new Date(j.created_at), { addSuffix: true })}</td>
                    <td>{j.trigger}</td>
                    <td className="font-mono">{j.repo}</td>
                    <td className="font-mono text-siem-muted">{j.kind === 'pr' ? `PR #${j.ref} → ${j.base_branch}` : j.ref}{j.head_sha && !j.head_sha.includes(':') ? ` @ ${j.head_sha.slice(0, 8)}` : ''}</td>
                    <td><JobStatus job={j} /></td>
                    <td className="text-right px-4 font-mono">{j.status === 'done' ? j.finding_count : '–'}</td>
                  </tr>
                  {open?.id === j.id && (
                    <tr className="bg-siem-bg/40"><td colSpan={6} className="px-4 py-3 space-y-2">
                      {open.error && <div className="text-red-400">{open.error}</div>}
                      {open.result?.reported?.length > 0 && <div className="text-siem-muted">Reported: {open.result.reported.join('; ')}</div>}
                      {open.result?.notes?.length > 0 && <div className="text-siem-muted">Notes: {open.result.notes.join('; ')}</div>}
                      {(open.result?.findings || []).slice(0, 50).map((f, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="uppercase text-2xs w-14 text-siem-muted">{f.severity}</span>
                          <span className="text-siem-text">{f.title}</span>
                          <span className="font-mono text-siem-muted ml-auto">{f.file}{f.line ? `:${f.line}` : ''}</span>
                        </div>
                      ))}
                    </td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
