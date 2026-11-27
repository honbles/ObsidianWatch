// Code step 3: per-connector scan automation (protected branches with their
// scan engines, push and scheduled scans, PR checks) and the automated scan jobs.
import { Fragment, useEffect, useState, useCallback } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { Play, RefreshCw, CheckCircle, XCircle, Clock, ShieldAlert, Plus, Trash2, GitBranch, Wrench, GitPullRequest, AlertTriangle } from 'lucide-react'
import api from '../../api/client'
import EnginePicker, { useEngines, engineLabels } from './EnginePicker'
import ConfirmPublic from './ConfirmPublic'

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
  return <span className="flex items-center gap-1 text-emerald-400"><CheckCircle size={11}/>{job.kind === 'pr' ? 'passed' : 'done'}</span>
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


function SetupBadge({ s }) {
  if (!s) return <span className="text-siem-muted">not set up</span>
  const title = (s.steps || []).map(x => `${x.step}: ${x.status}${x.detail ? ' – ' + x.detail : ''}`).join('\n')
  return s.ok
    ? <span title={title} className="flex items-center gap-1 text-emerald-400"><CheckCircle size={11}/>set up</span>
    : <span title={title} className="flex items-center gap-1 text-amber-400"><AlertTriangle size={11}/>incomplete</span>
}

function ProtectedBranches({ conn, value, onChange, saved, setup, onAction, visibility }) {
  const engData = useEngines(conn.id)
  const [repos, setRepos] = useState([])
  const [repo, setRepo] = useState('')
  const [branches, setBranches] = useState([])
  const [branch, setBranch] = useState('')
  const [engines, setEngines] = useState([])
  const [correlateNew, setCorrelateNew] = useState(false)
  const [remediateNew, setRemediateNew] = useState(false)
  const [editing, setEditing] = useState(null)

  useEffect(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/sast/repos`).then(r => setRepos(r.data.repos || [])).catch(() => {})
  }, [conn.id])
  useEffect(() => {
    setBranches([]); setBranch('')
    if (!repo || !repo.includes('/')) return
    const def = repos.find(r => r.repo === repo)?.branch
    const p = new URLSearchParams({ repo }); if (def && def !== 'HEAD') p.set('default', def)
    api.get(`/api/v1/devops-connectors/${conn.id}/sast/branches?${p}`).then(r => {
      const bs = (r.data.branches || []).filter(b => b.name && b.name !== 'HEAD')
      setBranches(bs)
      const d = bs.find(b => b.default) || bs[0]
      if (d) setBranch(d.name)
    }).catch(() => {})
  }, [conn.id, repo, repos])

  const list = value || []
  const exists = list.some(b => b.repo.toLowerCase() === repo.toLowerCase() && b.branch === branch)
  const add = () => {
    if (!repo || !branch || exists) return
    onChange([...list, { repo, branch, engines, correlate: correlateNew && engines.length !== 1, remediate: remediateNew }])
    setEngines([]); setCorrelateNew(false); setRemediateNew(false)
  }
  const update = (i, patch) => onChange(list.map((b, j) => j === i ? { ...b, ...patch } : b))
  const remove = (i) => onChange(list.filter((_, j) => j !== i))

  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="px-4 py-2 flex items-center gap-2 text-2xs uppercase tracking-wider text-siem-muted font-semibold border-b border-siem-border">
        <GitBranch size={11}/> Protected branches
      </div>
      <p className="px-4 pt-3 text-xs text-siem-muted">
        Automation works only on these branches: scheduled scans, scans on push, and the AI business-logic engine.
        Pull requests into a protected branch are scanned with its engines (the AI engine reads only the files the pull request changes).
      </p>
      {list.length > 0 && (
        <table className="w-full text-xs mt-2">
          <thead><tr className="text-siem-muted text-2xs uppercase">
            <th className="text-left px-4 py-1.5">Repository</th><th className="text-left">Branch</th><th className="text-left">Scan engines</th>
            <th className="text-left">Correlate</th><th className="text-left" title="Open fix pull requests for new findings after scheduled and manual scans">Fix PRs</th>
            <th className="text-left">Repository setup</th><th />
          </tr></thead>
          <tbody>
            {list.map((b, i) => (
              <Fragment key={b.repo + ' ' + b.branch}>
                <tr className="border-t border-siem-border/50">
                  <td className="px-4 py-2 font-mono">{b.repo}</td>
                  <td className="font-mono">{b.branch}</td>
                  <td>
                    <button onClick={() => setEditing(editing === i ? null : i)} className="text-left text-siem-text hover:text-siem-accent">
                      {engineLabels(b.engines, engData?.engines)}
                    </button>
                  </td>
                  <td>
                    <input type="checkbox" className="accent-siem-accent" checked={!!b.correlate} disabled={(b.engines || []).length === 1}
                      title={(b.engines || []).length === 1 ? 'One engine: nothing to correlate' : 'Correlate the engines\' findings with the code model after each automated scan'}
                      onChange={e => update(i, { correlate: e.target.checked })} />
                  </td>
                  <td>
                    <input type="checkbox" className="accent-siem-accent" checked={!!b.remediate}
                      title="After scheduled and manual scans, the agent opens fix pull requests for new findings (never merges)"
                      onChange={e => update(i, { remediate: e.target.checked })} />
                  </td>
                  <td>
                    {(() => {
                      const isSaved = (saved || []).some(x => x.repo === b.repo && x.branch === b.branch)
                      const s = setup[`${b.repo}\u0000${b.branch}`]
                      return (
                        <span className="flex items-center gap-2 flex-wrap">
                          <SetupBadge s={s} />
                          {isSaved && visibility[`${b.repo}\u0000${b.branch}`]?.public && (visibility[`${b.repo}\u0000${b.branch}`].confirmed
                            ? <span className="text-amber-400" title={`Fix PRs and agent replies allowed by ${visibility[`${b.repo}\u0000${b.branch}`].confirmed_by || 'an admin'}`}>public · confirmed
                                <button onClick={() => onAction('revoke', b)} className="ml-1 text-siem-muted hover:underline">revoke</button></span>
                            : <button onClick={() => onAction('confirm', b)} className="text-red-400 hover:underline" title="Fix PRs and agent replies are held until you confirm">public · confirm</button>)}
                          {isSaved && <button onClick={() => onAction('setup', b)} className="text-siem-accent hover:underline">{s ? 'again' : 'set up'}</button>}
                          {isSaved && b.remediate && <button onClick={() => onAction('remediate', b)} className="text-siem-accent hover:underline" title="Open fix pull requests now from the stored findings">fix now</button>}
                        </span>
                      )
                    })()}
                  </td>
                  <td className="text-right px-4">
                    <button onClick={() => remove(i)} title="Remove" className="text-red-400 hover:text-red-300"><Trash2 size={12}/></button>
                  </td>
                </tr>
                {editing === i && (
                  <tr className="bg-siem-bg/40"><td colSpan={7} className="px-4 py-3">
                    <EnginePicker connId={conn.id} value={b.engines} onChange={v => update(i, { engines: v, correlate: v.length === 1 ? false : b.correlate })} />
                  </td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      )}
      <div className="p-4 border-t border-siem-border mt-2 space-y-3">
        <div className="flex items-end gap-2 flex-wrap">
          <label className="flex flex-col gap-1">
            <span className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Repository</span>
            <input list={`ow-repos-${conn.id}`} value={repo} onChange={e => setRepo(e.target.value.trim())} placeholder="owner/repository"
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text font-mono min-w-[240px]" />
            <datalist id={`ow-repos-${conn.id}`}>{repos.map(r => <option key={r.repo} value={r.repo} />)}</datalist>
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Branch</span>
            <input list={`ow-branches-${conn.id}`} value={branch} onChange={e => setBranch(e.target.value.trim())} disabled={!repo} placeholder="main"
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text font-mono min-w-[160px] disabled:opacity-40" />
            <datalist id={`ow-branches-${conn.id}`}>{branches.map(b => <option key={b.name} value={b.name}>{b.default ? 'default branch' : ''}</option>)}</datalist>
          </label>
          <button onClick={add} disabled={!repo || !branch || exists}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs border border-siem-border text-siem-text hover:border-siem-accent rounded-lg disabled:opacity-40">
            <Plus size={11}/>{exists ? 'Already protected' : 'Add protected branch'}
          </button>
        </div>
        {repo && (
          <div>
            <div className="text-2xs uppercase tracking-wider text-siem-muted font-semibold mb-1.5">Scan engines for this branch</div>
            <EnginePicker connId={conn.id} value={engines} onChange={setEngines} />
            <label className="flex items-start gap-2 mt-3 text-xs cursor-pointer">
              <input type="checkbox" className="mt-0.5 accent-siem-accent" checked={correlateNew && engines.length !== 1} disabled={engines.length === 1}
                onChange={e => setCorrelateNew(e.target.checked)} />
              <span><span className="text-siem-text">Correlate findings after each automated scan</span>
                <span className="block text-siem-muted">Fix pull requests always correlate first when two or more engines ran; this also correlates scans that open none.</span>
                <span className="block text-siem-muted">The code model groups findings that several engines report for the same weakness; those become the branch's findings and the raw ones are kept. Needs two or more engines.</span></span>
            </label>
            <label className="flex items-start gap-2 mt-2 text-xs cursor-pointer">
              <input type="checkbox" className="mt-0.5 accent-siem-accent" checked={remediateNew} onChange={e => setRemediateNew(e.target.checked)} />
              <span><span className="text-siem-text">Open fix pull requests</span>
                <span className="block text-siem-muted">After each scheduled or manual scan, the remediation agent opens pull requests that fix new findings, grouped by kind (at most 10 open). It never merges: developers test and merge, and can mention @obsidianwatch in the pull request.</span></span>
            </label>
          </div>
        )}
      </div>
    </div>
  )
}

function FixPRs({ conn }) {
  const [prs, setPrs] = useState([])
  useEffect(() => {
    const load = () => api.get(`/api/v1/devops-connectors/${conn.id}/fix-prs`).then(r => setPrs(r.data.fix_prs || [])).catch(() => {})
    load(); const t = setInterval(load, 30000); return () => clearInterval(t)
  }, [conn.id])
  const color = { open: 'text-sky-400', merged: 'text-emerald-400', closed: 'text-siem-muted' }
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="px-4 py-2 flex items-center gap-2 text-2xs uppercase tracking-wider text-siem-muted font-semibold border-b border-siem-border">
        <GitPullRequest size={11}/> Fix pull requests
      </div>
      {prs.length === 0 ? <div className="p-4 text-xs text-siem-muted">None yet. Tick "Fix PRs" on a protected branch; the agent opens them after the next scheduled or manual scan.</div> : (
        <table className="w-full text-xs">
          <thead><tr className="text-siem-muted text-2xs uppercase">
            <th className="text-left px-4 py-1.5">Opened</th><th className="text-left">Repository</th><th className="text-left">Into</th>
            <th className="text-left">Pull request</th><th className="text-right">Findings</th><th className="text-right">Replies</th><th className="text-left px-4">State</th>
          </tr></thead>
          <tbody>
            {prs.map(p => (
              <tr key={p.id} className="border-t border-siem-border/50">
                <td className="px-4 py-2 text-siem-muted">{formatDistanceToNow(new Date(p.created_at), { addSuffix: true })}</td>
                <td className="font-mono">{p.repo}</td>
                <td className="font-mono">{p.base_branch}</td>
                <td><a href={p.url} target="_blank" rel="noreferrer" className="text-siem-accent hover:underline">#{p.number} {p.title}</a></td>
                <td className="text-right font-mono">{p.findings}</td>
                <td className="text-right font-mono">{p.agent_replies}</td>
                <td className={`px-4 ${color[p.status] || ''}`}>{p.status}</td>
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
  const [setup, setSetup] = useState({})
  const [publicURL, setPublicURL] = useState(null)
  const [saved, setSaved] = useState(null)
  const [jobs, setJobs] = useState([])
  const [open, setOpen] = useState(null)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const loadJobs = useCallback(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/scan-jobs`).then(r => setJobs(r.data.jobs || [])).catch(() => {})
  }, [conn.id])

  const loadSetup = useCallback(() => {
    api.get(`/api/v1/devops-connectors/${conn.id}/protected/setup`).then(r => {
      setSetup(Object.fromEntries((r.data.setup || []).map(s => [`${s.repo}\u0000${s.branch}`, s]))); setPublicURL(r.data.public_url || '')
    }).catch(() => {})
  }, [conn.id])
  useEffect(() => { loadSetup(); const t = setInterval(loadSetup, 15000); return () => clearInterval(t) }, [loadSetup])
  const [confirm, setConfirm] = useState(null)
  const [visibility, setVisibility] = useState({})
  const loadVisibility = useCallback(() => {
    for (const b of (saved?.protected || [])) {
      const p = new URLSearchParams({ repo: b.repo, branch: b.branch })
      api.get(`/api/v1/devops-connectors/${conn.id}/protected/visibility?${p}`)
        .then(r => setVisibility(v => ({ ...v, [`${b.repo}\u0000${b.branch}`]: r.data }))).catch(() => {})
    }
  }, [conn.id, saved])
  useEffect(() => { loadVisibility() }, [loadVisibility])
  const branchAction = async (kind, b) => {
    setError('')
    if (kind === 'confirm') { setConfirm({ b, then: null }); return }
    if (kind === 'revoke') {
      try { await api.post(`/api/v1/devops-connectors/${conn.id}/protected/public-ack`, { repo: b.repo, branch: b.branch, revoke: true }); loadVisibility() }
      catch (e) { setError(e.response?.data?.error || 'Could not revoke') }
      return
    }
    try { await api.post(`/api/v1/devops-connectors/${conn.id}/protected/${kind}`, { repo: b.repo, branch: b.branch }); loadJobs() }
    catch (e) {
      if (e.response?.status === 409 && e.response?.data?.public) setConfirm({ b, then: kind })
      else setError(e.response?.data?.error || 'Could not queue it')
    }
  }

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
      const body = { ...policy, protected: policy.protected || [] }
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
            help="Pull requests into a protected branch are always scanned; this adds every other branch. Needs the webhook (repository setup creates it)." />
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
          <div className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Protected branch scans</div>
          <Toggle label="Scan on every push to a protected branch" checked={policy.scan_on_push} onChange={v => set('scan_on_push', v)}
            help="Needs the push webhook. With no protected branch set, pushes to the default branch are scanned. The result updates the branch's stored SAST result." />
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-siem-text">Scheduled scan</span>
            <select value={policy.schedule} onChange={e => set('schedule', e.target.value)}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              <option value="off">off</option><option value="every5d">every 5 days (default)</option><option value="daily">daily</option><option value="weekly">weekly (Monday)</option>
            </select>
            <span className="text-xs text-siem-muted">at</span>
            <select value={policy.schedule_hour} onChange={e => set('schedule_hour', Number(e.target.value))}
              className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
              {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00 UTC</option>)}
            </select>
          </div>
          <p className="text-xs text-siem-muted">
            Scheduled scans run only on protected branches, each with its own engines.
            {(policy.protected || []).length === 0 && <span className="text-amber-400"> No protected branch is set, so nothing is scanned on a schedule.</span>}
            {' '}Each rescan replaces that branch's previous result, so fixed findings drop out.
          </p>
        </div>
      </div>

      {publicURL === '' && (policy.protected || []).length > 0 && (
        <div className="bg-amber-950/20 border border-amber-800/40 rounded-xl p-3 text-xs text-amber-300 flex gap-2">
          <AlertTriangle size={13} className="shrink-0 mt-0.5"/>
          <span>OW_PUBLIC_URL is not set on the server, so repository setup cannot create webhooks: set it to the address {conn.provider === 'github' ? 'GitHub' : conn.provider === 'gitlab' ? 'GitLab' : 'Azure DevOps'} can reach this console at, restart, then click "set up again". Branch protection is still applied.</span>
        </div>
      )}

      <ProtectedBranches conn={conn} value={policy.protected} onChange={v => set('protected', v)} saved={saved?.protected} setup={setup} onAction={branchAction} visibility={visibility} />
      {confirm && (
        <ConfirmPublic repo={confirm.b.repo}
          what={confirm.then === 'remediate'
            ? 'The remediation agent will open fix pull requests, and answer @obsidianwatch mentions, that describe the findings and show the fixes.'
            : 'Fix pull requests and @obsidianwatch replies on this branch will describe the findings and show the fixes.'}
          onClose={() => setConfirm(null)}
          onConfirm={async (typed) => {
            await api.post(`/api/v1/devops-connectors/${conn.id}/protected/public-ack`, { repo: confirm.b.repo, branch: confirm.b.branch, confirm: typed })
            if (confirm.then === 'remediate') await api.post(`/api/v1/devops-connectors/${conn.id}/protected/remediate`, { repo: confirm.b.repo, branch: confirm.b.branch })
            setConfirm(null); loadVisibility(); loadJobs()
          }} />
      )}

      <div className="bg-siem-surface border border-siem-border rounded-xl p-4 flex flex-wrap gap-6 items-start">
        <div className="flex items-center gap-2">
          <Wrench size={12} className="text-siem-muted"/>
          <span className="text-xs text-siem-text">Fix pull requests cover</span>
          <select value={policy.fix_min_severity || 'high'} onChange={e => set('fix_min_severity', e.target.value)}
            className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1 text-xs text-siem-text">
            {['critical', 'high', 'medium', 'low'].map(s => <option key={s} value={s}>{s} or above</option>)}
          </select>
        </div>
        <Toggle label="Set up repositories automatically" checked={!policy.manual_setup} onChange={v => set('manual_setup', !v)}
          help="When a protected branch is saved, create the webhook and turn on branch protection (pull requests only, the ObsidianWatch check required, no force push). Needs an admin token." />
      </div>

      <div className="flex items-center gap-2">
        <button onClick={save} disabled={!dirty || saving}
          className="px-4 py-2 text-xs font-semibold bg-siem-accent text-white rounded-xl disabled:opacity-40">{saving ? 'Saving…' : 'Save'}</button>
        <button onClick={scanNow} className="flex items-center gap-1.5 px-3 py-2 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-xl">
          <Play size={11}/> {(policy.protected || []).length ? 'Scan protected branches now' : 'Scan all repositories now'}
        </button>
        {error && <span className="text-xs text-red-400">{error}</span>}
      </div>

      <FixPRs conn={conn} />

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
                    <td className="font-mono text-siem-muted">{
                      j.kind === 'pr' ? `PR #${j.ref} → ${j.base_branch}` :
                      j.kind === 'agent' ? `reply on PR #${j.ref}` :
                      j.kind === 'fix' ? `fix PRs → ${j.ref}` :
                      j.kind === 'setup' ? `set up ${j.ref}` : j.ref}{j.head_sha && !j.head_sha.includes(':') ? ` @ ${j.head_sha.slice(0, 8)}` : ''}</td>
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
