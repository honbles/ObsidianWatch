// Commit scans in the SAST tab: a commit picker for the scan, the stored
// commit scans of a repository (pin, delete, view) and a compare of one with
// its branch's current result (fixed since / new since).
import { useEffect, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'
import { GitCommit, Pin, PinOff, Trash2, GitCompare, Eye, ChevronDown, ChevronRight, X, AlertTriangle } from 'lucide-react'
import api from '../../api/client'

const short = (sha) => (sha || '').slice(0, 7)
const ago = (t) => { try { return formatDistanceToNow(new Date(t), { addSuffix: true }) } catch { return '' } }

// value: '' = the branch head (a normal branch scan), else a full commit id.
export function CommitPicker({ connId, repo, branch, value, onChange, refreshKey }) {
  const [commits, setCommits] = useState([])
  const [warning, setWarning] = useState('')
  useEffect(() => {
    setCommits([]); setWarning('')
    if (!repo) return
    const p = new URLSearchParams({ repo }); if (branch) p.set('branch', branch)
    api.get(`/api/v1/devops-connectors/${connId}/sast/commits?${p}`)
      .then(r => { setCommits(r.data.commits || []); setWarning(r.data.warning || '') }).catch(() => setWarning('could not list commits'))
  }, [connId, repo, branch, refreshKey])
  return (
    <div className="flex flex-col gap-1">
      <label className="text-2xs uppercase tracking-wider text-siem-muted font-semibold">Commit</label>
      <select value={value} onChange={e => onChange(e.target.value)} title={warning || 'Latest scans the branch and updates its findings; a commit is scanned as a snapshot'}
        className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text font-mono focus:outline-none focus:border-siem-accent max-w-[340px]">
        <option value="">Latest (branch head)</option>
        {commits.map(c => (
          <option key={c.sha} value={c.sha}>
            {short(c.sha)} · {(c.message || '').slice(0, 48)}{c.author ? ` · ${c.author}` : ''}{c.scanned_at ? ' · scanned' : ''}
          </option>
        ))}
      </select>
    </div>
  )
}

// A confirmation for actions that send code to the AI model.
export function TokenConfirm({ title, children, confirmLabel = 'Continue', onConfirm, onClose }) {
  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-siem-surface border border-siem-border rounded-xl max-w-md w-full p-5 space-y-3" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 text-sm font-semibold text-siem-text">
          <AlertTriangle size={15} className="text-amber-400" />{title}
        </div>
        <div className="text-xs text-siem-muted space-y-2">{children}</div>
        <div className="flex justify-end gap-2 pt-1">
          <button onClick={onClose} className="px-3 py-1.5 text-xs rounded-lg border border-siem-border text-siem-text hover:border-siem-accent">Cancel</button>
          <button onClick={() => { onClose(); onConfirm() }} className="px-3 py-1.5 text-xs rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-semibold">{confirmLabel}</button>
        </div>
      </div>
    </div>
  )
}

const sevCls = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-sky-400', info: 'text-siem-muted' }

function CompareView({ connId, repo, scan, onClose }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    const p = new URLSearchParams({ repo, sha: scan.sha }); if (scan.branch) p.set('branch', scan.branch)
    api.get(`/api/v1/devops-connectors/${connId}/sast/commit-scans/compare?${p}`)
      .then(r => setData(r.data)).catch(e => setError(e.response?.data?.error || 'Compare failed'))
  }, [connId, repo, scan])
  const list = (fs, empty) => fs.length === 0 ? <div className="text-siem-muted/60 py-1">{empty}</div> : (
    <div className="divide-y divide-siem-border/40 max-h-64 overflow-auto">
      {fs.map((f, i) => (
        <div key={i} className="py-1.5 flex gap-2">
          <span className={`uppercase font-semibold w-16 shrink-0 ${sevCls[f.severity] || ''}`}>{f.severity}</span>
          <span className="text-siem-text">{f.title}</span>
          <span className="text-siem-muted font-mono ml-auto truncate">{f.file}{f.line ? `:${f.line}` : ''}</span>
        </div>
      ))}
    </div>
  )
  return (
    <div className="border border-siem-accent/30 rounded-lg p-3 mt-2 text-xs space-y-3">
      <div className="flex items-center gap-2">
        <GitCompare size={13} className="text-siem-accent" />
        <span className="text-siem-text font-semibold">{short(scan.sha)} compared with {data?.branch || scan.branch || 'the branch'}</span>
        {data && <span className="text-siem-muted">· branch scanned {ago(data.branch_scanned_at)} · {data.unchanged} unchanged</span>}
        <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={13} /></button>
      </div>
      {error && <div className="text-amber-400">{error}</div>}
      {data?.warning && <div className="text-amber-400/90">{data.warning}</div>}
      {data && (
        <div className="grid md:grid-cols-2 gap-3">
          <div>
            <div className="text-2xs uppercase tracking-wider text-emerald-400 font-semibold mb-1">Fixed since ({data.fixed.length})</div>
            {list(data.fixed, 'Nothing from this commit has been fixed.')}
          </div>
          <div>
            <div className="text-2xs uppercase tracking-wider text-red-400 font-semibold mb-1">New since ({data.new.length})</div>
            {list(data.new, 'No new findings on the branch.')}
          </div>
        </div>
      )}
    </div>
  )
}

export function CommitScansPanel({ connId, repo, viewing, onView, refreshKey, canDelete = true }) {
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState([])
  const [keep, setKeep] = useState(50)
  const [compare, setCompare] = useState(null)
  const [error, setError] = useState('')
  const load = () => {
    if (!repo) return
    api.get(`/api/v1/devops-connectors/${connId}/sast/commit-scans?${new URLSearchParams({ repo })}`)
      .then(r => { setRows(r.data.commit_scans || []); setKeep(r.data.keep || 50) }).catch(() => setRows([]))
  }
  useEffect(() => { setRows([]); setCompare(null); load() }, [connId, repo, refreshKey]) // eslint-disable-line react-hooks/exhaustive-deps
  if (!repo) return null
  const pin = async (s) => {
    setError('')
    try { await api.post(`/api/v1/devops-connectors/${connId}/sast/commit-scans/pin?${new URLSearchParams({ repo, sha: s.sha, pinned: s.pinned ? '0' : '1' })}`); load() }
    catch (e) { setError(e.response?.data?.error || 'Could not change the pin') }
  }
  const del = async (s) => {
    setError('')
    try { await api.delete(`/api/v1/devops-connectors/${connId}/sast/commit-scans?${new URLSearchParams({ repo, sha: s.sha })}`); load() }
    catch (e) { setError(e.response?.data?.error || 'Could not delete') }
  }
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center gap-2 px-4 py-2.5 text-xs text-siem-text">
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <GitCommit size={13} className="text-siem-accent" />
        <span className="font-semibold">Commit scans</span>
        <span className="text-siem-muted">({rows.length})</span>
        <span className="ml-auto text-2xs text-siem-muted">snapshots of single commits · the newest {keep} are kept, plus pinned ones</span>
      </button>
      {open && (
        <div className="px-4 pb-3 text-xs">
          {error && <div className="text-amber-400 mb-2">{error}</div>}
          {rows.length === 0 ? (
            <div className="text-siem-muted/70 py-2">No commit scans yet. Pick a commit in the Commit list above and run the scan.</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="text-2xs uppercase tracking-wider text-siem-muted/70 text-left">
                  <th className="py-1 font-semibold">Commit</th><th className="font-semibold">Message</th><th className="font-semibold">Author</th>
                  <th className="font-semibold">Scanned</th><th className="font-semibold text-right">C / H / M · total</th><th></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-siem-border/40">
                {rows.map(s => (
                  <tr key={s.sha} className={viewing === '@' + s.sha ? 'bg-siem-accent/5' : ''}>
                    <td className="py-1.5 font-mono text-siem-text whitespace-nowrap">
                      {s.pinned && <Pin size={10} className="inline mr-1 text-amber-400" />}{short(s.sha)}
                      {s.branch && <span className="text-siem-muted ml-1">({s.branch})</span>}
                    </td>
                    <td className="text-siem-text truncate max-w-[260px]" title={s.message}>{s.message || '—'}</td>
                    <td className="text-siem-muted">{s.author || '—'}</td>
                    <td className="text-siem-muted whitespace-nowrap">{ago(s.scanned_at)}</td>
                    <td className="text-right font-mono whitespace-nowrap">
                      <span className="text-red-400">{s.critical_count}</span> / <span className="text-orange-400">{s.high_count}</span> / <span className="text-yellow-400">{s.medium_count}</span>
                      <span className="text-siem-muted"> · {s.finding_count}</span>
                    </td>
                    <td className="text-right whitespace-nowrap pl-2">
                      <span className="inline-flex gap-2 text-siem-muted">
                        <button title="Show this commit's findings" onClick={() => onView('@' + s.sha)} className="hover:text-siem-text"><Eye size={13} /></button>
                        <button title="Compare with the branch's current result" onClick={() => setCompare(compare?.sha === s.sha ? null : s)} className="hover:text-siem-text"><GitCompare size={13} /></button>
                        <button title={s.pinned ? 'Unpin (it can then be pruned)' : 'Pin: never prune this scan'} onClick={() => pin(s)} className="hover:text-amber-400">
                          {s.pinned ? <PinOff size={13} /> : <Pin size={13} />}
                        </button>
                        {canDelete && <button title="Delete this commit scan" onClick={() => del(s)} className="hover:text-red-400"><Trash2 size={13} /></button>}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {compare && <CompareView connId={connId} repo={repo} scan={compare} onClose={() => setCompare(null)} />}
        </div>
      )}
    </div>
  )
}
