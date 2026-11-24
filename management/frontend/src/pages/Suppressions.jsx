import { useEffect, useState, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { EyeOff, RefreshCw, Trash2, Pencil, Plus } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'
import { PageHeader, Num, DenseTable, Drawer, Field } from '../components/ui'

const EMPTY = {
  rule_id: '', match_mode: 'exact', host: '', process_name: '', image_path_glob: '', parent_process: '',
  user_name: '', cmdline_contains: '', file_path_glob: '', reason: '', expires_in_days: 30, permanent: false,
}

const FIELDS = [
  ['host', 'Host', 'exact host name'],
  ['process_name', 'Process', 'exact process name'],
  ['image_path_glob', 'Image path', 'glob, e.g. /usr/sbin/modprobe'],
  ['parent_process', 'Parent process', 'basename, e.g. ccmexec.exe'],
  ['user_name', 'User', 'exact or glob'],
  ['cmdline_contains', 'Command line contains', 'case-insensitive text'],
  ['file_path_glob', 'File / registry path', 'glob (file and registry events)'],
]

function scopeSummary(r) {
  const parts = FIELDS.map(([k, label]) => r[k] ? `${label}: ${r[k]}` : null).filter(Boolean)
  return parts.length ? parts.join(' · ') : 'any event'
}

export default function Suppressions() {
  const [params] = useSearchParams()
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [form, setForm] = useState(null)         // null = closed
  const [editId, setEditId] = useState(null)
  const [covers, setCovers] = useState(null)     // rule IDs the form would suppress
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/suppressions')
      setRules(data.rules || [])
    } finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  // "Suppress this alert" links pre-fill the form from the alert's source event.
  useEffect(() => {
    if (!params.get('rule')) return
    setForm({
      ...EMPTY,
      rule_id: params.get('rule') || '',
      host: params.get('host') || '',
      process_name: params.get('process') || '',
      parent_process: params.get('parent') || '',
      user_name: params.get('user') || '',
    })
  }, [params])

  const preview = useCallback(async (f) => {
    if (!f?.rule_id) { setCovers(null); return }
    try {
      const { data } = await api.get('/api/v1/suppressions/preview', { params: { rule_id: f.rule_id, match_mode: f.match_mode } })
      setCovers(data)
    } catch { setCovers(null) }
  }, [])

  useEffect(() => { if (form) preview(form) }, [form?.rule_id, form?.match_mode]) // eslint-disable-line

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const openEdit = (r) => {
    setEditId(r.id)
    setError('')
    setForm({
      ...EMPTY, ...r,
      permanent: !!r.permanent,
      expires_in_days: r.expires_at
        ? Math.max(1, Math.ceil((new Date(r.expires_at) - Date.now()) / 86400000)) : 30,
    })
  }

  const openNew = () => { setEditId(null); setError(''); setForm({ ...EMPTY }) }

  const save = async () => {
    setError('')
    if (form.permanent && !window.confirm('A permanent suppression never expires. It will be recorded in the audit log. Continue?')) return
    setSaving(true)
    try {
      const body = { ...form }
      if (body.permanent) delete body.expires_in_days
      else body.expires_in_days = parseInt(body.expires_in_days, 10) || 0
      delete body.expires_at; delete body.suppressed_30d; delete body.id; delete body.created_at; delete body.created_by
      if (editId) await api.put(`/api/v1/suppressions/${editId}`, body)
      else await api.post('/api/v1/suppressions', body)
      setForm(null); setEditId(null)
      load()
    } catch (e) {
      setError(e.response?.data?.error || 'Could not save the suppression')
    } finally { setSaving(false) }
  }

  const remove = async (r) => {
    if (!window.confirm(`Delete the suppression for ${r.rule_id}?`)) return
    await api.delete(`/api/v1/suppressions/${r.id}`).catch(() => {})
    load()
  }

  const soon = (r) => !r.permanent && r.expires_at && new Date(r.expires_at) - Date.now() < 7 * 86400e3
  const total30 = rules.reduce((a, r) => a + (r.suppressed_30d || 0), 0)
  const permanent = rules.filter(r => r.permanent || !r.expires_at).length
  return (
    <div>
      <PageHeader title="Suppressions"
        sub={<>Hide known-benign alerts from endpoint rules, IOC matches (<span className="mono">IOC:source:type</span>) and Sigma rules (<span className="mono">SIGMA:rule-id</span>). Every field you fill in must match. Suppressed matches are counted, never silently dropped.</>}
        actions={<>
          <button className="ow-btn" onClick={load}><RefreshCw size={13}/>Refresh</button>
          <button className="ow-btn primary" onClick={openNew}><Plus size={13}/>New suppression</button>
        </>}
        nums={<>
          <Num k="Suppressions" v={rules.length}/>
          <Num k="Alerts suppressed, 30 days" v={total30.toLocaleString()}/>
          <Num k="Expiring within 7 days" v={rules.filter(soon).length} tone={rules.some(soon) ? 'warn' : undefined}/>
          <Num k="Permanent" v={permanent} tone={permanent ? 'warn' : undefined} title="Permanent suppressions never expire; review them periodically"/>
        </>}/>
      <div className="ow-body">
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <DenseTable rows={loading ? [] : [...rules].sort((a, b) => (b.suppressed_30d || 0) - (a.suppressed_30d || 0))} rowKey={r => r.id} onRow={openEdit} current={editId}
            rowState={r => soon(r) ? 'warn' : null}
            empty={loading ? 'Loading…' : 'No suppressions.'}
            cols={[
              { key: 'rule', label: 'Rule', width: 'minmax(160px, 1fr)', render: r => <span className="mono t1">{r.rule_id}{r.match_mode === 'prefix' && <span className="t3"> (prefix)</span>}</span> },
              { key: 'scope', label: 'Scope', width: 'minmax(220px, 1.6fr)', render: r => <span className="t2">{scopeSummary(r)}</span>, title: r => scopeSummary(r) },
              { key: 'reason', label: 'Reason', width: 'minmax(200px, 1.4fr)', render: r => <span className="t1">{r.reason} <span className="t3">· {r.created_by}</span></span>, title: r => r.reason },
              { key: 'exp', label: 'Expires', width: '110px', render: r => r.permanent ? <span className="c-warn">Never</span> : r.expires_at ? <span className={soon(r) ? 'c-warn' : 't2'}>{format(new Date(r.expires_at), 'yyyy-MM-dd')}</span> : <span className="c-warn">Never (legacy)</span> },
              { key: 'n', label: 'Hidden, 30 d', width: '96px', align: 'right', render: r => <span className="mono">{(r.suppressed_30d || 0).toLocaleString()}</span> },
              { key: 'x', label: '', width: '76px', render: r => <button className="ow-btn quiet" style={{ height: 24, color: 'var(--crit)' }} onClick={e => { e.stopPropagation(); remove(r) }}><Trash2 size={13}/>Delete</button> },
            ]}/>
        </div>
      </div>

      <Drawer open={!!form} onClose={() => { setForm(null); setEditId(null) }} label={editId ? 'Edit suppression' : 'New suppression'} width={600}>
        {form && (
          <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 12, overflowY: 'auto' }}>
            <div style={{ fontSize: 17, fontWeight: 600 }}>{editId ? 'Edit suppression' : 'New suppression'}</div>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
              <Field label="Rule ID"><input className="input mono" value={form.rule_id} onChange={e => set('rule_id', e.target.value)} placeholder="L-T1547.006, IOC:otx:hash or SIGMA:abc"/></Field>
              <Field label="Match"><select className="input" value={form.match_mode} onChange={e => set('match_mode', e.target.value)}>
                <option value="exact">Exact ID</option><option value="prefix">ID prefix (8+ characters)</option></select></Field>
            </div>
            {covers && (
              <div className="ow-card" style={{ padding: '8px 12px', background: 'var(--s2)', fontSize: 12.5 }}>
                {covers.dynamic ? 'Matches alerts raised under this IOC or Sigma namespace.'
                  : covers.covers.length === 0 ? <span className="c-crit">No registered rule has this ID.</span>
                    : <>Covers {covers.covers.length} rule{covers.covers.length === 1 ? '' : 's'}: <span className="mono t1">{covers.covers.join(', ')}</span></>}
              </div>
            )}
            <div className="ow-lbl" style={{ marginTop: 4 }}>Scope · all filled fields must match</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {FIELDS.map(([k, label, ph]) => <Field key={k} label={label}><input className="input mono" value={form[k] || ''} onChange={e => set(k, e.target.value)} placeholder={ph}/></Field>)}
            </div>
            <Field label="Reason" hint="Required. Shown to whoever reviews this later."><input className="input" value={form.reason} onChange={e => set('reason', e.target.value)} maxLength={500}/></Field>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }} className="t2">Expires after
                <input type="number" min="1" max="365" className="input" style={{ width: 80 }} disabled={form.permanent} value={form.expires_in_days} onChange={e => set('expires_in_days', e.target.value)}/> days (max 365)</label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8 }} className="t2"><input type="checkbox" className="ow-check" checked={form.permanent} onChange={e => set('permanent', e.target.checked)}/>Permanent</label>
            </div>
            {error && <div className="c-crit" style={{ fontSize: 12.5 }}>{error}</div>}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="ow-btn quiet" onClick={() => { setForm(null); setEditId(null) }}>Cancel</button>
              <button className="ow-btn primary" onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Save suppression'}</button>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}
