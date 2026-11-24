import { useEffect, useMemo, useState } from 'react'
import { Plus, RefreshCw, Copy, Check as CheckIcon } from 'lucide-react'
import api from '../../api/client'
import { Section, DenseTable, StatePill, Dialog, Field, relTime } from '../../components/ui'

// Agent enrollment (spec A1, A4): tokens agents use once at first boot to get
// their own certificate, and the identities issued with them.

function tokenState(t) {
  if (t.revoked_at) return { state: 'none', label: 'Revoked' }
  if (new Date(t.expires_at) <= new Date()) return { state: 'none', label: 'Expired' }
  if (t.uses >= t.max_uses) return { state: 'none', label: 'Used up' }
  return { state: 'ok', label: 'Active' }
}

function identityState(i) {
  if (i.revoked_at) return { state: 'crit', label: 'Revoked' }
  const left = new Date(i.cert_not_after) - new Date()
  if (left <= 0) return { state: 'warn', label: 'Certificate expired' }
  if (left < 7 * 864e5) return { state: 'warn', label: 'Renewal due' }
  return { state: 'ok', label: 'Valid' }
}

function CreateTokenDialog({ onClose, onCreated }) {
  const [label, setLabel] = useState('')
  const [ttl, setTtl] = useState('168')
  const [uses, setUses] = useState('50')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [made, setMade] = useState(null)
  const [copied, setCopied] = useState(false)

  const submit = async () => {
    setBusy(true); setErr('')
    try {
      const { data } = await api.post('/api/v1/enrollment-tokens', { label, ttl_hours: Number(ttl), max_uses: Number(uses) })
      setMade(data.token); onCreated()
    } catch (e) { setErr(e.response?.data?.error || 'Could not create the token') }
    setBusy(false)
  }
  const copy = () => { navigator.clipboard?.writeText(made); setCopied(true); setTimeout(() => setCopied(false), 1500) }

  if (made) return (
    <Dialog title="Enrollment token created" onClose={onClose} width={560}
      footer={<button className="ow-btn primary" onClick={onClose}>Done</button>}>
      <p style={{ margin: '0 0 10px', color: 'var(--t2)' }}>Copy it now. It is stored only as a hash and cannot be shown again.</p>
      <div style={{ display: 'flex', gap: 8 }}>
        <input className="input mono" readOnly value={made} style={{ flex: 1 }} onFocus={e => e.target.select()} aria-label="Enrollment token"/>
        <button className="ow-btn" onClick={copy}>{copied ? <CheckIcon size={13}/> : <Copy size={13}/>}{copied ? 'Copied' : 'Copy'}</button>
      </div>
      <p style={{ margin: '12px 0 0', fontSize: 12, color: 'var(--t3)' }}>
        Put it in the agent's install configuration. Each host enrolls once at first boot and gets its own certificate and a random agent ID, so a cloned image still yields one identity per machine.
      </p>
    </Dialog>
  )

  const bad = !(Number(ttl) >= 1 && Number(ttl) <= 2160) || !(Number(uses) >= 1 && Number(uses) <= 100000)
  return (
    <Dialog title="New enrollment token" onClose={onClose}
      footer={<><button className="ow-btn quiet" onClick={onClose}>Cancel</button>
        <button className="ow-btn primary" disabled={busy || bad} onClick={submit}>{busy ? 'Creating…' : 'Create token'}</button></>}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <Field label="Label" hint="Where it will be used, e.g. “Linux web tier rollout”."><input className="input" value={label} maxLength={120} onChange={e => setLabel(e.target.value)}/></Field>
        <div style={{ display: 'flex', gap: 12 }}>
          <Field label="Valid for (hours)" hint="1 to 2160 (90 days)"><input className="input mono" value={ttl} onChange={e => setTtl(e.target.value.replace(/\D/g, ''))}/></Field>
          <Field label="Maximum enrollments" hint="Hosts that may use it"><input className="input mono" value={uses} onChange={e => setUses(e.target.value.replace(/\D/g, ''))}/></Field>
        </div>
        {err && <div style={{ color: 'var(--crit)', fontSize: 12.5 }}>{err}</div>}
      </div>
    </Dialog>
  )
}

function RevokeIdentityDialog({ identity, onClose, onDone }) {
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const submit = async () => {
    setBusy(true); setErr('')
    try { await api.post(`/api/v1/agent-identities/${encodeURIComponent(identity.agent_id)}/revoke`, { reason }); onDone() }
    catch (e) { setErr(e.response?.data?.error || 'Revoke failed'); setBusy(false) }
  }
  return (
    <Dialog title={`Revoke ${identity.hostname || identity.agent_id}`} onClose={onClose}
      footer={<><button className="ow-btn quiet" onClick={onClose}>Cancel</button>
        <button className="ow-btn primary" disabled={busy || !reason.trim()} onClick={submit}>{busy ? 'Revoking…' : 'Revoke identity'}</button></>}>
      <p style={{ margin: '0 0 12px', color: 'var(--t2)' }}>
        The agent's live response tunnel closes now and ingest refuses its certificate within a minute. The host has to enroll again with a new token to report.
      </p>
      <Field label="Reason (audited)"><input className="input" value={reason} maxLength={500} onChange={e => setReason(e.target.value)} placeholder="Host reimaged, identity copied, decommissioned…"/></Field>
      {err && <div style={{ color: 'var(--crit)', fontSize: 12.5, marginTop: 8 }}>{err}</div>}
    </Dialog>
  )
}

export default function AgentEnrollment() {
  const [tokens, setTokens] = useState([])
  const [ids, setIds] = useState([])
  const [err, setErr] = useState('')
  const [creating, setCreating] = useState(false)
  const [revoking, setRevoking] = useState(null)
  const [q, setQ] = useState('')

  const load = () => {
    setErr('')
    Promise.all([api.get('/api/v1/enrollment-tokens'), api.get('/api/v1/agent-identities')])
      .then(([t, i]) => { setTokens(t.data.tokens || []); setIds(i.data.identities || []) })
      .catch(e => setErr(e.response?.status === 403 ? 'Only administrators can manage agent enrollment.' : 'Could not load enrollment data.'))
  }
  useEffect(load, [])

  const revokeToken = async (t) => {
    try { await api.delete(`/api/v1/enrollment-tokens/${t.id}`); load() } catch { setErr('Could not revoke the token.') }
  }

  const shown = useMemo(() => {
    const s = q.trim().toLowerCase()
    return s ? ids.filter(i => (i.hostname + ' ' + i.agent_id + ' ' + (i.token_label || '')).toLowerCase().includes(s)) : ids
  }, [ids, q])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {err && <div className="ow-card" style={{ padding: 12, color: 'var(--crit)' }}>{err}</div>}

      <Section title="Enrollment tokens" sub="Revocable, expiring and use-limited. Agents send one with a key request at first boot."
        actions={<div style={{ display: 'flex', gap: 8, marginLeft: 'auto' }}>
          <button className="ow-btn" onClick={load}><RefreshCw size={13}/>Refresh</button>
          <button className="ow-btn primary" onClick={() => setCreating(true)}><Plus size={13}/>New token</button></div>} pad={false}>
        <DenseTable rowKey={t => t.id} rows={tokens} empty="No enrollment tokens yet"
          cols={[
            { key: 'label', label: 'Label', width: '2fr', render: t => t.label || <span className="t3">Unlabelled</span> },
            { key: 'state', label: 'State', width: '110px', render: t => { const s = tokenState(t); return <StatePill state={s.state}>{s.label}</StatePill> } },
            { key: 'uses', label: 'Used', width: '100px', render: t => <span className="mono">{t.uses} / {t.max_uses}</span> },
            { key: 'exp', label: 'Expires', width: '130px', render: t => <span title={t.expires_at}>{relTime(t.expires_at)}</span> },
            { key: 'by', label: 'Created by', width: '140px', render: t => <>{t.created_by || '—'} <span className="t3">{relTime(t.created_at)}</span></> },
            { key: 'act', label: '', width: '90px', align: 'right', render: t => !t.revoked_at && <button className="ow-btn quiet" style={{ height: 24 }} onClick={() => revokeToken(t)}>Revoke</button> },
          ]}/>
      </Section>

      <Section title="Enrolled agents" sub={`${ids.length} identities · ${ids.filter(i => i.revoked_at).length} revoked`}
        actions={<label className="ow-field" style={{ marginLeft: 'auto', width: 240, height: 28 }}><input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by host, ID or token" aria-label="Filter identities"/></label>} pad={false}>
        <DenseTable rowKey={i => i.agent_id} rows={shown} empty="No agent has enrolled yet"
          rowState={i => i.revoked_at ? 'crit' : null}
          cols={[
            { key: 'host', label: 'Host', width: '1.4fr', render: i => <>{i.hostname || '—'} <span className="t3">{i.os}</span></> },
            { key: 'id', label: 'Agent ID', width: '2fr', render: i => <span className="mono" style={{ fontSize: 12 }}>{i.agent_id}</span> },
            { key: 'state', label: 'Certificate', width: '150px', render: i => { const s = identityState(i); return <StatePill state={s.state} title={i.revoke_reason || undefined}>{s.label}</StatePill> } },
            { key: 'exp', label: 'Expires', width: '120px', render: i => <span title={i.cert_not_after}>{relTime(i.cert_not_after)}</span> },
            { key: 'tok', label: 'Enrolled with', width: '1.2fr', render: i => <>{i.token_label || (i.token_id ? `token #${i.token_id}` : 'fleet key')} <span className="t3">{relTime(i.enrolled_at)}</span></> },
            { key: 'act', label: '', width: '90px', align: 'right', render: i => !i.revoked_at && <button className="ow-btn quiet" style={{ height: 24 }} onClick={() => setRevoking(i)}>Revoke</button> },
          ]}/>
      </Section>

      {creating && <CreateTokenDialog onClose={() => setCreating(false)} onCreated={load}/>}
      {revoking && <RevokeIdentityDialog identity={revoking} onClose={() => setRevoking(null)} onDone={() => { setRevoking(null); load() }}/>}
    </div>
  )
}
