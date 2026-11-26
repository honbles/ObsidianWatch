import { useEffect, useState } from 'react'
import { RefreshCw, Save } from 'lucide-react'
import api from '../../api/client'
import { Section, StatePill, Field, relTime } from '../../components/ui'
import { isAdminUser } from '../../components/ResponseActions.jsx'

// Prevention: agents match their own connections, files, processes and DNS
// answers against the indicator set the server publishes. The server writes
// no policy to hosts; each type is off, audit (report only) or enforce.

const TYPES = [
  ['ip', 'Malicious IP addresses', 'Linux refuses the connection before it is made. Windows and macOS block the address once the connection is seen.'],
  ['hash', 'Malicious files', 'Listed files are quarantined when they arrive; a listed program is killed when it starts.'],
  ['domain', 'Malicious domains', 'The addresses a listed domain resolves to are blocked. The lookup itself is not prevented.'],
]

const SOURCES = { threatfox: 'ThreatFox', feodo: 'Feodo Tracker', manual: 'Manual IOCs', fleet: 'Fleet verdicts' }

const MODES = [
  ['off', 'Off'],
  ['audit', 'Audit (alert only)'],
  ['enforce', 'Enforce'],
]

export default function Prevention() {
  const admin = isAdminUser()
  const [data, setData] = useState(null)
  const [pol, setPol] = useState(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const load = async () => {
    try {
      const { data } = await api.get('/api/v1/prevention')
      setData(data); setPol(data.policy)
    } catch (e) { setMsg(e.response?.data?.error || 'Could not load the prevention policy') }
  }
  useEffect(() => { load() }, [])
  if (!pol) return <div className="t3" style={{ padding: 14 }}>{msg || 'Loading…'}</div>
  const set = data.set || {}
  const enforcing = TYPES.some(([k]) => pol[k] === 'enforce')
  const save = async () => {
    if (enforcing && !(pol.enforce_tags || []).length &&
      !window.confirm('Enforce applies to every host because no canary tag is set. Continue?')) return
    setBusy(true); setMsg('')
    try {
      const { data } = await api.put('/api/v1/prevention', pol)
      setPol(data); setMsg('Saved. Agents pick it up within 15 minutes.')
      load()
    } catch (e) { setMsg(e.response?.data?.error || 'Could not save') }
    setBusy(false)
  }
  const upd = (k, v) => setPol(p => ({ ...p, [k]: v }))
  const counts = { ip: set.ips, hash: set.hashes, domain: set.domains }
  const bySrc = set.by_source || {}

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <Section title="Indicator types" sub="What agents match and what they do on a match"
        actions={<button className="ow-btn quiet" onClick={load}><RefreshCw size={13}/>Refresh</button>}>
        <p className="t2" style={{ margin: '0 0 12px', fontSize: 13 }}>
          Audit alerts only; enforce also blocks.
        </p>
        <div style={{ display: 'grid', gap: 10 }}>
          {TYPES.map(([k, label, how]) => (
            <div key={k} className="ow-card" style={{ padding: 12, display: 'grid', gridTemplateColumns: '1fr 190px', gap: 12, alignItems: 'start' }}>
              <div>
                <div style={{ fontWeight: 600, display: 'flex', gap: 8, alignItems: 'center' }}>
                  {label}
                  <StatePill state={pol[k] === 'enforce' ? 'crit' : pol[k] === 'audit' ? 'warn' : 'none'}>{MODES.find(m => m[0] === pol[k])?.[1]}</StatePill>
                </div>
                <div className="t3" style={{ fontSize: 12, marginTop: 4 }}>{how}</div>
                <div className="t3" style={{ fontSize: 11.5, marginTop: 6 }}>
                  {counts[k] ?? 0} indicators{Object.keys(bySrc[k] || {}).length > 0 && <> from {Object.keys(bySrc[k]).map(s => SOURCES[s] || s).join(', ')}</>}
                </div>
              </div>
              <select className="input" value={pol[k]} disabled={!admin} onChange={e => upd(k, e.target.value)} aria-label={`${label} mode`}>
                {MODES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Scope">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12 }}>
          <Field label="Enforce only on hosts tagged" hint="Empty means every host. Other hosts stay in audit.">
            <input className="input" disabled={!admin} value={(pol.enforce_tags || []).join(', ')}
              onChange={e => upd('enforce_tags', e.target.value.split(',').map(s => s.trim()).filter(Boolean))} placeholder="canary"/>
          </Field>
          <Field label="Extra folders to check for new files" hint="Comma-separated absolute paths, added to downloads, desktop, temp and removable media.">
            <input className="input mono" disabled={!admin} value={(pol.hash_watch_dirs || []).join(', ')}
              onChange={e => upd('hash_watch_dirs', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
              placeholder="/srv/uploads, D:\Shares\Incoming"/>
          </Field>
        </div>
        <p className="t3" style={{ fontSize: 12, margin: '12px 0 0' }}>
          Indicators come from ThreatFox, Feodo Tracker, manual IOCs (Threat intelligence) and files the fleet's reputation lookups judged malicious.
          Private addresses, the ObsidianWatch server and DNS resolvers are never blocked.
          {pol.updated_by && <> Last changed by {pol.updated_by} {relTime(pol.updated_at)}.</>}
        </p>
      </Section>

      {admin ? (
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button className="ow-btn primary" onClick={save} disabled={busy}><Save size={13}/>{busy ? 'Saving…' : 'Save policy'}</button>
          {msg && <span className="t3" style={{ fontSize: 12.5 }}>{msg}</span>}
        </div>
      ) : <div className="t3" style={{ fontSize: 12.5 }}>Only administrators can change the prevention policy.</div>}
    </div>
  )
}
