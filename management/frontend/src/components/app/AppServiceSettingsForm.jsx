import { useState } from 'react'
import { appApi } from '../../api/app'
import { appIsAdmin, appLearning, appLearningText } from './appFormat'

const lines = (v) => (v || []).join('\n')
const unlines = (s) => s.split('\n').map(x => x.trim()).filter(Boolean)
const toLocal = (iso) => { if (!iso) return ''; const d = new Date(iso); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16) }

function Field({ label, hint, children }) {
  return (
    <label className="block">
      <span className="block text-xs font-medium text-siem-text mb-1">{label}</span>
      {children}
      {hint && <span className="block text-mini text-siem-muted mt-1">{hint}</span>}
    </label>
  )
}
const inputCls = 'w-full bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text disabled:opacity-60'

// Per-service settings (spec 11.3 Settings). Viewers see the values read-only.
// service: a row from the services API (with .settings); requests: requests seen recently (for learning status).
export default function AppServiceSettingsForm({ service, requests, onSaved, compact }) {
  const admin = appIsAdmin()
  const s0 = service.settings
  const [f, setF] = useState(() => ({
    exposure: s0.exposure, criticality: s0.criticality, data_sensitivity: s0.data_sensitivity,
    owner: s0.owner || '', notify_route: s0.notify_route || '',
    trusted_proxies: lines(s0.trusted_proxies), login_routes: lines(s0.login_routes),
    export_routes: lines(s0.export_routes), public_routes: lines(s0.public_routes),
    latency_target_ms: s0.latency_target_ms ?? '', error_budget_pct: s0.error_budget_pct ?? '',
    maintenance: (s0.maintenance || []).map(m => ({ start: toLocal(m.start), end: toLocal(m.end), reason: m.reason || '' })),
    store_client_ip: s0.store_client_ip, cleartext_users: !!s0.cleartext_users, db_statement_mode: s0.db_statement_mode || 'off', error_message_mode: s0.error_message_mode || 'off', reset_learning: false,
    samp_baseline: s0.sampling?.baseline_pct ?? '', samp_error_max: s0.sampling?.error_max_per_min || '', samp_flush: s0.sampling?.max_per_flush || '',
    slo_window: s0.slo?.window_days || '', slo_avail: s0.slo?.availability_target_pct ?? '', slo_lat: s0.slo?.latency_target_pct ?? '',
  }))
  const [state, setState] = useState({ saving: false, error: '', ok: false })
  const set = (k) => (e) => setF(v => ({ ...v, [k]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }))
  const learn = appLearning(service.first_seen, s0.learning_started, requests)

  const save = async () => {
    setState({ saving: true, error: '', ok: false })
    try {
      const body = {
        exposure: f.exposure, criticality: f.criticality, data_sensitivity: f.data_sensitivity,
        owner: f.owner, notify_route: f.notify_route,
        trusted_proxies: unlines(f.trusted_proxies), login_routes: unlines(f.login_routes),
        export_routes: unlines(f.export_routes), public_routes: unlines(f.public_routes),
        latency_target_ms: f.latency_target_ms === '' ? null : Number(f.latency_target_ms),
        error_budget_pct: f.error_budget_pct === '' ? null : Number(f.error_budget_pct),
        maintenance: f.maintenance.filter(m => m.start && m.end).map(m => ({ start: new Date(m.start).toISOString(), end: new Date(m.end).toISOString(), reason: m.reason })),
        store_client_ip: f.store_client_ip, cleartext_users: f.cleartext_users, db_statement_mode: f.db_statement_mode, error_message_mode: f.error_message_mode,
        sampling: { ...(f.samp_baseline === '' ? {} : { baseline_pct: Number(f.samp_baseline) }), error_max_per_min: Number(f.samp_error_max) || 0, max_per_flush: Number(f.samp_flush) || 0 },
        slo: { ...(f.slo_window === '' ? {} : { window_days: Number(f.slo_window) }), ...(f.slo_avail === '' ? {} : { availability_target_pct: Number(f.slo_avail) }), ...(f.slo_lat === '' ? {} : { latency_target_pct: Number(f.slo_lat) }) },
        learning_started: s0.learning_started || null, reset_learning: f.reset_learning,
      }
      const res = await appApi.saveSettings(service.id, body)
      setState({ saving: false, error: '', ok: true })
      onSaved && onSaved(res.settings)
    } catch (e) {
      setState({ saving: false, ok: false, error: e.response?.data?.error || e.message || 'Save failed' })
    }
  }
  const dis = !admin || state.saving
  const tier = service.tier || 0 // fields that only matter with OpenTelemetry (T1) or the security helper (T2) are hidden below them
  return (
    <div className="space-y-4">
      {!admin && <div className="text-xs text-amber-300">Read-only: changing settings needs the admin role.</div>}
      <div className={`grid gap-3 ${compact ? 'grid-cols-1' : 'grid-cols-1 md:grid-cols-3'}`}>
        <Field label="Exposure" hint={f.exposure === 'unknown' && s0.exposure_inferred && s0.exposure_inferred !== 'unknown' ? `Inferred ${s0.exposure_inferred}: ${s0.exposure_reason}. Choose a value to override.` : 'Internet-facing services raise alert severity one level.'}>
          <select className={inputCls} value={f.exposure} onChange={set('exposure')} disabled={dis}>
            <option value="unknown">unknown</option><option value="internet">internet</option><option value="internal">internal</option></select></Field>
        <Field label="Criticality" hint="High and critical raise severity one level.">
          <select className={inputCls} value={f.criticality} onChange={set('criticality')} disabled={dis}>
            {['low', 'normal', 'high', 'critical'].map(x => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Data sensitivity">
          <select className={inputCls} value={f.data_sensitivity} onChange={set('data_sensitivity')} disabled={dis}>
            {['normal', 'sensitive', 'regulated'].map(x => <option key={x}>{x}</option>)}</select></Field>
        <Field label="Owner"><input className={inputCls} value={f.owner} onChange={set('owner')} disabled={dis} maxLength={128} /></Field>
        <Field label="Operational notification route" hint="Where operational (APM-O) alerts go."><input className={inputCls} value={f.notify_route} onChange={set('notify_route')} disabled={dis} maxLength={256} /></Field>
        {tier >= 1 && <><Field label="Client IP storage" hint="Applied by agents from their build configuration; rebuild the agent for a change to take effect.">
          <select className={inputCls} value={f.store_client_ip} onChange={set('store_client_ip')} disabled={dis}>
            <option value="full">full address</option><option value="truncated">truncated (/24, /48)</option><option value="off">do not store</option></select></Field></>}
        {tier >= 1 && <><Field label="Trusted proxies" hint="One CIDR or address per line. A forwarded client address is trusted only from these."><textarea rows={3} className={inputCls} value={f.trusted_proxies} onChange={set('trusted_proxies')} disabled={dis} /></Field></>}
        {tier >= 1 && <><Field label="Login routes" hint="One route template per line, e.g. /login."><textarea rows={3} className={inputCls} value={f.login_routes} onChange={set('login_routes')} disabled={dis} /></Field></>}
        {tier >= 1 && <><Field label="Export routes"><textarea rows={3} className={inputCls} value={f.export_routes} onChange={set('export_routes')} disabled={dis} /></Field></>}
        {tier >= 1 && <><Field label="Public routes" hint="Routes expected to be reachable without authentication."><textarea rows={3} className={inputCls} value={f.public_routes} onChange={set('public_routes')} disabled={dis} /></Field></>}
        {tier >= 1 && <><Field label="Latency target (ms)"><input type="number" min="0" className={inputCls} value={f.latency_target_ms} onChange={set('latency_target_ms')} disabled={dis} /></Field></>}
        {tier >= 1 && <><Field label="Error budget (%)"><input type="number" min="0" max="100" step="0.1" className={inputCls} value={f.error_budget_pct} onChange={set('error_budget_pct')} disabled={dis} /></Field></>}
      </div>

      <div>
        <div className="text-xs font-medium text-siem-text mb-1">Maintenance windows</div>
        {f.maintenance.map((m, i) => (
          <div key={i} className="flex flex-wrap gap-2 mb-1.5">
            <input type="datetime-local" className={`${inputCls} !w-auto`} value={m.start} disabled={dis} onChange={e => setF(v => ({ ...v, maintenance: v.maintenance.map((x, j) => j === i ? { ...x, start: e.target.value } : x) }))} />
            <input type="datetime-local" className={`${inputCls} !w-auto`} value={m.end} disabled={dis} onChange={e => setF(v => ({ ...v, maintenance: v.maintenance.map((x, j) => j === i ? { ...x, end: e.target.value } : x) }))} />
            <input className={`${inputCls} !w-48`} placeholder="reason" value={m.reason} disabled={dis} onChange={e => setF(v => ({ ...v, maintenance: v.maintenance.map((x, j) => j === i ? { ...x, reason: e.target.value } : x) }))} />
            <button className="btn btn-ghost" disabled={dis} onClick={() => setF(v => ({ ...v, maintenance: v.maintenance.filter((_, j) => j !== i) }))}>Remove</button>
          </div>
        ))}
        <button className="btn btn-ghost" disabled={dis || f.maintenance.length >= 50}
          onClick={() => setF(v => ({ ...v, maintenance: [...v.maintenance, { start: '', end: '', reason: '' }] }))}>Add window</button>
      </div>

{tier >= 2 && <>      <label className="flex items-start gap-2 text-xs text-siem-muted">
        <input type="checkbox" checked={f.cleartext_users} onChange={set('cleartext_users')} disabled={dis} />
        <span><b className="text-siem-text">Show user identifiers in clear text</b> - off by default (identifiers are hashed). Applied by agents from their build configuration.</span>
      </label></>}

{tier >= 1 && <>      <label className="flex items-start gap-2 text-xs text-siem-muted">
        <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={f.db_statement_mode} onChange={set('db_statement_mode')} disabled={dis}>
          <option value="off">Database: names only</option>
          <option value="fingerprint">Database: statement fingerprints</option>
        </select>
        <span>Fingerprints send the statement with every value removed on the host: <span className="font-mono">WHERE id = 5</span> becomes <span className="font-mono">where id = ?</span>.</span>
      </label></>}

{tier >= 1 && <>      <label className="flex items-start gap-2 text-xs text-siem-muted">
        <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={f.error_message_mode} onChange={set('error_message_mode')} disabled={dis}>
          <option value="off">Errors: no message</option>
          <option value="masked">Errors: masked message</option>
        </select>
        <span>A masked message replaces numbers, quoted text, emails, ids and long tokens with <span className="font-mono">?</span>. Off by default.</span>
      </label></>}

      {tier >= 1 && <>
      <div className="rounded-lg border border-siem-border p-3 text-xs space-y-2">
        <div className="text-siem-text font-medium">Service level objective</div>
        <div className="text-siem-muted">Empty fields use the defaults: availability 100 minus the error budget, 95% of requests under the latency target, 28 days.</div>
        <div className="flex gap-3 flex-wrap">
          <label className="flex flex-col gap-1 text-siem-muted">Availability target (%)
            <input className="input w-32" type="number" min="1" max="99.999" step="0.01" placeholder="99.9" value={f.slo_avail} onChange={set('slo_avail')} disabled={dis} /></label>
          <label className="flex flex-col gap-1 text-siem-muted">Latency target share (%)
            <input className="input w-32" type="number" min="1" max="99.999" step="0.1" placeholder="95" value={f.slo_lat} onChange={set('slo_lat')} disabled={dis} /></label>
          <label className="flex flex-col gap-1 text-siem-muted">Window
            <select className="bg-siem-surface2 border border-siem-border rounded px-1.5 py-1 text-siem-text" value={f.slo_window} onChange={set('slo_window')} disabled={dis}><option value="">28 days</option><option value="7">7 days</option><option value="28">28 days (explicit)</option></select></label>
        </div>
      </div>

      <div className="rounded-lg border border-siem-border p-3 text-xs space-y-2">
        <div className="text-siem-text font-medium">Trace sampling</div>
        <div className="text-siem-muted">Errors, slow and security traces are always kept. Applied by the agent within 5 minutes.</div>
        <div className="flex gap-3 flex-wrap">
          <label className="flex flex-col gap-1 text-siem-muted">Ordinary traces kept (%)
            <input className="input w-32" type="number" min="0" max="100" step="0.1" placeholder="1" value={f.samp_baseline} onChange={set('samp_baseline')} disabled={dis} /></label>
          <label className="flex flex-col gap-1 text-siem-muted">Error traces per minute (max)
            <input className="input w-32" type="number" min="0" placeholder="all" value={f.samp_error_max} onChange={set('samp_error_max')} disabled={dis} /></label>
          <label className="flex flex-col gap-1 text-siem-muted">Traces per flush (max)
            <input className="input w-32" type="number" min="0" max="5000" placeholder="500" value={f.samp_flush} onChange={set('samp_flush')} disabled={dis} /></label>
        </div>
      </div>

      </>}
      <div className="rounded-lg border border-siem-border p-3 text-xs flex items-center justify-between gap-3 flex-wrap">
        <div><span className="text-siem-muted">Learning: </span>{appLearningText(learn, service.tier)}</div>
        <label className="flex items-center gap-2 text-siem-muted"><input type="checkbox" checked={f.reset_learning} onChange={set('reset_learning')} disabled={dis} /> Restart learning on save</label>
      </div>

      {tier === 0 && <div className="text-xs text-siem-muted">Route, latency, SLO, sampling and privacy settings appear once this service sends OpenTelemetry (Tier 1); they have no effect on a host-only service.</div>}
      <div className="flex items-center gap-3">
        <button className="btn btn-primary" onClick={save} disabled={dis}>{state.saving ? 'Saving…' : 'Save settings'}</button>
        {state.ok && <span className="text-xs text-emerald-300">Saved</span>}
        {state.error && <span className="text-xs text-red-300">{state.error}</span>}
      </div>
    </div>
  )
}
