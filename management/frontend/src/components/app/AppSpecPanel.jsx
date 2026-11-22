import { useState } from 'react'
import { appApi } from '../../api/app'
import { appIsAdmin, appRel } from './appFormat'
import useAppLoad from './useAppLoad'

// Declare the service's API from an OpenAPI / Swagger document, so its routes and fields can be reviewed and
// masked before any traffic arrives. Admin only.
export default function AppSpecPanel({ service, onChanged }) {
  const admin = appIsAdmin()
  const cur = useAppLoad(() => appApi.openapi(service.id), [service.id], admin)
  const [open, setOpen] = useState(false)
  const [url, setUrl] = useState('')
  const [base, setBase] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState(null) // { ok, text }
  if (!admin) return null
  const info = cur.data

  const send = async (body) => {
    setBusy(true); setMsg(null)
    try {
      const r = await appApi.loadOpenapi(service.id, { ...body, base_path: base || undefined })
      setMsg({ ok: true, text: `Loaded ${r.title || 'the document'}: ${r.routes} routes, ${r.params} fields${r.matched ? `, ${r.matched} already seen in traffic` : ''}${r.skipped_routes ? `. ${r.skipped_routes} routes over the limit were skipped` : ''}.` })
      cur.reload(); onChanged && onChanged()
    } catch (e) { setMsg({ ok: false, text: e?.response?.data?.error || 'Could not load the document' }) } finally { setBusy(false) }
  }
  const onFile = async (e) => {
    const f = e.target.files && e.target.files[0]
    e.target.value = ''
    if (!f) return
    if (f.size > 5 * 1024 * 1024) { setMsg({ ok: false, text: 'The file is larger than 5 MB.' }); return }
    send({ spec: await f.text() })
  }
  const remove = async () => {
    setBusy(true); setMsg(null)
    try { await appApi.removeOpenapi(service.id); cur.reload(); onChanged && onChanged() }
    catch (e) { setMsg({ ok: false, text: e?.response?.data?.error || 'Could not remove the document' }) } finally { setBusy(false) }
  }

  return (
    <div className="card p-3 text-xs space-y-2">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="font-medium text-siem-text">API spec</span>
        {info?.loaded
          ? <span className="text-siem-muted">{info.title || 'Loaded'}{info.version ? ` v${info.version}` : ''}: {info.routes} routes, {info.params} fields, loaded {appRel(info.loaded_at)}{info.loaded_by ? ` by ${info.loaded_by}` : ''}</span>
          : <span className="text-siem-muted">None loaded. Load an OpenAPI or Swagger document to review routes and fields before any traffic arrives.</span>}
        <button className="ml-auto text-siem-accent hover:underline" onClick={() => setOpen(o => !o)}>{open ? 'Hide' : info?.loaded ? 'Replace or remove' : 'Load a spec'}</button>
      </div>
      {open && (
        <div className="space-y-2 border-t border-siem-border pt-2">
          <div className="flex items-center gap-2 flex-wrap">
            <label className="btn-secondary text-xs cursor-pointer">Upload a file (.json, .yaml)
              <input type="file" accept=".json,.yaml,.yml,application/json,text/yaml" className="hidden" disabled={busy} onChange={onFile} />
            </label>
            <span className="text-siem-muted">or fetch</span>
            <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://app.internal/v3/api-docs"
              className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text w-72" />
            <button className="btn-primary text-xs" disabled={busy || !url.trim()} onClick={() => send({ url: url.trim() })}>Fetch and load</button>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-siem-muted">Path prefix (optional)</span>
            <input value={base} onChange={e => setBase(e.target.value)} placeholder="/api/v1"
              className="bg-siem-surface2 border border-siem-border rounded-lg px-2.5 py-1.5 text-xs text-siem-text w-40" />
            <span className="text-siem-muted">only if the document's server path differs from what the application serves.</span>
          </div>
          <div className="text-[11px] text-siem-muted">
            The management server fetches the URL itself, so it must be reachable from the server (not from your browser). Loopback and link-local addresses are refused. If the application is not reachable, open the URL in your browser, save the document and upload it.
            Only path, query and header parameter names and body field names are read: never examples or defaults. Cookie parameters are skipped. Loading replaces the previous document.
          </div>
          {info?.loaded && <button className="text-red-300 hover:underline" disabled={busy} onClick={remove}>Remove the loaded spec</button>}
        </div>
      )}
      {msg && <div className={msg.ok ? 'text-emerald-300' : 'text-red-300'}>{msg.text}</div>}
    </div>
  )
}
