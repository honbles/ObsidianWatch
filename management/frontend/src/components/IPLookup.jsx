import { useEffect, useState } from 'react'
import { X } from 'lucide-react'
import api from '../api/client'

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

function scoreStyle(s) {
  if (s >= 75) return { cls: 'text-red-400', label: 'Very likely malicious' }
  if (s >= 25) return { cls: 'text-amber-400', label: 'Suspicious' }
  return { cls: 'text-emerald-400', label: 'No significant abuse reports' }
}

// IPLookupModal fetches reputation for one IP from AbuseIPDB through the
// backend (GET /api/v1/enrich/ip/{ip}; needs the AbuseIPDB key in Settings).
export function IPLookupModal({ ip, onClose }) {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let off = false
    setLoading(true); setErr(''); setData(null)
    api.get('/api/v1/enrich/ip/' + encodeURIComponent(ip))
      .then(r => { if (!off) setData(r.data) })
      .catch(e => { if (!off) setErr(e.response?.data?.error || 'Lookup failed') })
      .finally(() => { if (!off) setLoading(false) })
    return () => { off = true }
  }, [ip])

  const st = data ? scoreStyle(data.abuse_score) : null
  const rows = data ? [
    ['Abuse confidence', <span className={st.cls}>{data.abuse_score}% — {st.label}</span>],
    ['Reports', data.total_reports],
    ['Last reported', data.last_reported ? new Date(data.last_reported).toLocaleString() : '—'],
    ['Country', data.country_code || '—'],
    ['ISP', data.isp || '—'],
    ['Domain', data.domain || '—'],
    ['Usage type', data.usage_type || '—'],
    ['Tor exit node', data.is_tor ? 'Yes' : 'No'],
  ] : []

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50" onClick={onClose}>
      <div className="w-full max-w-md bg-siem-surface border border-siem-border rounded-xl shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-4 py-3 border-b border-siem-border">
          <div className="text-sm font-semibold text-siem-text font-mono">{ip}</div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={16} /></button>
        </div>
        <div className="p-4 text-xs space-y-3">
          {loading && <div className="text-siem-muted">Looking up reputation…</div>}
          {err && <div className="text-red-400">{err}</div>}
          {data && (
            <div className="border border-siem-border rounded-lg overflow-hidden">
              {rows.map(([k, v], i) => (
                <div key={k} className={`flex gap-3 px-3 py-2 ${i % 2 ? 'bg-white/[0.02]' : ''}`}>
                  <span className="text-siem-muted w-28 shrink-0">{k}</span>
                  <span className="text-siem-text break-all">{v}</span>
                </div>
              ))}
            </div>
          )}
          {data && <div className="text-siem-muted/70">Source: AbuseIPDB{data.cached ? ' (cached, up to 24h)' : ''}. A high score means many reports, not proof.</div>}
          <a className="text-siem-accent hover:underline inline-block" target="_blank" rel="noopener noreferrer"
             href={'https://www.abuseipdb.com/check/' + encodeURIComponent(ip)}>Open on AbuseIPDB ↗</a>
        </div>
      </div>
    </div>
  )
}

// IPLink renders an IPv4 address as a clickable value that opens the lookup.
export function IPLink({ ip, children, className = '' }) {
  const [open, setOpen] = useState(false)
  if (!ip || !IPV4.test(String(ip))) return <span className={className}>{children ?? ip}</span>
  return (
    <>
      <button type="button" onClick={e => { e.stopPropagation(); setOpen(true) }}
        title="Look up reputation" className={`underline decoration-dotted underline-offset-2 hover:text-siem-accent ${className}`}>
        {children ?? ip}
      </button>
      {open && <IPLookupModal ip={String(ip)} onClose={() => setOpen(false)} />}
    </>
  )
}
