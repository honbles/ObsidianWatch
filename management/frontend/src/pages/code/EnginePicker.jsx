// SAST engine choice: one checkbox per engine, from GET .../sast/engines.
import { useEffect, useState } from 'react'
import { Sparkles } from 'lucide-react'
import api from '../../api/client'

const cache = {}

export function useEngines(connId) {
  const [data, setData] = useState(cache[connId] || null)
  useEffect(() => {
    if (cache[connId]) return
    api.get(`/api/v1/devops-connectors/${connId}/sast/engines`)
      .then(r => { cache[connId] = r.data; setData(r.data) }).catch(() => setData({ engines: [] }))
  }, [connId])
  return data
}

export const defaultEngineIds = (engines) => (engines || []).filter(e => e.default).map(e => e.id)

// value: array of engine ids (empty = the default engines).
export default function EnginePicker({ connId, value, onChange, allowAI = true, compact = false }) {
  const data = useEngines(connId)
  const engines = data?.engines || []
  const chosen = value && value.length ? value : defaultEngineIds(engines)
  const toggle = (id, on) => {
    const next = on ? [...new Set([...chosen, id])] : chosen.filter(x => x !== id)
    onChange(engines.filter(e => next.includes(e.id)).map(e => e.id))
  }
  if (!data) return <span className="text-xs text-siem-muted">Loading engines…</span>
  return (
    <div className={compact ? 'flex flex-wrap gap-x-4 gap-y-1.5' : 'grid sm:grid-cols-2 gap-2'}>
      {engines.map(e => {
        const disabled = (e.ai && !allowAI)
        return (
          <label key={e.id} title={e.available ? e.help : e.reason}
            className={`flex items-start gap-2 text-xs ${disabled ? 'opacity-40 cursor-not-allowed' : 'cursor-pointer'}`}>
            <input type="checkbox" className="mt-0.5 accent-siem-accent" disabled={disabled}
              checked={chosen.includes(e.id)} onChange={ev => toggle(e.id, ev.target.checked)} />
            <span>
              <span className="text-siem-text flex items-center gap-1">
                {e.ai && <Sparkles size={11} className="text-violet-400" />}{e.label}
              </span>
              {!compact && <span className="block text-siem-muted">{e.available ? e.help : `Not available: ${e.reason}`}</span>}
              {compact && !e.available && <span className="block text-amber-400/80">{e.reason}</span>}
            </span>
          </label>
        )
      })}
      {data.code_model && engines.some(e => e.ai) && !compact && (
        <div className="text-2xs text-siem-muted sm:col-span-2">AI engine model: <span className="font-mono">{data.code_model}</span></div>
      )}
    </div>
  )
}

export function engineLabels(ids, engines) {
  if (!ids || !ids.length) return 'default engines'
  const byId = Object.fromEntries((engines || []).map(e => [e.id, e.label]))
  return ids.map(id => byId[id] || id).join(', ')
}
