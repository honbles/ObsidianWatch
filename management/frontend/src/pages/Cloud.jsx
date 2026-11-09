import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Cloud as CloudIcon, RefreshCw, ChevronRight, Plus } from 'lucide-react'
import api from '../api/client'
import { ConnectorDetail, ConnectorForm } from './cloud/connectors.jsx'
import { PROVIDERS, PROVIDER_COLORS } from './cloud/shared.jsx'

// ── Main Cloud page ────────────────────────────────────────────────────────────
export default function CloudPage() {
  const [searchParams] = useSearchParams()
  const [connectors, setConnectors] = useState([])
  const [selected, setSelected]     = useState(null)
  const [adding, setAdding]         = useState(null)
  const [syncing, setSyncing]       = useState({})
  const [loading, setLoading]       = useState(true)

  const load = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/cloud-connectors')
      const list = Array.isArray(data?.connectors) ? data.connectors : []
      setConnectors(list)
      const provider = searchParams.get('provider')
      if (provider) {
        const match = list.find(c => c.provider === provider)
        if (match) setSelected(match.id)
      } else if (!selected && list.length > 0) {
        setSelected(list[0].id)
      }
    } catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const triggerSync = async (id) => {
    setSyncing(s => ({...s,[id]:true}))
    try { await api.post(`/api/v1/cloud-connectors/${id}/sync`) } catch {}
    setTimeout(() => { setSyncing(s => ({...s,[id]:false})); load() }, 3000)
  }

  const disconnect = async (id) => {
    if (!confirm('Disconnect this cloud account?')) return
    await api.delete(`/api/v1/cloud-connectors/${id}`).catch(() => {})
    if (selected === id) setSelected(null)
    load()
  }

  const selectedConn = connectors.find(c => c.id === selected)

  return (
    <div className="flex h-screen bg-siem-bg text-siem-text overflow-hidden">
      {/* Sidebar */}
      <div className="w-64 flex-shrink-0 flex flex-col border-r border-siem-border">
        <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CloudIcon size={15} className="text-cyan-400"/>
              <span className="text-sm font-semibold">Cloud Accounts</span>
            </div>
            <button onClick={load} className="text-siem-muted hover:text-siem-text">
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''}/>
            </button>
          </div>
          <div className="text-[10px] text-siem-muted mt-1">
            {connectors.length} connected · {connectors.filter(c => c.status === 'connected').length} healthy
          </div>
        </div>

        <div className="flex-1 overflow-y-auto min-h-0 py-1">
          {connectors.map(conn => {
            const isSelected = selected === conn.id
            return (
              <button key={conn.id} onClick={() => { setSelected(conn.id); setAdding(null) }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 text-left transition-colors ${
                  isSelected ? 'bg-siem-accent/10 border-r-2 border-siem-accent' : 'hover:bg-siem-surface'
                }`}>
                <span className={`text-sm font-bold ${PROVIDER_COLORS[conn.provider] || 'text-siem-muted'}`}>
                  {conn.provider === 'aws' ? 'AWS' : conn.provider === 'azure' ? 'AZ' : 'GCP'}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium text-siem-text truncate">
                    {conn.account_label || conn.account_id || `${conn.provider.toUpperCase()} account`}
                  </div>
                  <div className="flex items-center gap-1.5 text-[10px] text-siem-muted">
                    <span className={`w-1.5 h-1.5 rounded-full ${
                      conn.status === 'connected' ? 'bg-emerald-400' : conn.status === 'error' ? 'bg-red-400' : 'bg-yellow-400'
                    }`}/>
                    {conn.status}
                  </div>
                </div>
                <ChevronRight size={11} className="text-siem-muted shrink-0"/>
              </button>
            )
          })}
          {!loading && connectors.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <CloudIcon size={22} className="opacity-30"/>No cloud accounts
            </div>
          )}
        </div>

        <div className="flex-shrink-0 border-t border-siem-border p-3 space-y-1">
          <p className="text-[10px] uppercase tracking-wider text-siem-muted mb-2">Add account</p>
          {Object.entries(PROVIDERS).map(([provider, cfg]) => (
            <button key={provider} onClick={() => { setAdding(provider); setSelected(null) }}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs border transition-colors ${
                adding === provider ? `${cfg.border} ${cfg.bg} ${cfg.color}` : 'border-siem-border text-siem-muted hover:text-siem-text hover:border-siem-text/30'
              }`}>
              <Plus size={10}/>{cfg.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 min-w-0 overflow-hidden">
        {adding && (
          <div className="p-6 max-w-2xl overflow-auto h-full">
            <div className="flex items-center gap-2 mb-4">
              <span className={`text-lg font-bold ${PROVIDERS[adding]?.color}`}>{PROVIDERS[adding]?.label}</span>
            </div>
            <ConnectorForm provider={adding} onSaved={() => { setAdding(null); load() }} onCancel={() => setAdding(null)}/>
          </div>
        )}

        {selectedConn && !adding && (
          <ConnectorDetail
            conn={selectedConn}
            onSync={() => triggerSync(selectedConn.id)}
            onDisconnect={() => disconnect(selectedConn.id)}
            syncing={syncing[selectedConn.id]}/>
        )}

        {!selectedConn && !adding && (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted gap-4">
            <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
              <CloudIcon size={30} className="opacity-40"/>
            </div>
            <div className="text-center">
              <div className="text-sm font-medium text-siem-text mb-1">Cloud Security Posture</div>
              <div className="text-xs max-w-xs text-center">Connect AWS, Azure, or GCP to start monitoring your cloud security posture.</div>
            </div>
            <div className="flex gap-3 text-[10px] mt-2">
              {Object.entries(PROVIDERS).map(([p, cfg]) => (
                <button key={p} onClick={() => setAdding(p)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${cfg.border} ${cfg.color} transition-colors`}>
                  <Plus size={10}/>{p.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

