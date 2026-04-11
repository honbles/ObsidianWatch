import { useEffect, useState, useRef, useCallback } from 'react'
import { MapPin, Wifi, WifiOff, RefreshCw, Monitor, Server, Globe,
         Navigation, Signal, Clock, ChevronRight } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'

// ── Source badge ──────────────────────────────────────────────────────────────
const SOURCE_META = {
  gps:  { label: 'GPS',    color: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-700' },
  wifi: { label: 'Wi-Fi',  color: 'text-blue-400',    bg: 'bg-blue-950/40',    border: 'border-blue-700' },
  ip:   { label: 'IP Est.',color: 'text-yellow-400',  bg: 'bg-yellow-950/40',  border: 'border-yellow-700' },
}

function SourceBadge({ source }) {
  const m = SOURCE_META[source] || SOURCE_META.ip
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${m.bg} ${m.border} ${m.color}`}>
      <Signal size={9} />
      {m.label}
    </span>
  )
}

// ── OS icon ───────────────────────────────────────────────────────────────────
function OSIcon({ os }) {
  const l = (os || '').toLowerCase()
  if (l.includes('win'))    return <Monitor size={13} className="text-blue-400" />
  if (l.includes('linux'))  return <Server  size={13} className="text-orange-400" />
  return                           <Globe   size={13} className="text-siem-muted" />
}

// ── Agent list item ───────────────────────────────────────────────────────────
function AgentRow({ agent, selected, onSelect }) {
  const online = agent.online
  return (
    <button
      onClick={() => onSelect(agent)}
      className={`w-full text-left px-3 py-2.5 border-b border-siem-border transition-colors
        ${selected ? 'bg-emerald-950/30 border-l-2 border-l-emerald-500' : 'hover:bg-siem-surface border-l-2 border-l-transparent'}`}
    >
      <div className="flex items-center gap-2 mb-0.5">
        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${online ? 'bg-emerald-400' : 'bg-siem-muted'}`} />
        <OSIcon os={agent.os} />
        <span className="text-xs font-medium text-siem-text truncate flex-1">{agent.hostname}</span>
        <SourceBadge source={agent.location_source} />
      </div>
      <div className="flex items-center gap-2 pl-5 text-[10px] text-siem-muted">
        <MapPin size={9} />
        <span className="truncate">{[agent.location_city, agent.location_country].filter(Boolean).join(', ') || 'Unknown location'}</span>
        {agent.location_updated && (
          <span className="ml-auto flex-shrink-0 flex items-center gap-1">
            <Clock size={9} />
            {formatDistanceToNow(new Date(agent.location_updated), { addSuffix: true })}
          </span>
        )}
      </div>
    </button>
  )
}

// ── Map accuracy circle colour by source ─────────────────────────────────────
function circleColor(source) {
  if (source === 'gps')  return '#34d399'
  if (source === 'wifi') return '#60a5fa'
  return '#facc15'
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Locations() {
  const [agents, setAgents]       = useState([])
  const [selected, setSelected]   = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [leafletReady, setLeafletReady] = useState(false)
  const mapRef   = useRef(null)
  const mapInst  = useRef(null)
  const markersRef = useRef({})

  // ── Load Leaflet from CDN ─────────────────────────────────────────────────
  useEffect(() => {
    if (window.L) { setLeafletReady(true); return }

    const link = document.createElement('link')
    link.rel  = 'stylesheet'
    link.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css'
    document.head.appendChild(link)

    const script = document.createElement('script')
    script.src   = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'
    script.onload = () => setLeafletReady(true)
    document.head.appendChild(script)
  }, [])

  // ── Fetch agent locations ─────────────────────────────────────────────────
  const fetchLocations = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/agents/locations')
      setAgents(Array.isArray(data) ? data : [])
      setError(null)
    } catch (e) {
      setError(e.message || 'Failed to load locations')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchLocations()
    const id = setInterval(fetchLocations, 30_000)
    return () => clearInterval(id)
  }, [fetchLocations])

  // ── Init map ──────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!leafletReady || !mapRef.current || mapInst.current) return
    const L = window.L

    const map = L.map(mapRef.current, {
      center: [20, 0],
      zoom: 2,
      zoomControl: true,
      attributionControl: true,
    })

    // Dark tile layer (CartoDB Dark Matter)
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(map)

    mapInst.current = map
  }, [leafletReady])

  // ── Sync markers when agents or map changes ───────────────────────────────
  useEffect(() => {
    if (!mapInst.current || !window.L) return
    const L   = window.L
    const map = mapInst.current

    // Remove old markers
    Object.values(markersRef.current).forEach(({ marker, circle }) => {
      map.removeLayer(marker)
      map.removeLayer(circle)
    })
    markersRef.current = {}

    agents.forEach(agent => {
      if (!agent.lat || !agent.lng) return

      const online = agent.online
      const color  = circleColor(agent.location_source)
      const label  = [agent.location_city, agent.location_country].filter(Boolean).join(', ') || agent.hostname

      // Custom pin icon
      const icon = L.divIcon({
        className: '',
        html: `
          <div style="
            width:26px; height:26px;
            background:${online ? color : '#6b7280'};
            border:2px solid ${online ? '#fff' : '#9ca3af'};
            border-radius:50% 50% 50% 0;
            transform:rotate(-45deg);
            box-shadow:0 2px 8px rgba(0,0,0,0.5);
            cursor:pointer;
          "></div>`,
        iconSize:   [26, 26],
        iconAnchor: [13, 26],
        popupAnchor:[0, -26],
      })

      const marker = L.marker([agent.lat, agent.lng], { icon })
        .bindPopup(`
          <div style="font-family:monospace;font-size:12px;min-width:180px;color:#e2e8f0;background:#1e293b;padding:8px;border-radius:6px">
            <div style="font-weight:700;font-size:13px;margin-bottom:6px">${agent.hostname}</div>
            <div style="color:#94a3b8;margin-bottom:3px">📍 ${label}</div>
            <div style="color:#94a3b8;margin-bottom:3px">🖥️ ${agent.os || 'unknown'}</div>
            <div style="color:#94a3b8;margin-bottom:3px">📡 Source: ${agent.location_source || 'unknown'}</div>
            ${agent.location_accuracy ? `<div style="color:#94a3b8;margin-bottom:3px">🎯 ±${Math.round(agent.location_accuracy)}m</div>` : ''}
            <div style="color:${online ? '#34d399' : '#6b7280'};margin-top:4px">● ${online ? 'Online' : 'Offline'}</div>
          </div>
        `, { className: 'obsidian-popup' })
        .addTo(map)

      // Accuracy radius circle
      const accuracyM = agent.location_accuracy || (agent.location_source === 'ip' ? 5000 : 300)
      const circle = L.circle([agent.lat, agent.lng], {
        radius:      accuracyM,
        color:       color,
        fillColor:   color,
        fillOpacity: 0.08,
        weight:      1,
        dashArray:   agent.location_source === 'ip' ? '4 4' : null,
      }).addTo(map)

      markersRef.current[agent.id] = { marker, circle }
    })
  }, [agents, leafletReady])

  // ── Pan to selected agent ─────────────────────────────────────────────────
  useEffect(() => {
    if (!selected || !mapInst.current) return
    if (!selected.lat || !selected.lng) return
    mapInst.current.flyTo([selected.lat, selected.lng], 12, { duration: 1.2 })
    const entry = markersRef.current[selected.id]
    if (entry) entry.marker.openPopup()
  }, [selected])

  // ── Stats ─────────────────────────────────────────────────────────────────
  const online   = agents.filter(a => a.online).length
  const gps      = agents.filter(a => a.location_source === 'gps').length
  const wifi     = agents.filter(a => a.location_source === 'wifi').length
  const ipBased  = agents.filter(a => a.location_source === 'ip').length

  return (
    <div className="flex flex-col h-screen bg-siem-bg text-siem-text overflow-hidden">

      {/* Header */}
      <div className="flex-shrink-0 flex items-center justify-between px-5 py-3 border-b border-siem-border bg-siem-surface">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Navigation size={18} className="text-emerald-400" />
            <h1 className="text-sm font-semibold tracking-wide">Endpoint Locations</h1>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-siem-muted">
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block" />
              {online} online
            </span>
            <span>·</span>
            <span>{agents.length} located</span>
            {gps  > 0 && <span>· <span className="text-emerald-400">{gps} GPS</span></span>}
            {wifi > 0 && <span>· <span className="text-blue-400">{wifi} Wi-Fi</span></span>}
            {ipBased > 0 && <span>· <span className="text-yellow-400">{ipBased} IP est.</span></span>}
          </div>
        </div>
        <button
          onClick={fetchLocations}
          className="flex items-center gap-1.5 text-[11px] text-siem-muted hover:text-siem-text px-2.5 py-1 rounded border border-siem-border hover:border-siem-text transition-colors"
        >
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Legend */}
      <div className="flex-shrink-0 flex items-center gap-4 px-5 py-2 border-b border-siem-border bg-siem-bg text-[10px] text-siem-muted">
        <span className="font-mono uppercase tracking-wider">Accuracy:</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full border border-emerald-500 bg-emerald-950/40 inline-block" /> GPS (&lt;50m)</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full border border-blue-500 bg-blue-950/40 inline-block" /> Wi-Fi (~100–300m)</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full border border-yellow-500 border-dashed bg-yellow-950/20 inline-block" /> IP estimate (~5km)</span>
        <span className="ml-auto">Auto-refreshes every 30s</span>
      </div>

      {/* Body: map + sidebar */}
      <div className="flex flex-1 min-h-0">

        {/* Sidebar */}
        <div className="w-72 flex-shrink-0 flex flex-col border-r border-siem-border bg-siem-surface overflow-hidden">
          <div className="px-3 py-2 border-b border-siem-border text-[10px] font-mono uppercase tracking-wider text-siem-muted">
            Endpoints ({agents.length})
          </div>

          <div className="flex-1 overflow-y-auto">
            {loading && agents.length === 0 && (
              <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
                <RefreshCw size={16} className="animate-spin" />
                Loading locations…
              </div>
            )}

            {error && (
              <div className="m-3 p-3 rounded bg-red-950/30 border border-red-800 text-xs text-red-300">
                {error}
              </div>
            )}

            {!loading && !error && agents.length === 0 && (
              <div className="flex flex-col items-center justify-center h-40 text-siem-muted text-xs gap-3 px-4 text-center">
                <MapPin size={24} className="opacity-30" />
                <div>No agent locations yet.</div>
                <div className="text-[10px] opacity-60">Agents report their location every 30 minutes. Check back shortly after agents connect.</div>
              </div>
            )}

            {agents.map(agent => (
              <AgentRow
                key={agent.id}
                agent={agent}
                selected={selected?.id === agent.id}
                onSelect={setSelected}
              />
            ))}
          </div>

          {selected && (
            <div className="flex-shrink-0 border-t border-siem-border bg-siem-bg p-3 text-[11px]">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-siem-text">{selected.hostname}</span>
                <button onClick={() => setSelected(null)} className="text-siem-muted hover:text-siem-text">✕</button>
              </div>
              <div className="space-y-1 text-siem-muted">
                <div className="flex justify-between"><span>OS</span><span className="text-siem-text">{selected.os}</span></div>
                <div className="flex justify-between"><span>City</span><span className="text-siem-text">{selected.location_city || '—'}</span></div>
                <div className="flex justify-between"><span>Country</span><span className="text-siem-text">{selected.location_country || '—'}</span></div>
                <div className="flex justify-between"><span>Source</span><SourceBadge source={selected.location_source} /></div>
                {selected.location_accuracy && (
                  <div className="flex justify-between"><span>Accuracy</span><span className="text-siem-text">±{Math.round(selected.location_accuracy)}m</span></div>
                )}
                <div className="flex justify-between"><span>IP</span><span className="text-siem-text font-mono">{selected.last_ip || '—'}</span></div>
                {selected.location_updated && (
                  <div className="flex justify-between"><span>Updated</span><span className="text-siem-text">{formatDistanceToNow(new Date(selected.location_updated), { addSuffix: true })}</span></div>
                )}
                <div className="flex justify-between">
                  <span>Status</span>
                  <span className={selected.online ? 'text-emerald-400' : 'text-siem-muted'}>
                    {selected.online ? '● Online' : '○ Offline'}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Map */}
        <div className="flex-1 relative">
          {!leafletReady && (
            <div className="absolute inset-0 flex items-center justify-center bg-siem-bg text-siem-muted text-sm z-10">
              <RefreshCw size={18} className="animate-spin mr-2" />
              Loading map…
            </div>
          )}
          <div ref={mapRef} className="w-full h-full" style={{ background: '#0f172a' }} />
        </div>
      </div>

      {/* Leaflet popup dark style override */}
      <style>{`
        .leaflet-popup-content-wrapper, .leaflet-popup-tip {
          background: #1e293b !important;
          color: #e2e8f0 !important;
          border: 1px solid #334155 !important;
          box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
        }
        .leaflet-popup-content { margin: 0 !important; }
        .leaflet-container { background: #0f172a; }
        .leaflet-control-zoom a {
          background: #1e293b !important;
          color: #94a3b8 !important;
          border-color: #334155 !important;
        }
        .leaflet-control-zoom a:hover { background: #334155 !important; color: #e2e8f0 !important; }
        .leaflet-control-attribution { background: rgba(15,23,42,0.8) !important; color: #475569 !important; }
        .leaflet-control-attribution a { color: #64748b !important; }
      `}</style>
    </div>
  )
}
