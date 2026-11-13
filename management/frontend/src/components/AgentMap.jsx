import { useEffect, useRef, useState } from 'react'

// Draggable, zoomable Leaflet map for one agent location. Leaflet is loaded
// from the same CDN as the fleet Locations page (loaded once, shared).
let leafletLoad = null
function loadLeaflet() {
  if (window.L) return Promise.resolve(window.L)
  if (leafletLoad) return leafletLoad
  leafletLoad = new Promise((resolve, reject) => {
    const link = document.createElement('link')
    link.rel = 'stylesheet'
    link.href = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css'
    document.head.appendChild(link)
    const s = document.createElement('script')
    s.src = 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js'
    s.onload = () => resolve(window.L)
    s.onerror = () => { leafletLoad = null; reject(new Error('Could not load the map library')) }
    document.head.appendChild(s)
  })
  return leafletLoad
}

export default function AgentMap({ lat, lng, accuracy, label }) {
  const el = useRef(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let map, ro, off = false
    loadLeaflet().then(L => {
      if (off || !el.current) return
      map = L.map(el.current, {
        center: [lat, lng], zoom: accuracy && accuracy < 1000 ? 14 : 11,
        dragging: true, scrollWheelZoom: true, doubleClickZoom: true, touchZoom: true, inertia: true,
        zoomControl: true,
      })
      L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap &copy; CARTO', subdomains: 'abcd', maxZoom: 19,
      }).addTo(map)
      L.circle([lat, lng], { radius: accuracy || 5000, color: '#38bdf8', fillColor: '#38bdf8', fillOpacity: 0.1, weight: 1 }).addTo(map)
      L.circleMarker([lat, lng], { radius: 7, color: '#fff', weight: 2, fillColor: '#38bdf8', fillOpacity: 1 })
        .bindTooltip(label || 'Agent', { permanent: false }).addTo(map)
      // the tab lays out after mount; without this Leaflet mis-measures and drag feels dead
      ro = new ResizeObserver(() => map && map.invalidateSize())
      ro.observe(el.current)
      setTimeout(() => map && map.invalidateSize(), 50)
    }).catch(e => setErr(e.message))
    return () => { off = true; if (ro) ro.disconnect(); if (map) map.remove() }
  }, [lat, lng, accuracy, label])

  if (err) return <div className="p-4 text-xs text-red-400">{err}</div>
  return <div ref={el} className="w-full h-full" style={{ minHeight: 320, background: '#0f172a', cursor: 'grab' }} />
}
