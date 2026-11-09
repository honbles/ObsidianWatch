import { useEffect, useRef, useState, useCallback } from 'react'
import { getWSTicket } from './client'

export function useLiveFeed(maxEvents = 200) {
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const wsRef = useRef(null)
  const reconnectRef = useRef(null)

  const stoppedRef = useRef(false)

  const connect = useCallback(async () => {
    const token = localStorage.getItem('token')
    if (!token || stoppedRef.current) return
    let ticket
    try { ticket = await getWSTicket() } catch {
      if (!stoppedRef.current) reconnectRef.current = setTimeout(connect, 5000)
      return
    }
    if (stoppedRef.current) return

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host = window.location.host
    const ws = new WebSocket(`${proto}://${host}/ws/events?ticket=${encodeURIComponent(ticket)}`)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
    }

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        if (data.type === 'events' && Array.isArray(data.events)) {
          setEvents(prev => {
            const combined = [...data.events, ...prev]
            return combined.slice(0, maxEvents)
          })
        }
      } catch {}
    }

    ws.onclose = () => {
      setConnected(false)
      // Reconnect after 3 seconds
      reconnectRef.current = setTimeout(connect, 3000)
    }

    ws.onerror = () => ws.close()
  }, [maxEvents])

  useEffect(() => {
    stoppedRef.current = false
    connect()
    return () => {
      stoppedRef.current = true
      if (wsRef.current) wsRef.current.close()
      if (reconnectRef.current) clearTimeout(reconnectRef.current)
    }
  }, [connect])

  return { events, connected }
}
