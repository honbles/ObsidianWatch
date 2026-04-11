import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Radio, Activity, Bell, RefreshCw, ChevronRight,
         Wifi, Database, Clock, MapPin, Server } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'

export default function NetworkProbes() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/agents')
      const probes = (data?.agents || []).filter(a =>
        a.os?.toLowerCase().includes('network-probe'))
      setAgents(probes)
    } catch {} finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-siem-text tracking-tight flex items-center gap-2.5">
            <Radio size={18} className="text-cyan-400"/>
            Network Probes
          </h1>
          <p className="text-[11px] text-siem-muted mt-1">
            Network intelligence sensors — collect syslog, NetFlow, SNMP from all network devices
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load}
            className="flex items-center gap-1.5 text-xs text-siem-muted border border-siem-border rounded-lg px-3 py-1.5 hover:text-siem-text transition-colors">
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''}/> Refresh
          </button>
          <button onClick={() => navigate('/agent-builder')}
            className="flex items-center gap-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg px-3 py-1.5 transition-colors">
            Deploy Probe
          </button>
        </div>
      </div>

      {/* Architecture explainer */}
      <div className="bg-cyan-950/20 border border-cyan-800/30 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <Radio size={14} className="text-cyan-400 mt-0.5 shrink-0"/>
          <div className="text-[11px] text-cyan-300/80 leading-relaxed">
            Network probes sit inside your network, receive syslog from all devices (port 514),
            NetFlow from routers (port 2055), and poll SNMP for device health. All analysis runs locally —
            only alerts and summaries are sent to this management server.
          </div>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-16 gap-2 text-siem-muted">
          <RefreshCw size={14} className="animate-spin"/>
          <span className="text-sm">Loading probes…</span>
        </div>
      ) : agents.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-4">
          <div className="w-20 h-20 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
            <Radio size={36} className="text-siem-muted/30"/>
          </div>
          <div className="text-center">
            <div className="text-sm font-medium text-siem-text mb-1">No network probes deployed</div>
            <div className="text-xs text-siem-muted max-w-sm text-center mb-4">
              Deploy a probe to any Linux host on each network segment you want to monitor.
              One probe per site is enough.
            </div>
            <button onClick={() => navigate('/agent-builder')}
              className="text-xs bg-cyan-600 hover:bg-cyan-500 text-white px-4 py-2 rounded-lg transition-colors">
              Build Network Probe
            </button>
          </div>

          {/* Quick setup guide */}
          <div className="mt-4 bg-siem-surface border border-siem-border rounded-xl p-5 max-w-lg w-full">
            <div className="text-xs font-semibold text-siem-text mb-3">Quick Setup</div>
            <div className="space-y-3">
              {[
                { step: '1', text: 'Go to Agent Builder → Build a Network Probe', icon: Server },
                { step: '2', text: 'Copy binary to a Linux host on your network', icon: Database },
                { step: '3', text: 'Run: sudo ./obsidianwatch-network-probe install --subnet 192.168.1.0/24', icon: Radio },
                { step: '4', text: 'Point your network devices to send syslog to the probe IP:514', icon: Wifi },
              ].map(({ step, text, icon: Icon }) => (
                <div key={step} className="flex items-start gap-3">
                  <div className="w-5 h-5 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-[9px] font-bold text-cyan-400">{step}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Icon size={11} className="text-siem-muted shrink-0"/>
                    <span className="text-[11px] text-siem-muted">{text}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="grid gap-3">
          {agents.map(probe => (
            <div key={probe.id}
              onClick={() => navigate(`/agents?host=${encodeURIComponent(probe.hostname)}`)}
              className="bg-siem-surface border border-siem-border rounded-xl p-4 hover:border-siem-accent/30 cursor-pointer transition-all group">
              <div className="flex items-center gap-4">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                  probe.online ? 'bg-cyan-950/40 border border-cyan-800/40' : 'bg-siem-bg border border-siem-border'
                }`}>
                  <Radio size={18} className={probe.online ? 'text-cyan-400' : 'text-siem-muted/40'}/>
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-siem-text">{probe.hostname}</span>
                    <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${
                      probe.online
                        ? 'text-cyan-400 bg-cyan-950/30 border-cyan-800/40'
                        : 'text-siem-muted bg-siem-bg border-siem-border'
                    }`}>
                      {probe.online ? '● ONLINE' : '○ OFFLINE'}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 mt-1">
                    {probe.last_seen && (
                      <span className="flex items-center gap-1 text-[10px] text-siem-muted">
                        <Clock size={9}/>
                        {formatDistanceToNow(new Date(probe.last_seen), { addSuffix: true })}
                      </span>
                    )}
                    {probe.last_ip && (
                      <span className="flex items-center gap-1 text-[10px] text-siem-muted font-mono">
                        <MapPin size={9}/>
                        {probe.last_ip}
                      </span>
                    )}
                    <span className="flex items-center gap-1 text-[10px] text-siem-muted">
                      <Activity size={9}/>
                      {probe.event_count?.toLocaleString() || 0} events
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={e => { e.stopPropagation(); navigate(`/alerts?host=${probe.hostname}`) }}
                    className="flex items-center gap-1 text-[10px] text-siem-muted border border-siem-border rounded-lg px-2.5 py-1.5 hover:text-siem-accent hover:border-siem-accent/30 transition-colors">
                    <Bell size={10}/> Alerts
                  </button>
                  <ChevronRight size={14} className="text-siem-muted/30 group-hover:text-siem-muted transition-colors"/>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
