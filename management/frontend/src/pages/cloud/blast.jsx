import { useState, useEffect, useRef } from 'react'
import { NODE_COLORS_BLAST, RISK_COLORS_BLAST } from './shared.jsx'

// Focussed force-directed graph for a single selected principal
export function BlastFocusGraph({ principal, allNodes, allEdges }) {
  const canvasRef = useRef(null)
  const animRef   = useRef(null)
  const simRef    = useRef({ nodes: [], edges: [] })
  const [tooltip, setTooltip] = useState(null)

  useEffect(() => {
    cancelAnimationFrame(animRef.current)
    const canvas = canvasRef.current
    if (!canvas || !principal) return
    const ctx = canvas.getContext('2d')
    const W = canvas.width  = canvas.offsetWidth
    const H = canvas.height = canvas.offsetHeight

    // Collect connected node IDs (1-hop outbound + inbound)
    const connectedIDs = new Set([principal.id])
    const focusEdges   = allEdges.filter(e => e.from === principal.id || e.to === principal.id)
    focusEdges.forEach(e => { connectedIDs.add(e.from); connectedIDs.add(e.to) })

    // Also grab 2nd-hop outbound from direct targets (shows full reach)
    const directTargets = new Set(focusEdges.filter(e => e.from === principal.id).map(e => e.to))
    allEdges.forEach(e => {
      if (directTargets.has(e.from)) {
        connectedIDs.add(e.from)
        connectedIDs.add(e.to)
        focusEdges.push(e)
      }
    })

    const focusNodes = allNodes.filter(n => connectedIDs.has(n.id))
    if (!focusNodes.length) return

    // Layout: principal in centre, others in a ring
    const cx = W / 2, cy = H / 2
    const sim = focusNodes.map((n, i) => {
      const isCenter = n.id === principal.id
      const angle    = (i / (focusNodes.length - 1 || 1)) * Math.PI * 2
      const radius   = Math.min(W, H) * 0.33
      return {
        ...n,
        x: isCenter ? cx : cx + Math.cos(angle) * radius,
        y: isCenter ? cy : cy + Math.sin(angle) * radius,
        vx: 0, vy: 0,
        r: isCenter ? 16 : n.type === 'internet' ? 12 : n.risk && n.risk !== 'none' ? 11 : 8,
        isCenter,
      }
    })

    const nodeMap = {}
    sim.forEach(n => { nodeMap[n.id] = n })

    const simEdges = focusEdges
      .map(e => ({ ...e, source: nodeMap[e.from], target: nodeMap[e.to] }))
      .filter(e => e.source && e.target)

    simRef.current = { nodes: sim, edges: simEdges }
    let tick = 0

    const draw = () => {
      tick++
      const ns = sim

      // Repulsion
      for (let i = 0; i < ns.length; i++) {
        for (let j = i + 1; j < ns.length; j++) {
          const dx = ns[j].x - ns[i].x, dy = ns[j].y - ns[i].y
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const f = Math.min(600 / (dist * dist), 6)
          ns[i].vx -= (dx/dist)*f; ns[i].vy -= (dy/dist)*f
          ns[j].vx += (dx/dist)*f; ns[j].vy += (dy/dist)*f
        }
      }
      // Spring edges
      simEdges.forEach(e => {
        if (!e.source || !e.target) return
        const dx = e.target.x - e.source.x, dy = e.target.y - e.source.y
        const dist = Math.sqrt(dx * dx + dy * dy) || 1
        const ideal = n => n.isCenter ? 160 : 100
        const f = (dist - ideal(e.source)) * 0.025
        e.source.vx += (dx/dist)*f; e.source.vy += (dy/dist)*f
        e.target.vx -= (dx/dist)*f; e.target.vy -= (dy/dist)*f
      })
      // Anchor centre node
      const centre = ns.find(n => n.isCenter)
      if (centre) { centre.vx += (cx - centre.x) * 0.08; centre.vy += (cy - centre.y) * 0.08 }

      ns.forEach(n => {
        if (n.isCenter) { n.vx *= 0.5; n.vy *= 0.5 }
        else { n.vx *= 0.82; n.vy *= 0.82 }
        n.x = Math.max(n.r + 5, Math.min(W - n.r - 5, n.x + n.vx))
        n.y = Math.max(n.r + 15, Math.min(H - n.r - 15, n.y + n.vy))
      })

      ctx.clearRect(0, 0, W, H)

      // Edges
      simEdges.forEach(e => {
        if (!e.source || !e.target) return
        const isRisk = e.risk_boost
        ctx.beginPath()
        ctx.moveTo(e.source.x, e.source.y)
        ctx.lineTo(e.target.x, e.target.y)
        ctx.strokeStyle = isRisk ? 'rgba(248,113,113,0.55)' : 'rgba(100,116,139,0.25)'
        ctx.lineWidth   = isRisk ? 2 : 1
        ctx.stroke()

        // Arrow head
        const angle = Math.atan2(e.target.y - e.source.y, e.target.x - e.source.x)
        const ax = e.target.x - Math.cos(angle) * (e.target.r + 4)
        const ay = e.target.y - Math.sin(angle) * (e.target.r + 4)
        ctx.beginPath()
        ctx.moveTo(ax, ay)
        ctx.lineTo(ax - Math.cos(angle-0.4)*8, ay - Math.sin(angle-0.4)*8)
        ctx.lineTo(ax - Math.cos(angle+0.4)*8, ay - Math.sin(angle+0.4)*8)
        ctx.closePath()
        ctx.fillStyle = isRisk ? 'rgba(248,113,113,0.7)' : 'rgba(100,116,139,0.35)'
        ctx.fill()

        // Relationship label
        const mx = (e.source.x + e.target.x) / 2
        const my = (e.source.y + e.target.y) / 2
        ctx.font = '9px DM Mono,monospace'
        ctx.fillStyle = isRisk ? 'rgba(248,113,113,0.8)' : 'rgba(148,163,184,0.65)'
        ctx.textAlign = 'center'
        ctx.fillText((e.relationship || '').replace(/_/g, ' '), mx, my - 4)
      })

      // Nodes
      ns.forEach(n => {
        const col = (n.risk && n.risk !== 'none')
          ? RISK_COLORS_BLAST[n.risk]
          : (NODE_COLORS_BLAST[n.type] || NODE_COLORS_BLAST.default)

        // Glow ring for risk
        if (n.risk === 'critical' || n.risk === 'high') {
          const grd = ctx.createRadialGradient(n.x, n.y, n.r, n.x, n.y, n.r + 10)
          grd.addColorStop(0, n.risk === 'critical' ? 'rgba(248,113,113,0.4)' : 'rgba(251,146,60,0.3)')
          grd.addColorStop(1, 'transparent')
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 10, 0, Math.PI * 2)
          ctx.fillStyle = grd; ctx.fill()
        }

        // Selected principal: bright ring
        if (n.isCenter) {
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 4, 0, Math.PI * 2)
          ctx.strokeStyle = 'rgba(0,194,224,0.7)'; ctx.lineWidth = 2; ctx.stroke()
        }

        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
        ctx.fillStyle = col; ctx.fill()
        ctx.strokeStyle = 'rgba(0,0,0,0.5)'; ctx.lineWidth = 1; ctx.stroke()

        // Label below node
        ctx.font = `${n.isCenter ? 11 : 9}px Sora,sans-serif`
        ctx.fillStyle = n.isCenter ? '#e2eaf2' : '#94a3b8'
        ctx.textAlign = 'center'
        const label = (n.name || '').length > 20 ? (n.name||'').slice(0,19)+'…' : (n.name||'')
        ctx.fillText(label, n.x, n.y + n.r + 13)
      })

      if (tick < 250) animRef.current = requestAnimationFrame(draw)
    }
    draw()
    return () => cancelAnimationFrame(animRef.current)
  }, [principal, allNodes, allEdges])

  const handleMouseMove = (e) => {
    const canvas = canvasRef.current; if (!canvas) return
    const rect = canvas.getBoundingClientRect()
    const mx = e.clientX - rect.left, my = e.clientY - rect.top
    const hit = simRef.current.nodes.find(n => {
      const dx = n.x - mx, dy = n.y - my
      return Math.sqrt(dx*dx + dy*dy) < n.r + 8
    })
    setTooltip(hit ? { node: hit, x: e.clientX, y: e.clientY } : null)
  }

  return (
    <div style={{ position:'relative', width:'100%', height:'100%' }}>
      <canvas ref={canvasRef} style={{ width:'100%', height:'100%', cursor:'crosshair' }}
        onMouseMove={handleMouseMove} onMouseLeave={() => setTooltip(null)}/>
      {tooltip && (
        <div style={{ position:'fixed', left:tooltip.x+14, top:tooltip.y-10,
          background:'var(--surface)', border:'1px solid var(--border)',
          borderRadius:10, padding:'10px 14px', fontSize:11.5, zIndex:999,
          boxShadow:'0 10px 30px rgba(0,0,0,0.6)', pointerEvents:'none', maxWidth:260 }}>
          <div style={{ fontWeight:700, color:'var(--text)', marginBottom:5 }}>{tooltip.node.name}</div>
          <div style={{ color:'var(--text3)', marginBottom:3 }}>
            Type: <span style={{ color:'var(--text2)' }}>{(tooltip.node.type||'').replace(/_/g,' ')}</span>
          </div>
          {tooltip.node.risk && tooltip.node.risk !== 'none' && (
            <div style={{ color: RISK_COLORS_BLAST[tooltip.node.risk], fontWeight:600 }}>
              Risk: {tooltip.node.risk.toUpperCase()}
            </div>
          )}
          {tooltip.node.has_findings && (
            <div style={{ color:'#fb923c', marginTop:3 }}>{tooltip.node.finding_count} CSPM finding(s)</div>
          )}
          {Object.entries(tooltip.node.properties || {}).slice(0,4).map(([k,v]) => v && (
            <div key={k} style={{ color:'var(--text3)', fontSize:10.5, marginTop:2 }}>
              {k.replace(/_/g,' ')}: <span style={{ color:'var(--text2)' }}>{String(v).slice(0,40)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// Risk badge pill helper
export function RiskBadge({ risk }) {
  const colors = { critical:'#f87171', high:'#fb923c', medium:'#fbbf24', low:'#60a5fa', none:'#64748b' }
  const bgs    = { critical:'rgba(248,113,113,0.12)', high:'rgba(251,146,60,0.12)', medium:'rgba(251,191,36,0.1)', low:'rgba(96,165,250,0.1)', none:'rgba(100,116,139,0.1)' }
  const c = colors[risk] || colors.none
  const bg = bgs[risk]   || bgs.none
  return (
    <span style={{ fontSize:9.5, fontWeight:700, color:c, background:bg,
      border:`1px solid ${c}55`, borderRadius:5, padding:'1px 7px',
      fontFamily:'DM Mono,monospace', textTransform:'uppercase' }}>
      {risk || 'none'}
    </span>
  )
}

export function PanelBlastRadius({ blast, loading, scanning, onRunScan, conn }) {
  const [selected, setSelected] = useState(null)

  // Separate principals (users, SPs, managed identities) from resources
  const principals = (blast?.nodes || []).filter(n =>
    ['service_account','user','principal'].includes(n.type) || n.id?.startsWith('principal:')
  ).sort((a, b) => {
    // Sort: critical > high > medium > low > none
    const order = { critical:0, high:1, medium:2, low:3, none:4 }
    return (order[a.risk]??4) - (order[b.risk]??4)
  })

  // Edges for the selected principal
  const selectedEdges = selected
    ? (blast?.edges || []).filter(e => e.from === selected.id || e.to === selected.id)
    : []

  // Summary stats for selected
  const reachableNodes = selected
    ? [...new Set(selectedEdges.map(e => e.from === selected.id ? e.to : e.from))]
        .map(id => blast.nodes.find(n => n.id === id)).filter(Boolean)
    : []
  const hasOwnerRole = reachableNodes.some(n =>
    (n.name||'').toLowerCase().includes('owner') || (n.name||'').toLowerCase().includes('editor')
  )

  return (
    <div style={{ height:'100%', display:'flex', flexDirection:'column', overflow:'hidden', background:'var(--bg)' }}>

      {/* Header */}
      <div style={{ padding:'14px 22px', borderBottom:'1px solid var(--border)', flexShrink:0,
        display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:2 }}>Blast Radius Analysis</div>
          <div style={{ fontSize:11, color:'var(--text3)' }}>
            Click any principal to explore their access graph — what can they reach if compromised?
          </div>
        </div>
        <button onClick={onRunScan} disabled={scanning}
          style={{ display:'flex', alignItems:'center', gap:7, padding:'7px 14px',
            background: scanning ? 'var(--surface2)' : 'var(--accent)',
            color: scanning ? 'var(--text2)' : '#000',
            border:'none', borderRadius:8, fontSize:12, fontWeight:600,
            cursor: scanning ? 'wait' : 'pointer', fontFamily:'inherit', flexShrink:0 }}>
          {scanning ? '⟳ Scanning…' : '⟳ Run Analysis'}
        </button>
      </div>

      {loading && (
        <div style={{ flex:1, display:'flex', alignItems:'center', justifyContent:'center', color:'var(--text3)', gap:8 }}>
          <span style={{ fontSize:13 }}>Loading blast radius data…</span>
        </div>
      )}

      {!loading && !blast && (
        <div style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', color:'var(--text3)', gap:10 }}>
          <div style={{ fontSize:32 }}>💥</div>
          <div style={{ fontSize:13, fontWeight:600, color:'var(--text2)' }}>No blast radius data yet</div>
          <div style={{ fontSize:11 }}>Run Analysis to map how far each principal can reach</div>
        </div>
      )}

      {blast && !loading && (
        <div style={{ flex:1, display:'flex', overflow:'hidden' }}>

          {/* ── LEFT: Principal list ── */}
          <div style={{ width:280, flexShrink:0, borderRight:'1px solid var(--border)',
            display:'flex', flexDirection:'column', overflow:'hidden' }}>

            {/* Summary bar */}
            <div style={{ padding:'10px 14px', borderBottom:'1px solid var(--border)', background:'var(--surface)',
              display:'flex', gap:12, flexShrink:0 }}>
              {[
                { label:'Principals', value: principals.length,               color:'var(--text2)' },
                { label:'Attack Paths', value: blast.summary?.critical_paths,  color:'#f87171' },
                { label:'Priv Esc',     value: blast.summary?.priv_esc_paths,  color:'#fb923c' },
                { label:'Public Exp.', value: blast.summary?.public_exposures, color:'#fbbf24' },
              ].map(k => (
                <div key={k.label} style={{ flex:1, textAlign:'center' }}>
                  <div style={{ fontSize:16, fontWeight:800, color:k.color, fontFamily:'DM Mono,monospace', lineHeight:1 }}>
                    {k.value || 0}
                  </div>
                  <div style={{ fontSize:9, color:'var(--text3)', marginTop:2 }}>{k.label}</div>
                </div>
              ))}
            </div>

            <div style={{ padding:'8px 10px', borderBottom:'1px solid var(--border)', flexShrink:0 }}>
              <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em' }}>
                {principals.length} Principals — click to explore
              </div>
            </div>

            {/* Principal rows */}
            <div style={{ flex:1, overflowY:'auto' }}>
              {principals.length === 0 && (
                <div style={{ padding:20, textAlign:'center', color:'var(--text3)', fontSize:12 }}>
                  No principals found in blast radius data
                </div>
              )}
              {principals.map(p => {
                const isSelected = selected?.id === p.id
                const outEdges   = (blast.edges||[]).filter(e => e.from === p.id)
                const riskEdges  = outEdges.filter(e => e.risk_boost)
                const reachCount = [...new Set(outEdges.map(e => e.to))].length

                return (
                  <button key={p.id} onClick={() => setSelected(isSelected ? null : p)}
                    style={{ width:'100%', display:'flex', alignItems:'center', gap:10,
                      padding:'10px 12px', textAlign:'left', fontFamily:'inherit',
                      background: isSelected ? 'rgba(0,194,224,0.08)' : 'transparent',
                      borderLeft: `3px solid ${isSelected ? 'var(--accent)' : (RISK_COLORS_BLAST[p.risk] || 'transparent')}`,
                      borderRight:'none', borderTop:'none',
                      borderBottom:'1px solid var(--border)', cursor:'pointer',
                      transition:'all 0.12s' }}>

                    {/* Risk dot */}
                    <div style={{ width:10, height:10, borderRadius:'50%', flexShrink:0,
                      background: RISK_COLORS_BLAST[p.risk] || '#64748b',
                      boxShadow: (p.risk === 'critical' || p.risk === 'high')
                        ? `0 0 6px ${RISK_COLORS_BLAST[p.risk]}` : 'none' }}/>

                    <div style={{ flex:1, minWidth:0 }}>
                      <div style={{ fontSize:11.5, fontWeight:600, color:'var(--text)',
                        whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
                        {p.name}
                      </div>
                      <div style={{ fontSize:10, color:'var(--text3)', marginTop:1 }}>
                        {(p.type||'').replace(/_/g,' ')}
                        {reachCount > 0 && <span style={{ marginLeft:6, color:'var(--text2)' }}>· {reachCount} resource{reachCount!==1?'s':''}</span>}
                        {riskEdges.length > 0 && <span style={{ marginLeft:5, color:'#f87171' }}>· {riskEdges.length} risk path{riskEdges.length!==1?'s':''}</span>}
                      </div>
                    </div>

                    <RiskBadge risk={p.risk}/>
                  </button>
                )
              })}
            </div>

            {/* Legend */}
            <div style={{ padding:'10px 14px', borderTop:'1px solid var(--border)', background:'var(--surface)', flexShrink:0 }}>
              <div style={{ fontSize:9, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:6 }}>Risk Level</div>
              <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
                {['critical','high','medium','low'].map(r => (
                  <div key={r} style={{ display:'flex', alignItems:'center', gap:4 }}>
                    <span style={{ width:7, height:7, borderRadius:'50%', background:RISK_COLORS_BLAST[r], display:'inline-block' }}/>
                    <span style={{ fontSize:10, color:'var(--text2)', textTransform:'capitalize' }}>{r}</span>
                  </div>
                ))}
              </div>
              <div style={{ marginTop:6, fontSize:9.5, color:'var(--text3)' }}>
                <span style={{ color:'#f87171' }}>Red border + glow arrows</span> = risk escalation path
              </div>
            </div>
          </div>

          {/* ── RIGHT: Focus graph or prompt ── */}
          <div style={{ flex:1, display:'flex', flexDirection:'column', overflow:'hidden' }}>

            {!selected && (
              <div style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', color:'var(--text3)', gap:10 }}>
                <div style={{ fontSize:36, opacity:0.4 }}>👤</div>
                <div style={{ fontSize:13, fontWeight:600, color:'var(--text2)' }}>Select a principal</div>
                <div style={{ fontSize:11, maxWidth:300, textAlign:'center', lineHeight:1.6 }}>
                  Click any user or service account on the left to see their access graph — all resources they can reach, and the risk paths from their account.
                </div>
              </div>
            )}

            {selected && (
              <>
                {/* Selected principal header */}
                <div style={{ padding:'12px 18px', borderBottom:'1px solid var(--border)',
                  background:'var(--surface)', flexShrink:0,
                  display:'flex', alignItems:'center', gap:12 }}>
                  <div style={{ width:10, height:10, borderRadius:'50%', flexShrink:0,
                    background: RISK_COLORS_BLAST[selected.risk] || '#64748b',
                    boxShadow: (selected.risk === 'critical' || selected.risk === 'high')
                      ? `0 0 8px ${RISK_COLORS_BLAST[selected.risk]}` : 'none' }}/>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:12.5, fontWeight:700, color:'var(--text)', marginBottom:2 }}>
                      {selected.name}
                    </div>
                    <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
                      <span style={{ fontSize:10, color:'var(--text3)' }}>{(selected.type||'').replace(/_/g,' ')}</span>
                      <RiskBadge risk={selected.risk}/>
                      {selectedEdges.length > 0 && (
                        <span style={{ fontSize:10, color:'var(--text3)' }}>
                          {reachableNodes.length} reachable resource{reachableNodes.length!==1?'s':''}
                        </span>
                      )}
                      {hasOwnerRole && (
                        <span style={{ fontSize:10, fontWeight:700, color:'#f87171',
                          background:'rgba(248,113,113,0.12)', border:'1px solid rgba(248,113,113,0.3)',
                          borderRadius:4, padding:'1px 7px' }}>
                          ⚠ FULL SUBSCRIPTION ACCESS
                        </span>
                      )}
                    </div>
                  </div>
                  <button onClick={() => setSelected(null)}
                    style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', fontSize:18, padding:'0 4px' }}>×</button>
                </div>

                {/* Reach summary chips */}
                {reachableNodes.length > 0 && (
                  <div style={{ padding:'8px 18px', borderBottom:'1px solid var(--border)',
                    display:'flex', gap:6, flexWrap:'wrap', flexShrink:0 }}>
                    {reachableNodes.slice(0, 8).map(n => (
                      <span key={n.id} style={{ fontSize:10.5, padding:'2px 8px', borderRadius:5,
                        background: (n.risk && n.risk !== 'none') ? `${RISK_COLORS_BLAST[n.risk]}18` : 'var(--surface2)',
                        border: `1px solid ${(n.risk && n.risk !== 'none') ? RISK_COLORS_BLAST[n.risk]+'44' : 'var(--border)'}`,
                        color: (n.risk && n.risk !== 'none') ? RISK_COLORS_BLAST[n.risk] : 'var(--text3)' }}>
                        {n.name?.slice(0, 22) || n.id.split(':').pop()?.slice(0, 22)}
                      </span>
                    ))}
                    {reachableNodes.length > 8 && (
                      <span style={{ fontSize:10.5, color:'var(--text3)', padding:'2px 8px' }}>
                        +{reachableNodes.length - 8} more
                      </span>
                    )}
                  </div>
                )}

                {/* The focus graph */}
                <div style={{ flex:1, position:'relative' }}>
                  <BlastFocusGraph
                    principal={selected}
                    allNodes={blast.nodes}
                    allEdges={blast.edges}
                  />
                </div>
              </>
            )}
          </div>

          {/* ── Attack paths panel if any ── */}
          {blast.high_risk_paths?.length > 0 && !selected && (
            <div style={{ width:300, flexShrink:0, borderLeft:'1px solid var(--border)', overflow:'auto', padding:'14px 16px', background:'var(--surface)' }}>
              <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:10 }}>
                Attack Paths ({blast.high_risk_paths.length})
              </div>
              {blast.high_risk_paths.map((p, i) => (
                <div key={i} style={{ background:'var(--surface2)',
                  border:`1px solid ${p.severity==='critical'?'rgba(248,113,113,0.3)':'rgba(251,146,60,0.3)'}`,
                  borderLeft:`3px solid ${RISK_COLORS_BLAST[p.severity]||'var(--border)'}`,
                  borderRadius:8, padding:'10px 12px', marginBottom:8 }}>
                  <div style={{ fontSize:11, fontWeight:600, color:RISK_COLORS_BLAST[p.severity], marginBottom:4 }}>
                    {p.end_privilege?.replace(/_/g,' ').toUpperCase()}
                  </div>
                  <div style={{ fontSize:10.5, color:'var(--text2)', lineHeight:1.5, marginBottom:6 }}>{p.description}</div>
                  <div style={{ display:'flex', alignItems:'center', gap:4, flexWrap:'wrap' }}>
                    {p.path?.map((node, ni) => (
                      <span key={ni} style={{ display:'flex', alignItems:'center', gap:4 }}>
                        <span style={{ fontSize:9.5, fontFamily:'DM Mono,monospace', color:'var(--text3)',
                          background:'var(--surface)', padding:'2px 6px', borderRadius:4, border:'1px solid var(--border)' }}>
                          {node.split(':').pop()?.slice(0,20)}
                        </span>
                        {ni < p.path.length-1 && <span style={{ color:'#f87171', fontSize:11 }}>→</span>}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

