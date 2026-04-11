import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api/client'

// ── Animated SOC network background ──────────────────────────────────────────
function SOCBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let raf

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    // Nodes — represent endpoints, servers, threats
    const NODE_COUNT = 28
    const nodes = Array.from({ length: NODE_COUNT }, (_, i) => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 3.5 + 2,
      type: i < 4 ? 'threat' : i < 10 ? 'server' : 'endpoint',
      pulse: Math.random() * Math.PI * 2,
      pulseSpeed: Math.random() * 0.02 + 0.01,
    }))

    // Data packets travelling along edges
    const packets = []
    const spawnPacket = () => {
      const a = Math.floor(Math.random() * nodes.length)
      let b = Math.floor(Math.random() * nodes.length)
      while (b === a) b = Math.floor(Math.random() * nodes.length)
      packets.push({ from: a, to: b, t: 0, speed: Math.random() * 0.008 + 0.004,
        threat: nodes[a].type === 'threat' || nodes[b].type === 'threat' })
    }
    for (let i = 0; i < 6; i++) spawnPacket()

    const COLORS = {
      endpoint: 'rgba(56,189,248,1)',
      server:   'rgba(52,211,153,1)',
      threat:   'rgba(248,113,113,1)',
      edge:     'rgba(56,189,248,0.15)',
      threatEdge: 'rgba(248,113,113,0.18)',
      packet:   'rgba(255,255,255,1)',
      threatPkt:'rgba(248,113,113,1)',
    }

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)

      // Move nodes
      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy; n.pulse += n.pulseSpeed
        if (n.x < 0 || n.x > canvas.width) n.vx *= -1
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1
      })

      // Draw edges between nearby nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const dist = Math.sqrt(dx*dx + dy*dy)
          if (dist < 180) {
            const isThreat = nodes[i].type === 'threat' || nodes[j].type === 'threat'
            const alpha = (1 - dist / 180) * (isThreat ? 0.55 : 0.35)
            ctx.beginPath()
            ctx.strokeStyle = isThreat
              ? `rgba(248,113,113,${alpha})`
              : `rgba(56,189,248,${alpha})`
            ctx.lineWidth = isThreat ? 0.8 : 0.5
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.stroke()
          }
        }
      }

      // Draw packets
      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i]
        p.t += p.speed
        if (p.t >= 1) { packets.splice(i, 1); spawnPacket(); continue }
        const nx = nodes[p.from].x + (nodes[p.to].x - nodes[p.from].x) * p.t
        const ny = nodes[p.from].y + (nodes[p.to].y - nodes[p.from].y) * p.t
        ctx.beginPath()
        ctx.arc(nx, ny, 2, 0, Math.PI * 2)
        ctx.fillStyle = p.threat ? COLORS.threatPkt : COLORS.packet
        ctx.fill()
        // Tail
        const tx = nodes[p.from].x + (nodes[p.to].x - nodes[p.from].x) * Math.max(0, p.t - 0.06)
        const ty = nodes[p.from].y + (nodes[p.to].y - nodes[p.from].y) * Math.max(0, p.t - 0.06)
        ctx.beginPath()
        ctx.strokeStyle = p.threat ? 'rgba(248,113,113,0.85)' : 'rgba(255,255,255,0.75)'
        ctx.lineWidth = 1
        ctx.moveTo(tx, ty)
        ctx.lineTo(nx, ny)
        ctx.stroke()
      }

      // Draw nodes
      nodes.forEach(n => {
        const glow = (Math.sin(n.pulse) * 0.5 + 0.5)
        // Outer glow ring
        if (n.type === 'threat') {
          ctx.beginPath()
          ctx.arc(n.x, n.y, n.r + 4 + glow * 3, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(248,113,113,${0.05 + glow * 0.08})`
          ctx.fill()
        }
        // Node dot
        ctx.beginPath()
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2)
        ctx.fillStyle = COLORS[n.type]
        ctx.fill()
        // Inner highlight
        ctx.beginPath()
        ctx.arc(n.x - n.r * 0.3, n.y - n.r * 0.3, n.r * 0.4, 0, Math.PI * 2)
        ctx.fillStyle = 'rgba(255,255,255,0.3)'
        ctx.fill()
      })

      raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  }, [])

  return (
    <canvas ref={canvasRef} style={{
      position: 'fixed', inset: 0, width: '100%', height: '100%',
      opacity: 1, pointerEvents: 'none'
    }}/>
  )
}

function OWLogo({ size = 48 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <radialGradient id="lg-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.5"/>
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0"/>
        </radialGradient>
        <radialGradient id="lg-lens" cx="38%" cy="35%" r="60%">
          <stop offset="0%" stopColor="#1a3a4a"/>
          <stop offset="60%" stopColor="#0a1a22"/>
          <stop offset="100%" stopColor="#040e14"/>
        </radialGradient>
        <radialGradient id="lg-pupil" cx="42%" cy="40%" r="55%">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.95"/>
          <stop offset="40%" stopColor="#0ea5e9"/>
          <stop offset="100%" stopColor="#0d1b3e"/>
        </radialGradient>
      </defs>
      <circle cx="110" cy="110" r="95" fill="url(#lg-glow)"/>
      <polygon points="110,12 193,59 193,161 110,208 27,161 27,59"
        fill="#06111a" stroke="#1e3a5a" strokeWidth="2"/>
      <polygon points="110,22 183,65 183,155 110,198 37,155 37,65"
        fill="none" stroke="#38bdf8" strokeWidth="0.6" strokeOpacity="0.4"/>
      <circle cx="110" cy="108" r="63" fill="url(#lg-lens)"/>
      <circle cx="110" cy="108" r="63" fill="none" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.8"/>
      <circle cx="110" cy="108" r="43" fill="#0d2040"/>
      <circle cx="110" cy="108" r="24" fill="url(#lg-pupil)"/>
      <circle cx="110" cy="108" r="10" fill="#001830"/>
      <ellipse cx="97" cy="93" rx="10" ry="6.5" fill="white" fillOpacity="0.14" transform="rotate(-30 97 93)"/>
      <line x1="70" y1="108" x2="150" y2="108" stroke="#38bdf8" strokeWidth="0.4" strokeOpacity="0.25"/>
      <line x1="75" y1="96"  x2="145" y2="96"  stroke="#38bdf8" strokeWidth="0.3" strokeOpacity="0.15"/>
      <line x1="75" y1="120" x2="145" y2="120" stroke="#38bdf8" strokeWidth="0.3" strokeOpacity="0.15"/>
    </svg>
  )
}

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const [mounted, setMounted]   = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/api/v1/setup/status').then(r => {
      if (!r.data.is_complete) navigate('/setup')
    }).catch(() => {})
    setTimeout(() => setMounted(true), 80)
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    if (!username || !password) return
    setLoading(true); setError('')
    try {
      const { data } = await api.post('/auth/login', { username, password })
      localStorage.setItem('token', data.token)
      localStorage.setItem('user', JSON.stringify(data.user))
      onLogin(data.user, data.require_password_change)
    } catch (err) {
      setError(err.response?.data?.error || 'Authentication failed')
    } finally { setLoading(false) }
  }

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)', display:'flex',
                  alignItems:'center', justifyContent:'center', position:'relative',
                  overflow:'hidden' }}>

      {/* Animated network background */}
      <SOCBackground/>

      {/* Deep gradient overlays for depth */}
      <div style={{
        position:'fixed', inset:0, pointerEvents:'none',
        background: 'radial-gradient(ellipse 80% 60% at 50% 50%, rgba(13,27,62,0.6) 0%, rgba(14,17,23,0.85) 70%)'
      }}/>

      {/* Left panel — branding */}
      <div style={{
        position:'fixed', left:0, top:0, bottom:0, width:'42%',
        display:'flex', flexDirection:'column', justifyContent:'center',
        padding:'0 60px', zIndex:1,
        opacity: mounted ? 1 : 0,
        transform: mounted ? 'translateX(0)' : 'translateX(-20px)',
        transition: 'opacity 0.7s ease 0.1s, transform 0.7s ease 0.1s',
      }}>
        <div style={{ display:'flex', alignItems:'center', gap:14, marginBottom:32 }}>
          <OWLogo size={52}/>
          <div>
            <div style={{ fontSize:22, fontWeight:700, color:'#fff', letterSpacing:'-0.3px' }}>
              ObsidianWatch
            </div>
            <div style={{ fontSize:10, color:'var(--text3)', letterSpacing:'0.14em',
                          fontFamily:'DM Mono, monospace', textTransform:'uppercase', marginTop:3 }}>
              Security Intelligence Platform
            </div>
          </div>
        </div>

        <h2 style={{ fontSize:32, fontWeight:300, color:'var(--text)', lineHeight:1.3,
                      letterSpacing:'-0.5px', marginBottom:16 }}>
          Full-spectrum<br/>
          <span style={{ fontWeight:700, color:'var(--accent)' }}>threat visibility</span><br/>
          across your estate.
        </h2>
        <p style={{ fontSize:13, color:'var(--text2)', lineHeight:1.7, maxWidth:340 }}>
          Real-time detection, endpoint telemetry, cloud monitoring,
          network visibility, application security and DevOps intelligence
          — unified in one platform.
        </p>

        {/* Stats row */}
        <div style={{ display:'flex', gap:24, marginTop:40 }}>
          {[
            { label:'Detection Rules', value:'Evaluated' },
            { label:'Threat Intel',    value:'20+' },
            { label:'MITRE Coverage',  value:'ATT&CK' },
          ].map(s => (
            <div key={s.label}>
              <div style={{ fontSize:18, fontWeight:700, color:'var(--accent)',
                             fontFamily:'DM Mono, monospace' }}>{s.value}</div>
              <div style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Live indicator */}
        <div style={{ display:'flex', alignItems:'center', gap:8, marginTop:48,
                       fontSize:11, color:'var(--text3)' }}>
          <span className="pulse" style={{ width:6, height:6, borderRadius:'50%',
            background:'var(--green)', display:'inline-block' }}/>
          Network monitoring active
        </div>
      </div>

      {/* Center — fading rotating eye */}
      <div style={{
        position: 'fixed',
        left: '50%', top: '50%',
        transform: 'translate(-50%, -50%)',
        zIndex: 1, pointerEvents: 'none',
      }}>
        <style>{`
          @keyframes slowRotate {
            from { transform: rotate(0deg); }
            to   { transform: rotate(360deg); }
          }
          @keyframes slowRotateReverse {
            from { transform: rotate(0deg); }
            to   { transform: rotate(-360deg); }
          }
          @keyframes eyePulse {
            0%,100% { opacity: 0.07; }
            50%      { opacity: 0.14; }
          }
          .eye-outer { animation: slowRotate 32s linear infinite, eyePulse 6s ease-in-out infinite; }
          .eye-mid   { animation: slowRotateReverse 18s linear infinite; }
          .eye-inner { animation: slowRotate 10s linear infinite; }
        `}</style>

        {/* Outer hex ring */}
        <svg className="eye-outer" width="380" height="380" viewBox="0 0 380 380"
          style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%) rotate(0deg)' }}>
          <polygon points="190,18 348,103 348,277 190,362 32,277 32,103"
            fill="none" stroke="rgba(56,189,248,0.25)" strokeWidth="1"/>
          <polygon points="190,30 336,110 336,270 190,350 44,270 44,110"
            fill="none" stroke="rgba(56,189,248,0.1)" strokeWidth="0.5"/>
          {/* tick marks on hex */}
          {[0,60,120,180,240,300].map((deg,i) => {
            const rad = (deg - 90) * Math.PI / 180
            const r1 = 158, r2 = 168
            const x1 = 190 + r1 * Math.cos(rad), y1 = 190 + r1 * Math.sin(rad)
            const x2 = 190 + r2 * Math.cos(rad), y2 = 190 + r2 * Math.sin(rad)
            return <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="rgba(56,189,248,0.5)" strokeWidth="1.5"/>
          })}
        </svg>

        {/* Mid ring — counter-rotates */}
        <svg className="eye-mid" width="260" height="260" viewBox="0 0 260 260"
          style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)' }}>
          <circle cx="130" cy="130" r="118"
            fill="none" stroke="rgba(56,189,248,0.12)" strokeWidth="0.8"
            strokeDasharray="4 8"/>
          <circle cx="130" cy="130" r="108"
            fill="none" stroke="rgba(56,189,248,0.06)" strokeWidth="0.5"/>
        </svg>

        {/* The eye itself — center, static */}
        <svg width="160" height="160" viewBox="0 0 220 220"
          style={{ position:'absolute', top:'50%', left:'50%',
                   transform:'translate(-50%,-50%)', opacity:0.12 }}>
          <defs>
            <radialGradient id="ctr-lens" cx="38%" cy="35%" r="60%">
              <stop offset="0%" stopColor="#1a3a4a"/>
              <stop offset="100%" stopColor="#040e14"/>
            </radialGradient>
            <radialGradient id="ctr-pupil" cx="42%" cy="40%" r="55%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.9"/>
              <stop offset="100%" stopColor="#0d1b3e"/>
            </radialGradient>
          </defs>
          <polygon points="110,12 193,59 193,161 110,208 27,161 27,59"
            fill="#06111a" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.6"/>
          <circle cx="110" cy="108" r="63" fill="url(#ctr-lens)"/>
          <circle cx="110" cy="108" r="63" fill="none" stroke="#38bdf8" strokeWidth="1.5" strokeOpacity="0.8"/>
          <circle cx="110" cy="108" r="43" fill="#0d2040"/>
          <circle cx="110" cy="108" r="24" fill="url(#ctr-pupil)"/>
          <circle cx="110" cy="108" r="10" fill="#001830"/>
          <ellipse cx="97" cy="93" rx="10" ry="6.5" fill="white" fillOpacity="0.2" transform="rotate(-30 97 93)"/>
          <line x1="70" y1="108" x2="150" y2="108" stroke="#38bdf8" strokeWidth="0.5" strokeOpacity="0.4"/>
          <line x1="75" y1="96"  x2="145" y2="96"  stroke="#38bdf8" strokeWidth="0.3" strokeOpacity="0.2"/>
          <line x1="75" y1="120" x2="145" y2="120" stroke="#38bdf8" strokeWidth="0.3" strokeOpacity="0.2"/>
        </svg>

        {/* Inner rotating ring */}
        <svg className="eye-inner" width="200" height="200" viewBox="0 0 200 200"
          style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)' }}>
          <circle cx="100" cy="100" r="88"
            fill="none" stroke="rgba(56,189,248,0.08)" strokeWidth="0.5"
            strokeDasharray="2 12"/>
        </svg>

        {/* Radial fade gradient so it dissolves into background */}
        <div style={{
          position:'absolute', top:'50%', left:'50%',
          transform:'translate(-50%,-50%)',
          width:420, height:420, borderRadius:'50%',
          background:'radial-gradient(circle, transparent 30%, var(--bg) 70%)',
          pointerEvents:'none',
        }}/>
      </div>

      {/* Right panel — login form */}
      <div style={{
        position:'relative', zIndex:2,
        marginLeft:'auto', marginRight:'8%',
        width:'100%', maxWidth:380,
        opacity: mounted ? 1 : 0,
        transform: mounted ? 'translateY(0)' : 'translateY(16px)',
        transition: 'opacity 0.6s ease 0.25s, transform 0.6s ease 0.25s',
      }}>
        <div style={{
          background: 'color-mix(in srgb, var(--surface) 92%, transparent)',
          border: '1px solid var(--border2)',
          borderRadius: 16,
          overflow: 'hidden',
          boxShadow: '0 32px 80px rgba(0,0,0,0.5), 0 0 0 1px rgba(56,189,248,0.06)',
          backdropFilter: 'blur(20px)',
        }}>
          {/* Top accent */}
          <div style={{ height:2, background:'linear-gradient(90deg, transparent, var(--accent) 50%, transparent)' }}/>

          <div style={{ padding:'32px 32px 36px' }}>
            <div style={{ marginBottom:28 }}>
              <h3 style={{ fontSize:16, fontWeight:600, color:'var(--text)', marginBottom:4 }}>
                Sign in to your workspace
              </h3>
              <p style={{ fontSize:11.5, color:'var(--text3)' }}>
                All sessions are encrypted and audited
              </p>
            </div>

            <form onSubmit={submit}>
              <div style={{ marginBottom:14 }}>
                <label style={{ display:'block', fontSize:10.5, fontWeight:600,
                                 letterSpacing:'0.08em', textTransform:'uppercase',
                                 color:'var(--text3)', marginBottom:6 }}>
                  Username
                </label>
                <input className="input" type="text" value={username}
                  onChange={e => setUsername(e.target.value)}
                  placeholder="Enter username"
                  autoComplete="username" autoFocus required/>
              </div>

              <div style={{ marginBottom:20 }}>
                <label style={{ display:'block', fontSize:10.5, fontWeight:600,
                                 letterSpacing:'0.08em', textTransform:'uppercase',
                                 color:'var(--text3)', marginBottom:6 }}>
                  Password
                </label>
                <input className="input" type="password" value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter password"
                  autoComplete="current-password" required/>
              </div>

              {error && (
                <div style={{
                  background:'var(--red-bg)', border:'1px solid rgba(248,113,113,0.2)',
                  borderRadius:8, padding:'9px 12px', fontSize:12, color:'var(--red)',
                  marginBottom:16, display:'flex', alignItems:'center', gap:8
                }}>
                  <span>⚠</span> {error}
                </div>
              )}

              <button type="submit" disabled={loading || !username || !password}
                style={{
                  width:'100%', padding:'10px 0',
                  background: 'var(--accent)', color:'#000',
                  border:'none', borderRadius:9,
                  fontSize:13, fontWeight:600, cursor: loading ? 'wait' : 'pointer',
                  transition:'all 0.15s', opacity: (!username || !password) ? 0.5 : 1,
                  display:'flex', alignItems:'center', justifyContent:'center', gap:8,
                  fontFamily:'inherit',
                }}>
                {loading ? (
                  <>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                      style={{ animation:'spin 0.8s linear infinite' }}>
                      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
                      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3"
                        strokeDasharray="30 40" strokeLinecap="round"/>
                    </svg>
                    Authenticating…
                  </>
                ) : 'Sign In'}
              </button>
            </form>

            <div style={{ marginTop:20, paddingTop:16, borderTop:'1px solid var(--border)',
                           display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <span style={{ fontSize:10.5, color:'var(--text3)' }}>
                v0.3.1 · Enterprise
              </span>
              <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10.5,
                             color:'var(--green)' }}>
                <span style={{ width:5, height:5, borderRadius:'50%',
                  background:'var(--green)', display:'inline-block' }}/>
                System operational
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
