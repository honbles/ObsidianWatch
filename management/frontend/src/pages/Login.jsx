import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Eye, EyeOff, AlertCircle, ArrowRight, Monitor, Boxes, GitBranch, Cloud, Radar, Fingerprint } from 'lucide-react'
import api from '../api/client'
import { STAGE } from '../utils/brand'

const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`

// ── Animated network: endpoints, servers and the occasional threat, with traffic between them ──
function NetworkBackground() {
  const canvasRef = useRef(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const still = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    let raf
    const resize = () => { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight }
    resize()
    window.addEventListener('resize', resize)

    const nodes = Array.from({ length: 30 }, (_, i) => ({
      x: Math.random() * canvas.width, y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.28, vy: (Math.random() - 0.5) * 0.28,
      r: Math.random() * 3 + 1.8,
      type: i < 4 ? 'threat' : i < 10 ? 'server' : 'endpoint',
      pulse: Math.random() * Math.PI * 2, pulseSpeed: Math.random() * 0.02 + 0.01,
    }))
    const colour = { endpoint: STAGE.endpoint, server: STAGE.server, threat: STAGE.threat }
    const packets = []
    const spawn = () => {
      const a = Math.floor(Math.random() * nodes.length)
      let b = Math.floor(Math.random() * nodes.length)
      while (b === a) b = Math.floor(Math.random() * nodes.length)
      packets.push({ from: a, to: b, t: 0, speed: Math.random() * 0.007 + 0.004, threat: nodes[a].type === 'threat' || nodes[b].type === 'threat' })
    }
    for (let i = 0; i < 6; i++) spawn()

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      nodes.forEach(n => {
        n.x += n.vx; n.y += n.vy; n.pulse += n.pulseSpeed
        if (n.x < 0 || n.x > canvas.width) n.vx *= -1
        if (n.y < 0 || n.y > canvas.height) n.vy *= -1
      })
      for (let i = 0; i < nodes.length; i++) for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y, d = Math.sqrt(dx * dx + dy * dy)
        if (d < 180) {
          const threat = nodes[i].type === 'threat' || nodes[j].type === 'threat'
          ctx.beginPath()
          ctx.strokeStyle = rgba(threat ? STAGE.threat : STAGE.endpoint, (1 - d / 180) * (threat ? 0.45 : 0.3))
          ctx.lineWidth = threat ? 0.8 : 0.5
          ctx.moveTo(nodes[i].x, nodes[i].y); ctx.lineTo(nodes[j].x, nodes[j].y); ctx.stroke()
        }
      }
      for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i]
        p.t += p.speed
        if (p.t >= 1) { packets.splice(i, 1); spawn(); continue }
        const A = nodes[p.from], B = nodes[p.to]
        const nx = A.x + (B.x - A.x) * p.t, ny = A.y + (B.y - A.y) * p.t
        const tt = Math.max(0, p.t - 0.06), tx = A.x + (B.x - A.x) * tt, ty = A.y + (B.y - A.y) * tt
        ctx.beginPath(); ctx.arc(nx, ny, 1.8, 0, Math.PI * 2); ctx.fillStyle = rgba(p.threat ? STAGE.threat : STAGE.packet, 1); ctx.fill()
        ctx.beginPath(); ctx.strokeStyle = rgba(p.threat ? STAGE.threat : STAGE.packet, 0.7); ctx.lineWidth = 1
        ctx.moveTo(tx, ty); ctx.lineTo(nx, ny); ctx.stroke()
      }
      nodes.forEach(n => {
        const glow = Math.sin(n.pulse) * 0.5 + 0.5
        if (n.type === 'threat') {
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 4 + glow * 3, 0, Math.PI * 2)
          ctx.fillStyle = rgba(STAGE.threat, 0.05 + glow * 0.08); ctx.fill()
        }
        ctx.beginPath(); ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2); ctx.fillStyle = rgba(colour[n.type], 0.9); ctx.fill()
      })
      if (!still) raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize) }
  }, [])
  return <canvas ref={canvasRef} className="login-net" aria-hidden="true"/>
}

// ── The watching eye: a large eye behind the form that fades into the stage; the iris turns slowly ──
function StageEye() {
  const rays = Array.from({ length: 96 }, (_, i) => {
    const a = (i / 96) * Math.PI * 2, r1 = 50 + (i % 3) * 4, r2 = 104 + ((i * 7) % 11)
    return <line key={i} x1={300 + r1 * Math.cos(a)} y1={200 + r1 * Math.sin(a)} x2={300 + r2 * Math.cos(a)} y2={200 + r2 * Math.sin(a)}
      stroke="var(--ch-acc)" strokeOpacity={0.12 + ((i * 13) % 7) / 28} strokeWidth={i % 4 === 0 ? 1.4 : 0.7}/>
  })
  return (
    <div className="login-eye" aria-hidden="true">
      <svg viewBox="0 0 600 400" className="eye-svg">
        <defs>
          <clipPath id="eye-lids"><path d="M30 200 Q300 8 570 200 Q300 392 30 200Z"/></clipPath>
          <radialGradient id="eye-iris" cx="50%" cy="50%" r="50%">
            <stop offset="35%" stopColor="var(--brand)" stopOpacity=".55"/>
            <stop offset="80%" stopColor="var(--brand)" stopOpacity=".18"/>
            <stop offset="100%" stopColor="var(--brand)" stopOpacity="0"/>
          </radialGradient>
        </defs>
        <path d="M30 200 Q300 8 570 200" fill="none" stroke="var(--ch-acc)" strokeOpacity=".45" strokeWidth="1.6"/>
        <path d="M30 200 Q300 392 570 200" fill="none" stroke="var(--ch-acc)" strokeOpacity=".35" strokeWidth="1.2"/>
        <path d="M60 176 Q300 -10 540 176" fill="none" stroke="var(--ch-acc)" strokeOpacity=".12" strokeWidth=".8"/>
        <g clipPath="url(#eye-lids)">
          <g className="eye-iris">
            <circle cx="300" cy="200" r="122" fill="url(#eye-iris)"/>
            {rays}
            <circle cx="300" cy="200" r="118" fill="none" stroke="var(--ch-acc)" strokeOpacity=".4" strokeWidth="1.2" strokeDasharray="3 7"/>
            <circle cx="300" cy="200" r="82" fill="none" stroke="var(--ch-acc)" strokeOpacity=".18" strokeWidth=".8" strokeDasharray="1 9"/>
          </g>
          <circle cx="300" cy="200" r="46" fill="var(--ch-field)"/>
          <circle cx="300" cy="200" r="46" fill="none" stroke="var(--ch-acc)" strokeOpacity=".5" strokeWidth="1"/>
          <ellipse cx="282" cy="182" rx="12" ry="7" fill="var(--ch-t1)" fillOpacity=".22" transform="rotate(-30 282 182)"/>
        </g>
      </svg>
    </div>
  )
}

const DOMAINS = [
  { icon: Monitor, name: 'Endpoint' }, { icon: Boxes, name: 'Application' }, { icon: GitBranch, name: 'Code' },
  { icon: Cloud, name: 'Cloud' }, { icon: Radar, name: 'Network' }, { icon: Fingerprint, name: 'ITDR' },
]

export default function Login({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [show, setShow]         = useState(false)
  const [caps, setCaps]         = useState(false)
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)
  const [server, setServer]     = useState('checking') // checking | up | down
  const [mounted, setMounted]   = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    api.get('/api/v1/setup/status').then(r => {
      setServer('up')
      if (!r.data.is_complete) navigate('/setup')
    }).catch(() => setServer('down'))
    const t = setTimeout(() => setMounted(true), 60)
    return () => clearTimeout(t)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

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
      setError(err.response?.data?.error || (err.response ? 'Sign-in failed' : "Can't reach the server. Check your connection and try again."))
    } finally { setLoading(false) }
  }
  const capsCheck = (e) => setCaps(!!e.getModifierState?.('CapsLock'))

  return (
    <div className={`login force-dark ${mounted ? 'in' : ''}`}>
      <NetworkBackground/>
      <div className="login-vignette"/>

      <section className="login-brand">
        <div className="login-tag">ObsidianWatch · Security intelligence platform</div>
        <h2>Full-spectrum<br/><b>threat visibility</b><br/>across your estate.</h2>
        <p>Endpoint, application, code, cloud, network and identity security, unified in one console.</p>
        <ul className="login-domains">
          {DOMAINS.map(d => <li key={d.name}><d.icon size={14} strokeWidth={1.7}/>{d.name}</li>)}
        </ul>
      </section>

      <StageEye/>

      <section className="login-card-wrap">
        <div className="login-card">
          <div className="login-card-top"/>
          <h1 className="auth-title">Sign in</h1>
          <p className="auth-sub">Use your ObsidianWatch account.</p>

          <form onSubmit={submit} className="auth-form" noValidate>
            <label className="auth-label" htmlFor="ow-user">Username</label>
            <input id="ow-user" className="input auth-input" type="text" value={username}
              onChange={e => setUsername(e.target.value)} autoComplete="username" autoFocus required
              autoCapitalize="none" spellCheck={false}/>

            <label className="auth-label" htmlFor="ow-pass">Password</label>
            <div className="auth-pass">
              <input id="ow-pass" className="input auth-input" type={show ? 'text' : 'password'} value={password}
                onChange={e => setPassword(e.target.value)} onKeyUp={capsCheck} onKeyDown={capsCheck}
                autoComplete="current-password" required/>
              <button type="button" className="auth-reveal" onClick={() => setShow(s => !s)}
                aria-label={show ? 'Hide password' : 'Show password'} title={show ? 'Hide password' : 'Show password'}>
                {show ? <EyeOff size={15}/> : <Eye size={15}/>}
              </button>
            </div>
            {caps && <div className="auth-hint">Caps Lock is on.</div>}

            {error && <div className="auth-error" role="alert"><AlertCircle size={15}/><span>{error}</span></div>}

            <button type="submit" className="ow-btn primary auth-submit" disabled={loading || !username || !password}>
              {loading ? <><span className="ow-spin" aria-hidden="true"/>Signing in…</> : <>Sign in <ArrowRight size={15}/></>}
            </button>
          </form>

          <div className="auth-meta">
            <span className={`auth-server ${server}`}>
              <span className={`ow-dot ${server === 'up' ? 'ok' : server === 'down' ? 'crit' : 'none'}`}/>
              {server === 'up' ? 'Server reachable' : server === 'down' ? "Can't reach the server" : 'Checking the server…'}
            </span>
            <span>Sign-ins and failed attempts are recorded in the audit log.</span>
          </div>
        </div>
      </section>
    </div>
  )
}
