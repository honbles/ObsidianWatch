// First-run setup (sign in has its own stage, pages/Login.jsx): the brand panel on the left keeps the chrome colours in
// both themes; the form panel on the right follows the theme. Under 960 px only the form panel shows.
import { Monitor, Boxes, GitBranch, Cloud, Sun, Moon } from 'lucide-react'
import { OWMark, OWWordmark } from './Shell'
import { useTheme } from '../api/useTheme'

const DOMAINS = [
  { icon: Monitor,   name: 'Endpoint',    text: 'Linux, Windows and macOS agents: telemetry, detection and response.' },
  { icon: Boxes,     name: 'Application', text: 'Traces, errors and runtime security from your services, through OpenTelemetry.' },
  { icon: GitBranch, name: 'Code',        text: 'Secrets, SAST, dependencies and posture across GitHub, GitLab and Azure DevOps.' },
  { icon: Cloud,     name: 'Cloud',       text: 'AWS, Azure and GCP: logs, posture and CIS benchmarks.' },
]

// Faceted obsidian: large flat shards with lit edges, drawn once. Decorative only.
function Facets() {
  return (
    <svg className="auth-facets" viewBox="0 0 400 420" preserveAspectRatio="xMaxYMax meet" aria-hidden="true">
      <path d="M262 40 400 128 400 420 196 420 150 236z" fill="var(--ch-2)" opacity=".75"/>
      <path d="M262 40 316 222 196 420 150 236z" fill="var(--ch-3)" opacity=".45"/>
      <path d="M316 222 400 128 400 420 196 420z" fill="var(--ch-field)" opacity=".55"/>
      <path d="M262 40 400 128M262 40 150 236M262 40 316 222 196 420M316 222 400 128" stroke="var(--ch-acc)" strokeOpacity=".2" fill="none"/>
      <path d="M70 330 150 236 196 420 46 420z" fill="var(--ch-2)" opacity=".5"/>
      <path d="M70 330 150 236 196 420" stroke="var(--ch-acc)" strokeOpacity=".12" fill="none"/>
    </svg>
  )
}

export function AuthLayout({ children, wide = false }) {
  const { theme, toggle } = useTheme()
  return (
    <div className="auth">
      <aside className="auth-brand">
        <Facets/>
        <div className="auth-brand-in">
          <div className="auth-lockup"><OWMark size={30}/><OWWordmark/></div>
          <div className="auth-pitch">
            <div className="auth-eyebrow">Security intelligence platform</div>
            <h2>One watch over your endpoints, applications, code and cloud.</h2>
            <ul className="auth-domains">
              {DOMAINS.map(d => (
                <li key={d.name}><span className="auth-dicon"><d.icon size={15} strokeWidth={1.7}/></span>
                  <div><b>{d.name}</b><span>{d.text}</span></div></li>
              ))}
            </ul>
          </div>
        </div>
      </aside>
      <main className="auth-main">
        <div className="auth-top">
          <div className="auth-lockup auth-lockup-sm"><OWMark size={24}/><OWWordmark/></div>
          <button type="button" className="ow-btn quiet auth-theme" onClick={toggle}
            title={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} aria-label="Toggle theme">
            {theme === 'dark' ? <Sun size={14}/> : <Moon size={14}/>}
          </button>
        </div>
        <div className={`auth-panel ${wide ? 'wide' : ''}`}>{children}</div>
      </main>
    </div>
  )
}
