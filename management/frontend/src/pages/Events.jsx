import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Search, Wifi, Download, X, ChevronRight, Cloud, Monitor, Terminal,
         Shield, Globe, FileText, Key, Activity, AlertTriangle, Cpu,
         GitBranch, GitCommit, Trash2, User, Boxes } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { LIBRARY_GROUPS, tagsToQuery, legacyToQuery, queryChip, searchError } from './events/library'
import { useLiveFeed } from '../api/useLiveFeed'
import { appApi } from '../api/app'
import { SeverityBadge } from '../components/SeverityBadge'
import { PageHeader, Histogram, SEV_STACKS, SEV_WORD, SevPill, fmtCompact } from '../components/ui'
import { IPLink } from '../components/IPLookup'

// ── Event type metadata ───────────────────────────────────────────────────────

const EVENT_TYPE_META = {
  // Endpoint
  process:          { label: 'Process',     color: 'text-indigo-400',  icon: Cpu,       group: 'Endpoint' },
  network:          { label: 'Network',     color: 'text-blue-400',    icon: Globe,     group: 'Endpoint' },
  dns:              { label: 'DNS',         color: 'text-cyan-400',    icon: Globe,     group: 'Endpoint' },
  logon:            { label: 'Logon',       color: 'text-emerald-400', icon: Shield,    group: 'Endpoint' },
  file:             { label: 'File',        color: 'text-yellow-400',  icon: FileText,  group: 'Endpoint' },
  registry:         { label: 'Registry',   color: 'text-purple-400',  icon: Key,       group: 'Endpoint' },
  sysmon:           { label: 'Sysmon',     color: 'text-pink-400',    icon: Activity,  group: 'Endpoint' },
  // Cloud - AWS
  'cloud.cloudtrail':   { label: 'CloudTrail',   color: 'text-orange-400', icon: Cloud, group: 'AWS' },
  'cloud.guardduty':    { label: 'GuardDuty',    color: 'text-red-400',    icon: Shield,group: 'AWS' },
  // Cloud - Azure
  'cloud.azure_activity': { label: 'Azure Activity', color: 'text-blue-400',  icon: Cloud, group: 'Azure' },
  'cloud.entra_signin':   { label: 'Entra Sign-in',  color: 'text-blue-300',  icon: Shield,group: 'Azure' },
  // Cloud - GCP
  'cloud.gcp_audit': { label: 'GCP Audit', color: 'text-green-400', icon: Cloud, group: 'GCP' },

  // Network Probe
  'net.fw_deny':       { label: 'FW Deny',       color: 'text-red-400',     icon: Shield,    group: 'Network' },
  'net.fw_allow':      { label: 'FW Allow',       color: 'text-emerald-400', icon: Globe,     group: 'Network' },
  'net.auth_failure':  { label: 'Auth Failure',   color: 'text-orange-400',  icon: Shield,    group: 'Network' },
  'net.brute_force':   { label: 'Brute Force',    color: 'text-red-500',     icon: Shield,    group: 'Network' },
  'net.new_device':    { label: 'New Device',     color: 'text-yellow-400',  icon: Activity,  group: 'Network' },
  'net.mac_change':    { label: 'MAC Changed',    color: 'text-red-500',     icon: AlertTriangle, group: 'Network' },
  'net.port_scan':     { label: 'Port Scan',      color: 'text-orange-400',  icon: Search,    group: 'Network' },
  'net.lateral':       { label: 'Lateral Move',   color: 'text-purple-400',  icon: Activity,  group: 'Network' },
  'net.vpn_connect':   { label: 'VPN Connect',    color: 'text-blue-400',    icon: Globe,     group: 'Network' },
  'net.config_change': { label: 'Config Change',  color: 'text-red-400',     icon: AlertTriangle, group: 'Network' },
  'net.device_health': { label: 'Device Health',  color: 'text-cyan-400',    icon: Activity,  group: 'Network' },
  'net.top_talker':    { label: 'Bandwidth',       color: 'text-blue-300',   icon: Activity,  group: 'Network' },
  'net.iface_down':    { label: 'Interface Down', color: 'text-red-400',     icon: AlertTriangle, group: 'Network' },
  'net.dhcp_lease':    { label: 'DHCP Lease',     color: 'text-emerald-300', icon: Globe,     group: 'Network' },
  'net.syslog':        { label: 'Syslog',         color: 'text-siem-muted',  icon: FileText,  group: 'Network' },

  // DevOps
  'devops.secret_push':    { label: 'Secret Pushed',    color: 'text-red-500',     icon: Shield,    group: 'DevOps' },
  'devops.cicd_modified':  { label: 'CI/CD Modified',   color: 'text-orange-400',  icon: GitBranch, group: 'DevOps' },
  'devops.sensitive_file': { label: 'Sensitive File',   color: 'text-yellow-400',  icon: FileText,  group: 'DevOps' },
  'devops.push':           { label: 'Push',             color: 'text-emerald-400', icon: GitCommit, group: 'DevOps' },
  'devops.repo_publicized':{ label: 'Repo Made Public', color: 'text-red-500',     icon: Shield,    group: 'DevOps' },
  'devops.repo_deleted':   { label: 'Repo Deleted',     color: 'text-red-400',     icon: Trash2,    group: 'DevOps' },
  'devops.member_added':   { label: 'Member Added',     color: 'text-blue-400',    icon: User,      group: 'DevOps' },
  'devops.workflow_run':   { label: 'Pipeline Run',     color: 'text-purple-400',  icon: Activity,  group: 'DevOps' },
}

function EventTypeBadge({ type }) {
  const etClass = {
    process:'et et-process', network:'et et-network', dns:'et et-dns',
    file:'et et-file', logon:'et et-logon', registry:'et et-registry',
    sysmon:'et et-sysmon', health:'et et-health'
  }[type] || 'et et-default'
  return <span className={etClass}>{type || '-'}</span>
}

// ── Preconfigured saved searches ─────────────────────────────────────────────



// ── EventPanel (detail slide-out) ─────────────────────────────────────────────

export function EventPanel({ event, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/events/${event.id}`)
      .then(r => setDetail(r.data))
      .catch(() => setDetail(null))
      .finally(() => setLoading(false))
  }, [event.id])

  const ev = detail?.event || event
  const related = detail?.related || []
  const isCloud = ev.event_type?.startsWith('cloud.')
  const isDevops = ev.event_type?.startsWith('devops.')

  const fields = [
    ['Time',         format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss.SSS')],
    ['Agent ID',     ev.agent_id],
    ['Host',         ev.host],
    ['OS',           ev.os],
    ['Event Type',   ev.event_type],
    ['Source',       ev.source],
    ['Severity',     ev.severity],
    // Endpoint fields
    ...(!isCloud && !isDevops ? [
      ['PID',          ev.pid],
      ['PPID',         ev.ppid],
      ['Process',      ev.process_name],
      ['Command Line', ev.command_line],
      ['Image Path',   ev.image_path],
      ['User',         ev.user_name],
      ['Domain',       ev.domain],
      ['Src IP',       ev.src_ip],
      ['Src Port',     ev.src_port],
      ['Dst IP',       ev.dst_ip],
      ['Dst Port',     ev.dst_port],
      ['Protocol',     ev.proto],
      ['File Path',    ev.file_path],
      ['File Hash',    ev.file_hash],
      ['Reg Key',      ev.reg_key],
      ['Reg Value',    ev.reg_value],
      ['Event ID',     ev.event_id],
      ['Channel',      ev.channel],
    ] : []),
    // Cloud fields (from raw JSON)
    ...(isCloud ? cloudFields(ev) : []),
    ...(isDevops ? devopsFields(ev) : []),
  ].filter(([, v]) => v !== null && v !== undefined && v !== '' && v !== 0)

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl"
           onClick={e => e.stopPropagation()}>

        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={ev.severity} />
            <EventTypeBadge type={ev.event_type} />
            <span className="text-siem-muted text-xs">on {ev.host}</span>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text transition-colors">
            <X size={18} />
          </button>
        </div>

        {loading ? (
          <div className="p-6 text-siem-muted text-sm">Loading...</div>
        ) : (
          <div className="p-5 space-y-6">
            <div>
              <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">Event Details</div>
              <div className="bg-siem-bg rounded-xl border border-siem-border overflow-hidden">
                {fields.map(([label, value], i) => (
                  <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                    <span className="text-siem-muted w-32 shrink-0">{label}</span>
                    <span className="text-siem-text break-all font-mono text-xs">{(label === 'Src IP' || label === 'Dst IP') ? <IPLink ip={String(value)} /> : String(value)}</span>
                  </div>
                ))}
              </div>
            </div>

            {ev.raw && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">Raw Data</div>
                <pre className="bg-siem-bg border border-siem-border rounded-xl p-4 text-xs text-siem-accent overflow-x-auto max-h-80">
                  {JSON.stringify(typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw, null, 2)}
                </pre>
              </div>
            )}

            {related.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">
                  Related Events <span className="text-siem-muted/50">(±5 min)</span>
                </div>
                <div className="space-y-1">
                  {related.map(r => (
                    <div key={r.id} className="flex items-center gap-3 bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs">
                      <SeverityBadge severity={r.severity} />
                      <EventTypeBadge type={r.event_type} />
                      <span className="text-siem-muted">{r.process_name || r.src_ip || r.user_name || '-'}</span>
                      <span className="text-siem-muted ml-auto">{formatDistanceToNow(new Date(r.time), { addSuffix: true })}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <CreateAlertFromEvent event={ev} />
          </div>
        )}
      </div>
    </div>
  )
}

// Extract human-readable fields from cloud event raw JSON
// devopsFields: human-readable summary of a devops.* event from its raw JSON.
export function devopsFields(ev) {
  let r = {}
  try { r = typeof ev.raw === 'string' ? JSON.parse(ev.raw) : (ev.raw || {}) } catch { r = {} }
  const files = Array.isArray(r.files) ? r.files.map(f => (typeof f === 'string' ? f : f.filename || f.path || '')).filter(Boolean).slice(0, 25).join(', ') : r.files
  return [
    ['User', ev.user_name || r.author || r.author_login],
    ['Repo', r.repo],
    ['Branch', r.branch || r.ref],
    ['Commit', r.sha],
    ['Message', r.message],
    ['Additions', r.additions],
    ['Deletions', r.deletions],
    ['Verified', r.verified === undefined ? undefined : String(r.verified)],
    ['Files', files],
    ['URL', r.url],
  ]
}

function cloudFields(ev) {
  if (!ev.raw) return []
  try {
    const raw = typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw
    const pairs = []
    const add = (k, v) => { if (v !== undefined && v !== null && v !== '') pairs.push([k, String(v)]) }

    add('Src IP',          ev.src_ip)
    add('User / Identity', ev.user_name)

    // AWS CloudTrail fields
    add('Event Name',      raw.event_name)
    add('Event Source',    raw.event_source)
    add('AWS Region',      raw.aws_region)
    add('Error Code',      raw.error_code)
    add('Error Message',   raw.error_message)
    add('User Agent',      raw.user_agent)

    // Azure fields
    add('Operation',       raw.operation_name)
    add('Status',          raw.status)
    add('Resource ID',     raw.resource_id)
    add('Caller',          raw.caller)

    // GCP fields
    add('Method',          raw.method_name)
    add('Log Type',        raw.log_type)

    // GuardDuty
    add('Finding Type',    raw.finding_type)
    add('Title',           raw.title)
    add('GD Severity',     raw.severity)

    // Entra sign-in
    add('App',             raw.app_display_name)
    add('Risk Level',      raw.risk_level)
    add('Risk State',      raw.risk_state)
    add('Location',        raw.location ? `${raw.location.city}, ${raw.location.countryOrRegion}` : null)

    // Identity detail
    if (raw.user_identity) {
      const ui = raw.user_identity
      add('Identity Type', ui.type)
      add('Identity ARN',  ui.arn)
    }

    return pairs
  } catch {
    return []
  }
}

function CreateAlertFromEvent({ event }) {
  const [open, setOpen] = useState(false)
  const [title, setTitle] = useState(`Manual alert: ${event.event_type} on ${event.host}`)
  const [desc, setDesc] = useState('')
  const [severity, setSeverity] = useState(event.severity)
  const [done, setDone] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    await api.post('/api/v1/alerts', {
      title, description: desc, severity, host: event.host,
      agent_id: event.agent_id, event_type: event.event_type, event_id: event.id,
    })
    setDone(true)
    setTimeout(() => { setOpen(false); setDone(false) }, 1500)
  }

  if (!open) return (
    <button onClick={() => setOpen(true)}
      className="w-full text-xs border border-siem-border rounded-lg py-2 text-siem-muted hover:text-siem-accent hover:border-siem-accent transition-colors">
      + Create alert from this event
    </button>
  )

  return (
    <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
      <div className="text-xs font-medium text-siem-text mb-3">Create Alert</div>
      {done ? <div className="text-siem-green text-xs text-center py-2">Alert created</div> : (
        <form onSubmit={submit} className="space-y-3">
          <input className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
            value={title} onChange={e => setTitle(e.target.value)} required />
          <textarea rows={2} className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent resize-none"
            placeholder="Description (optional)" value={desc} onChange={e => setDesc(e.target.value)} />
          <div className="flex gap-2">
            <select className="bg-siem-surface border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text focus:outline-none"
              value={severity} onChange={e => setSeverity(Number(e.target.value))}>
              {[1,2,3,4,5].map(s => <option key={s} value={s}>Severity {s}</option>)}
            </select>
            <button type="button" onClick={() => setOpen(false)}
              className="text-xs text-siem-muted hover:text-siem-text px-3 py-1.5 border border-siem-border rounded-lg">Cancel</button>
            <button type="submit"
              className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-1.5 rounded-lg ml-auto">Create</button>
          </div>
        </form>
      )}
    </div>
  )
}

// ── Saved Searches Panel ──────────────────────────────────────────────────────

function SavedSearchPanel({ onSelect, onClose }) {
  const [activeGroup, setActiveGroup] = useState(LIBRARY_GROUPS[0].group)
  const group = LIBRARY_GROUPS.find(g => g.group === activeGroup)

  const GROUP_ICONS = {
    Windows: Monitor, Linux: Terminal, macOS: Monitor,
    AWS: Cloud, Azure: Cloud, GCP: Cloud, 'All Cloud': Cloud, Cloud: Cloud,
    Code: GitBranch, Application: Boxes,
  }

  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-siem-border">
        <span className="text-xs font-semibold text-siem-text">Query library</span>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={12}/></button>
      </div>
      <div className="flex">
        {/* Group tabs */}
        <div className="w-28 border-r border-siem-border shrink-0">
          {LIBRARY_GROUPS.map(({ group }) => {
            const Icon = GROUP_ICONS[group] || Shield
            const isCloud = false
            return (
              <button key={group} onClick={() => setActiveGroup(group)}
                className={`w-full flex items-center gap-1.5 px-3 py-2 text-mini transition-colors text-left ${
                  activeGroup === group
                    ? 'bg-siem-accent/10 text-siem-accent border-r-2 border-siem-accent'
                    : 'text-siem-muted hover:text-siem-text'
                }`}>
                <Icon size={10}/>
                {group}
                {isCloud && <Cloud size={10} className="ml-auto text-orange-400/60"/>}
              </button>
            )
          })}
        </div>
        {/* Searches */}
        <div className="flex-1 p-2 space-y-1 max-h-72 overflow-y-auto">
          {group?.searches.map((s, i) => (
            <button key={i} onClick={() => { onSelect([queryChip(s.q)]); onClose() }}
              className="w-full text-left px-3 py-2 rounded-lg border border-transparent hover:border-siem-border hover:bg-white/[0.02] transition-colors group">
              <div className="text-xs font-medium text-siem-text group-hover:text-siem-accent flex items-center gap-2">{s.label}
                {s.needs && <span className="tag" style={{ height: 16, fontSize: 12 }} title={`Needs ${s.needs}`}>{s.needs}</span>}</div>
              <div className="text-mini text-siem-muted mt-0.5 mono">{s.q}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Main Events Page ──────────────────────────────────────────────────────────

const TAG_COLORS = {
  search:        'bg-siem-accent/20 text-siem-accent border-siem-accent/40',
  event_type:    'bg-purple-900/30 text-purple-300 border-purple-700/40',
  src_or_dst_ip: 'bg-orange-900/30 text-orange-300 border-orange-700/40',
  dst_port:      'bg-cyan-900/30 text-cyan-300 border-cyan-700/40',
  severity:      'bg-red-900/30 text-red-300 border-red-700/40',
  os:            'bg-blue-900/30 text-blue-300 border-blue-700/40',
  proto:         'bg-green-900/30 text-green-300 border-green-700/40',
  host:          'bg-yellow-900/30 text-yellow-300 border-yellow-700/40',
  source:        'bg-pink-900/30 text-pink-300 border-pink-700/40',
  kql:           'bg-violet-900/30 text-violet-300 border-violet-700/40 font-mono',
}

// Mirrors the backend query language: a field op value condition, parentheses,
// or and/or/not make the input a query rather than a plain search word.
const KQL_FIELDS = new Set(['host','os','user','proc','process','cmd','cmdline','image','file','path','hash','reg','regkey',
  'regvalue','domain','channel','source','proto','guid','logon','src','src_ip','dst','dst_ip','ip','pid','ppid','port',
  'dstport','srcport','event_id','eid','sev','severity','type','event','time','dns','query','action',
  'app','service','route','trace','status'])
export function looksLikeKQL(raw) {
  const l = ' ' + String(raw).toLowerCase() + ' '
  if (/[()]/.test(l) || / (and|or|not) /.test(l)) return true
  return String(raw).split(/\s+/).some(w => {
    const m = w.match(/^-?([a-z_]+)(>=|<=|!=|[:=<>])/i)
    return !!m && KQL_FIELDS.has(m[1].toLowerCase())
  })
}

const KQL_HELP = [
  ['severity>=high and host:web*', 'AND / OR / NOT with ( ) grouping; adjacent terms are ANDed'],
  ['proc:powershell cmd:"-enc"', 'field:value is "contains" (use * as a wildcard); quote values with spaces'],
  ['type:(process or network)', 'one field, several values'],
  ['user=SYSTEM   user!=SYSTEM', '= exact, != not equal'],
  ['port>1024   pid<100   severity=critical', 'numbers compare with > >= < <= ; sev:high means high or worse'],
  ['dst:203.0.113.7   ip:10.0.', 'dst/src/ip: exact for a full IP, otherwise contains'],
  ['dns:ngrok   domain:corp.local', 'dns: DNS query names; domain: also logon domains'],
  ['action:ssh_login_failure', "the collector's action tag (Linux journald and auditd, file actions)"],
  ['os:macos   type:sysmon', 'macos and darwin are the same; type:sysmon covers Sysmon events of every type'],
  ['app:checkout status:500   route:/orders', 'application records (requests with their spans, payloads, errors, jobs): searched only when the query names an application or type:app.*'],
  ['app:checkout type:app.error trace:4bf92f', 'an application\'s errors; trace: finds one request\'s records'],
  ['time>=2026-11-14T10:30', 'UTC date or date-time'],
  ['-chrome   not user:SYSTEM', 'exclude'],
]

const PRESETS = [
  { label: '15m',  ms: 15*60000, name: 'Last 15 minutes' },
  { label: '1h',   ms: 3600000, name: 'Last hour' },
  { label: '24h',  ms: 86400000, name: 'Last 24 hours' },
  { label: '7d',   ms: 7*86400000, name: 'Last 7 days' },
  { label: '30d',  ms: 30*86400000, name: 'Last 30 days' },
]
// <input type="datetime-local"> wants local wall-clock time, not UTC.
const toLocalInput = (d) => { const x = new Date(d); x.setMinutes(x.getMinutes() - x.getTimezoneOffset()); return x.toISOString().slice(0, 16) }
const FACET_FIELDS = [
  ['event_type', 'Event type'], ['host', 'Host'], ['source', 'Source'], ['user_name', 'User'], ['process_name', 'Process'],
]

export default function Events() {
  const [events, setEvents]       = useState([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(false)
  const [page, setPage]           = useState(0)
  const [live, setLive]           = useState(false)
  const [selected, setSelected]   = useState(null)
  const [showSaved, setShowSaved] = useState(false)
  const { events: liveEvents, connected } = useLiveFeed(200)

  const [tags, setTags]     = useState([])
  // Application scope: picking an application adds app:"<name>", which is what brings its records
  // (requests, payloads, errors, jobs) into the search.
  const [appScope, setAppScope] = useState(() => new URLSearchParams(window.location.search).get('app') || '')
  const [appNames, setAppNames] = useState([])
  useEffect(() => {
    const to = new Date(), from = new Date(to.getTime() - 7 * 86400000)
    appApi.services({ from: from.toISOString(), to: to.toISOString() }, { limit: 500 })
      .then(r => setAppNames([...new Set((r?.services || []).map(x => x.name))].sort()))
      .catch(() => {})
  }, [])
  const [inputVal, setInputVal] = useState('')
  const [queryErr, setQueryErr] = useState('')
  const [showHelp, setShowHelp] = useState(false)
  // A search always has a time range (rolling preset or custom). Default: last 24 hours.
  const [preset, setPreset] = useState('24h')
  const [since, setSince]   = useState(() => toLocalInput(Date.now() - 86400000))
  const [until, setUntil]   = useState('')
  const [summary, setSummary] = useState(null)   // server-side counts for the whole query
  const [summaryOK, setSummaryOK] = useState(true)
  const [showCustom, setShowCustom] = useState(false)
  const [showNL, setShowNL] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)
  const inputRef = useRef(null)
  const debounceRef = useRef(null)

  const [nlQuestion, setNlQuestion] = useState('')
  const [nlResult, setNlResult] = useState(null) // {q, since} proposed by AI, editable before applying
  const [nlBusy, setNlBusy] = useState(false)
  const [nlErr, setNlErr] = useState('')
  const askNL = async () => {
    if (!nlQuestion.trim()) return
    setNlBusy(true); setNlErr(''); setNlResult(null)
    try { setNlResult((await api.post('/api/v1/events/nl-query', { question: nlQuestion })).data) }
    catch (e) { setNlErr(e.response?.data?.error || 'Could not generate a query') }
    finally { setNlBusy(false) }
  }
  const applyNL = () => {
    if (!nlResult?.q) return
    setTags([{ id: Date.now() + Math.random(), ...queryChip(nlResult.q) }])
    const ms = { '15m': 9e5, '1h': 36e5, '6h': 216e5, '24h': 864e5, '7d': 6048e5, '30d': 2592e6 }[nlResult.since] || 864e5
    setSince(toLocalInput(Date.now() - ms)); setUntil(''); setPreset(Object.entries({ '15m': 9e5, '1h': 36e5, '24h': 864e5, '7d': 6048e5, '30d': 2592e6 }).find(([, v]) => v === ms)?.[0] || '')
  }

  const limit = 100
  const [savedQueries, setSavedQueries] = useState([])
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [saveQueryName, setSaveQueryName] = useState('')

  const loadSavedQueries = useCallback(async () => {
    try {
      const { data } = await api.get('/api/v1/events/saved-queries')
      setSavedQueries(data.queries || [])
    } catch {}
  }, [])

  const saveQuery = async () => {
    if (!saveQueryName.trim()) return
    const queryStr = [tagsToQuery(tags), inputVal.trim()].filter(Boolean).join(' ')
    if (!queryStr) return
    try {
      await api.post('/api/v1/events/saved-queries', { name: saveQueryName, query: queryStr })
      setSaveQueryName('')
      setShowSaveDialog(false)
      loadSavedQueries()
    } catch {}
  }

  const deleteSavedQuery = async (id) => {
    await api.delete(`/api/v1/events/saved-queries/${id}`)
    loadSavedQueries()
  }

  useEffect(() => { loadSavedQueries() }, [loadSavedQueries])

  const classifyTerm = (val) => {
    const v = val.trim()
    if (!v) return null
    const lower = v.toLowerCase()
    if (looksLikeKQL(v)) return { field: 'kql', label: v, value: v }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v))
      return { field: 'src_or_dst_ip', label: 'IP: ' + v, value: v }
    if (/^\d{1,5}$/.test(v) && parseInt(v) <= 65535)
      return { field: 'dst_port', label: 'Port: ' + v, value: v }

    // Cloud event types - exact and wildcard
    if (lower.startsWith('cloud.') || lower === 'cloud.*' || lower === 'cloud')
      return { field: 'event_type', label: 'Type: ' + (lower === 'cloud' ? 'cloud.*' : v), value: lower === 'cloud' ? 'cloud.*' : lower }

    const types = ['process','network','dns','file','logon','registry','sysmon','raw','health','applog']
    if (types.includes(lower))
      return { field: 'event_type', label: 'Type: ' + v, value: lower }

    const oses = ['windows','linux','darwin','macos']
    if (oses.includes(lower))
      return { field: 'os', label: 'OS: ' + v, value: lower === 'macos' ? 'darwin' : lower }

    // Cloud provider shortcuts → event_type wildcard
    if (lower === 'aws')
      return { field: 'event_type', label: 'Type: cloud.*', value: 'cloud.*' }
    if (lower === 'azure')
      return { field: 'event_type', label: 'Type: cloud.*', value: 'cloud.*' }
    if (lower === 'gcp')
      return { field: 'event_type', label: 'Type: cloud.gcp_audit', value: 'cloud.gcp_audit' }

    const sevMap = { critical:5, high:4, medium:3, low:2, info:1 }
    if (sevMap[lower])
      return { field: 'severity', label: 'Severity: ' + v, value: String(sevMap[lower]) }

    if (['tcp','udp','icmp'].includes(lower))
      return { field: 'proto', label: 'Proto: ' + v, value: lower }

    // Cloud sources
    const sources = ['cloudtrail','guardduty','azure_activity','entra','gcp_audit','auditpipe','inotify','fanotify','proc-net']
    if (sources.some(s => lower.includes(s)))
      return { field: 'source', label: 'Source: ' + v, value: v }

    return { field: 'search', label: v, value: v }
  }

  const addTag = (raw) => {
    const term = classifyTerm(raw)
    if (!term) return
    setTags(t => [...t, { id: Date.now() + Math.random(), ...term }])
    setInputVal('')
  }

  const applySearch = (searchTags) => {
    setTags(searchTags.map(t => ({ ...t, id: Date.now() + Math.random() })))
  }

  const removeTag = (id) => setTags(t => t.filter(tag => tag.id !== id))

  const handleKeyDown = (e) => {
    if ((e.key === 'Enter' || (e.key === ',' && !looksLikeKQL(inputVal))) && inputVal.trim()) {
      e.preventDefault(); addTag(inputVal)
    }
    if (e.key === 'Backspace' && !inputVal && tags.length > 0)
      setTags(t => t.slice(0, -1))
  }

  // Every chip and the typed text become one query in the server's query language.
  const buildQuery = useCallback((liveInput = '') => {
    const live = liveInput.trim()
    const scope = appScope ? `app:"${appScope.replace(/"/g, '')}"` : ''
    return [scope, tagsToQuery(tags), live ? (looksLikeKQL(live) ? '(' + live + ')' : live) : ''].filter(Boolean).join(' ')
  }, [tags, appScope])

  const buildParams = useCallback((p = 0) => {
    const params = { limit, offset: p * limit }
    if (since) params.since = new Date(since).toISOString()
    if (until) params.until = new Date(until + ':59').toISOString()
    return params
  }, [since, until])

  const fetchEvents = useCallback(async (p = 0, liveInput = '') => {
    setLoading(true)
    setQueryErr('')
    const params = buildParams(p)
    const q = buildQuery(liveInput)
    // Timeline and facet counts over the whole query (not just this page), when the server offers them.
    if (p === 0) {
      const sumParams = { ...params }
      delete sumParams.limit; delete sumParams.offset
      if (q) sumParams.q = q
      api.get('/api/v1/events/summary', { params: sumParams })
        .then(r => { setSummary(r.data?.summary || null); setSummaryOK(!!r.data?.summary) })
        .catch(() => { setSummary(null); setSummaryOK(false) })
    }
    try {
      const { data } = q
        ? await api.get('/api/v1/events/search', { params: { ...params, q } })
        : await api.get('/api/v1/events', { params })
      setEvents(data.events || [])
      setTotal(data.total || 0)
    } catch (e) {
      // Say why: a bad query, a timeout or a server error. Keep the previous results on screen.
      setQueryErr(searchError(e))
    } finally { setLoading(false) }
  }, [buildParams, buildQuery])

  useEffect(() => {
    // Debounce search - fire 300ms after last change
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      fetchEvents(0, inputVal); setPage(0)
    }, 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [tags, since, until, inputVal, appScope])

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const eventId = params.get('id')
    const hostParam = params.get('host')

    if (eventId) {
      api.get(`/api/v1/events/${eventId}`).then(r => {
        const ev = r.data?.event
        if (ev) { setSelected(ev); window.history.replaceState({}, '', '/events') }
      }).catch(() => {})
      return
    }

    // Build tags from URL params (from Saved Queries or Quick Actions)
    const newTags = []
    const FIELD_LABELS = { os:'OS', event_type:'Type', severity:'Severity', source:'Source', dst_port:'Port', host:'Host', search:null }
    const paramFields = ['host','os','event_type','severity','source','dst_port','search']
    paramFields.forEach(field => {
      const val = params.get(field)
      if (!val) return
      const label = FIELD_LABELS[field]
      newTags.push({ id: Date.now() + Math.random(), field, label: label ? `${label}: ${val}` : val, value: val })
    })
    if (hostParam && !newTags.find(t => t.field === 'host')) {
      newTags.push({ id: Date.now(), field: 'host', label: 'Host: ' + hostParam, value: hostParam })
    }
    if (newTags.length > 0) {
      setTags(newTags)
      window.history.replaceState({}, '', '/events')
    }
  }, [])

  const exportEvents = async (fmt) => {
    const params = new URLSearchParams({ format: fmt, limit: 10000 })
    Object.entries(buildParams()).forEach(([k, v]) => { if (v && k !== 'limit' && k !== 'offset') params.set(k, String(v)) })
    const q = buildQuery(inputVal)
    if (q) params.set('q', q)
    const token = localStorage.getItem('token')
    const res = await fetch(`/api/v1/events/export?${params}`, { headers: { Authorization: `Bearer ${token}` } })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `obsidianwatch-events.${fmt}`; a.click()
    URL.revokeObjectURL(url)
  }

  const clearAll = () => { setTags([]); setInputVal('') }
  const displayed = live ? liveEvents : events

  // Quick hints: one click adds the term as a filter
  const HINTS = ['process', 'network', 'dns', 'logon', 'file', 'cloud', 'windows', 'linux', 'darwin', 'critical', 'high']

  const applyPreset = (key) => {
    const p = PRESETS.find(x => x.label === key)
    if (!p) return
    setPreset(key); setShowCustom(false)
    setSince(toLocalInput(Date.now() - p.ms)); setUntil('')
  }
  const refresh = () => { if (preset) applyPreset(preset); else fetchEvents(page, inputVal) }
  const rangeName = preset ? PRESETS.find(p => p.label === preset)?.name
    : `${since ? new Date(since).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'start'} – ${until ? new Date(until).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'now'}`

  // Facet click → a real filter (server-side), so the counts and the list always agree with the query.
  const addFacet = (field, v) => {
    if (field === 'event_type') setTags(t => [...t, { id: Date.now() + Math.random(), field: 'event_type', label: 'Type: ' + v, value: v }])
    else if (field === 'host') setTags(t => [...t, { id: Date.now() + Math.random(), field: 'host', label: 'Host: ' + v, value: v }])
    else if (field === 'source') setTags(t => [...t, { id: Date.now() + Math.random(), field: 'source', label: 'Source: ' + v, value: v }])
    else if (field === 'severity') setTags(t => [...t.filter(x => x.field !== 'severity'), { id: Date.now() + Math.random(), field: 'severity', label: `Severity ≥ ${SEV_WORD[v]}`, value: String(v) }])
    else {
      const k = field === 'user_name' ? 'user' : 'proc'
      const q = `${k}="${String(v).replace(/"/g, '')}"`
      setTags(t => [...t, { id: Date.now() + Math.random(), field: 'kql', label: q, value: q }])
    }
  }

  // Facets: from the server summary when available (whole query), else from the page shown (labelled as such).
  const facetData = useMemo(() => {
    if (summary) {
      const sev = [5, 4, 3, 2, 1].map(k => ({ v: k, n: (summary.buckets || []).reduce((a, b) => a + (b.by_sev?.[k] || 0), 0) })).filter(x => x.n)
      return { scope: 'all', sev, fields: summary.facets || {} }
    }
    const count = (get) => { const m = new Map(); events.forEach(e => { const v = get(e); if (v) m.set(v, (m.get(v) || 0) + 1) }); return [...m].map(([v, n]) => ({ v, n })).sort((a, b) => b.n - a.n).slice(0, 10) }
    return {
      scope: 'page',
      sev: [5, 4, 3, 2, 1].map(k => ({ v: k, n: events.filter(e => (e.severity || 1) === k).length })).filter(x => x.n),
      fields: { event_type: count(e => e.event_type), host: count(e => e.host), source: count(e => e.source), user_name: count(e => e.user_name), process_name: count(e => e.process_name) },
    }
  }, [summary, events])

  const histItems = useMemo(() => {
    if (summary) return null
    return events.map(e => ({ t: e.time, k: Math.min(5, Math.max(1, e.severity || 1)) }))
  }, [summary, events])

  const summaryTotal = summary ? (summary.buckets || []).reduce((a, b) => a + b.n, 0) : null
  const fromMs = since ? new Date(since).getTime() : Date.now() - 86400000
  const toMs = until ? new Date(until + ':59').getTime() : Date.now()

  const summaryOf = (ev) => {
    const raw = ev.raw ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return {} } })() : ev.raw) : {}
    const parts = []
    if (ev.user_name) parts.push(ev.user_name)
    if (ev.process_name) parts.push(ev.process_name)
    if (ev.command_line) parts.push(ev.command_line.slice(0, 160))
    if (ev.src_ip) parts.push(`${ev.src_ip}${ev.src_port ? ':' + ev.src_port : ''}`)
    if (ev.dst_ip) parts.push(`→ ${ev.dst_ip}${ev.dst_port ? ':' + ev.dst_port : ''}`)
    if (ev.file_path) parts.push(ev.file_path)
    if (ev.reg_key) parts.push(ev.reg_key)
    const app = raw?.app
    if (app && !parts.length) {
      const svc = app.service ? `[${app.service}] ` : ''
      if (ev.event_type === 'app.request') return `${svc}${app.route || ''}  ${app.status || ''}  ${app.duration_ms ?? ''} ms  ·  ${app.span_count || 0} spans${app.keep_reason && app.keep_reason !== 'baseline' ? '  ·  kept: ' + app.keep_reason : ''}`
      if (ev.event_type === 'app.payload') return `${svc}${app.method || ''} ${app.route || ''}  ${app.http_status || ''}  ·  ${Object.keys(app.params || {}).join(', ')}`
      if (ev.event_type === 'app.error') return `${svc}${app.error_type || 'error'}: ${app.message || app.frame || ''}${app.count > 1 ? '  ×' + app.count : ''}`
      if (ev.event_type === 'app.operation') return `${svc}${app.operation_kind || ''} ${app.operation || ''}  ·  ${app.runs} runs${app.failures ? ', ' + app.failures + ' failed' : ''}`
      if (app['event.name']) return `${svc}${String(app['event.name']).replace(/_/g, ' ')}${app.version ? ' ' + app.version : ''}${app.dependency ? ' → ' + app.dependency : ''}`
    }
    if (!parts.length) {
      const c = raw?.event_name || raw?.operation_name || raw?.method_name || raw?.repo || raw?.message || raw?.action || raw?.finding_type || raw?.commit_sha?.slice(0, 8)
      if (c) parts.push(String(c))
    }
    return parts.join('  ·  ') || ev.source || ev.event_type
  }

  const shownTotal = live ? displayed.length : total
  const tpl = '150px 88px minmax(120px, 0.9fr) 128px minmax(240px, 3fr)'

  return (
    <div>
      {selected && <EventPanel event={selected} onClose={() => setSelected(null)} />}
      <PageHeader
        title="Events"
        sub={live ? (connected ? 'Live tail: newest events as they arrive (last 200).' : 'Live tail: reconnecting…')
          : <>{loading ? 'Searching…' : <><span className="t1 mono">{total.toLocaleString()}</span> events</>} · {rangeName}{tags.length > 0 && ` · ${tags.length} filter${tags.length > 1 ? 's' : ''}`}</>}
        actions={<>
          <button className={`ow-btn ${showSaved ? 'primary' : ''}`} onClick={() => setShowSaved(s => !s)}>Query library</button>
          {!live && (
            <div style={{ position: 'relative' }}>
              <button className="ow-btn" onClick={() => setExportOpen(o => !o)} aria-haspopup="menu" aria-expanded={exportOpen}><Download size={13}/>Export</button>
              {exportOpen && (
                <div className="dropdown" role="menu" style={{ right: 0, left: 'auto', minWidth: 190 }} onMouseLeave={() => setExportOpen(false)}>
                  <div className="dropdown-item" role="menuitem" onClick={() => { setExportOpen(false); exportEvents('csv') }}>CSV, up to 10,000 rows</div>
                  <div className="dropdown-item" role="menuitem" onClick={() => { setExportOpen(false); exportEvents('json') }}>JSON, up to 10,000 rows</div>
                </div>
              )}
            </div>
          )}
          <button className={`ow-btn ${live ? 'primary' : ''}`} onClick={() => setLive(l => !l)} aria-pressed={live}>
            <Wifi size={13}/>{live ? (connected ? 'Live tail on' : 'Reconnecting') : 'Live tail'}
          </button>
        </>}
      />

      <div className="ow-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {!live && (
          <div className="ow-card" style={{ padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {/* Query + time range, one line, like a log explorer */}
            <div style={{ display: 'flex', gap: 8, alignItems: 'stretch', flexWrap: 'wrap' }}>
              <select className="input" style={{ height: 34, width: 'auto', maxWidth: 240, alignSelf: 'flex-start', color: appScope ? 'var(--acc)' : undefined }}
                value={appScope} onChange={e => setAppScope(e.target.value)} aria-label="Application"
                title="Application records (requests, payloads, errors, jobs) are searched only for the application chosen here">
                <option value="">Hosts and platform</option>
                {appNames.map(n => <option key={n} value={n}>App: {n}</option>)}
              </select>
              <div className="ow-field" style={{ flex: '1 1 480px', height: 'auto', minHeight: 34, flexWrap: 'wrap', padding: '3px 10px', cursor: 'text' }} onClick={() => inputRef.current?.focus()}>
                <Search size={14} style={{ color: 'var(--t3)' }}/>
                {tags.map(tag => (
                  <span key={tag.id} className="tag mono" style={{ background: tag.field === 'kql' ? 'var(--abg)' : 'var(--s3)', color: tag.field === 'kql' ? 'var(--acc)' : 'var(--t1)' }}>
                    {tag.label}
                    <button onClick={e => { e.stopPropagation(); removeTag(tag.id) }} aria-label={`Remove ${tag.label}`} style={{ background: 'none', border: 0, color: 'inherit', cursor: 'pointer', padding: 0, marginLeft: 2 }}>×</button>
                  </span>
                ))}
                <input ref={inputRef} className="mono" style={{ minWidth: 200, fontSize: 13.5 }}
                  placeholder={tags.length === 0 ? 'host:web* and proc:powershell, an IP, a user, or any text. Enter adds a filter.' : 'Add a filter…'}
                  value={inputVal} onChange={e => setInputVal(e.target.value)} onKeyDown={handleKeyDown} aria-label="Event query"/>
                {(tags.length > 0 || inputVal) && <button className="ow-btn quiet" style={{ height: 22, padding: '0 4px' }} onClick={() => { setTags([]); setInputVal('') }}>Clear</button>}
              </div>
              <div style={{ display: 'flex', border: '1px solid var(--line2)', borderRadius: 6, overflow: 'hidden', alignSelf: 'flex-start', height: 34 }} role="group" aria-label="Time range">
                {PRESETS.map(p => (
                  <button key={p.label} onClick={() => applyPreset(p.label)} title={p.name}
                    style={{ padding: '0 10px', border: 0, borderRight: '1px solid var(--line)', background: preset === p.label ? 'var(--abg)' : 'transparent', color: preset === p.label ? 'var(--acc)' : 'var(--t2)', font: '500 12px var(--font-ui)', cursor: 'pointer' }}>{p.label}</button>
                ))}
                <button onClick={() => setShowCustom(c => !c)} style={{ padding: '0 10px', border: 0, background: !preset ? 'var(--abg)' : 'transparent', color: !preset ? 'var(--acc)' : 'var(--t2)', font: '500 12px var(--font-ui)', cursor: 'pointer' }}>Custom</button>
              </div>
              <button className="ow-btn" style={{ height: 34 }} onClick={refresh} title="Run again (rolling ranges move to now)">Refresh</button>
            </div>

            {showCustom && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', fontSize: 13.5 }}>
                <span className="t2">From</span>
                <input type="datetime-local" className="input" style={{ width: 200 }} value={since} onChange={e => { setPreset(''); setSince(e.target.value) }}/>
                <span className="t2">to</span>
                <input type="datetime-local" className="input" style={{ width: 200 }} value={until} onChange={e => { setPreset(''); setUntil(e.target.value) }}/>
                <span className="t3">Leave "to" empty for now.</span>
              </div>
            )}

            {queryErr && <div className="c-crit" style={{ fontSize: 13.5 }}>{queryErr}</div>}

            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <button className={`ow-btn quiet ${showHelp ? 'c-acc' : ''}`} style={{ height: 24, padding: '0 6px' }} onClick={() => setShowHelp(h => !h)}>Query syntax</button>
              <button className={`ow-btn quiet ${showNL ? 'c-acc' : ''}`} style={{ height: 24, padding: '0 6px' }} onClick={() => setShowNL(v => !v)}>Ask in plain English</button>
              <span style={{ width: 1, height: 16, background: 'var(--line2)', margin: '0 4px' }}/>
              {HINTS.map(h => <button key={h} className="tag" style={{ cursor: 'pointer', border: 0 }} onClick={() => addTag(h)}>{h}</button>)}
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
                {savedQueries.map(sq => (
                  <span key={sq.id} className="tag" style={{ paddingRight: 4 }}>
                    <button style={{ background: 'none', border: 0, color: 'var(--t1)', cursor: 'pointer', font: 'inherit', padding: 0 }} title={sq.query}
                      onClick={() => { const q = legacyToQuery(sq.query).trim(); if (q) setTags([{ id: Date.now() + Math.random(), ...queryChip(q) }]) }}>{sq.name}</button>
                    <button onClick={() => deleteSavedQuery(sq.id)} aria-label={`Delete saved query ${sq.name}`} style={{ background: 'none', border: 0, color: 'var(--t3)', cursor: 'pointer', padding: 0 }}><X size={10}/></button>
                  </span>
                ))}
                {tags.length > 0 && (showSaveDialog ? (
                  <span style={{ display: 'flex', gap: 6 }}>
                    <input className="input" style={{ width: 160, height: 26 }} autoFocus placeholder="Name this query" value={saveQueryName}
                      onChange={e => setSaveQueryName(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') saveQuery(); if (e.key === 'Escape') setShowSaveDialog(false) }}/>
                    <button className="ow-btn primary" style={{ height: 26 }} onClick={saveQuery}>Save</button>
                  </span>
                ) : <button className="ow-btn" style={{ height: 26 }} onClick={() => setShowSaveDialog(true)}>Save query</button>)}
              </span>
            </div>

            {showHelp && (
              <div className="ow-card" style={{ padding: 12, background: 'var(--s2)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div className="ow-lbl">Query language · click an example to add it</div>
                {KQL_HELP.map(([q, d]) => (
                  <div key={q} style={{ display: 'flex', gap: 14, fontSize: 13.5 }}>
                    <button onClick={() => addTag(q)} className="mono c-acc" style={{ background: 'none', border: 0, cursor: 'pointer', textAlign: 'left', minWidth: 300, padding: 0 }}>{q}</button>
                    <span className="t2">{d}</span>
                  </div>
                ))}
                <div className="t3" style={{ fontSize: 13.5 }}>Fields: <span className="mono">host os user proc cmd image file hash reg domain channel source proto src dst ip port pid ppid eid sev type time</span></div>
              </div>
            )}

            {showNL && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input className="input" style={{ flex: 1 }} maxLength={300} autoFocus value={nlQuestion} onChange={e => setNlQuestion(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') askNL() }}
                    placeholder='e.g. "PowerShell started by Word in the last 7 days"'/>
                  <button className="ow-btn" onClick={askNL} disabled={nlBusy || !nlQuestion.trim()}>{nlBusy ? 'Thinking…' : 'Propose query'}</button>
                </div>
                {nlErr && <div className="c-crit" style={{ fontSize: 13.5 }}>{nlErr}</div>}
                {nlResult && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 13.5 }}>
                    <span className="t2">Review, then apply:</span>
                    <input className="input mono" style={{ flex: 1 }} value={nlResult.q} onChange={e => setNlResult(r => ({ ...r, q: e.target.value }))}/>
                    <span className="t3">last {nlResult.since}</span>
                    <button className="ow-btn primary" onClick={applyNL}>Apply</button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {showSaved && <SavedSearchPanel onSelect={applySearch} onClose={() => setShowSaved(false)} />}

        {!live && (
          <div className="ow-card" style={{ padding: '12px 16px' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 8 }}>
              <span style={{ fontWeight: 500 }}>{summary ? <><span className="mono">{fmtCompact(summaryTotal)}</span> events</> : 'Events'} over time</span>
              <span className="t3" style={{ fontSize: 13.5 }}>{summary ? `${summary.step} buckets · click a bar to zoom` : summaryOK ? 'Loading…' : `of the ${events.length} on this page (the server has no summary endpoint)`}</span>
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 12, fontSize: 13, color: 'var(--t3)' }}>
                {SEV_STACKS.slice().reverse().map(x => <span key={x.k} style={{ display: 'flex', alignItems: 'center', gap: 5 }}><span style={{ width: 8, height: 8, borderRadius: 2, background: x.color }}/>{x.label}</span>)}
              </span>
            </div>
            <Histogram
              items={summary ? (summary.buckets || []).flatMap(b => [1, 2, 3, 4, 5].filter(k => b.by_sev?.[k]).map(k => ({ t: b.t, k, n: b.by_sev[k] }))) : histItems}
              stacks={SEV_STACKS} from={fromMs} to={toMs} label="events"
              onRange={(a, b) => { setPreset(''); setSince(toLocalInput(a)); setUntil(toLocalInput(b)) }}/>
          </div>
        )}

        <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          {!live && (
            <aside className="ow-facets" aria-label="Facets">
              <div className="t3" style={{ fontSize: 13 }}>{facetData.scope === 'all' ? 'Counts over the whole query. Click to filter.' : `Counts in the ${events.length} shown. Click to filter.`}</div>
              {facetData.sev.length > 0 && (
                <div><div className="ow-lbl" style={{ marginBottom: 6 }}>Severity</div>
                  {facetData.sev.map(x => <button key={x.v} className="ow-fc" onClick={() => addFacet('severity', x.v)} title={`Severity ${SEV_WORD[x.v]} or worse`}><span>{SEV_WORD[x.v]}</span><b>{fmtCompact(x.n)}</b></button>)}
                </div>)}
              {FACET_FIELDS.map(([f, label]) => (facetData.fields[f] || []).length > 0 && (
                <div key={f}><div className="ow-lbl" style={{ marginBottom: 6 }}>{label}</div>
                  {facetData.fields[f].slice(0, 8).map(x => <button key={x.v} className="ow-fc" onClick={() => addFacet(f, x.v)} title={x.v}><span className={f === 'event_type' ? '' : 'mono'}>{x.v}</span><b>{fmtCompact(x.n)}</b></button>)}
                </div>
              ))}
            </aside>
          )}

          <div className="ow-card" style={{ flex: 1, minWidth: 0, overflow: 'hidden' }}>
            <div className="ow-grid h" style={{ gridTemplateColumns: tpl }}><div>Time</div><div>Severity</div><div>Host</div><div>Type</div><div>Summary</div></div>
            {loading && !live ? <div className="t3" style={{ padding: '40px 14px', textAlign: 'center' }}>Searching…</div>
              : displayed.length === 0 ? (
                <div className="t3" style={{ padding: '40px 14px', textAlign: 'center' }}>
                  {live ? 'Waiting for events…' : tags.length ? 'No events match this query in this time range.' : 'No events in this time range. Try a longer range.'}
                </div>
              ) : displayed.map((ev, i) => (
                <div key={ev.id || i} className={`ow-grid click ${(ev.severity || 1) >= 5 ? 's-crit' : (ev.severity || 1) >= 4 ? 's-warn' : ''}`} role="row" tabIndex={0}
                  style={{ gridTemplateColumns: tpl, minHeight: 34 }} onClick={() => setSelected(ev)} onKeyDown={e => { if (e.key === 'Enter') setSelected(ev) }}>
                  <span className="mono t2" style={{ fontSize: 13.5 }} title={new Date(ev.time).toISOString()}>{format(new Date(ev.time), 'MMM dd HH:mm:ss')}</span>
                  <span>{(ev.severity || 1) >= 3 ? <SevPill sev={ev.severity}/> : <span className="t3" style={{ fontSize: 13.5 }}>{SEV_WORD[ev.severity || 1]}</span>}</span>
                  <span className="mono t1" title={ev.host}>{ev.host || '—'}</span>
                  <span><EventTypeBadge type={ev.event_type}/></span>
                  <span className="mono t2" style={{ fontSize: 13.5 }} title={summaryOf(ev)}>{summaryOf(ev)}</span>
                </div>
              ))}
            {!live && total > limit && (
              <div className="ow-card-foot">
                <span>Showing {(page * limit + 1).toLocaleString()}–{Math.min(total, (page + 1) * limit).toLocaleString()} of {shownTotal.toLocaleString()}</span>
                <span style={{ display: 'flex', gap: 4 }}>
                  <button className="ow-btn quiet" style={{ height: 24 }} disabled={page === 0} onClick={() => { const p = page - 1; setPage(p); fetchEvents(p, inputVal) }}>‹ Newer</button>
                  <button className="ow-btn quiet" style={{ height: 24 }} disabled={(page + 1) * limit >= total} onClick={() => { const p = page + 1; setPage(p); fetchEvents(p, inputVal) }}>Older ›</button>
                </span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
