import { useState, useEffect, useCallback, useRef } from 'react'
import { Search as SearchIcon, Play, BookOpen, X, ChevronRight, ExternalLink } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

// ── 100 Saved Queries ─────────────────────────────────────────────────────────
// DNS note: old agent stored DNS as event_type=network source=DNS-Client
//           new agent (fixed) stores as event_type=dns. We search both via source filter.
const SAVED_QUERIES = [
  // PROCESS
  { cat: 'Process', label: 'All processes on all hosts',          params: { event_type: 'process' } },
  { cat: 'Process', label: 'All PowerShell executions',           params: { event_type: 'process', process_name: 'powershell' } },
  { cat: 'Process', label: 'PowerShell encoded commands',         params: { event_type: 'process', command_line: '-enc' } },
  { cat: 'Process', label: 'PowerShell download cradles',         params: { event_type: 'process', command_line: 'downloadstring' } },
  { cat: 'Process', label: 'CMD executions',                      params: { event_type: 'process', process_name: 'cmd.exe' } },
  { cat: 'Process', label: 'Rundll32 executions',                 params: { event_type: 'process', process_name: 'rundll32' } },
  { cat: 'Process', label: 'MSHTA executions',                    params: { event_type: 'process', process_name: 'mshta' } },
  { cat: 'Process', label: 'WScript / CScript',                   params: { event_type: 'process', search: 'wscript' } },
  { cat: 'Process', label: 'Regsvr32 executions',                 params: { event_type: 'process', process_name: 'regsvr32' } },
  { cat: 'Process', label: 'Certutil abuse',                      params: { event_type: 'process', process_name: 'certutil' } },
  { cat: 'Process', label: 'BITSAdmin executions',                params: { event_type: 'process', search: 'bitsadmin' } },
  { cat: 'Process', label: 'Scheduled task creation',             params: { event_type: 'process', command_line: 'schtasks' } },
  { cat: 'Process', label: 'New service (sc create)',             params: { event_type: 'process', command_line: 'sc create' } },
  { cat: 'Process', label: 'PsExec remote execution',             params: { event_type: 'process', search: 'psexec' } },
  { cat: 'Process', label: 'High severity process events',        params: { event_type: 'process', severity: '4' } },
  { cat: 'Process', label: 'Net.exe account commands',            params: { event_type: 'process', search: 'net user' } },
  { cat: 'Process', label: 'whoami execution',                    params: { event_type: 'process', command_line: 'whoami' } },
  { cat: 'Process', label: 'Shadow copy deletion',                params: { event_type: 'process', command_line: 'vssadmin' } },
  { cat: 'Process', label: 'WMIC command execution',              params: { event_type: 'process', process_name: 'wmic' } },
  { cat: 'Process', label: 'bcdedit (recovery disabled)',         params: { event_type: 'process', command_line: 'bcdedit' } },

  // CREDENTIAL
  { cat: 'Credential', label: 'All logon events',                 params: { event_type: 'logon' } },
  { cat: 'Credential', label: 'Failed logons (Event 4625)',        params: { event_type: 'logon', event_id: '4625' } },
  { cat: 'Credential', label: 'Successful logons (Event 4624)',    params: { event_type: 'logon', event_id: '4624' } },
  { cat: 'Credential', label: 'Logon with explicit creds (4648)', params: { event_type: 'logon', event_id: '4648' } },
  { cat: 'Credential', label: 'LSASS access attempts',            params: { event_type: 'process', search: 'lsass' } },
  { cat: 'Credential', label: 'Mimikatz indicators',              params: { event_type: 'process', search: 'mimikatz' } },
  { cat: 'Credential', label: 'Procdump usage',                   params: { event_type: 'process', search: 'procdump' } },
  { cat: 'Credential', label: 'SAM registry access',              params: { event_type: 'registry', reg_key: 'SAM' } },
  { cat: 'Credential', label: 'Password string search',           params: { event_type: 'process', command_line: 'password' } },
  { cat: 'Credential', label: 'High severity logon events',       params: { event_type: 'logon', severity: '4' } },

  // NETWORK
  { cat: 'Network', label: 'All network connections',             params: { event_type: 'network' } },
  { cat: 'Network', label: 'Outbound RDP (port 3389)',            params: { event_type: 'network', dst_port: '3389' } },
  { cat: 'Network', label: 'Outbound SMB (port 445)',             params: { event_type: 'network', dst_port: '445' } },
  { cat: 'Network', label: 'Outbound SSH (port 22)',              params: { event_type: 'network', dst_port: '22' } },
  { cat: 'Network', label: 'Outbound FTP (port 21)',              params: { event_type: 'network', dst_port: '21' } },
  { cat: 'Network', label: 'HTTP traffic (port 80)',              params: { event_type: 'network', dst_port: '80' } },
  { cat: 'Network', label: 'HTTPS traffic (port 443)',            params: { event_type: 'network', dst_port: '443' } },
  { cat: 'Network', label: 'DNS traffic (port 53)',               params: { event_type: 'network', dst_port: '53' } },
  { cat: 'Network', label: 'SMTP outbound (port 587)',            params: { event_type: 'network', dst_port: '587' } },
  { cat: 'Network', label: 'WinRM (port 5985)',                   params: { event_type: 'network', dst_port: '5985' } },
  { cat: 'Network', label: 'LDAP (port 389)',                     params: { event_type: 'network', dst_port: '389' } },
  { cat: 'Network', label: 'Kerberos (port 88)',                  params: { event_type: 'network', dst_port: '88' } },
  { cat: 'Network', label: 'SQL Server (port 1433)',              params: { event_type: 'network', dst_port: '1433' } },
  { cat: 'Network', label: 'All TCP connections',                 params: { event_type: 'network', proto: 'tcp' } },
  { cat: 'Network', label: 'High severity network events',        params: { event_type: 'network', severity: '4' } },

  // DNS — searches BOTH old (network+DNS-Client source) and new (event_type=dns) 
  { cat: 'DNS / Web', label: 'All websites visited (DNS)',        params: { event_type: 'dns' }, fallback: { search: 'DNS-Client' } },
  { cat: 'DNS / Web', label: 'RustDesk DNS queries',              params: { event_type: 'dns', search: 'rustdesk' }, fallback: { search: 'rustdesk' } },
  { cat: 'DNS / Web', label: 'WPAD proxy discovery',             params: { event_type: 'dns', search: 'wpad' },     fallback: { search: 'wpad' } },
  { cat: 'DNS / Web', label: 'Urban VPN queries',                params: { event_type: 'dns', search: 'urban-vpn' },fallback: { search: 'urban-vpn' } },
  { cat: 'DNS / Web', label: 'ngrok tunnel queries',             params: { event_type: 'dns', search: 'ngrok' },    fallback: { search: 'ngrok' } },
  { cat: 'DNS / Web', label: 'Pastebin lookups',                 params: { event_type: 'dns', search: 'pastebin' } },
  { cat: 'DNS / Web', label: 'TOR / .onion domains',             params: { event_type: 'dns', search: '.onion' } },
  { cat: 'DNS / Web', label: 'AnyDesk DNS queries',              params: { event_type: 'dns', search: 'anydesk' },  fallback: { search: 'anydesk' } },
  { cat: 'DNS / Web', label: 'TeamViewer DNS queries',           params: { event_type: 'dns', search: 'teamviewer' } },
  { cat: 'DNS / Web', label: 'High severity DNS events',         params: { event_type: 'dns', severity: '4' } },

  // FILE
  { cat: 'File', label: 'All file events',                       params: { event_type: 'file' } },
  { cat: 'File', label: 'Temp directory writes',                 params: { event_type: 'file', file_path: '\\temp\\' } },
  { cat: 'File', label: 'AppData writes',                        params: { event_type: 'file', file_path: 'appdata' } },
  { cat: 'File', label: 'Desktop file drops',                    params: { event_type: 'file', file_path: '\\desktop\\' } },
  { cat: 'File', label: 'Executable files written (.exe)',       params: { event_type: 'file', file_path: '.exe' } },
  { cat: 'File', label: 'PowerShell scripts written (.ps1)',     params: { event_type: 'file', file_path: '.ps1' } },
  { cat: 'File', label: 'Startup folder writes',                 params: { event_type: 'file', file_path: 'startup' } },
  { cat: 'File', label: 'System32 writes',                       params: { event_type: 'file', file_path: 'system32' } },
  { cat: 'File', label: 'Encrypted file extensions',             params: { event_type: 'file', search: '.locked' } },
  { cat: 'File', label: 'High severity file events',             params: { event_type: 'file', severity: '4' } },


  // LINUX — Process
  { cat: 'Linux', label: 'All Linux process events',              params: { event_type: 'process', os: 'linux' } },
  { cat: 'Linux', label: 'Shell executions (bash/sh/zsh)',        params: { event_type: 'process', search: 'bash' } },
  { cat: 'Linux', label: 'Python interpreter executions',         params: { event_type: 'process', search: 'python' } },
  { cat: 'Linux', label: 'Perl executions',                       params: { event_type: 'process', search: 'perl' } },
  { cat: 'Linux', label: 'Curl / wget commands',                  params: { event_type: 'process', search: 'curl' } },
  { cat: 'Linux', label: 'Ncat / netcat usage',                   params: { event_type: 'process', search: 'ncat' } },
  { cat: 'Linux', label: 'chmod +x executions',                   params: { event_type: 'process', command_line: 'chmod' } },
  { cat: 'Linux', label: 'Process from /tmp',                     params: { event_type: 'process', search: '/tmp/' } },
  { cat: 'Linux', label: 'Process from /dev/shm',                 params: { event_type: 'process', search: '/dev/shm' } },
  { cat: 'Linux', label: 'LD_PRELOAD in command line',            params: { event_type: 'process', search: 'ld_preload' } },
  { cat: 'Linux', label: 'strace / ptrace usage',                 params: { event_type: 'process', search: 'strace' } },
  { cat: 'Linux', label: 'nmap scanning',                         params: { event_type: 'process', search: 'nmap' } },
  { cat: 'Linux', label: 'High severity Linux processes',         params: { event_type: 'process', severity: '4' } },

  // LINUX — Privilege / Auth
  { cat: 'Linux', label: 'All sudo executions',                   params: { event_type: 'process', process_name: 'sudo' } },
  { cat: 'Linux', label: 'sudo auth failures',                    params: { event_type: 'logon', search: 'sudo_failed' } },
  { cat: 'Linux', label: 'SSH logins (accepted)',                 params: { event_type: 'logon', search: 'ssh_login' } },
  { cat: 'Linux', label: 'SSH failures (brute force)',            params: { event_type: 'logon', search: 'ssh_failed' } },
  { cat: 'Linux', label: 'su / user switching',                   params: { event_type: 'logon', search: 'su_login' } },
  { cat: 'Linux', label: 'PAM auth failures',                     params: { event_type: 'logon', search: 'pam_auth_failed' } },
  { cat: 'Linux', label: 'All Linux logon events',                params: { event_type: 'logon', os: 'linux' } },
  { cat: 'Linux', label: 'User account added',                    params: { event_type: 'logon', search: 'ADD_USER' } },
  { cat: 'Linux', label: 'User account deleted',                  params: { event_type: 'logon', search: 'DEL_USER' } },
  { cat: 'Linux', label: 'Root account activity (uid=0)',         params: { event_type: 'process', user_name: 'root' } },

  // LINUX — FIM (File Integrity)
  { cat: 'Linux', label: 'All FIM events',                        params: { event_type: 'file', source: 'inotify' } },
  { cat: 'Linux', label: '/etc/passwd modifications',             params: { event_type: 'file', file_path: '/etc/passwd' } },
  { cat: 'Linux', label: '/etc/shadow modifications',             params: { event_type: 'file', file_path: '/etc/shadow' } },
  { cat: 'Linux', label: '/etc/sudoers modifications',            params: { event_type: 'file', file_path: '/etc/sudoers' } },
  { cat: 'Linux', label: 'SSH config changes',                    params: { event_type: 'file', file_path: '/etc/ssh' } },
  { cat: 'Linux', label: 'Crontab modifications',                 params: { event_type: 'file', file_path: 'cron' } },
  { cat: 'Linux', label: '/tmp file drops',                       params: { event_type: 'file', file_path: '/tmp/' } },
  { cat: 'Linux', label: '/dev/shm file drops',                   params: { event_type: 'file', file_path: '/dev/shm' } },
  { cat: 'Linux', label: 'ld.so.preload changes',                 params: { event_type: 'file', file_path: 'ld.so.preload' } },
  { cat: 'Linux', label: 'Systemd unit file changes',             params: { event_type: 'file', file_path: 'systemd' } },
  { cat: 'Linux', label: 'Binary replaced in /usr/bin',           params: { event_type: 'file', file_path: '/usr/bin' } },
  { cat: 'Linux', label: 'Profile/bashrc modifications',          params: { event_type: 'file', search: '.bashrc' } },
  { cat: 'Linux', label: 'High severity FIM events',              params: { event_type: 'file', severity: '4' } },

  // LINUX — Audit / Journal
  { cat: 'Linux', label: 'All auditd events',                     params: { source: 'auditd' } },
  { cat: 'Linux', label: 'All journald events',                   params: { source: 'journald' } },
  { cat: 'Linux', label: 'Kernel OOM kills',                      params: { search: 'oom_kill' } },
  { cat: 'Linux', label: 'Kernel module loads',                   params: { search: 'kernel_module_load' } },
  { cat: 'Linux', label: 'Cron job executions',                   params: { search: 'cron_exec' } },
  { cat: 'Linux', label: 'Service failures (systemd)',            params: { search: 'service_failed' } },
  { cat: 'Linux', label: 'Segfault / crash events',               params: { search: 'segfault' } },
  { cat: 'Linux', label: 'All Linux health events',               params: { event_type: 'health', os: 'linux' } },

  // REGISTRY
  { cat: 'Registry', label: 'All registry events',               params: { event_type: 'registry' } },
  { cat: 'Registry', label: 'Run key modifications',             params: { event_type: 'registry', reg_key: 'CurrentVersion\\Run' } },
  { cat: 'Registry', label: 'RunOnce key modifications',         params: { event_type: 'registry', reg_key: 'RunOnce' } },
  { cat: 'Registry', label: 'Security policy changes',           params: { event_type: 'registry', reg_key: 'Policies' } },
  { cat: 'Registry', label: 'Service registry changes',          params: { event_type: 'registry', reg_key: 'Services' } },
  { cat: 'Registry', label: 'LSA registry changes',              params: { event_type: 'registry', reg_key: 'Lsa' } },
  { cat: 'Registry', label: 'Winlogon key changes',              params: { event_type: 'registry', reg_key: 'Winlogon' } },
  { cat: 'Registry', label: 'AppInit DLLs',                      params: { event_type: 'registry', reg_key: 'AppInit_DLLs' } },
  { cat: 'Registry', label: 'IE Zone settings',                  params: { event_type: 'registry', reg_key: 'ZoneMap' } },
  { cat: 'Registry', label: 'High severity registry events',     params: { event_type: 'registry', severity: '4' } },

  // USER
  { cat: 'User', label: 'All events for SYSTEM account',         params: { user_name: 'SYSTEM' } },
  { cat: 'User', label: 'All events for administrator',          params: { user_name: 'administrator' } },
  { cat: 'User', label: 'Guest account activity',                params: { user_name: 'guest' } },
  { cat: 'User', label: 'Network service account',               params: { user_name: 'NETWORK SERVICE' } },
  { cat: 'User', label: 'All logon events',                      params: { event_type: 'logon' } },
  { cat: 'User', label: 'Service account logons',                params: { event_type: 'logon', search: 'svc' } },
  { cat: 'User', label: 'Account creation (Event 4720)',         params: { event_id: '4720' } },
  { cat: 'User', label: 'High severity user events',             params: { severity: '4' } },

  // SYSMON
  { cat: 'Sysmon', label: 'All Sysmon events',                   params: { event_type: 'sysmon' } },
  { cat: 'Sysmon', label: 'Sysmon process creation (ID 1)',       params: { event_type: 'sysmon', event_id: '1' } },
  { cat: 'Sysmon', label: 'Sysmon network connection (ID 3)',     params: { event_type: 'sysmon', event_id: '3' } },
  { cat: 'Sysmon', label: 'Sysmon file creation (ID 11)',         params: { event_type: 'sysmon', event_id: '11' } },
  { cat: 'Sysmon', label: 'Sysmon registry event (ID 12)',        params: { event_type: 'sysmon', event_id: '12' } },
  { cat: 'Sysmon', label: 'Sysmon image loaded (ID 7)',           params: { event_type: 'sysmon', event_id: '7' } },
  { cat: 'Sysmon', label: 'Sysmon process access (ID 10)',        params: { event_type: 'sysmon', event_id: '10' } },
  { cat: 'Sysmon', label: 'All critical severity events',        params: { severity: '5' } },
  { cat: 'Sysmon', label: 'All high severity events',            params: { severity: '4' } },
  { cat: 'Sysmon', label: 'Windows Security channel',            params: { channel: 'Security' } },
  { cat: 'Sysmon', label: 'Windows System channel',              params: { channel: 'System' } },
  { cat: 'Sysmon', label: 'PowerShell Operational channel',      params: { channel: 'PowerShell' } },
  { cat: 'Sysmon', label: 'Event log cleared (ID 1102)',         params: { event_id: '1102' } },
  { cat: 'Sysmon', label: 'AppLocker block events (8004)',       params: { event_id: '8004' } },
  { cat: 'Sysmon', label: 'All raw events',                      params: { event_type: 'raw' } },
]

const CATEGORIES = [...new Set(SAVED_QUERIES.map(q => q.cat))]

function parseQuickSearch(raw) {
  const params = {}
  const tokens = raw.trim().split(/\s+/)
  const leftover = []
  const map = {
    host: 'host', type: 'event_type', process: 'process_name', user: 'user_name',
    cmd: 'command_line', ip: 'search', src: 'src_ip', dst: 'dst_ip',
    port: 'dst_port', proto: 'proto', file: 'file_path', reg: 'reg_key',
    channel: 'channel', id: 'event_id', sev: 'severity', severity: 'severity',
  }
  for (const token of tokens) {
    const colon = token.indexOf(':')
    if (colon > 0) {
      const key = token.slice(0, colon).toLowerCase()
      const val = token.slice(colon + 1)
      if (map[key] && val) { params[map[key]] = val; continue }
    }
    leftover.push(token)
  }
  if (leftover.length > 0) params.search = leftover.join(' ')
  return params
}

const SEV_COLOR = { 5:'text-red-400', 4:'text-orange-400', 3:'text-yellow-400', 2:'text-blue-400', 1:'text-gray-400' }
const TYPE_COLOR = {
  process:'text-purple-400', network:'text-blue-400', logon:'text-green-400',
  dns:'text-cyan-400', registry:'text-orange-400', file:'text-yellow-400',
  sysmon:'text-pink-400', raw:'text-gray-400',
}
const SEV_LABEL = { 1:'Info', 2:'Low', 3:'Medium', 4:'High', 5:'Critical' }
const CHIP_LABEL = {
  event_type:'Type', process_name:'Process', command_line:'Cmd', user_name:'User',
  src_ip:'Src IP', dst_ip:'Dst IP', dst_port:'Port', proto:'Proto',
  file_path:'File', reg_key:'Reg', channel:'Channel', event_id:'Event ID',
  severity:'Sev ≥', search:'Search', host:'Host', image_path:'Image', agent_id:'Agent',
}

// ── Event Detail Panel ───────────────────────────────────────────────────────
function EventPanel({ eventId, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    setData(null)
    api.get(`/api/v1/events/${eventId}`)
      .then(r => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [eventId])

  const ev = data?.event
  const related = data?.related || []

  const allFields = ev ? [
    ['Time',          format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss')],
    ['Host',          ev.host],
    ['OS',            ev.os],
    ['Agent ID',      ev.agent_id],
    ['Event Type',    ev.event_type],
    ['Source',        ev.source],
    ['Severity',      ev.severity ? `${ev.severity} — ${SEV_LABEL[ev.severity]}` : null],
    ['Event ID',      ev.event_id],
    ['Channel',       ev.channel],
    ['PID',           ev.pid],
    ['PPID',          ev.ppid],
    ['Process',       ev.process_name],
    ['Image Path',    ev.image_path],
    ['Command Line',  ev.command_line],
    ['User',          ev.user_name],
    ['Domain',        ev.domain],
    ['Src IP',        ev.src_ip],
    ['Src Port',      ev.src_port],
    ['Dst IP / Domain', ev.dst_ip],
    ['Dst Port',      ev.dst_port],
    ['Protocol',      ev.proto],
    ['File Path',     ev.file_path],
    ['File Hash',     ev.file_hash],
    ['Registry Key',  ev.reg_key],
    ['Registry Value',ev.reg_value],
    ['Registry Data', ev.reg_data],
    ['Logon ID',      ev.logon_id],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '') : []

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl flex flex-col"
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <SearchIcon size={15} className="text-siem-accent" />
            <span className="text-sm font-semibold text-siem-text">Event Detail</span>
            {ev && <span className={`text-xs px-2 py-0.5 rounded-full border ${
              ev.severity >= 5 ? 'border-red-700 text-red-400 bg-red-900/20' :
              ev.severity >= 4 ? 'border-orange-700 text-orange-400 bg-orange-900/20' :
              'border-siem-border text-siem-muted'
            }`}>{SEV_LABEL[ev?.severity]}</span>}
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text p-1"><X size={18} /></button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center flex-1 text-siem-muted text-sm gap-2">
            <div className="w-4 h-4 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
            Loading...
          </div>
        ) : !ev ? (
          <div className="p-6 text-siem-muted text-sm">Event details not available</div>
        ) : (
          <div className="flex-1 overflow-y-auto">
            {/* All fields */}
            <div className="p-5 space-y-4">
              <div className="text-xs uppercase tracking-wider text-siem-muted font-medium">Event Fields</div>
              <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
                {allFields.map(([label, value], i) => (
                  <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                    <span className="text-siem-muted w-36 shrink-0 text-xs">{label}</span>
                    <span className="text-siem-text font-mono text-xs break-all">{String(value)}</span>
                  </div>
                ))}
              </div>

              {/* Raw JSON */}
              {ev.raw && (
                <div>
                  <div className="text-xs uppercase tracking-wider text-siem-muted font-medium mb-2">Raw Payload</div>
                  <pre className="bg-siem-bg border border-siem-border rounded-xl p-4 text-xs text-siem-accent font-mono overflow-x-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw, null, 2)}
                  </pre>
                </div>
              )}

              {/* Related events */}
              {related.length > 0 && (
                <div>
                  <div className="text-xs uppercase tracking-wider text-siem-muted font-medium mb-2">
                    Related Events on {ev.host} <span className="normal-case text-siem-muted font-normal">(±5 min)</span>
                  </div>
                  <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
                    {related.slice(0, 20).map((r, i) => (
                      <div key={r.id || i} className="flex items-center gap-3 px-4 py-2.5 border-b border-siem-border/30 last:border-0 text-xs">
                        <span className="text-siem-muted font-mono w-32 shrink-0">{format(new Date(r.time), 'HH:mm:ss')}</span>
                        <span className={`w-16 shrink-0 ${TYPE_COLOR[r.event_type] || 'text-siem-muted'}`}>{r.event_type}</span>
                        <span className={`w-6 font-bold shrink-0 ${SEV_COLOR[r.severity]}`}>{r.severity}</span>
                        <span className="text-siem-muted truncate">{r.process_name || r.dst_ip || r.reg_key || r.file_path || r.user_name || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Result Row ────────────────────────────────────────────────────────────────
function ResultRow({ ev, onClick }) {
  // Smart subject/detail per event type
  let subject, detail
  const t = ev.event_type
  if (t === 'process' || t === 'sysmon') {
    subject = ev.process_name || ev.image_path || '—'
    detail  = ev.command_line || ev.image_path || '—'
  } else if (t === 'network') {
    subject = (ev.dst_ip ? `${ev.dst_ip}` : ev.src_ip) || '—'
    detail  = ev.dst_port ? `→ port ${ev.dst_port}${ev.proto ? ' '+ev.proto.toUpperCase() : ''}` : (ev.src_ip || '—')
  } else if (t === 'dns') {
    let domain = ev.dst_ip || ''
    if (!domain && ev.raw) {
      try { const r = typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw; domain = r.query_name || r.QueryName || r.dst_ip || '' } catch {}
    }
    subject = domain || '—'
    detail  = ev.src_ip ? `from ${ev.src_ip}` : (ev.process_name || '—')
  } else if (t === 'logon') {
    subject = ev.user_name ? `${ev.domain ? ev.domain+'\\\\' : ''}${ev.user_name}` : '—'
    detail  = ev.event_id ? `EventID ${ev.event_id}` : (ev.src_ip ? `from ${ev.src_ip}` : '—')
  } else if (t === 'registry') {
    subject = ev.reg_key || '—'
    detail  = ev.reg_value || ev.reg_data || '—'
  } else if (t === 'file') {
    subject = ev.file_path || '—'
    detail  = ev.file_hash ? `SHA256: ${ev.file_hash.slice(0,16)}…` : (ev.process_name || '—')
  } else {
    subject = ev.process_name || ev.reg_key || ev.file_path || ev.dst_ip || ev.src_ip || '—'
    detail  = ev.command_line || ev.reg_value || ev.dst_ip || ev.file_path || '—'
  }

  return (
    <tr className="border-b border-siem-border/20 hover:bg-white/[0.03] transition-colors cursor-pointer group"
        onClick={() => onClick(ev)}>
      <td className="px-4 py-2.5 text-siem-muted text-xs whitespace-nowrap font-mono">
        {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
      </td>
      <td className="px-3 py-2.5">
        <span className={`text-xs font-bold ${SEV_COLOR[ev.severity] || 'text-siem-muted'}`}>{ev.severity}</span>
      </td>
      <td className="px-3 py-2.5 text-siem-text text-xs font-medium whitespace-nowrap">{ev.host}</td>
      <td className="px-3 py-2.5">
        <span className={`text-xs font-medium ${TYPE_COLOR[ev.event_type] || 'text-siem-muted'}`}>{ev.event_type}</span>
      </td>
      <td className="px-3 py-2.5 text-siem-muted text-xs truncate max-w-[120px]" title={ev.user_name}>
        {ev.user_name ? (ev.domain ? `${ev.domain}\\${ev.user_name}` : ev.user_name) : '—'}
      </td>
      <td className="px-3 py-2.5 text-siem-muted text-xs max-w-[160px] truncate" title={subject}>{subject}</td>
      <td className="px-3 py-2.5 text-siem-muted text-xs max-w-[260px] truncate font-mono text-[11px]" title={detail}>{detail}</td>
      <td className="px-3 py-2.5 text-siem-muted group-hover:text-siem-accent transition-colors">
        <ChevronRight size={13} />
      </td>
    </tr>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Search() {
  const [activeCat, setActiveCat]     = useState('Process')
  const [quickText, setQuickText]     = useState('')
  const [chips, setChips]             = useState({})
  const [results, setResults]         = useState([])
  const [total, setTotal]             = useState(0)
  const [loading, setLoading]         = useState(false)
  const [ran, setRan]                 = useState(false)
  const [activeLabel, setActiveLabel] = useState('')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const inputRef = useRef(null)

  const runQuery = useCallback(async (p, allTime = false) => {
    const cleaned = Object.fromEntries(Object.entries({ ...p, limit: 200 }).filter(([, v]) => v !== '' && v !== undefined))
    if (allTime) cleaned.all_time = '1'
    setLoading(true)
    setRan(true)
    try {
      const { data } = await api.get('/api/v1/events', { params: cleaned })
      let events = data.events || []
      // If dns query returns nothing, auto-fallback to searching source=DNS-Client
      if (events.length === 0 && cleaned.event_type === 'dns' && !allTime) {
        const fallback = { ...cleaned, all_time: '1' }
        delete fallback.event_type
        fallback.search = fallback.search ? fallback.search + ' DNS-Client' : 'DNS-Client'
        const r2 = await api.get('/api/v1/events', { params: fallback })
        events = r2.data?.events || []
        if (events.length > 0) setTotal(r2.data?.total || 0)
      } else {
        setTotal(data.total || 0)
      }
      setResults(events)
    } catch { setResults([]) }
    finally { setLoading(false) }
  }, [])

  const loadSaved = (q) => {
    setChips(q.params)
    setActiveLabel(q.label)
    setQuickText('')
    setSelectedEvent(null)
    runQuery(q.params)
  }

  const handleQuickSearch = (e) => {
    e.preventDefault()
    if (!quickText.trim()) return
    const parsed = parseQuickSearch(quickText)
    setChips(parsed)
    setActiveLabel(quickText)
    setSelectedEvent(null)
    runQuery(parsed)
  }

  const removeChip = (key) => {
    const next = { ...chips }
    delete next[key]
    setChips(next)
    runQuery(next)
  }

  const clearAll = () => {
    setChips({}); setResults([]); setRan(false)
    setActiveLabel(''); setQuickText(''); setSelectedEvent(null)
  }

  return (
    <div className="flex h-[calc(100vh-0px)] overflow-hidden bg-siem-bg">
      {selectedEvent && (
        <EventPanel eventId={selectedEvent.id} onClose={() => setSelectedEvent(null)} />
      )}

      {/* Sidebar */}
      <div className="w-60 bg-siem-surface border-r border-siem-border flex flex-col shrink-0">
        <div className="px-4 py-3 border-b border-siem-border flex items-center gap-2">
          <BookOpen size={13} className="text-siem-accent" />
          <span className="text-xs font-semibold text-siem-text">Saved Queries</span>
          <span className="ml-auto text-[10px] text-siem-muted bg-siem-border/50 rounded px-1.5 py-0.5">{SAVED_QUERIES.length}</span>
        </div>
        <div className="flex flex-wrap gap-1 px-2 py-2 border-b border-siem-border">
          {CATEGORIES.map(c => (
            <button key={c} onClick={() => setActiveCat(c)}
              className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                activeCat === c ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text hover:bg-white/[0.04]'
              }`}>{c}</button>
          ))}
        </div>
        <div className="flex-1 overflow-y-auto">
          {SAVED_QUERIES.filter(q => q.cat === activeCat).map((q, i) => (
            <button key={i} onClick={() => loadSaved(q)}
              className={`w-full text-left px-4 py-2.5 text-xs border-b border-siem-border/20 transition-colors ${
                activeLabel === q.label
                  ? 'bg-siem-accent/15 text-siem-accent border-l-2 border-l-siem-accent pl-3'
                  : 'text-siem-muted hover:bg-white/[0.04] hover:text-siem-text'
              }`}>{q.label}</button>
          ))}
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Search bar */}
        <div className="bg-siem-surface border-b border-siem-border px-5 py-3 space-y-2">
          <form onSubmit={handleQuickSearch} className="flex gap-2">
            <div className="relative flex-1">
              <SearchIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted pointer-events-none" />
              <input ref={inputRef}
                className="w-full bg-siem-bg border border-siem-border rounded-lg pl-9 pr-4 py-2 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-siem-accent"
                placeholder="host:CORP-VAPT type:process  |  type:dns  |  user:admin  |  port:3389  |  free text"
                value={quickText} onChange={e => setQuickText(e.target.value)}
              />
            </div>
            <button type="submit" className="flex items-center gap-1.5 bg-siem-accent hover:bg-siem-accent/90 text-white text-sm px-4 py-2 rounded-lg shrink-0">
              <Play size={12} fill="currentColor" /> Search
            </button>
            {ran && <button type="button" onClick={clearAll} className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-2">Clear</button>}
          </form>

          {/* Hint chips */}
          <div className="flex flex-wrap gap-1.5">
            {[
              ['host:CORP-VAPT type:process', 'All processes on host'],
              ['type:dns', 'Websites visited'],
              ['type:logon', 'Logon history'],
              ['port:3389', 'RDP connections'],
              ['cmd:powershell', 'PowerShell activity'],
              ['sev:4', 'High severity events'],
            ].map(([ex, tip]) => (
              <button key={ex} onClick={() => { setQuickText(ex); setTimeout(() => inputRef.current?.focus(), 0) }}
                title={tip}
                className="text-[10px] bg-siem-bg border border-siem-border/50 rounded px-2 py-0.5 text-siem-muted hover:border-siem-accent/50 hover:text-siem-accent transition-colors">
                {ex}
              </button>
            ))}
          </div>

          {/* Active chips */}
          {Object.keys(chips).length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {Object.entries(chips).map(([k, v]) => (
                <span key={k} className="flex items-center gap-1 bg-siem-accent/10 border border-siem-accent/30 rounded-full px-2.5 py-0.5 text-xs">
                  <span className="text-siem-accent font-medium">{CHIP_LABEL[k] || k}:</span>
                  <span className="text-siem-text">{v}</span>
                  <button onClick={() => removeChip(k)} className="text-siem-muted hover:text-red-400 ml-0.5"><X size={9} /></button>
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Results */}
        <div className="flex-1 overflow-y-auto">
          {!ran ? (
            <div className="flex flex-col items-center justify-center h-full text-siem-muted select-none px-6">
              <SearchIcon size={44} className="opacity-10 mb-4" />
              <div className="text-sm font-medium text-siem-text/50 mb-1">Search endpoint telemetry</div>
              <div className="text-xs mb-6 text-center">Click any saved query on the left, or type in the search bar above.<br/>Click any result row to see full event details.</div>
              <div className="grid grid-cols-2 gap-2 text-xs max-w-lg w-full">
                {[
                  { label: '🖥  All processes on this host',  q: { event_type:'process', host:'CORP-VAPT' },        l: 'Processes on CORP-VAPT' },
                  { label: '🌐 Websites visited (DNS)',        q: { event_type:'dns' },                              l: 'Websites visited' },
                  { label: '🔐 Failed logon attempts',         q: { event_type:'logon', event_id:'4625' },          l: 'Failed logons' },
                  { label: '⚡ Critical events',               q: { severity:'5' },                                  l: 'Critical severity' },
                  { label: '🔌 RDP connections',               q: { event_type:'network', dst_port:'3389' },        l: 'RDP connections' },
                  { label: '📋 Run key persistence',           q: { event_type:'registry', reg_key:'CurrentVersion\\Run' }, l: 'Run key changes' },
                ].map(({ label, q, l }) => (
                  <button key={label} onClick={() => { setChips(q); setActiveLabel(l); runQuery(q) }}
                    className="text-left bg-siem-surface border border-siem-border rounded-lg px-3 py-2.5 hover:border-siem-accent/40 hover:bg-white/[0.03] transition-colors text-siem-muted hover:text-siem-text">
                    {label}
                  </button>
                ))}
              </div>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center h-32 gap-2 text-siem-muted text-sm">
              <div className="w-4 h-4 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
              Searching...
            </div>
          ) : (
            <>
              <div className="flex items-center gap-3 px-5 py-2 border-b border-siem-border/40 bg-siem-surface/60 sticky top-0 z-10 text-xs">
                {results.length === 0 ? (
                  <span className="text-yellow-400">No results found — try removing filters or clicking "Search all time"</span>
                ) : (
                  <span className="text-siem-muted">
                    <span className="text-siem-text font-medium">{results.length.toLocaleString()}</span>
                    {total > results.length && <> of <span className="text-siem-text font-medium">{total.toLocaleString()}</span></>}
                    {' '}events · click any row for details
                  </span>
                )}
                {activeLabel && <span className="text-siem-accent/70 truncate max-w-xs ml-1">"{activeLabel}"</span>}
                {results.length === 0 && (
                  <button onClick={() => runQuery(chips, true)}
                    className="ml-auto text-siem-accent border border-siem-accent/30 rounded px-2 py-0.5 hover:bg-siem-accent/10">
                    Search all time →
                  </button>
                )}
              </div>

              {results.length > 0 && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-siem-border text-siem-muted text-xs bg-siem-surface/80 sticky top-[33px] z-10">
                      <th className="text-left px-4 py-2.5 font-medium">Time</th>
                      <th className="text-left px-3 py-2.5 font-medium">Sev</th>
                      <th className="text-left px-3 py-2.5 font-medium">Host</th>
                      <th className="text-left px-3 py-2.5 font-medium">Type</th>
                      <th className="text-left px-3 py-2.5 font-medium">User / Domain</th>
                      <th className="text-left px-3 py-2.5 font-medium">Process / Domain / Key / Path</th>
                      <th className="text-left px-3 py-2.5 font-medium">Command / URL / Value / Port</th>
                      <th className="px-3 py-2.5"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((ev, i) => (
                      <ResultRow key={ev.id || i} ev={ev} onClick={setSelectedEvent} />
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
