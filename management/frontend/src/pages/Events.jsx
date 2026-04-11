import { useEffect, useState, useCallback, useRef } from 'react'
import { Search, Wifi, Download, X, ChevronRight, Cloud, Monitor, Terminal,
         Shield, Globe, FileText, Key, Activity, AlertTriangle, Cpu,
         GitBranch, GitCommit, Trash2, User } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
import { SeverityBadge } from '../components/SeverityBadge'

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
  // Cloud — AWS
  'cloud.cloudtrail':   { label: 'CloudTrail',   color: 'text-orange-400', icon: Cloud, group: 'AWS' },
  'cloud.guardduty':    { label: 'GuardDuty',    color: 'text-red-400',    icon: Shield,group: 'AWS' },
  // Cloud — Azure
  'cloud.azure_activity': { label: 'Azure Activity', color: 'text-blue-400',  icon: Cloud, group: 'Azure' },
  'cloud.entra_signin':   { label: 'Entra Sign-in',  color: 'text-blue-300',  icon: Shield,group: 'Azure' },
  // Cloud — GCP
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
  return <span className={etClass}>{type || '—'}</span>
}

// ── Preconfigured saved searches ─────────────────────────────────────────────

export const SAVED_SEARCHES = [
  // ── Windows ───────────────────────────────────────────────────────────────
  {
    group: 'Windows',
    searches: [
      // Execution
      {
        label: 'PowerShell Encoded Command',
        desc: 'T1059.001 — -EncodedCommand or -enc flag, used to hide malicious scripts',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'encodedcommand', value: 'encodedcommand' }],
      },
      {
        label: 'PowerShell Download Cradle',
        desc: 'T1059.001 — DownloadString / IEX / WebClient used to pull remote payloads',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'downloadstring', value: 'downloadstring' }],
      },
      {
        label: 'MSHTA / WScript Execution',
        desc: 'T1218.005 / T1059.005 — LOLBin script execution via mshta or wscript',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'mshta', value: 'mshta' }],
      },
      {
        label: 'Regsvr32 / Rundll32 Abuse',
        desc: 'T1218.010 / T1218.011 — LOLBins used to execute unsigned code',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'regsvr32', value: 'regsvr32' }],
      },
      {
        label: 'WMI Process Creation',
        desc: 'T1047 — wmic process call create, used for lateral movement and persistence',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'wmic', value: 'wmic' }],
      },
      // Persistence
      {
        label: 'Registry Run Key Persistence',
        desc: 'T1547.001 — HKCU/HKLM CurrentVersion\\Run key modification',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: registry', value: 'registry' },
               { field: 'search', label: 'currentversion\\run', value: 'currentversion\\run' }],
      },
      {
        label: 'Scheduled Task Created',
        desc: 'T1053.005 — schtasks /create or New-ScheduledTask',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'schtasks /create', value: 'schtasks /create' }],
      },
      {
        label: 'New Service Installed',
        desc: 'T1543.003 — sc.exe create or New-Service — persistence or lateral movement',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'sc create', value: 'sc create' }],
      },
      // Privilege Escalation
      {
        label: 'UAC Bypass Attempt',
        desc: 'T1548.002 — fodhelper, eventvwr, sdclt, computerdefaults UAC bypass',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'fodhelper', value: 'fodhelper' }],
      },
      // Defence Evasion
      {
        label: 'AMSI Bypass',
        desc: 'T1562.001 — amsiutils, [Ref].Assembly or AmsiContext patching',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'amsiutils', value: 'amsiutils' }],
      },
      {
        label: 'Event Log Cleared',
        desc: 'T1070.001 — wevtutil cl or Clear-EventLog — attacker hiding tracks',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'wevtutil cl', value: 'wevtutil cl' }],
      },
      {
        label: 'Defender / AV Disabled',
        desc: 'T1562.001 — Set-MpPreference or sc stop windefend',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'disablerealtimemonitoring', value: 'disablerealtimemonitoring' }],
      },
      // Credential Access
      {
        label: 'LSASS / Mimikatz',
        desc: 'T1003.001 — lsass dump via procdump, comsvcs.dll, or mimikatz',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'lsass', value: 'lsass' }],
      },
      {
        label: 'SAM / NTDS Dump',
        desc: 'T1003.002 — reg save HKLM\\SAM or ntdsutil — AD credential dump',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'ntds', value: 'ntds' }],
      },
      {
        label: 'Failed Logons (4625)',
        desc: 'T1110 — repeated Event ID 4625 — brute force indicator',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: '4625', value: '4625' }],
      },
      // Lateral Movement
      {
        label: 'SMB Lateral Movement',
        desc: 'T1021.002 — outbound port 445 connections',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: network', value: 'network' },
               { field: 'dst_port', label: 'Port: 445', value: '445' }],
      },
      {
        label: 'RDP Lateral Movement',
        desc: 'T1021.001 — outbound port 3389 — Remote Desktop',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: network', value: 'network' },
               { field: 'dst_port', label: 'Port: 3389', value: '3389' }],
      },
      {
        label: 'PsExec / Remote Exec',
        desc: 'T1570 — psexec, paexec, wmiexec remote execution tools',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'psexec', value: 'psexec' }],
      },
      // Impact
      {
        label: 'Shadow Copy Deletion',
        desc: 'T1490 — vssadmin delete shadows — ransomware pre-encryption step',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'vssadmin delete', value: 'vssadmin delete' }],
      },
      // Discovery
      {
        label: 'Process / Account Discovery',
        desc: 'T1057 / T1087 — tasklist, net user, whoami /all, Get-ADUser',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'tasklist', value: 'tasklist' }],
      },
      {
        label: 'High Severity Windows',
        desc: 'All critical/high severity events on Windows hosts',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'severity', label: 'Severity: 4', value: '4' }],
      },
    ],
  },
  // ── Linux ─────────────────────────────────────────────────────────────────
  {
    group: 'Linux',
    searches: [
      // Execution
      {
        label: 'Reverse Shell (bash -i)',
        desc: 'T1059.004 — bash -i >& /dev/tcp/... interactive shell to attacker',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'bash -i', value: 'bash -i' }],
      },
      {
        label: 'Python / Perl Shell',
        desc: 'T1059.006 — python/perl one-liner reverse shell or exec',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'python -c', value: 'python -c' }],
      },
      {
        label: 'curl / wget Download',
        desc: 'T1105 — file download to /tmp — staging malware',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'curl -o /tmp', value: 'curl -o /tmp' }],
      },
      // Persistence
      {
        label: 'Cron Persistence',
        desc: 'T1053.003 — crontab -e or /etc/cron* modifications',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'crontab', value: 'crontab' }],
      },
      {
        label: 'New Systemd Service',
        desc: 'T1543.002 — new .service file linked — persistence',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'Created symlink', value: 'Created symlink' }],
      },
      {
        label: 'SSH Authorized Keys Modified',
        desc: 'T1098.004 — ~/.ssh/authorized_keys written — backdoor access',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: 'authorized_keys', value: 'authorized_keys' }],
      },
      // Privilege Escalation
      {
        label: 'SUID Binary Set',
        desc: 'T1548.001 — chmod +s or u+s — creates setuid binary for privesc',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'chmod +s', value: 'chmod +s' }],
      },
      {
        label: 'Sudo Root Shell',
        desc: 'T1548.003 — sudo used to spawn /bin/bash or /bin/sh as root',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: 'COMMAND=/bin/bash', value: 'COMMAND=/bin/bash' }],
      },
      {
        label: 'Kernel Module Loaded',
        desc: 'T1547.006 — insmod / modprobe — rootkit installation',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'insmod', value: 'insmod' }],
      },
      // Credential Access
      {
        label: 'SSH Brute Force',
        desc: 'T1110.001 — repeated sshd Failed password from single source',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: 'Failed password', value: 'Failed password' }],
      },
      {
        label: 'Shadow File Access',
        desc: 'T1003.008 — /etc/shadow read — credential dumping attempt',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: '/etc/shadow', value: '/etc/shadow' }],
      },
      // Defence Evasion
      {
        label: '/etc Changes',
        desc: 'T1565.001 — config file tampering under /etc',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: '/etc/', value: '/etc/' }],
      },
      {
        label: 'History File Cleared',
        desc: 'T1070.003 — unset HISTFILE or > ~/.bash_history — anti-forensics',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'bash_history', value: 'bash_history' }],
      },
      // Discovery
      {
        label: 'Network Port Scanning',
        desc: 'T1046 — nmap, masscan, or rustscan process',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'nmap', value: 'nmap' }],
      },
      // C2 / Exfiltration
      {
        label: 'Cloud Metadata SSRF',
        desc: 'T1552.005 — 169.254.169.254 access — EC2/GCP/Azure credential theft',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: '169.254.169.254', value: '169.254.169.254' }],
      },
      {
        label: 'DNS Reconnaissance',
        desc: 'T1590 — dig/nslookup used for zone transfers or internal recon',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'dig axfr', value: 'dig axfr' }],
      },
      {
        label: 'High Severity Linux',
        desc: 'All critical/high severity events on Linux hosts',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'severity', label: 'Severity: 4', value: '4' }],
      },
    ],
  },
  // ── macOS ─────────────────────────────────────────────────────────────────
  {
    group: 'macOS',
    searches: [
      // Persistence
      {
        label: 'LaunchDaemon Installed',
        desc: 'T1543.004 — /Library/LaunchDaemons/ write — system-wide persistence',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'LaunchDaemon', value: 'LaunchDaemon' }],
      },
      {
        label: 'LaunchAgent Installed',
        desc: 'T1543.001 — ~/Library/LaunchAgents/ write — user-level persistence',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'LaunchAgents', value: 'LaunchAgents' }],
      },
      {
        label: 'Login Item Added',
        desc: 'T1547.015 — SMLoginItem or login item plist — persistence at login',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'loginitems', value: 'loginitems' }],
      },
      // Privilege Escalation / Defence Evasion
      {
        label: 'Gatekeeper Bypass',
        desc: 'T1553.001 — spctl --master-disable or xattr -d com.apple.quarantine',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'spctl', value: 'spctl' }],
      },
      {
        label: 'SIP Bypass (csrutil)',
        desc: 'T1562.001 — csrutil disable — System Integrity Protection removed',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'csrutil', value: 'csrutil' }],
      },
      {
        label: 'TCC Database Access',
        desc: 'T1562.001 — TCC.db read/write — privacy permission bypass',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: 'TCC.db', value: 'TCC.db' }],
      },
      // Credential Access
      {
        label: 'Keychain Access',
        desc: 'T1555.001 — security command or keychain database accessed',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'keychain', value: 'keychain' }],
      },
      // Execution
      {
        label: 'osascript (AppleScript)',
        desc: 'T1059.002 — osascript execution — phishing dialogs, UAC bypass',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'osascript', value: 'osascript' }],
      },
      {
        label: 'curl Download',
        desc: 'T1105 — curl used to pull remote files — staging malware',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'curl', value: 'curl' }],
      },
      {
        label: 'Python / Perl Exec',
        desc: 'T1059.006 — scripting language one-liner or reverse shell',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'python -c', value: 'python -c' }],
      },
      {
        label: 'High Severity macOS',
        desc: 'All critical/high severity events on macOS hosts',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'severity', label: 'Severity: 4', value: '4' }],
      },
    ],
  },
]


// ── EventPanel (detail slide-out) ─────────────────────────────────────────────

function EventPanel({ event, onClose }) {
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

  const fields = [
    ['Time',         format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss.SSS')],
    ['Agent ID',     ev.agent_id],
    ['Host',         ev.host],
    ['OS',           ev.os],
    ['Event Type',   ev.event_type],
    ['Source',       ev.source],
    ['Severity',     ev.severity],
    // Endpoint fields
    ...(!isCloud ? [
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
                    <span className="text-siem-text break-all font-mono text-xs">{String(value)}</span>
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
                      <span className="text-siem-muted">{r.process_name || r.src_ip || r.user_name || '—'}</span>
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
  const [activeGroup, setActiveGroup] = useState(SAVED_SEARCHES[0].group)
  const group = SAVED_SEARCHES.find(g => g.group === activeGroup)

  const GROUP_ICONS = {
    Windows: Monitor, Linux: Terminal, macOS: Monitor,
    AWS: Cloud, Azure: Cloud, GCP: Cloud, 'All Cloud': Cloud,
  }

  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-siem-border">
        <span className="text-xs font-semibold text-siem-text">Saved Searches</span>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={12}/></button>
      </div>
      <div className="flex">
        {/* Group tabs */}
        <div className="w-28 border-r border-siem-border shrink-0">
          {SAVED_SEARCHES.map(({ group }) => {
            const Icon = GROUP_ICONS[group] || Shield
            const isCloud = ['AWS','Azure','GCP','All Cloud'].includes(group)
            return (
              <button key={group} onClick={() => setActiveGroup(group)}
                className={`w-full flex items-center gap-1.5 px-3 py-2 text-[10px] transition-colors text-left ${
                  activeGroup === group
                    ? 'bg-siem-accent/10 text-siem-accent border-r-2 border-siem-accent'
                    : 'text-siem-muted hover:text-siem-text'
                }`}>
                <Icon size={10}/>
                {group}
                {isCloud && <span className="ml-auto text-[8px] text-orange-400/60">☁</span>}
              </button>
            )
          })}
        </div>
        {/* Searches */}
        <div className="flex-1 p-2 space-y-1 max-h-72 overflow-y-auto">
          {group?.searches.map((s, i) => (
            <button key={i} onClick={() => { onSelect(s.tags); onClose() }}
              className="w-full text-left px-3 py-2 rounded-lg border border-transparent hover:border-siem-border hover:bg-white/[0.02] transition-colors group">
              <div className="text-[11px] font-medium text-siem-text group-hover:text-siem-accent">{s.label}</div>
              <div className="text-[9px] text-siem-muted mt-0.5">{s.desc}</div>
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
}

const PRESETS = [
  { label: '15m',  ms: 15*60000 },
  { label: '1h',   ms: 3600000 },
  { label: '24h',  ms: 86400000 },
  { label: '7d',   ms: 7*86400000 },
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
  const [inputVal, setInputVal] = useState('')
  const [since, setSince]   = useState('')
  const [until, setUntil]   = useState('')
  const inputRef = useRef(null)
  const debounceRef = useRef(null)

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
    const queryStr = tags.map(t => t.label).join(' ')
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

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v))
      return { field: 'src_or_dst_ip', label: 'IP: ' + v, value: v }
    if (/^\d{1,5}$/.test(v) && parseInt(v) <= 65535)
      return { field: 'dst_port', label: 'Port: ' + v, value: v }

    // Cloud event types — exact and wildcard
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
    if ((e.key === 'Enter' || e.key === ',') && inputVal.trim()) {
      e.preventDefault(); addTag(inputVal)
    }
    if (e.key === 'Backspace' && !inputVal && tags.length > 0)
      setTags(t => t.slice(0, -1))
  }

  const buildParams = useCallback((p = 0) => {
    const params = { limit, offset: p * limit }
    const searchTerms = []
    tags.forEach(tag => {
      if (tag.field === 'src_or_dst_ip' || tag.field === 'search') {
        searchTerms.push(tag.value)
      } else {
        params[tag.field] = tag.value
      }
    })
    if (searchTerms.length > 0) params.search = searchTerms.join(' ')
    if (since) params.since = new Date(since).toISOString()
    if (until) params.until = new Date(until + ':59').toISOString()
    return params
  }, [tags, since, until])

  const fetchEvents = useCallback(async (p = 0, liveInput = '') => {
    setLoading(true)
    try {
      const params = buildParams(p)
      // Combine tag-based search terms with live input
      const searchTokens = tags.filter(t => t.field === 'search').map(t => t.value)
      // Split live input into tokens too
      const liveTokens = liveInput.trim().split(/\s+/).filter(Boolean)
      const allTokens = [...searchTokens, ...liveTokens]

      if (allTokens.length > 0) {
        const searchParams = { ...params, q: allTokens.join(' ') }
        delete searchParams.search
        // If no time range set, search all time (let user narrow with time picker)
        if (!since && !until) searchParams.since = 'all'
        const { data } = await api.get('/api/v1/events/search', { params: searchParams })
        setEvents(data.events || [])
        setTotal(data.total || 0)
      } else {
        const { data } = await api.get('/api/v1/events', { params })
        setEvents(data.events || [])
        setTotal(data.total || 0)
      }
    } finally { setLoading(false) }
  }, [buildParams, tags])

  useEffect(() => {
    // Debounce search — fire 300ms after last change
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      fetchEvents(0, inputVal); setPage(0)
    }, 300)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [tags, since, until, inputVal])

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
    Object.entries(buildParams()).forEach(([k, v]) => { if (v) params.set(k, String(v)) })
    const token = localStorage.getItem('token')
    const res = await fetch(`/api/v1/events/export?${params}`, { headers: { Authorization: `Bearer ${token}` } })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = `obsidianwatch-events.${fmt}`; a.click()
    URL.revokeObjectURL(url)
  }

  const clearAll = () => { setTags([]); setSince(''); setUntil(''); setInputVal('') }
  const displayed = live ? liveEvents : events

  // Quick hints — includes cloud types
  const HINTS = ['process','network','dns','logon','file','cloud','cloud.cloudtrail',
                 'cloud.guardduty','cloud.azure_activity','cloud.entra_signin','cloud.gcp_audit',
                 'windows','linux','darwin','critical','high','aws','azure','gcp']

  return (
    <div className="p-6 space-y-4">
      {selected && <EventPanel event={selected} onClose={() => setSelected(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-siem-text">Events</h1>
          <p className="text-[10px] text-siem-muted mt-0.5">
            Search endpoint and cloud events — type to filter, or use saved searches
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!live && (
            <div className="flex items-center gap-1">
              <button onClick={() => exportEvents('csv')}
                className="flex items-center gap-1 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-2.5 py-1.5">
                <Download size={12}/> CSV
              </button>
              <button onClick={() => exportEvents('json')}
                className="flex items-center gap-1 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-2.5 py-1.5">
                <Download size={12}/> JSON
              </button>
            </div>
          )}
          <button onClick={() => setLive(l => !l)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              live ? 'bg-siem-green/10 border-siem-green text-siem-green' : 'border-siem-border text-siem-muted hover:text-siem-text'
            }`}>
            <Wifi size={13}/>
            {live ? (connected ? 'Live' : 'Reconnecting') : 'Historical'}
          </button>
        </div>
      </div>

      {/* Search Bar */}
      {!live && (
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 space-y-3">

          {/* Tag input */}
          <div className="min-h-[42px] flex flex-wrap gap-1.5 items-center bg-siem-bg border border-siem-border rounded-xl px-3 py-2 cursor-text focus-within:border-siem-accent transition-colors"
               onClick={() => inputRef.current?.focus()}>
            <Search size={14} className="text-siem-muted shrink-0"/>
            {tags.map(tag => (
              <span key={tag.id}
                className={`inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border font-medium ${TAG_COLORS[tag.field] || TAG_COLORS.search}`}>
                {tag.label}
                <button onClick={e => { e.stopPropagation(); removeTag(tag.id) }}
                  className="hover:opacity-70 ml-0.5 leading-none">×</button>
              </span>
            ))}
            <input ref={inputRef}
              className="flex-1 min-w-[140px] bg-transparent text-sm text-siem-text outline-none placeholder:text-siem-muted/50"
              placeholder={tags.length === 0 ? 'Type anything — hostname, IP, process, username, error message…' : 'Add more terms to narrow down…'}
              value={inputVal}
              onChange={e => setInputVal(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            {(tags.length > 0 || since || until) && (
              <button onClick={clearAll} className="text-[10px] text-siem-muted hover:text-red-400 ml-1 shrink-0">Clear all</button>
            )}
          </div>

          {/* Saved searches button + hints */}
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={() => setShowSaved(s => !s)}
              className={`flex items-center gap-1 text-[10px] px-2.5 py-1 rounded-full border transition-colors ${
                showSaved
                  ? 'bg-siem-accent/10 border-siem-accent text-siem-accent'
                  : 'border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent'
              }`}>
              <Search size={9}/> Saved Searches
            </button>
            <span className="text-siem-border text-xs">|</span>
            {HINTS.map(hint => (
              <button key={hint} onClick={() => addTag(hint)}
                className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors ${
                  hint.startsWith('cloud')
                    ? 'border-orange-800/50 text-orange-400/70 hover:border-orange-500 hover:text-orange-400'
                    : 'border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent'
                }`}>
                {hint}
              </button>
            ))}
          </div>

          {/* Saved searches panel */}
          {showSaved && (
            <SavedSearchPanel
              onSelect={applySearch}
              onClose={() => setShowSaved(false)}
            />
          )}

          {/* Time range */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] text-siem-muted uppercase tracking-wider">Time range</span>
            <div className="flex items-center gap-1.5">
              <input type="datetime-local"
                className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
                value={since} onChange={e => setSince(e.target.value)}/>
              <span className="text-siem-muted text-xs">to</span>
              <input type="datetime-local"
                className="bg-siem-bg border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
                value={until} onChange={e => setUntil(e.target.value)}/>
              {(since || until) && (
                <button onClick={() => { setSince(''); setUntil('') }}
                  className="text-[10px] text-siem-muted hover:text-red-400"><X size={11}/></button>
              )}
            </div>
            <div className="flex gap-1 ml-1">
              {PRESETS.map(p => (
                <button key={p.label}
                  onClick={() => {
                    const now = new Date()
                    setSince(new Date(now - p.ms).toISOString().slice(0, 16))
                    setUntil(now.toISOString().slice(0, 16))
                  }}
                  className="text-[10px] px-2 py-0.5 rounded-full border border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent transition-colors">
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-xs text-siem-muted">
                {loading ? 'Searching…' : `${total.toLocaleString()} events`}
              </span>
              {tags.length > 0 && (
                <span className="text-[10px] text-siem-muted">· {tags.length} filter{tags.length > 1 ? 's' : ''} active</span>
              )}
            </div>
            {/* Save current query */}
            {tags.length > 0 && (
              <div className="flex items-center gap-2">
                {showSaveDialog ? (
                  <div className="flex items-center gap-2">
                    <input
                      value={saveQueryName}
                      onChange={e => setSaveQueryName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') saveQuery(); if (e.key === 'Escape') setShowSaveDialog(false) }}
                      placeholder="Query name…"
                      autoFocus
                      className="bg-siem-bg border border-siem-accent/50 rounded-lg px-2 py-1 text-xs text-siem-text outline-none w-40"
                    />
                    <button onClick={saveQuery}
                      className="text-[10px] px-2.5 py-1 bg-siem-accent text-white rounded-lg">Save</button>
                    <button onClick={() => setShowSaveDialog(false)}
                      className="text-[10px] text-siem-muted hover:text-red-400"><X size={11}/></button>
                  </div>
                ) : (
                  <button onClick={() => setShowSaveDialog(true)}
                    className="text-[10px] px-2.5 py-1 border border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent rounded-lg transition-colors">
                    + Save query
                  </button>
                )}
              </div>
            )}
          </div>

          {/* User-saved queries */}
          {savedQueries.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap pt-1">
              <span className="text-[10px] text-siem-muted uppercase tracking-wider shrink-0">Saved:</span>
              {savedQueries.map(sq => (
                <div key={sq.id} className="flex items-center gap-1">
                  <button
                    onClick={() => {
                      const newTags = sq.query.split(' ').filter(Boolean).map(t => {
                        const classified = classifyTerm(t)
                        return classified ? { id: Date.now() + Math.random(), ...classified } : null
                      }).filter(Boolean)
                      if (newTags.length) setTags(newTags)
                    }}
                    className="text-[10px] px-2.5 py-0.5 rounded-full border border-siem-border text-siem-muted hover:border-siem-accent hover:text-siem-accent transition-colors">
                    {sq.name}
                  </button>
                  <button onClick={() => deleteSavedQuery(sq.id)}
                    className="text-siem-muted/30 hover:text-red-400 transition-colors">
                    <X size={9}/>
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Event List — simple clickable rows */}
      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16 text-siem-muted text-sm gap-2">
            <Search size={14} className="animate-pulse"/> Searching…
          </div>
        ) : displayed.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-siem-muted gap-2">
            <Search size={24} className="opacity-30"/>
            <span className="text-sm">{tags.length > 0 || since || until ? 'No events match your filters' : 'No events — try a different time range'}</span>
          </div>
        ) : (
          <div className="divide-y divide-siem-border/30">
            {displayed.map((ev, i) => {
              const raw = ev.raw
                ? (typeof ev.raw === 'string' ? (() => { try { return JSON.parse(ev.raw) } catch { return {} } })() : ev.raw)
                : {}
              // Build a single summary line from the most relevant fields
              const summaryParts = []
              if (ev.user_name)    summaryParts.push(ev.user_name)
              if (ev.process_name) summaryParts.push(ev.process_name)
              if (ev.command_line) summaryParts.push(ev.command_line.slice(0, 80))
              if (ev.src_ip)       summaryParts.push(`${ev.src_ip}${ev.src_port ? ':'+ev.src_port : ''}`)
              if (ev.dst_ip)       summaryParts.push(`→ ${ev.dst_ip}${ev.dst_port ? ':'+ev.dst_port : ''}`)
              if (ev.file_path)    summaryParts.push(ev.file_path)
              if (ev.reg_key)      summaryParts.push(ev.reg_key)
              // Cloud/DevOps fields from raw
              if (!summaryParts.length) {
                const r = raw
                const cloudSummary = r?.event_name || r?.operation_name || r?.method_name ||
                  r?.repo || r?.message || r?.action || r?.finding_type ||
                  r?.commit_sha?.slice(0,8)
                if (cloudSummary) summaryParts.push(String(cloudSummary))
              }
              const summary = summaryParts.join('  ·  ')

              return (
                <div key={ev.id || i}
                  className="flex items-center gap-3 px-4 py-2.5 hover:bg-white/[0.03] cursor-pointer transition-colors group"
                  onClick={() => setSelected(ev)}>
                  {/* Time */}
                  <span className="text-[11px] text-siem-muted/70 font-mono whitespace-nowrap w-[120px] shrink-0">
                    {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
                  </span>
                  {/* Severity */}
                  <SeverityBadge severity={ev.severity}/>
                  {/* Host */}
                  <span className="text-xs font-medium text-siem-text w-[100px] shrink-0 truncate">
                    {ev.host || '—'}
                  </span>
                  {/* Type badge */}
                  <EventTypeBadge type={ev.event_type}/>
                  {/* Summary — everything else */}
                  <span className="text-[11px] text-siem-muted/80 truncate flex-1 font-mono">
                    {summary || ev.source || ev.event_type}
                  </span>
                  {/* Chevron */}
                  <ChevronRight size={13} className="text-siem-muted/30 group-hover:text-siem-muted shrink-0"/>
                </div>
              )
            })}
          </div>
        )}

        {!live && total > limit && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-siem-border">
            <span className="text-xs text-siem-muted">
              Page {page + 1} of {Math.ceil(total / limit)} · {total.toLocaleString()} total
            </span>
            <div className="flex gap-2">
              <button disabled={page === 0}
                onClick={() => { const p = page - 1; setPage(p); fetchEvents(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">
                Previous
              </button>
              <button disabled={(page + 1) * limit >= total}
                onClick={() => { const p = page + 1; setPage(p); fetchEvents(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
