import { useEffect, useState, useCallback, useRef, useMemo } from 'react'
import { Search, Wifi, Download, X, ChevronRight, Cloud, Monitor, Terminal,
         Shield, Globe, FileText, Key, Activity, AlertTriangle, Cpu,
         GitBranch, GitCommit, Trash2, User, Boxes } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
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

export const SAVED_SEARCHES = [
  // ── Windows ───────────────────────────────────────────────────────────────
  {
    group: 'Windows',
    searches: [
      // Execution
      {
        label: 'PowerShell Encoded Command',
        desc: 'T1059.001 - -EncodedCommand or -enc flag, used to hide malicious scripts',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'encodedcommand', value: 'encodedcommand' }],
      },
      {
        label: 'PowerShell Download Cradle',
        desc: 'T1059.001 - DownloadString / IEX / WebClient used to pull remote payloads',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'downloadstring', value: 'downloadstring' }],
      },
      {
        label: 'MSHTA / WScript Execution',
        desc: 'T1218.005 / T1059.005 - LOLBin script execution via mshta or wscript',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'mshta', value: 'mshta' }],
      },
      {
        label: 'Regsvr32 / Rundll32 Abuse',
        desc: 'T1218.010 / T1218.011 - LOLBins used to execute unsigned code',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'regsvr32', value: 'regsvr32' }],
      },
      {
        label: 'WMI Process Creation',
        desc: 'T1047 - wmic process call create, used for lateral movement and persistence',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'wmic', value: 'wmic' }],
      },
      // Persistence
      {
        label: 'Registry Run Key Persistence',
        desc: 'T1547.001 - HKCU/HKLM CurrentVersion\\Run key modification',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: registry', value: 'registry' },
               { field: 'search', label: 'currentversion\\run', value: 'currentversion\\run' }],
      },
      {
        label: 'Scheduled Task Created',
        desc: 'T1053.005 - schtasks /create or New-ScheduledTask',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'schtasks /create', value: 'schtasks /create' }],
      },
      {
        label: 'New Service Installed',
        desc: 'T1543.003 - sc.exe create or New-Service - persistence or lateral movement',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'sc create', value: 'sc create' }],
      },
      // Privilege Escalation
      {
        label: 'UAC Bypass Attempt',
        desc: 'T1548.002 - fodhelper, eventvwr, sdclt, computerdefaults UAC bypass',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'fodhelper', value: 'fodhelper' }],
      },
      // Defence Evasion
      {
        label: 'AMSI Bypass',
        desc: 'T1562.001 - amsiutils, [Ref].Assembly or AmsiContext patching',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'amsiutils', value: 'amsiutils' }],
      },
      {
        label: 'Event Log Cleared',
        desc: 'T1070.001 - wevtutil cl or Clear-EventLog - attacker hiding tracks',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'wevtutil cl', value: 'wevtutil cl' }],
      },
      {
        label: 'Defender / AV Disabled',
        desc: 'T1562.001 - Set-MpPreference or sc stop windefend',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'disablerealtimemonitoring', value: 'disablerealtimemonitoring' }],
      },
      // Credential Access
      {
        label: 'LSASS / Mimikatz',
        desc: 'T1003.001 - lsass dump via procdump, comsvcs.dll, or mimikatz',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'lsass', value: 'lsass' }],
      },
      {
        label: 'SAM / NTDS Dump',
        desc: 'T1003.002 - reg save HKLM\\SAM or ntdsutil - AD credential dump',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'search', label: 'ntds', value: 'ntds' }],
      },
      {
        label: 'Failed Logons (4625)',
        desc: 'T1110 - repeated Event ID 4625 - brute force indicator',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: '4625', value: '4625' }],
      },
      // Lateral Movement
      {
        label: 'SMB Lateral Movement',
        desc: 'T1021.002 - outbound port 445 connections',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: network', value: 'network' },
               { field: 'dst_port', label: 'Port: 445', value: '445' }],
      },
      {
        label: 'RDP Lateral Movement',
        desc: 'T1021.001 - outbound port 3389 - Remote Desktop',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: network', value: 'network' },
               { field: 'dst_port', label: 'Port: 3389', value: '3389' }],
      },
      {
        label: 'PsExec / Remote Exec',
        desc: 'T1570 - psexec, paexec, wmiexec remote execution tools',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'psexec', value: 'psexec' }],
      },
      // Impact
      {
        label: 'Shadow Copy Deletion',
        desc: 'T1490 - vssadmin delete shadows - ransomware pre-encryption step',
        tags: [{ field: 'os', label: 'OS: windows', value: 'windows' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'vssadmin delete', value: 'vssadmin delete' }],
      },
      // Discovery
      {
        label: 'Process / Account Discovery',
        desc: 'T1057 / T1087 - tasklist, net user, whoami /all, Get-ADUser',
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
        desc: 'T1059.004 - bash -i >& /dev/tcp/... interactive shell to attacker',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'bash -i', value: 'bash -i' }],
      },
      {
        label: 'Python / Perl Shell',
        desc: 'T1059.006 - python/perl one-liner reverse shell or exec',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'python -c', value: 'python -c' }],
      },
      {
        label: 'curl / wget Download',
        desc: 'T1105 - file download to /tmp - staging malware',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'curl -o /tmp', value: 'curl -o /tmp' }],
      },
      // Persistence
      {
        label: 'Cron Persistence',
        desc: 'T1053.003 - crontab -e or /etc/cron* modifications',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'crontab', value: 'crontab' }],
      },
      {
        label: 'New Systemd Service',
        desc: 'T1543.002 - new .service file linked - persistence',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'Created symlink', value: 'Created symlink' }],
      },
      {
        label: 'SSH Authorized Keys Modified',
        desc: 'T1098.004 - ~/.ssh/authorized_keys written - backdoor access',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: 'authorized_keys', value: 'authorized_keys' }],
      },
      // Privilege Escalation
      {
        label: 'SUID Binary Set',
        desc: 'T1548.001 - chmod +s or u+s - creates setuid binary for privesc',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'chmod +s', value: 'chmod +s' }],
      },
      {
        label: 'Sudo Root Shell',
        desc: 'T1548.003 - sudo used to spawn /bin/bash or /bin/sh as root',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: 'COMMAND=/bin/bash', value: 'COMMAND=/bin/bash' }],
      },
      {
        label: 'Kernel Module Loaded',
        desc: 'T1547.006 - insmod / modprobe - rootkit installation',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'insmod', value: 'insmod' }],
      },
      // Credential Access
      {
        label: 'SSH Brute Force',
        desc: 'T1110.001 - repeated sshd Failed password from single source',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: logon', value: 'logon' },
               { field: 'search', label: 'Failed password', value: 'Failed password' }],
      },
      {
        label: 'Shadow File Access',
        desc: 'T1003.008 - /etc/shadow read - credential dumping attempt',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: '/etc/shadow', value: '/etc/shadow' }],
      },
      // Defence Evasion
      {
        label: '/etc Changes',
        desc: 'T1565.001 - config file tampering under /etc',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: '/etc/', value: '/etc/' }],
      },
      {
        label: 'History File Cleared',
        desc: 'T1070.003 - unset HISTFILE or > ~/.bash_history - anti-forensics',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: 'bash_history', value: 'bash_history' }],
      },
      // Discovery
      {
        label: 'Network Port Scanning',
        desc: 'T1046 - nmap, masscan, or rustscan process',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'nmap', value: 'nmap' }],
      },
      // C2 / Exfiltration
      {
        label: 'Cloud Metadata SSRF',
        desc: 'T1552.005 - 169.254.169.254 access - EC2/GCP/Azure credential theft',
        tags: [{ field: 'os', label: 'OS: linux', value: 'linux' },
               { field: 'search', label: '169.254.169.254', value: '169.254.169.254' }],
      },
      {
        label: 'DNS Reconnaissance',
        desc: 'T1590 - dig/nslookup used for zone transfers or internal recon',
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
    
      // From the former Search page
      { label: "All Linux process events", desc: "type:process os:linux", tags: [{ field: 'kql', label: "type:process os:linux", value: "type:process os:linux" }] },
      { label: "Shell executions (bash/sh/zsh)", desc: "type:process bash", tags: [{ field: 'kql', label: "type:process bash", value: "type:process bash" }] },
      { label: "Python interpreter executions", desc: "type:process python", tags: [{ field: 'kql', label: "type:process python", value: "type:process python" }] },
      { label: "Perl executions", desc: "type:process perl", tags: [{ field: 'kql', label: "type:process perl", value: "type:process perl" }] },
      { label: "Curl / wget commands", desc: "type:process curl", tags: [{ field: 'kql', label: "type:process curl", value: "type:process curl" }] },
      { label: "Ncat / netcat usage", desc: "type:process ncat", tags: [{ field: 'kql', label: "type:process ncat", value: "type:process ncat" }] },
      { label: "chmod +x executions", desc: "type:process cmd:chmod", tags: [{ field: 'kql', label: "type:process cmd:chmod", value: "type:process cmd:chmod" }] },
      { label: "Process from /tmp", desc: "type:process /tmp/", tags: [{ field: 'kql', label: "type:process /tmp/", value: "type:process /tmp/" }] },
      { label: "Process from /dev/shm", desc: "type:process /dev/shm", tags: [{ field: 'kql', label: "type:process /dev/shm", value: "type:process /dev/shm" }] },
      { label: "LD_PRELOAD in command line", desc: "type:process ld_preload", tags: [{ field: 'kql', label: "type:process ld_preload", value: "type:process ld_preload" }] },
      { label: "strace / ptrace usage", desc: "type:process strace", tags: [{ field: 'kql', label: "type:process strace", value: "type:process strace" }] },
      { label: "nmap scanning", desc: "type:process nmap", tags: [{ field: 'kql', label: "type:process nmap", value: "type:process nmap" }] },
      { label: "High severity Linux processes", desc: "type:process sev>=4", tags: [{ field: 'kql', label: "type:process sev>=4", value: "type:process sev>=4" }] },
      { label: "All sudo executions", desc: "type:process proc:sudo", tags: [{ field: 'kql', label: "type:process proc:sudo", value: "type:process proc:sudo" }] },
      { label: "sudo auth failures", desc: "type:logon sudo_failed", tags: [{ field: 'kql', label: "type:logon sudo_failed", value: "type:logon sudo_failed" }] },
      { label: "SSH logins (accepted)", desc: "type:logon ssh_login", tags: [{ field: 'kql', label: "type:logon ssh_login", value: "type:logon ssh_login" }] },
      { label: "SSH failures (brute force)", desc: "type:logon ssh_failed", tags: [{ field: 'kql', label: "type:logon ssh_failed", value: "type:logon ssh_failed" }] },
      { label: "su / user switching", desc: "type:logon su_login", tags: [{ field: 'kql', label: "type:logon su_login", value: "type:logon su_login" }] },
      { label: "PAM auth failures", desc: "type:logon pam_auth_failed", tags: [{ field: 'kql', label: "type:logon pam_auth_failed", value: "type:logon pam_auth_failed" }] },
      { label: "All Linux logon events", desc: "type:logon os:linux", tags: [{ field: 'kql', label: "type:logon os:linux", value: "type:logon os:linux" }] },
      { label: "User account added", desc: "type:logon ADD_USER", tags: [{ field: 'kql', label: "type:logon ADD_USER", value: "type:logon ADD_USER" }] },
      { label: "User account deleted", desc: "type:logon DEL_USER", tags: [{ field: 'kql', label: "type:logon DEL_USER", value: "type:logon DEL_USER" }] },
      { label: "Root account activity (uid=0)", desc: "type:process user:root", tags: [{ field: 'kql', label: "type:process user:root", value: "type:process user:root" }] },
      { label: "All FIM events", desc: "type:file source:inotify", tags: [{ field: 'kql', label: "type:file source:inotify", value: "type:file source:inotify" }] },
      { label: "/etc/passwd modifications", desc: "type:file file:/etc/passwd", tags: [{ field: 'kql', label: "type:file file:/etc/passwd", value: "type:file file:/etc/passwd" }] },
      { label: "/etc/shadow modifications", desc: "type:file file:/etc/shadow", tags: [{ field: 'kql', label: "type:file file:/etc/shadow", value: "type:file file:/etc/shadow" }] },
      { label: "/etc/sudoers modifications", desc: "type:file file:/etc/sudoers", tags: [{ field: 'kql', label: "type:file file:/etc/sudoers", value: "type:file file:/etc/sudoers" }] },
      { label: "SSH config changes", desc: "type:file file:/etc/ssh", tags: [{ field: 'kql', label: "type:file file:/etc/ssh", value: "type:file file:/etc/ssh" }] },
      { label: "Crontab modifications", desc: "type:file file:cron", tags: [{ field: 'kql', label: "type:file file:cron", value: "type:file file:cron" }] },
      { label: "/tmp file drops", desc: "type:file file:/tmp/", tags: [{ field: 'kql', label: "type:file file:/tmp/", value: "type:file file:/tmp/" }] },
      { label: "/dev/shm file drops", desc: "type:file file:/dev/shm", tags: [{ field: 'kql', label: "type:file file:/dev/shm", value: "type:file file:/dev/shm" }] },
      { label: "ld.so.preload changes", desc: "type:file file:ld.so.preload", tags: [{ field: 'kql', label: "type:file file:ld.so.preload", value: "type:file file:ld.so.preload" }] },
      { label: "Systemd unit file changes", desc: "type:file file:systemd", tags: [{ field: 'kql', label: "type:file file:systemd", value: "type:file file:systemd" }] },
      { label: "Binary replaced in /usr/bin", desc: "type:file file:/usr/bin", tags: [{ field: 'kql', label: "type:file file:/usr/bin", value: "type:file file:/usr/bin" }] },
      { label: "Profile/bashrc modifications", desc: "type:file .bashrc", tags: [{ field: 'kql', label: "type:file .bashrc", value: "type:file .bashrc" }] },
      { label: "High severity FIM events", desc: "type:file sev>=4", tags: [{ field: 'kql', label: "type:file sev>=4", value: "type:file sev>=4" }] },
      { label: "All auditd events", desc: "source:auditd", tags: [{ field: 'kql', label: "source:auditd", value: "source:auditd" }] },
      { label: "All journald events", desc: "source:journald", tags: [{ field: 'kql', label: "source:journald", value: "source:journald" }] },
      { label: "Kernel OOM kills", desc: "oom_kill", tags: [{ field: 'kql', label: "oom_kill", value: "oom_kill" }] },
      { label: "Kernel module loads", desc: "kernel_module_load", tags: [{ field: 'kql', label: "kernel_module_load", value: "kernel_module_load" }] },
      { label: "Cron job executions", desc: "cron_exec", tags: [{ field: 'kql', label: "cron_exec", value: "cron_exec" }] },
      { label: "Service failures (systemd)", desc: "service_failed", tags: [{ field: 'kql', label: "service_failed", value: "service_failed" }] },
      { label: "Segfault / crash events", desc: "segfault", tags: [{ field: 'kql', label: "segfault", value: "segfault" }] },
      { label: "All Linux health events", desc: "type:health os:linux", tags: [{ field: 'kql', label: "type:health os:linux", value: "type:health os:linux" }] },
    ],
  },
  // ── macOS ─────────────────────────────────────────────────────────────────
  {
    group: 'macOS',
    searches: [
      // Persistence
      {
        label: 'LaunchDaemon Installed',
        desc: 'T1543.004 - /Library/LaunchDaemons/ write - system-wide persistence',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'LaunchDaemon', value: 'LaunchDaemon' }],
      },
      {
        label: 'LaunchAgent Installed',
        desc: 'T1543.001 - ~/Library/LaunchAgents/ write - user-level persistence',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'LaunchAgents', value: 'LaunchAgents' }],
      },
      {
        label: 'Login Item Added',
        desc: 'T1547.015 - SMLoginItem or login item plist - persistence at login',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'loginitems', value: 'loginitems' }],
      },
      // Privilege Escalation / Defence Evasion
      {
        label: 'Gatekeeper Bypass',
        desc: 'T1553.001 - spctl --master-disable or xattr -d com.apple.quarantine',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'spctl', value: 'spctl' }],
      },
      {
        label: 'SIP Bypass (csrutil)',
        desc: 'T1562.001 - csrutil disable - System Integrity Protection removed',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'csrutil', value: 'csrutil' }],
      },
      {
        label: 'TCC Database Access',
        desc: 'T1562.001 - TCC.db read/write - privacy permission bypass',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: file', value: 'file' },
               { field: 'search', label: 'TCC.db', value: 'TCC.db' }],
      },
      // Credential Access
      {
        label: 'Keychain Access',
        desc: 'T1555.001 - security command or keychain database accessed',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'search', label: 'keychain', value: 'keychain' }],
      },
      // Execution
      {
        label: 'osascript (AppleScript)',
        desc: 'T1059.002 - osascript execution - phishing dialogs, UAC bypass',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'osascript', value: 'osascript' }],
      },
      {
        label: 'curl Download',
        desc: 'T1105 - curl used to pull remote files - staging malware',
        tags: [{ field: 'os', label: 'OS: darwin', value: 'darwin' },
               { field: 'event_type', label: 'Type: process', value: 'process' },
               { field: 'search', label: 'curl', value: 'curl' }],
      },
      {
        label: 'Python / Perl Exec',
        desc: 'T1059.006 - scripting language one-liner or reverse shell',
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
  {
    group: "Process",
    searches: [
      { label: "All processes on all hosts", desc: "type:process", tags: [{ field: 'kql', label: "type:process", value: "type:process" }] },
      { label: "All PowerShell executions", desc: "type:process proc:powershell", tags: [{ field: 'kql', label: "type:process proc:powershell", value: "type:process proc:powershell" }] },
      { label: "PowerShell encoded commands", desc: "type:process cmd:-enc", tags: [{ field: 'kql', label: "type:process cmd:-enc", value: "type:process cmd:-enc" }] },
      { label: "PowerShell download cradles", desc: "type:process cmd:downloadstring", tags: [{ field: 'kql', label: "type:process cmd:downloadstring", value: "type:process cmd:downloadstring" }] },
      { label: "CMD executions", desc: "type:process proc:cmd.exe", tags: [{ field: 'kql', label: "type:process proc:cmd.exe", value: "type:process proc:cmd.exe" }] },
      { label: "Rundll32 executions", desc: "type:process proc:rundll32", tags: [{ field: 'kql', label: "type:process proc:rundll32", value: "type:process proc:rundll32" }] },
      { label: "MSHTA executions", desc: "type:process proc:mshta", tags: [{ field: 'kql', label: "type:process proc:mshta", value: "type:process proc:mshta" }] },
      { label: "WScript / CScript", desc: "type:process wscript", tags: [{ field: 'kql', label: "type:process wscript", value: "type:process wscript" }] },
      { label: "Regsvr32 executions", desc: "type:process proc:regsvr32", tags: [{ field: 'kql', label: "type:process proc:regsvr32", value: "type:process proc:regsvr32" }] },
      { label: "Certutil abuse", desc: "type:process proc:certutil", tags: [{ field: 'kql', label: "type:process proc:certutil", value: "type:process proc:certutil" }] },
      { label: "BITSAdmin executions", desc: "type:process bitsadmin", tags: [{ field: 'kql', label: "type:process bitsadmin", value: "type:process bitsadmin" }] },
      { label: "Scheduled task creation", desc: "type:process cmd:schtasks", tags: [{ field: 'kql', label: "type:process cmd:schtasks", value: "type:process cmd:schtasks" }] },
      { label: "New service (sc create)", desc: "type:process cmd:\"sc create\"", tags: [{ field: 'kql', label: "type:process cmd:\"sc create\"", value: "type:process cmd:\"sc create\"" }] },
      { label: "PsExec remote execution", desc: "type:process psexec", tags: [{ field: 'kql', label: "type:process psexec", value: "type:process psexec" }] },
      { label: "High severity process events", desc: "type:process sev>=4", tags: [{ field: 'kql', label: "type:process sev>=4", value: "type:process sev>=4" }] },
      { label: "Net.exe account commands", desc: "type:process \"net user\"", tags: [{ field: 'kql', label: "type:process \"net user\"", value: "type:process \"net user\"" }] },
      { label: "whoami execution", desc: "type:process cmd:whoami", tags: [{ field: 'kql', label: "type:process cmd:whoami", value: "type:process cmd:whoami" }] },
      { label: "WMIC command execution", desc: "type:process proc:wmic", tags: [{ field: 'kql', label: "type:process proc:wmic", value: "type:process proc:wmic" }] },
      { label: "bcdedit (recovery disabled)", desc: "type:process cmd:bcdedit", tags: [{ field: 'kql', label: "type:process cmd:bcdedit", value: "type:process cmd:bcdedit" }] },
    ],
  },
  {
    group: "Credential",
    searches: [
      { label: "All logon events", desc: "type:logon", tags: [{ field: 'kql', label: "type:logon", value: "type:logon" }] },
      { label: "Failed logons (Event 4625)", desc: "type:logon event_id:4625", tags: [{ field: 'kql', label: "type:logon event_id:4625", value: "type:logon event_id:4625" }] },
      { label: "Successful logons (Event 4624)", desc: "type:logon event_id:4624", tags: [{ field: 'kql', label: "type:logon event_id:4624", value: "type:logon event_id:4624" }] },
      { label: "Logon with explicit creds (4648)", desc: "type:logon event_id:4648", tags: [{ field: 'kql', label: "type:logon event_id:4648", value: "type:logon event_id:4648" }] },
      { label: "LSASS access attempts", desc: "type:process lsass", tags: [{ field: 'kql', label: "type:process lsass", value: "type:process lsass" }] },
      { label: "Mimikatz indicators", desc: "type:process mimikatz", tags: [{ field: 'kql', label: "type:process mimikatz", value: "type:process mimikatz" }] },
      { label: "Procdump usage", desc: "type:process procdump", tags: [{ field: 'kql', label: "type:process procdump", value: "type:process procdump" }] },
      { label: "SAM registry access", desc: "type:registry reg:SAM", tags: [{ field: 'kql', label: "type:registry reg:SAM", value: "type:registry reg:SAM" }] },
      { label: "Password string search", desc: "type:process cmd:password", tags: [{ field: 'kql', label: "type:process cmd:password", value: "type:process cmd:password" }] },
      { label: "High severity logon events", desc: "type:logon sev>=4", tags: [{ field: 'kql', label: "type:logon sev>=4", value: "type:logon sev>=4" }] },
    ],
  },
  {
    group: "Network",
    searches: [
      { label: "All network connections", desc: "type:network", tags: [{ field: 'kql', label: "type:network", value: "type:network" }] },
      { label: "Outbound RDP (port 3389)", desc: "type:network port:3389", tags: [{ field: 'kql', label: "type:network port:3389", value: "type:network port:3389" }] },
      { label: "Outbound SMB (port 445)", desc: "type:network port:445", tags: [{ field: 'kql', label: "type:network port:445", value: "type:network port:445" }] },
      { label: "Outbound SSH (port 22)", desc: "type:network port:22", tags: [{ field: 'kql', label: "type:network port:22", value: "type:network port:22" }] },
      { label: "Outbound FTP (port 21)", desc: "type:network port:21", tags: [{ field: 'kql', label: "type:network port:21", value: "type:network port:21" }] },
      { label: "HTTP traffic (port 80)", desc: "type:network port:80", tags: [{ field: 'kql', label: "type:network port:80", value: "type:network port:80" }] },
      { label: "HTTPS traffic (port 443)", desc: "type:network port:443", tags: [{ field: 'kql', label: "type:network port:443", value: "type:network port:443" }] },
      { label: "DNS traffic (port 53)", desc: "type:network port:53", tags: [{ field: 'kql', label: "type:network port:53", value: "type:network port:53" }] },
      { label: "SMTP outbound (port 587)", desc: "type:network port:587", tags: [{ field: 'kql', label: "type:network port:587", value: "type:network port:587" }] },
      { label: "WinRM (port 5985)", desc: "type:network port:5985", tags: [{ field: 'kql', label: "type:network port:5985", value: "type:network port:5985" }] },
      { label: "LDAP (port 389)", desc: "type:network port:389", tags: [{ field: 'kql', label: "type:network port:389", value: "type:network port:389" }] },
      { label: "Kerberos (port 88)", desc: "type:network port:88", tags: [{ field: 'kql', label: "type:network port:88", value: "type:network port:88" }] },
      { label: "SQL Server (port 1433)", desc: "type:network port:1433", tags: [{ field: 'kql', label: "type:network port:1433", value: "type:network port:1433" }] },
      { label: "All TCP connections", desc: "type:network proto:tcp", tags: [{ field: 'kql', label: "type:network proto:tcp", value: "type:network proto:tcp" }] },
      { label: "High severity network events", desc: "type:network sev>=4", tags: [{ field: 'kql', label: "type:network sev>=4", value: "type:network sev>=4" }] },
    ],
  },
  {
    group: "DNS / Web",
    searches: [
      { label: "All websites visited (DNS)", desc: "type:dns", tags: [{ field: 'kql', label: "type:dns", value: "type:dns" }] },
      { label: "RustDesk DNS queries", desc: "type:dns rustdesk", tags: [{ field: 'kql', label: "type:dns rustdesk", value: "type:dns rustdesk" }] },
      { label: "WPAD proxy discovery", desc: "type:dns wpad", tags: [{ field: 'kql', label: "type:dns wpad", value: "type:dns wpad" }] },
      { label: "Urban VPN queries", desc: "type:dns urban-vpn", tags: [{ field: 'kql', label: "type:dns urban-vpn", value: "type:dns urban-vpn" }] },
      { label: "ngrok tunnel queries", desc: "type:dns ngrok", tags: [{ field: 'kql', label: "type:dns ngrok", value: "type:dns ngrok" }] },
      { label: "Pastebin lookups", desc: "type:dns pastebin", tags: [{ field: 'kql', label: "type:dns pastebin", value: "type:dns pastebin" }] },
      { label: "TOR / .onion domains", desc: "type:dns .onion", tags: [{ field: 'kql', label: "type:dns .onion", value: "type:dns .onion" }] },
      { label: "AnyDesk DNS queries", desc: "type:dns anydesk", tags: [{ field: 'kql', label: "type:dns anydesk", value: "type:dns anydesk" }] },
      { label: "TeamViewer DNS queries", desc: "type:dns teamviewer", tags: [{ field: 'kql', label: "type:dns teamviewer", value: "type:dns teamviewer" }] },
      { label: "High severity DNS events", desc: "type:dns sev>=4", tags: [{ field: 'kql', label: "type:dns sev>=4", value: "type:dns sev>=4" }] },
    ],
  },
  {
    group: "File",
    searches: [
      { label: "All file events", desc: "type:file", tags: [{ field: 'kql', label: "type:file", value: "type:file" }] },
      { label: "Temp directory writes", desc: "type:file file:\\\\temp\\\\", tags: [{ field: 'kql', label: "type:file file:\\\\temp\\\\", value: "type:file file:\\\\temp\\\\" }] },
      { label: "AppData writes", desc: "type:file file:appdata", tags: [{ field: 'kql', label: "type:file file:appdata", value: "type:file file:appdata" }] },
      { label: "Desktop file drops", desc: "type:file file:\\\\desktop\\\\", tags: [{ field: 'kql', label: "type:file file:\\\\desktop\\\\", value: "type:file file:\\\\desktop\\\\" }] },
      { label: "Executable files written (.exe)", desc: "type:file file:.exe", tags: [{ field: 'kql', label: "type:file file:.exe", value: "type:file file:.exe" }] },
      { label: "PowerShell scripts written (.ps1)", desc: "type:file file:.ps1", tags: [{ field: 'kql', label: "type:file file:.ps1", value: "type:file file:.ps1" }] },
      { label: "Startup folder writes", desc: "type:file file:startup", tags: [{ field: 'kql', label: "type:file file:startup", value: "type:file file:startup" }] },
      { label: "System32 writes", desc: "type:file file:system32", tags: [{ field: 'kql', label: "type:file file:system32", value: "type:file file:system32" }] },
      { label: "Encrypted file extensions", desc: "type:file .locked", tags: [{ field: 'kql', label: "type:file .locked", value: "type:file .locked" }] },
      { label: "High severity file events", desc: "type:file sev>=4", tags: [{ field: 'kql', label: "type:file sev>=4", value: "type:file sev>=4" }] },
    ],
  },
  {
    group: "Registry",
    searches: [
      { label: "All registry events", desc: "type:registry", tags: [{ field: 'kql', label: "type:registry", value: "type:registry" }] },
      { label: "Run key modifications", desc: "type:registry reg:CurrentVersion\\\\Run", tags: [{ field: 'kql', label: "type:registry reg:CurrentVersion\\\\Run", value: "type:registry reg:CurrentVersion\\\\Run" }] },
      { label: "RunOnce key modifications", desc: "type:registry reg:RunOnce", tags: [{ field: 'kql', label: "type:registry reg:RunOnce", value: "type:registry reg:RunOnce" }] },
      { label: "Security policy changes", desc: "type:registry reg:Policies", tags: [{ field: 'kql', label: "type:registry reg:Policies", value: "type:registry reg:Policies" }] },
      { label: "Service registry changes", desc: "type:registry reg:Services", tags: [{ field: 'kql', label: "type:registry reg:Services", value: "type:registry reg:Services" }] },
      { label: "LSA registry changes", desc: "type:registry reg:Lsa", tags: [{ field: 'kql', label: "type:registry reg:Lsa", value: "type:registry reg:Lsa" }] },
      { label: "Winlogon key changes", desc: "type:registry reg:Winlogon", tags: [{ field: 'kql', label: "type:registry reg:Winlogon", value: "type:registry reg:Winlogon" }] },
      { label: "AppInit DLLs", desc: "type:registry reg:AppInit_DLLs", tags: [{ field: 'kql', label: "type:registry reg:AppInit_DLLs", value: "type:registry reg:AppInit_DLLs" }] },
      { label: "IE Zone settings", desc: "type:registry reg:ZoneMap", tags: [{ field: 'kql', label: "type:registry reg:ZoneMap", value: "type:registry reg:ZoneMap" }] },
      { label: "High severity registry events", desc: "type:registry sev>=4", tags: [{ field: 'kql', label: "type:registry sev>=4", value: "type:registry sev>=4" }] },
    ],
  },
  {
    group: "User",
    searches: [
      { label: "All events for SYSTEM account", desc: "user:SYSTEM", tags: [{ field: 'kql', label: "user:SYSTEM", value: "user:SYSTEM" }] },
      { label: "All events for administrator", desc: "user:administrator", tags: [{ field: 'kql', label: "user:administrator", value: "user:administrator" }] },
      { label: "Guest account activity", desc: "user:guest", tags: [{ field: 'kql', label: "user:guest", value: "user:guest" }] },
      { label: "Network service account", desc: "user:\"NETWORK SERVICE\"", tags: [{ field: 'kql', label: "user:\"NETWORK SERVICE\"", value: "user:\"NETWORK SERVICE\"" }] },
      { label: "All logon events", desc: "type:logon", tags: [{ field: 'kql', label: "type:logon", value: "type:logon" }] },
      { label: "Service account logons", desc: "type:logon svc", tags: [{ field: 'kql', label: "type:logon svc", value: "type:logon svc" }] },
      { label: "Account creation (Event 4720)", desc: "event_id:4720", tags: [{ field: 'kql', label: "event_id:4720", value: "event_id:4720" }] },
      { label: "High severity user events", desc: "sev>=4", tags: [{ field: 'kql', label: "sev>=4", value: "sev>=4" }] },
    ],
  },
  {
    group: "Sysmon",
    searches: [
      { label: "All Sysmon events", desc: "type:sysmon", tags: [{ field: 'kql', label: "type:sysmon", value: "type:sysmon" }] },
      { label: "Sysmon process creation (ID 1)", desc: "type:sysmon event_id:1", tags: [{ field: 'kql', label: "type:sysmon event_id:1", value: "type:sysmon event_id:1" }] },
      { label: "Sysmon network connection (ID 3)", desc: "type:sysmon event_id:3", tags: [{ field: 'kql', label: "type:sysmon event_id:3", value: "type:sysmon event_id:3" }] },
      { label: "Sysmon file creation (ID 11)", desc: "type:sysmon event_id:11", tags: [{ field: 'kql', label: "type:sysmon event_id:11", value: "type:sysmon event_id:11" }] },
      { label: "Sysmon registry event (ID 12)", desc: "type:sysmon event_id:12", tags: [{ field: 'kql', label: "type:sysmon event_id:12", value: "type:sysmon event_id:12" }] },
      { label: "Sysmon image loaded (ID 7)", desc: "type:sysmon event_id:7", tags: [{ field: 'kql', label: "type:sysmon event_id:7", value: "type:sysmon event_id:7" }] },
      { label: "Sysmon process access (ID 10)", desc: "type:sysmon event_id:10", tags: [{ field: 'kql', label: "type:sysmon event_id:10", value: "type:sysmon event_id:10" }] },
      { label: "All critical severity events", desc: "sev>=5", tags: [{ field: 'kql', label: "sev>=5", value: "sev>=5" }] },
      { label: "All high severity events", desc: "sev>=4", tags: [{ field: 'kql', label: "sev>=4", value: "sev>=4" }] },
      { label: "Windows Security channel", desc: "channel:Security", tags: [{ field: 'kql', label: "channel:Security", value: "channel:Security" }] },
      { label: "Windows System channel", desc: "channel:System", tags: [{ field: 'kql', label: "channel:System", value: "channel:System" }] },
      { label: "PowerShell Operational channel", desc: "channel:PowerShell", tags: [{ field: 'kql', label: "channel:PowerShell", value: "channel:PowerShell" }] },
      { label: "Event log cleared (ID 1102)", desc: "event_id:1102", tags: [{ field: 'kql', label: "event_id:1102", value: "event_id:1102" }] },
      { label: "AppLocker block events (8004)", desc: "event_id:8004", tags: [{ field: 'kql', label: "event_id:8004", value: "event_id:8004" }] },
      { label: "All raw events", desc: "type:raw", tags: [{ field: 'kql', label: "type:raw", value: "type:raw" }] },
    ],
  },
  {
    group: "Code",
    searches: [
      { label: "All code-platform events", desc: "type:devops.*", tags: [{ field: 'kql', label: "type:devops.*", value: "type:devops.*" }] },
      { label: "Secrets pushed to a repository", desc: "type:devops.secret_push", tags: [{ field: 'kql', label: "type:devops.secret_push", value: "type:devops.secret_push" }] },
      { label: "CI/CD pipeline or workflow changed", desc: "type:devops.cicd_modified", tags: [{ field: 'kql', label: "type:devops.cicd_modified", value: "type:devops.cicd_modified" }] },
      { label: "Sensitive files changed", desc: "type:devops.sensitive_file", tags: [{ field: 'kql', label: "type:devops.sensitive_file", value: "type:devops.sensitive_file" }] },
      { label: "Repositories made public", desc: "type:devops.repo_publicized", tags: [{ field: 'kql', label: "type:devops.repo_publicized", value: "type:devops.repo_publicized" }] },
      { label: "Repositories deleted", desc: "type:devops.repo_deleted", tags: [{ field: 'kql', label: "type:devops.repo_deleted", value: "type:devops.repo_deleted" }] },
      { label: "Members added to the organisation", desc: "type:devops.member_added", tags: [{ field: 'kql', label: "type:devops.member_added", value: "type:devops.member_added" }] },
      { label: "Dependency changes", desc: "type:devops.dependency_change", tags: [{ field: 'kql', label: "type:devops.dependency_change", value: "type:devops.dependency_change" }] },
      { label: "Mass deletion", desc: "type:devops.mass_deletion", tags: [{ field: 'kql', label: "type:devops.mass_deletion", value: "type:devops.mass_deletion" }] },
      { label: "Pipeline runs", desc: "type:(devops.pipeline_run or devops.workflow_run)", tags: [{ field: 'kql', label: "type:(devops.pipeline_run or devops.workflow_run)", value: "type:(devops.pipeline_run or devops.workflow_run)" }] },
      { label: "Platform audit log", desc: "type:devops.audit", tags: [{ field: 'kql', label: "type:devops.audit", value: "type:devops.audit" }] },
      { label: "High-severity code events", desc: "type:devops.* sev:high", tags: [{ field: 'kql', label: "type:devops.* sev:high", value: "type:devops.* sev:high" }] },
    ],
  },
  {
    group: "Cloud",
    searches: [
      { label: "All cloud events", desc: "type:cloud.*", tags: [{ field: 'kql', label: "type:cloud.*", value: "type:cloud.*" }] },
      { label: "AWS CloudTrail", desc: "type:(cloud.cloudtrail or cloud.aws_cloudtrail)", tags: [{ field: 'kql', label: "type:(cloud.cloudtrail or cloud.aws_cloudtrail)", value: "type:(cloud.cloudtrail or cloud.aws_cloudtrail)" }] },
      { label: "AWS GuardDuty findings", desc: "type:cloud.guardduty", tags: [{ field: 'kql', label: "type:cloud.guardduty", value: "type:cloud.guardduty" }] },
      { label: "AWS Security Hub", desc: "type:cloud.securityhub", tags: [{ field: 'kql', label: "type:cloud.securityhub", value: "type:cloud.securityhub" }] },
      { label: "Azure activity log", desc: "type:cloud.azure_activity", tags: [{ field: 'kql', label: "type:cloud.azure_activity", value: "type:cloud.azure_activity" }] },
      { label: "Azure Defender alerts", desc: "type:cloud.azure_defender", tags: [{ field: 'kql', label: "type:cloud.azure_defender", value: "type:cloud.azure_defender" }] },
      { label: "Entra ID sign-ins", desc: "type:cloud.entra_signin", tags: [{ field: 'kql', label: "type:cloud.entra_signin", value: "type:cloud.entra_signin" }] },
      { label: "Entra ID audit", desc: "type:cloud.entra_audit", tags: [{ field: 'kql', label: "type:cloud.entra_audit", value: "type:cloud.entra_audit" }] },
      { label: "GCP audit log", desc: "type:cloud.gcp_audit", tags: [{ field: 'kql', label: "type:cloud.gcp_audit", value: "type:cloud.gcp_audit" }] },
      { label: "GKE audit log", desc: "type:cloud.gcp_gke_audit", tags: [{ field: 'kql', label: "type:cloud.gcp_gke_audit", value: "type:cloud.gcp_gke_audit" }] },
      { label: "GCP policy denials", desc: "type:cloud.gcp_policy_denied", tags: [{ field: 'kql', label: "type:cloud.gcp_policy_denied", value: "type:cloud.gcp_policy_denied" }] },
      { label: "GCP Security Command Center", desc: "type:cloud.gcp_scc", tags: [{ field: 'kql', label: "type:cloud.gcp_scc", value: "type:cloud.gcp_scc" }] },
      { label: "Cloud posture findings", desc: "type:cloud.cspm", tags: [{ field: 'kql', label: "type:cloud.cspm", value: "type:cloud.cspm" }] },
      { label: "Cloud anomalies and correlations", desc: "type:(cloud.aws_anomaly or cloud.azure_anomaly or cloud.gcp_anomaly or cloud.azure_correlation or cloud.gcp_correlation)", tags: [{ field: 'kql', label: "type:(cloud.aws_anomaly or cloud.azure_anomaly or cloud.gcp_anomaly or cloud.azure_correlation or cloud.gcp_correlation)", value: "type:(cloud.aws_anomaly or cloud.azure_anomaly or cloud.gcp_anomaly or cloud.azure_correlation or cloud.gcp_correlation)" }] },
      { label: "High-severity cloud events", desc: "type:cloud.* sev:high", tags: [{ field: 'kql', label: "type:cloud.* sev:high", value: "type:cloud.* sev:high" }] },
    ],
  },
  {
    group: "Application",
    searches: [
      { label: "Application security alerts", desc: "type:app.alert", tags: [{ field: 'kql', label: "type:app.alert", value: "type:app.alert" }] },
      { label: "High-severity application alerts", desc: "type:app.alert sev:high", tags: [{ field: 'kql', label: "type:app.alert sev:high", value: "type:app.alert sev:high" }] },
      { label: "Application logs", desc: "type:applog", tags: [{ field: 'kql', label: "type:applog", value: "type:applog" }] },
      { label: "All application events", desc: "type:app.*", tags: [{ field: 'kql', label: "type:app.*", value: "type:app.*" }] },
    ],
  },
]


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
  const [activeGroup, setActiveGroup] = useState(SAVED_SEARCHES[0].group)
  const group = SAVED_SEARCHES.find(g => g.group === activeGroup)

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
          {SAVED_SEARCHES.map(({ group }) => {
            const Icon = GROUP_ICONS[group] || Shield
            const isCloud = false
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
  kql:           'bg-violet-900/30 text-violet-300 border-violet-700/40 font-mono',
}

// Mirrors the backend query language: a field op value condition, parentheses,
// or and/or/not make the input a query rather than a plain search word.
const KQL_FIELDS = new Set(['host','os','user','proc','process','cmd','cmdline','image','file','path','hash','reg','regkey',
  'regvalue','domain','channel','source','proto','guid','logon','src','src_ip','dst','dst_ip','ip','pid','ppid','port',
  'dstport','srcport','event_id','eid','sev','severity','type','event','time'])
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
    const terms = nlResult.q.match(/-?"[^"]*"|\S+/g) || []
    setTags(terms.map(raw => ({ id: Date.now() + Math.random(), ...classifyTerm(raw.replace(/^"|"$/g, '')) })).filter(t => t.field))
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

  const buildParams = useCallback((p = 0) => {
    const params = { limit, offset: p * limit }
    const searchTerms = []
    const kql = []
    tags.forEach(tag => {
      if (tag.field === 'kql') {
        kql.push('(' + tag.value + ')')
      } else if (tag.field === 'src_or_dst_ip' || tag.field === 'search') {
        searchTerms.push(tag.value)
      } else {
        params[tag.field] = tag.value
      }
    })
    if (searchTerms.length > 0) params.search = searchTerms.join(' ')
    if (kql.length > 0) params.q = kql.join(' ')
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
      const kqlTokens = tags.filter(t => t.field === 'kql').map(t => '(' + t.value + ')')
      // A query typed live is kept whole; plain words are split as before.
      const live = liveInput.trim()
      const liveTokens = !live ? [] : looksLikeKQL(live) ? ['(' + live + ')'] : live.split(/\s+/).filter(Boolean)
      const allTokens = [...kqlTokens, ...searchTokens, ...liveTokens]
      setQueryErr('')

      // Timeline and facet counts over the whole query (not just this page), when the server offers them.
      const sumParams = { ...params }
      delete sumParams.limit; delete sumParams.offset
      if (allTokens.length > 0) { sumParams.q = allTokens.join(' '); delete sumParams.search }
      if (p === 0) api.get('/api/v1/events/summary', { params: sumParams })
        .then(r => { setSummary(r.data?.summary || null); setSummaryOK(!!r.data?.summary) })
        .catch(() => { setSummary(null); setSummaryOK(false) })
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
    } catch (e) {
      // A bad query is the user's to fix: show why, keep the previous results.
      const msg = e?.response?.status === 400 ? e.response.data?.error : ''
      if (msg) setQueryErr(msg)
    } finally { setLoading(false) }
  }, [buildParams, tags])

  useEffect(() => {
    // Debounce search - fire 300ms after last change
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
              <div className="ow-field" style={{ flex: '1 1 480px', height: 'auto', minHeight: 34, flexWrap: 'wrap', padding: '3px 10px', cursor: 'text' }} onClick={() => inputRef.current?.focus()}>
                <Search size={14} style={{ color: 'var(--t3)' }}/>
                {tags.map(tag => (
                  <span key={tag.id} className="tag mono" style={{ background: tag.field === 'kql' ? 'var(--abg)' : 'var(--s3)', color: tag.field === 'kql' ? 'var(--acc)' : 'var(--t1)' }}>
                    {tag.label}
                    <button onClick={e => { e.stopPropagation(); removeTag(tag.id) }} aria-label={`Remove ${tag.label}`} style={{ background: 'none', border: 0, color: 'inherit', cursor: 'pointer', padding: 0, marginLeft: 2 }}>×</button>
                  </span>
                ))}
                <input ref={inputRef} className="mono" style={{ minWidth: 200, fontSize: 12.5 }}
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
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', fontSize: 12 }}>
                <span className="t2">From</span>
                <input type="datetime-local" className="input" style={{ width: 200 }} value={since} onChange={e => { setPreset(''); setSince(e.target.value) }}/>
                <span className="t2">to</span>
                <input type="datetime-local" className="input" style={{ width: 200 }} value={until} onChange={e => { setPreset(''); setUntil(e.target.value) }}/>
                <span className="t3">Leave "to" empty for now.</span>
              </div>
            )}

            {queryErr && <div className="c-crit" style={{ fontSize: 12.5 }}>Query problem: {queryErr}</div>}

            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <button className={`ow-btn quiet ${showHelp ? 'c-acc' : ''}`} style={{ height: 24, padding: '0 6px' }} onClick={() => setShowHelp(h => !h)}>Query syntax</button>
              <button className={`ow-btn quiet ${showNL ? 'c-acc' : ''}`} style={{ height: 24, padding: '0 6px' }} onClick={() => setShowNL(v => !v)}>Ask in plain English</button>
              <span style={{ width: 1, height: 16, background: 'var(--line2)', margin: '0 4px' }}/>
              {HINTS.map(h => <button key={h} className="tag" style={{ cursor: 'pointer', border: 0 }} onClick={() => addTag(h)}>{h}</button>)}
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
                {savedQueries.map(sq => (
                  <span key={sq.id} className="tag" style={{ paddingRight: 4 }}>
                    <button style={{ background: 'none', border: 0, color: 'var(--t1)', cursor: 'pointer', font: 'inherit', padding: 0 }} title={sq.query}
                      onClick={() => { const nt = sq.query.split(' ').filter(Boolean).map(t => { const c = classifyTerm(t); return c ? { id: Date.now() + Math.random(), ...c } : null }).filter(Boolean); if (nt.length) setTags(nt) }}>{sq.name}</button>
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
                  <div key={q} style={{ display: 'flex', gap: 14, fontSize: 12.5 }}>
                    <button onClick={() => addTag(q)} className="mono c-acc" style={{ background: 'none', border: 0, cursor: 'pointer', textAlign: 'left', minWidth: 300, padding: 0 }}>{q}</button>
                    <span className="t2">{d}</span>
                  </div>
                ))}
                <div className="t3" style={{ fontSize: 12 }}>Fields: <span className="mono">host os user proc cmd image file hash reg domain channel source proto src dst ip port pid ppid eid sev type time</span></div>
              </div>
            )}

            {showNL && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', gap: 8 }}>
                  <input className="input" style={{ flex: 1 }} maxLength={300} autoFocus value={nlQuestion} onChange={e => setNlQuestion(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') askNL() }}
                    placeholder='e.g. "PowerShell started by Word in the last 7 days"'/>
                  <button className="ow-btn" onClick={askNL} disabled={nlBusy || !nlQuestion.trim()}>{nlBusy ? 'Thinking…' : 'Propose query'}</button>
                </div>
                {nlErr && <div className="c-crit" style={{ fontSize: 12.5 }}>{nlErr}</div>}
                {nlResult && (
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center', fontSize: 12.5 }}>
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
              <span className="t3" style={{ fontSize: 12 }}>{summary ? `${summary.step} buckets · click a bar to zoom` : summaryOK ? 'Loading…' : `of the ${events.length} on this page (the server has no summary endpoint)`}</span>
              <span style={{ marginLeft: 'auto', display: 'flex', gap: 12, fontSize: 11.5, color: 'var(--t3)' }}>
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
              <div className="t3" style={{ fontSize: 11.5 }}>{facetData.scope === 'all' ? 'Counts over the whole query. Click to filter.' : `Counts in the ${events.length} shown. Click to filter.`}</div>
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
                  <span className="mono t2" style={{ fontSize: 12 }} title={new Date(ev.time).toISOString()}>{format(new Date(ev.time), 'MMM dd HH:mm:ss')}</span>
                  <span>{(ev.severity || 1) >= 3 ? <SevPill sev={ev.severity}/> : <span className="t3" style={{ fontSize: 12 }}>{SEV_WORD[ev.severity || 1]}</span>}</span>
                  <span className="mono t1" title={ev.host}>{ev.host || '—'}</span>
                  <span><EventTypeBadge type={ev.event_type}/></span>
                  <span className="mono t2" style={{ fontSize: 12 }} title={summaryOf(ev)}>{summaryOf(ev)}</span>
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
