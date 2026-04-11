import { useEffect, useState } from 'react'
import { BookOpen, Plus, Trash2, ToggleLeft, ToggleRight, Pencil } from 'lucide-react'
import api from '../api/client'

const EVENT_TYPES = ['', 'process', 'network', 'logon', 'registry', 'file', 'dns', 'sysmon', 'raw']
const OS_OPTIONS  = ['', 'linux', 'windows', 'macos']

const emptyRule = {
  name: '', description: '', enabled: true,
  event_type: '', severity: 1,
  os_match: '',
  host_match: '', user_match: '', process_match: '', command_line_match: '',
  src_ip_match: '', dst_ip_match: '', dns_match: '', source_match: '',
}

function Field({ label, value, onChange, placeholder, hint }) {
  return (
    <div>
      <label className="block text-xs text-siem-muted mb-1">{label}</label>
      {hint && <p className="text-xs text-siem-muted/60 mb-1">{hint}</p>}
      <input
        className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
        placeholder={placeholder || '(any)'}
        value={value}
        onChange={e => onChange(e.target.value)}
      />
    </div>
  )
}

function RuleForm({ initial, onSave, onCancel }) {
  const [rule, setRule] = useState(initial || emptyRule)
  const set = (k, v) => setRule(r => ({ ...r, [k]: v }))

  return (
    <form onSubmit={e => { e.preventDefault(); onSave(rule) }}
      className="bg-siem-bg border border-siem-border rounded-xl p-4 space-y-4">

      {/* ── Identity ── */}
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="block text-xs text-siem-muted mb-1">Rule name *</label>
          <input className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            value={rule.name} onChange={e => set('name', e.target.value)} required />
        </div>
        <div className="col-span-2">
          <label className="block text-xs text-siem-muted mb-1">Description</label>
          <input className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            value={rule.description} onChange={e => set('description', e.target.value)} />
        </div>
      </div>

      {/* ── Primary filters ── */}
      <div>
        <p className="text-xs font-semibold text-siem-muted uppercase tracking-wide mb-2">Primary Filters</p>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-siem-muted mb-1">Min severity</label>
            <select className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
              value={rule.severity} onChange={e => set('severity', Number(e.target.value))}>
              <option value={1}>1 — Info</option>
              <option value={2}>2 — Low</option>
              <option value={3}>3 — Medium</option>
              <option value={4}>4 — High</option>
              <option value={5}>5 — Critical</option>
            </select>
          </div>
          <div>
            <label className="block text-xs text-siem-muted mb-1">Event type</label>
            <select className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
              value={rule.event_type} onChange={e => set('event_type', e.target.value)}>
              {EVENT_TYPES.map(t => <option key={t} value={t}>{t || 'Any'}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-xs text-siem-muted mb-1">OS</label>
            <select className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
              value={rule.os_match} onChange={e => set('os_match', e.target.value)}>
              {OS_OPTIONS.map(o => <option key={o} value={o}>{o || 'Any'}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* ── Host / Identity filters ── */}
      <div>
        <p className="text-xs font-semibold text-siem-muted uppercase tracking-wide mb-2">Host / Identity</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Host contains"    value={rule.host_match}    onChange={v => set('host_match', v)} />
          <Field label="User contains"    value={rule.user_match}    onChange={v => set('user_match', v)} />
          <Field label="Source contains"  value={rule.source_match}  onChange={v => set('source_match', v)}
            hint="e.g. sshd, Sysmon, configmon, proc-net" />
        </div>
      </div>

      {/* ── Process filters ── */}
      <div>
        <p className="text-xs font-semibold text-siem-muted uppercase tracking-wide mb-2">Process</p>
        <div className="grid grid-cols-1 gap-3">
          <Field label="Process name contains"   value={rule.process_match}      onChange={v => set('process_match', v)} />
          <Field label="Command line contains"   value={rule.command_line_match} onChange={v => set('command_line_match', v)}
            hint="Matches any substring in the full command line" />
        </div>
      </div>

      {/* ── Network / DNS filters ── */}
      <div>
        <p className="text-xs font-semibold text-siem-muted uppercase tracking-wide mb-2">Network / DNS</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Source IP contains"      value={rule.src_ip_match} onChange={v => set('src_ip_match', v)}
            hint="Matches src_ip on network events" />
          <Field label="Destination IP contains" value={rule.dst_ip_match} onChange={v => set('dst_ip_match', v)}
            hint="Matches dst_ip on network events" />
          <div className="col-span-2">
            <Field label="DNS domain contains"   value={rule.dns_match}    onChange={v => set('dns_match', v)}
              hint="Only matches dns events — dst_ip holds the queried domain name" />
          </div>
        </div>
      </div>

      {/* ── Actions ── */}
      <div className="flex items-center gap-2 pt-1">
        <button type="submit"
          className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-4 py-2 rounded-lg">
          Save rule
        </button>
        <button type="button" onClick={onCancel}
          className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-4 py-2">
          Cancel
        </button>
        <label className="flex items-center gap-1.5 text-xs text-siem-muted ml-auto cursor-pointer">
          <input type="checkbox" checked={rule.enabled} onChange={e => set('enabled', e.target.checked)}
            className="accent-siem-accent" />
          Enabled
        </label>
      </div>
    </form>
  )
}

function FilterBadges({ rule }) {
  const badges = [
    rule.host_match          && `host:${rule.host_match}`,
    rule.user_match          && `user:${rule.user_match}`,
    rule.os_match            && `os:${rule.os_match}`,
    rule.process_match       && `proc:${rule.process_match}`,
    rule.command_line_match  && `cmd:${rule.command_line_match}`,
    rule.src_ip_match        && `src:${rule.src_ip_match}`,
    rule.dst_ip_match        && `dst:${rule.dst_ip_match}`,
    rule.dns_match           && `dns:${rule.dns_match}`,
    rule.source_match        && `source:${rule.source_match}`,
  ].filter(Boolean)

  if (badges.length === 0) return <span className="text-siem-muted">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {badges.map(b => (
        <span key={b} className="bg-siem-surface border border-siem-border rounded px-1.5 py-0.5 text-xs text-siem-muted">
          {b}
        </span>
      ))}
    </div>
  )
}

export default function AlertRules() {
  const [rules, setRules]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing]   = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/alert-rules')
      setRules(data.rules || [])
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const create = async (rule) => { await api.post('/api/v1/alert-rules', rule);          setShowCreate(false); load() }
  const update = async (rule) => { await api.put(`/api/v1/alert-rules/${rule.id}`, rule); setEditing(null);    load() }
  const toggle = async (rule) => { await api.put(`/api/v1/alert-rules/${rule.id}`, { ...rule, enabled: !rule.enabled }); load() }
  const del    = async (id)   => { if (!confirm('Delete this rule?')) return; await api.delete(`/api/v1/alert-rules/${id}`); load() }

  const severityLabel = s => ['', 'Info', 'Low', 'Medium', 'High', 'Critical'][s] || s
  const severityColor = s => s >= 5 ? 'text-red-400' : s >= 4 ? 'text-orange-400' : s >= 3 ? 'text-yellow-400' : 'text-siem-muted'

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BookOpen className="text-siem-accent" size={20} />
          <h1 className="text-xl font-bold text-siem-text">Alert Rules</h1>
        </div>
        <button onClick={() => setShowCreate(true)}
          className="flex items-center gap-1.5 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-2 rounded-lg">
          <Plus size={13} /> New rule
        </button>
      </div>

      <div className="text-xs text-siem-muted bg-siem-surface border border-siem-border rounded-xl p-3">
        Rules are evaluated every 30 seconds. All conditions must match (AND logic). Leave a field blank to match any value.
        The <span className="text-siem-accent">DNS domain</span> filter only matches <code>dns</code> events — the queried domain is stored in the destination IP field on all platforms.
      </div>

      {showCreate && <RuleForm onSave={create} onCancel={() => setShowCreate(false)} />}

      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-siem-border text-siem-muted text-xs">
              <th className="text-left px-4 py-3">Name</th>
              <th className="text-left px-4 py-3">Min Severity</th>
              <th className="text-left px-4 py-3">Event Type</th>
              <th className="text-left px-4 py-3">Filters</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={6} className="text-center py-10 text-siem-muted">Loading...</td></tr>
            ) : rules.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-10 text-siem-muted">No rules yet — create one above.</td></tr>
            ) : rules.map(rule => (
              <>
                <tr key={rule.id} className="border-b border-siem-border/40">
                  <td className="px-4 py-3">
                    <div className="text-siem-text font-medium">{rule.name}</div>
                    {rule.description && <div className="text-xs text-siem-muted">{rule.description}</div>}
                  </td>
                  <td className={`px-4 py-3 font-medium ${severityColor(rule.severity)}`}>
                    {rule.severity} — {severityLabel(rule.severity)}
                  </td>
                  <td className="px-4 py-3 text-siem-accent">{rule.event_type || 'Any'}</td>
                  <td className="px-4 py-3"><FilterBadges rule={rule} /></td>
                  <td className="px-4 py-3">
                    <button onClick={() => toggle(rule)}>
                      {rule.enabled
                        ? <span className="flex items-center gap-1 text-siem-green text-xs"><ToggleRight size={16} /> Enabled</span>
                        : <span className="flex items-center gap-1 text-siem-muted text-xs"><ToggleLeft size={16} /> Disabled</span>}
                    </button>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2 justify-end">
                      <button onClick={() => setEditing(editing === rule.id ? null : rule.id)}
                        className="text-siem-muted hover:text-siem-accent transition-colors"><Pencil size={14} /></button>
                      <button onClick={() => del(rule.id)}
                        className="text-siem-muted hover:text-siem-red transition-colors"><Trash2 size={14} /></button>
                    </div>
                  </td>
                </tr>
                {editing === rule.id && (
                  <tr key={`edit-${rule.id}`} className="border-b border-siem-border/40">
                    <td colSpan={6} className="px-4 py-3">
                      <RuleForm initial={rule} onSave={update} onCancel={() => setEditing(null)} />
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
