import { useEffect, useState } from 'react'
import { BookOpen, Plus, Trash2, ToggleLeft, ToggleRight, Pencil } from 'lucide-react'
import api from '../api/client'
import { PageHeader, Num, DenseTable, SevPill, Drawer } from '../components/ui'

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
              <option value={1}>1 - Info</option>
              <option value={2}>2 - Low</option>
              <option value={3}>3 - Medium</option>
              <option value={4}>4 - High</option>
              <option value={5}>5 - Critical</option>
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
              hint="Only matches dns events - dst_ip holds the queried domain name" />
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

  if (badges.length === 0) return <span className="t3">any event</span>
  return <span className="mono t2" style={{ fontSize: 12 }} title={badges.join('  ')}>{badges.join('  ·  ')}</span>
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

  const [q, setQ] = useState('')
  const shown = rules.filter(r => !q || `${r.name} ${r.description || ''} ${r.event_type || ''}`.toLowerCase().includes(q.toLowerCase()))
  const on = rules.filter(r => r.enabled).length
  const editRule = rules.find(r => r.id === editing)

  return (
    <div>
      <PageHeader title="Alert rules"
        sub="Your own match rules. Every condition must match; a blank field matches anything."
        actions={<button className="ow-btn primary" onClick={() => { setEditing(null); setShowCreate(true) }}><Plus size={13}/>New rule</button>}
        nums={<>
          <Num k="Rules" v={rules.length}/>
          <Num k="Enabled" v={on} unit={`of ${rules.length}`}/>
          <Num k="Critical" v={rules.filter(r => r.severity >= 5).length}/>
        </>}/>
      <div className="ow-body">
        <div className="ow-card" style={{ overflow: 'hidden' }}>
          <div className="ow-card-bar">
            <label className="ow-field" style={{ flex: 1, maxWidth: 380, height: 28 }}>
              <input value={q} onChange={e => setQ(e.target.value)} placeholder="Filter rules" aria-label="Filter rules"/>
            </label>
            <span className="t2" style={{ fontSize: 12 }}>{shown.length} of {rules.length}</span>
          </div>
          <DenseTable rows={loading ? [] : shown} rowKey={r => r.id} onRow={r => { setShowCreate(false); setEditing(r.id) }} current={editing}
            empty={loading ? 'Loading…' : rules.length ? 'No rules match.' : 'No alert rules yet. Built-in detections live under Rules; add your own here.'}
            cols={[
              { key: 'on', label: 'On', width: '52px', render: r => (
                <button className={`ow-switch ${r.enabled ? 'on' : ''}`} role="switch" aria-checked={r.enabled} aria-label={`${r.enabled ? 'Disable' : 'Enable'} ${r.name}`}
                  onClick={e => { e.stopPropagation(); toggle(r) }}><span/></button>) },
              { key: 'sev', label: 'Severity', width: '92px', render: r => <SevPill sev={r.severity}/> },
              { key: 'name', label: 'Rule', width: 'minmax(220px, 1.6fr)', render: r => <span className={r.enabled ? 't1' : 't3'}>{r.name}</span>, title: r => r.description },
              { key: 'type', label: 'Event type', width: '110px', render: r => <span className="mono t2">{r.event_type || 'any'}</span> },
              { key: 'f', label: 'Conditions', width: 'minmax(240px, 2fr)', render: r => <FilterBadges rule={r}/> },
              { key: 'x', label: '', width: '76px', render: r => <button className="ow-btn quiet" style={{ height: 24, color: 'var(--crit)' }} onClick={e => { e.stopPropagation(); del(r.id) }}><Trash2 size={13}/>Delete</button> },
            ]}/>
        </div>
      </div>
      <Drawer open={showCreate || !!editRule} onClose={() => { setShowCreate(false); setEditing(null) }} label={editRule ? 'Edit alert rule' : 'New alert rule'} width={620}>
        <div style={{ padding: 20, overflowY: 'auto' }}>
          <div style={{ fontSize: 17, fontWeight: 600, marginBottom: 14 }}>{editRule ? `Edit "${editRule.name}"` : 'New alert rule'}</div>
          {showCreate && <RuleForm onSave={create} onCancel={() => setShowCreate(false)} />}
          {editRule && <RuleForm key={editRule.id} initial={editRule} onSave={update} onCancel={() => setEditing(null)} />}
        </div>
      </Drawer>
    </div>
  )
}
