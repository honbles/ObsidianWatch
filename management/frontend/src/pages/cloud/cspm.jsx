import { useState } from 'react'
import { safeHref } from '../../utils/safeHref'
import { RefreshCw, Activity, Search, Shield, Zap, Database, Globe, Lock, Server, HardDrive, Key, Wifi, ExternalLink, ChevronDown, ChevronUp, Filter, Layers, FileText, Sparkles, X } from 'lucide-react'
import { format } from 'date-fns'
import api from '../../api/client'
import { CAT_META, CIS_MAPPING, SEV_BG, SEV_BORDER, SEV_COLOR, riskLabel, riskScore } from './shared.jsx'

// ── FindingCard — expandable, AI-explain, resource link ───────────────────────
export function FindingCard({ f, provider, projectId, subscriptionId }) {
  const [open, setOpen]         = useState(false)
  const [aiText, setAiText]     = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const sev = f.severity || 'info'
  const catMeta = CAT_META[f.category] || CAT_META.default
  const CatIcon = catMeta.icon
  const cis = CIS_MAPPING[f.resource_type] || CIS_MAPPING[f.category] || ''

  const explainWithAI = async (e) => {
    e.stopPropagation()
    if (aiText) { setAiText(null); return }
    setAiLoading(true)
    try {
      const cloudName = provider === 'azure' ? 'Azure' : 'GCP'
      const prompt = `You are a ${cloudName} cloud security engineer. Explain this ${cloudName} CSPM finding in plain English for a security analyst.

Finding: ${f.title}
Severity: ${f.severity}
Category: ${f.category}
Resource: ${f.resource} (${f.resource_type})
Description: ${f.description}
Remediation: ${f.remediation}
MITRE: ${f.mitre || 'N/A'}

Respond with a JSON object:
{
  "plain_english": "1-2 sentences explaining what this means in non-technical terms",
  "business_impact": "what could an attacker do if this is exploited",
  "urgency": "why this needs to be fixed now or can wait",
  "steps": ["step 1", "step 2", "step 3"]
}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', {
        prompt, finding: f
      })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      try { setAiText(JSON.parse(clean)) } catch { setAiText({ plain_english: clean }) }
    } catch (err) {
      setAiText({ plain_english: 'AI explanation unavailable — check your API key in Settings → AI.' })
    } finally { setAiLoading(false) }
  }

  // Build GCP console deep link
  const consoleLink = () => {
    // Azure Portal links
    if (provider === 'azure' && subscriptionId) {
      const base = 'https://portal.azure.com'
      const sub = subscriptionId
      switch (f.resource_type) {
        case 'nsg':                return `${base}/#view/Microsoft_Azure_Network/NetworkSecurityGroupMenuBlade/~/overview/id/${encodeURIComponent(`/subscriptions/${sub}/resourceGroups/default/providers/Microsoft.Network/networkSecurityGroups/${f.resource}`)}`
        case 'storage_account':    return `${base}/#view/Microsoft_Azure_Storage/StorageAccountMenuBlade/~/overview/storageAccountId/${encodeURIComponent(`/subscriptions/${sub}/providers/Microsoft.Storage/storageAccounts/${f.resource}`)}`
        case 'virtual_machine':    return `${base}/#view/Microsoft_Azure_Compute/VirtualMachineMenuBlade/~/overview/virtualMachineId/${encodeURIComponent(`/subscriptions/${sub}/providers/Microsoft.Compute/virtualMachines/${f.resource.split(' ')[0]}`)}`
        case 'sql_server':         return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers`
        case 'sql_database':       return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Sql%2Fservers%2Fdatabases`
        case 'key_vault':          return `${base}/#view/Microsoft_Azure_KeyVault/VaultMenuBlade/~/overview/vaultId/${encodeURIComponent(`/subscriptions/${sub}/providers/Microsoft.KeyVault/vaults/${f.resource}`)}`
        case 'aks_cluster':        return `${base}/#view/Microsoft_Azure_ContainerService/ContainerServiceMenuBlade/~/overview`
        case 'role_assignment':    return `${base}/#view/Microsoft_Azure_AD/IAMMenuBlade/~/RoleAssignments`
        case 'classic_admin':      return `${base}/#view/Microsoft_Azure_Billing/SubscriptionsBlade`
        case 'entra_tenant':       return `${base}/#view/Microsoft_AAD_IAM/ConditionalAccessBlade`
        case 'diagnostic_setting': return `${base}/#view/microsoft_azure_activitylog/ActivityLogBlade/~/DiagnosticSettings`
        case 'subscription':       return `${base}/#view/Microsoft_Azure_Policy/PolicyMenuBlade/~/Overview`
        case 'defender_plan':      return `${base}/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/Environment`
        case 'application_gateway':return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FapplicationGateways`
        case 'app_service':        return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites`
        case 'function_app':       return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Web%2Fsites`
        case 'container_registry': return `${base}/#view/HubsExtension/BrowseResource/resourceType/Microsoft.ContainerRegistry%2Fregistries`
        default:                   return `${base}/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/Environment`
      }
    }
    // GCP Console links
    if (!projectId) return null
    const base = 'https://console.cloud.google.com'
    const p = `?project=${projectId}`
    switch (f.resource_type) {
      case 'firewall_rule':        return `${base}/networking/firewalls/details/${f.resource}${p}`
      case 'storage_bucket':       return `${base}/storage/browser/${f.resource}${p}`
      case 'gcs_bucket':           return `${base}/storage/browser/${f.resource}${p}`
      case 'compute_instance':     return `${base}/compute/instancesDetail/zones/-/instances/${f.resource.split(' ')[0]}${p}`
      case 'cloud_sql':            return `${base}/sql/instances/${f.resource}/overview${p}`
      case 'iam_binding':          return `${base}/iam-admin/iam${p}`
      case 'org_iam_binding':      return `${base}/iam-admin/iam${p}`
      case 'service_account':      return `${base}/iam-admin/serviceaccounts${p}`
      case 'service_account_key':  return `${base}/iam-admin/serviceaccounts${p}`
      case 'kms_key':              return `${base}/security/kms/keyrings${p}`
      case 'vpc_subnet':           return `${base}/networking/subnetworks/list${p}`
      case 'dns_policy':           return `${base}/net-services/dns/policies${p}`
      case 'audit_config':         return `${base}/iam-admin/audit-log${p}`
      case 'cloud_run_service':    return `${base}/run/services/${f.resource}${p}`
      case 'artifact_registry':    return `${base}/artifacts${p}`
      case 'cloud_function':       return `${base}/functions/list${p}`
      case 'pubsub_topic':         return `${base}/cloudpubsub/topic/detail/${f.resource}${p}`
      case 'pubsub_subscription':  return `${base}/cloudpubsub/subscription/detail/${f.resource}${p}`
      case 'gke_cluster':          return `${base}/kubernetes/clusters/details/-/${f.resource.split('/')[0]}/${f.resource.split('/')[1] || f.resource}${p}`
      case 'gke_node_pool':        return `${base}/kubernetes/nodepool${p}`
      case 'org_policy':           return `${base}/iam-admin/orgpolicies/list${p}`
      case 'bigquery_dataset':     return `${base}/bigquery${p}`
      case 'secret':               return `${base}/security/secret-manager${p}`
      default:                     return `${base}/home/dashboard${p}`
    }
  }

  const link = consoleLink()

  return (
    <div style={{
      background: open ? SEV_BG[sev] : 'var(--surface)',
      border: `1px solid ${open ? SEV_BORDER[sev] : 'var(--border)'}`,
      borderLeft: `3px solid ${SEV_COLOR[sev] || '#94a3b8'}`,
      borderRadius: 10,
      transition: 'all 0.15s',
      overflow: 'hidden',
    }}>
      {/* Row — always visible */}
      <div onClick={() => setOpen(o => !o)}
        style={{ display:'flex', alignItems:'center', gap:10, padding:'12px 14px', cursor:'pointer' }}>
        <CatIcon size={14} color={catMeta.color} style={{ flexShrink:0 }}/>
        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontSize:12.5, fontWeight:600, color:'var(--text)', marginBottom:2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
            {f.title}
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:6, flexWrap:'wrap' }}>
            <span style={{ fontSize:9.5, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 5px', color:'var(--text3)', fontFamily:'DM Mono, monospace' }}>
              {f.resource_type}
            </span>
            <span style={{ fontSize:10, color:'var(--text3)', fontFamily:'DM Mono, monospace' }}>{f.resource}</span>
            {cis && <span style={{ fontSize:9, color:'var(--text3)', opacity:0.7 }}>{cis}</span>}
          </div>
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8, flexShrink:0 }}>
          {f.mitre && (
            <span style={{ fontSize:9, background:'rgba(0,194,224,0.1)', border:'1px solid rgba(0,194,224,0.2)', color:'var(--accent)', borderRadius:4, padding:'1px 5px', fontFamily:'DM Mono, monospace' }}>
              {f.mitre}
            </span>
          )}
          {open ? <ChevronUp size={13} color="var(--text3)"/> : <ChevronDown size={13} color="var(--text3)"/>}
        </div>
      </div>

      {/* Expanded body */}
      {open && (
        <div style={{ padding:'0 14px 14px', borderTop:'1px solid var(--border)', paddingTop:12 }}>
          {/* Description */}
          <p style={{ fontSize:12, color:'var(--text2)', lineHeight:1.6, marginBottom:10 }}>{f.description}</p>

          {/* Remediation */}
          <div style={{ background:'rgba(52,211,153,0.06)', border:'1px solid rgba(52,211,153,0.15)', borderRadius:7, padding:'8px 12px', marginBottom:10 }}>
            <div style={{ fontSize:10, fontWeight:700, color:'#34d399', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:4 }}>✓ Remediation</div>
            <p style={{ fontSize:11.5, color:'var(--text2)', lineHeight:1.6 }}>{f.remediation}</p>
          </div>

          {/* Action bar */}
          <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap' }}>
            <button onClick={explainWithAI} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                background: aiText ? 'rgba(139,92,246,0.15)' : 'rgba(0,194,224,0.1)',
                border: `1px solid ${aiText ? 'rgba(139,92,246,0.3)' : 'rgba(0,194,224,0.25)'}`,
                color: aiText ? '#a78bfa' : 'var(--accent)', borderRadius:6, cursor:'pointer', fontFamily:'inherit' }}>
              <Sparkles size={11}/>{aiLoading ? 'Explaining…' : aiText ? 'Hide AI Explanation' : 'Explain with AI'}
            </button>
            {link && (
              <a href={safeHref(link)} target="_blank" rel="noopener noreferrer"
                style={{ display:'flex', alignItems:'center', gap:5, fontSize:11, padding:'5px 10px',
                  background:'var(--surface2)', border:'1px solid var(--border)',
                  color:'var(--text2)', borderRadius:6, textDecoration:'none' }}>
                <ExternalLink size={11}/>{provider === 'azure' ? 'Open in Azure Portal' : 'Open in GCP Console'}
              </a>
            )}
            <span style={{ fontSize:10, color:'var(--text3)', marginLeft:'auto' }}>
              Found: {f.scanned_at ? format(new Date(f.scanned_at), 'MMM d, yyyy HH:mm') : '—'}
            </span>
          </div>

          {/* AI Explanation */}
          {aiText && (
            <div style={{ marginTop:10, background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:8, padding:'12px 14px' }}>
              <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>
                ✦ AI Security Analyst
              </div>
              {aiText.plain_english && (
                <p style={{ fontSize:12, color:'var(--text)', lineHeight:1.6, marginBottom:8 }}>{aiText.plain_english}</p>
              )}
              {aiText.business_impact && (
                <div style={{ marginBottom:6 }}>
                  <span style={{ fontSize:10, color:'#f87171', fontWeight:600 }}>Business Impact: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.business_impact}</span>
                </div>
              )}
              {aiText.urgency && (
                <div style={{ marginBottom:8 }}>
                  <span style={{ fontSize:10, color:'#fbbf24', fontWeight:600 }}>Urgency: </span>
                  <span style={{ fontSize:11, color:'var(--text2)' }}>{aiText.urgency}</span>
                </div>
              )}
              {aiText.steps?.length > 0 && (
                <div>
                  <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:4 }}>Steps:</div>
                  {aiText.steps.map((s,i) => (
                    <div key={i} style={{ display:'flex', gap:6, marginBottom:3 }}>
                      <span style={{ fontSize:10, color:'var(--accent)', fontFamily:'DM Mono, monospace', flexShrink:0 }}>{i+1}.</span>
                      <span style={{ fontSize:11, color:'var(--text2)', lineHeight:1.5 }}>{s}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── RiskScoreGauge ─────────────────────────────────────────────────────────────
export function RiskScoreGauge({ score }) {
  const rl = riskLabel(score)
  const r = 40, cx = 52, cy = 52
  const circumference = 2 * Math.PI * r
  const dash = circumference * (score / 100)
  return (
    <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
      <svg width={104} height={104} viewBox="0 0 104 104">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth={8}/>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={rl.color} strokeWidth={8}
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          style={{ transformOrigin:'center', transform:'rotate(-90deg)', transition:'stroke-dasharray 0.6s ease' }}/>
        <text x={cx} y={cy-2} textAnchor="middle" style={{ fill:'var(--text)', fontSize:18, fontWeight:700, fontFamily:'DM Mono, monospace' }}>{score}</text>
        <text x={cx} y={cy+13} textAnchor="middle" style={{ fill:'var(--text3)', fontSize:9 }}>/100</text>
      </svg>
      <span style={{ fontSize:11, fontWeight:600, color:rl.color }}>{rl.label}</span>
    </div>
  )
}

// ── ComplianceBadges ───────────────────────────────────────────────────────────
export function ComplianceBadges({ findings }) {
  const frameworks = [
    { name: 'CIS GCP 1.3', categories: ['iam','network','storage','compute','sql','logging','kms'] },
    { name: 'NIST CSF',    categories: ['iam','network','logging','kms'] },
    { name: 'ISO 27001',   categories: ['iam','storage','logging'] },
    { name: 'SOC 2',       categories: ['logging','iam','network'] },
  ]
  const catCount = {}
  for (const f of (findings||[])) {
    if (f.severity === 'critical' || f.severity === 'high') {
      catCount[f.category] = (catCount[f.category]||0) + 1
    }
  }
  return (
    <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
      {frameworks.map(fw => {
        const issues = fw.categories.reduce((s,c) => s+(catCount[c]||0), 0)
        const status = issues === 0 ? 'pass' : issues <= 3 ? 'warn' : 'fail'
        const colors = { pass: ['#34d399','rgba(52,211,153,0.1)','rgba(52,211,153,0.2)'], warn: ['#fbbf24','rgba(251,191,36,0.1)','rgba(251,191,36,0.2)'], fail: ['#f87171','rgba(248,113,113,0.1)','rgba(248,113,113,0.2)'] }
        const [c, bg, border] = colors[status]
        return (
          <div key={fw.name} style={{ fontSize:10.5, padding:'4px 10px', borderRadius:6, background:bg, border:`1px solid ${border}`, color:c, fontWeight:600 }}>
            {status === 'pass' ? '✓' : status === 'warn' ? '⚠' : '✕'} {fw.name}
            {issues > 0 && <span style={{ marginLeft:4, opacity:0.8 }}>({issues})</span>}
          </div>
        )
      })}
    </div>
  )
}

// ── AssetInventory ─────────────────────────────────────────────────────────────
export function AssetInventory({ findings }) {
  const inventory = {}
  for (const f of (findings||[])) {
    const t = f.resource_type || 'other'
    if (!inventory[t]) inventory[t] = { resources: new Set(), issues: 0 }
    inventory[t].resources.add(f.resource)
    inventory[t].issues++
  }
  const typeLabels = {
    // GCP
    firewall_rule: { icon: Wifi, label: 'Firewall Rules' },
    storage_bucket: { icon: HardDrive, label: 'Storage Buckets' },
    gcs_bucket: { icon: HardDrive, label: 'Storage Buckets' },
    compute_instance: { icon: Server, label: 'Compute Instances' },
    cloud_sql: { icon: Database, label: 'Cloud SQL' },
    iam_binding: { icon: Lock, label: 'IAM Bindings' },
    org_iam_binding: { icon: Lock, label: 'Org IAM Bindings' },
    service_account: { icon: Key, label: 'Service Accounts' },
    service_account_key: { icon: Key, label: 'SA Keys' },
    kms_key: { icon: Key, label: 'KMS Keys' },
    vpc_subnet: { icon: Layers, label: 'VPC Subnets' },
    dns_policy: { icon: Globe, label: 'DNS Policies' },
    audit_config: { icon: FileText, label: 'Audit Configs' },
    gke_cluster: { icon: Server, label: 'GKE Clusters' },
    gke_node_pool: { icon: Server, label: 'GKE Node Pools' },
    bigquery_dataset: { icon: Database, label: 'BigQuery Datasets' },
    cloud_run_service: { icon: Zap, label: 'Cloud Run' },
    cloud_function: { icon: Zap, label: 'Cloud Functions' },
    artifact_registry: { icon: HardDrive, label: 'Artifact Registry' },
    pubsub_topic: { icon: Activity, label: 'Pub/Sub Topics' },
    // Azure
    nsg: { icon: Wifi, label: 'Network Security Groups' },
    storage_account: { icon: HardDrive, label: 'Storage Accounts' },
    virtual_machine: { icon: Server, label: 'Virtual Machines' },
    sql_server: { icon: Database, label: 'SQL Servers' },
    sql_database: { icon: Database, label: 'SQL Databases' },
    key_vault: { icon: Key, label: 'Key Vaults' },
    aks_cluster: { icon: Server, label: 'AKS Clusters' },
    role_assignment: { icon: Lock, label: 'Role Assignments' },
    classic_admin: { icon: Lock, label: 'Classic Admins' },
    entra_tenant: { icon: Lock, label: 'Entra ID' },
    diagnostic_setting: { icon: FileText, label: 'Diagnostic Settings' },
    defender_plan: { icon: Shield, label: 'Defender Plans' },
    application_gateway: { icon: Globe, label: 'App Gateways' },
    app_service: { icon: Zap, label: 'App Services' },
    function_app: { icon: Zap, label: 'Function Apps' },
    container_registry: { icon: HardDrive, label: 'Container Registries' },
  }
  return (
    <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(150px,1fr))', gap:8 }}>
      {Object.entries(inventory).map(([type, data]) => {
        const meta = typeLabels[type] || { icon: Shield, label: type }
        const Icon = meta.icon
        return (
          <div key={type} style={{ background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:'10px 12px' }}>
            <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
              <Icon size={12} color="var(--text3)"/>
              <span style={{ fontSize:10, color:'var(--text3)', fontWeight:600 }}>{meta.label}</span>
            </div>
            <div style={{ fontSize:18, fontWeight:700, color:'var(--text)', fontFamily:'DM Mono, monospace' }}>{data.resources.size}</div>
            <div style={{ fontSize:10, color: data.issues > 0 ? '#f87171' : '#34d399' }}>
              {data.issues} issue{data.issues !== 1 ? 's' : ''}
            </div>
          </div>
        )
      })}
      {Object.keys(inventory).length === 0 && (
        <div style={{ gridColumn:'1/-1', textAlign:'center', color:'var(--text3)', fontSize:12, padding:20 }}>
          No assets found — run a scan first
        </div>
      )}
    </div>
  )
}

// ── NetworkExposure ────────────────────────────────────────────────────────────
export function NetworkExposure({ findings }) {
  const exposed = (findings||[]).filter(f => f.category === 'network' || f.resource_type === 'compute_instance')
  const publicResources = {}
  for (const f of exposed) {
    if (!publicResources[f.resource]) publicResources[f.resource] = []
    publicResources[f.resource].push(f)
  }
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
      {Object.entries(publicResources).slice(0,8).map(([res, issues]) => (
        <div key={res} style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 10px',
          background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:7 }}>
          <Globe size={12} color={issues.some(i => i.severity === 'critical') ? '#f87171' : '#fb923c'}/>
          <span style={{ flex:1, fontSize:11, color:'var(--text2)', fontFamily:'DM Mono, monospace' }}>{res}</span>
          <div style={{ display:'flex', gap:4 }}>
            {issues.map((issue,i) => (
              <span key={i} style={{ fontSize:9, padding:'1px 5px', borderRadius:4,
                background: SEV_BG[issue.severity], border:`1px solid ${SEV_BORDER[issue.severity]}`,
                color: SEV_COLOR[issue.severity] }}>
                {issue.severity}
              </span>
            ))}
          </div>
        </div>
      ))}
      {Object.keys(publicResources).length === 0 && (
        <div style={{ textAlign:'center', color:'#34d399', fontSize:12, padding:16 }}>
          ✓ No publicly exposed resources detected
        </div>
      )}
    </div>
  )
}

// ── IdentityRisk ───────────────────────────────────────────────────────────────
export function IdentityRisk({ findings }) {
  const iamFindings = (findings||[]).filter(f => f.category === 'iam')
  const isAzure = iamFindings.some(f => ['role_assignment','classic_admin','entra_tenant'].includes(f.resource_type))

  const groups = isAzure ? {
    'Public Access / Guest Users':        iamFindings.filter(f => f.title?.toLowerCase().includes('guest') || f.title?.toLowerCase().includes('public')),
    'Owner / Contributor Assignments':    iamFindings.filter(f => f.title?.includes('Owner') || f.title?.includes('Contributor')),
    'Classic Administrator Accounts':     iamFindings.filter(f => f.resource_type === 'classic_admin'),
    'No Conditional Access / MFA':        iamFindings.filter(f => f.resource_type === 'entra_tenant'),
    'Service Principal Over-Privileged':  iamFindings.filter(f => f.resource_type === 'role_assignment' && f.title?.includes('service principal')),
    'Custom Roles with Wildcard':         iamFindings.filter(f => f.title?.toLowerCase().includes('custom') && f.title?.toLowerCase().includes('role')),
    'Other IAM Issues':                   iamFindings.filter(f => {
      const covered = ['guest','public','Owner','Contributor','classic_admin','entra_tenant','service principal','custom']
      return !covered.some(k => (f.title||'').toLowerCase().includes(k.toLowerCase()) || f.resource_type === 'classic_admin' || f.resource_type === 'entra_tenant')
    }),
  } : {
    'Public Access (allUsers)':           iamFindings.filter(f => f.title?.includes('allUsers') || f.title?.includes('public')),
    'Primitive Roles (Owner/Editor)':     iamFindings.filter(f => f.title?.includes('Primitive') || f.title?.includes('Owner') || f.title?.includes('Editor')),
    'Admin Roles on External Identities': iamFindings.filter(f => f.title?.includes('Admin') && f.title?.includes('external')),
    'Old Service Account Keys':           iamFindings.filter(f => f.resource_type === 'service_account_key'),
    'Default SA with Broad Scope':        iamFindings.filter(f => f.title?.includes('Default service account') || f.title?.includes('cloud-platform scope')),
    'Cross-Project SA Access':            iamFindings.filter(f => f.title?.includes('Cross-project')),
    'Other IAM Issues':                   iamFindings.filter(f => {
      const covered = ['allUsers','public','Primitive','Owner','Editor','Admin','service_account_key','Default service','cloud-platform','Cross-project']
      return !covered.some(t => f.title?.includes(t))
    }),
  }
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
      {Object.entries(groups).map(([label, items]) => {
        if (!items.length) return null
        const worst = items.reduce((a,b) => {
          const order = ['critical','high','medium','low','info']
          return order.indexOf(a.severity) <= order.indexOf(b.severity) ? a : b
        }, items[0])
        return (
          <div key={label} style={{ display:'flex', alignItems:'center', justifyContent:'space-between',
            padding:'8px 10px', background:'var(--surface2)', border:`1px solid ${SEV_BORDER[worst.severity]}`,
            borderRadius:7 }}>
            <div style={{ display:'flex', alignItems:'center', gap:7 }}>
              <Lock size={11} color={SEV_COLOR[worst.severity]}/>
              <span style={{ fontSize:11.5, color:'var(--text)' }}>{label}</span>
            </div>
            <span style={{ fontSize:11, fontWeight:700, color: SEV_COLOR[worst.severity],
              background: SEV_BG[worst.severity], border:`1px solid ${SEV_BORDER[worst.severity]}`,
              borderRadius:4, padding:'1px 7px' }}>{items.length}</span>
          </div>
        )
      })}
      {!iamFindings.length && (
        <div style={{ textAlign:'center', color:'#34d399', fontSize:12, padding:16 }}>
          ✓ No IAM issues detected
        </div>
      )}
    </div>
  )
}

// ── CSPM Dashboard ─────────────────────────────────────────────────────────────
export function CSPMDashboard({ conn, cspm, loading, onRunScan, scanning }) {
  const [section, setSection] = useState('findings') // findings|assets|network|identity|compliance
  const [sevFilter, setSevFilter] = useState('all')
  const [showErrors, setShowErrors] = useState(false)
  const [catFilter, setCatFilter] = useState('all')
  const [search, setSearch]     = useState('')
  const [aiSummary, setAiSummary] = useState(null)
  const [aiLoading, setAiLoading] = useState(false)

  const score = riskScore(cspm)
  const rl    = riskLabel(score)

  const allFindings = cspm?.findings || []

  const filteredFindings = allFindings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false
    if (catFilter !== 'all' && f.category !== catFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (f.title+f.description+f.resource+f.category).toLowerCase().includes(q)
    }
    return true
  })

  const categories = [...new Set(allFindings.map(f => f.category))].sort()

  const runAISummary = async () => {
    if (!cspm || aiLoading) return
    setAiLoading(true)
    try {
      const compact = {
        project: cspm.project_id,
        critical: cspm.critical, high: cspm.high, medium: cspm.medium, low: cspm.low, passed: cspm.passed,
        top_findings: allFindings
          .filter(f => f.severity === 'critical' || f.severity === 'high')
          .slice(0,15)
          .map(f => ({ sev: f.severity, cat: f.category, title: f.title, resource: f.resource }))
      }
      const prompt = `You are a GCP cloud security architect. Analyse this CSPM scan and give a concise executive summary.

Return ONLY this JSON (no markdown):
{
  "executive_summary": "2-3 sentences for a CISO — overall posture and top concerns",
  "top_risks": ["risk 1", "risk 2", "risk 3"],
  "immediate_actions": ["action 1 with specific GCP console path", "action 2", "action 3"],
  "compliance_notes": "brief note on CIS GCP benchmark compliance status",
  "positive_findings": ["what is configured correctly"]
}

CSPM Data:
${JSON.stringify(compact)}`
      const { data } = await api.post('/api/v1/cloud-connectors/ai-explain', { prompt })
      const text = data.content?.find(b => b.type === 'text')?.text || data.text || ''
      const clean = text.replace(/\x60{3}json\n?|\x60{3}/g, '').trim()
      try { setAiSummary(JSON.parse(clean)) } catch { setAiSummary({ executive_summary: clean }) }
    } catch { setAiSummary({ executive_summary: 'AI summary unavailable — configure an AI key in Settings.' }) }
    finally { setAiLoading(false) }
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100%', overflow:'hidden' }}>

      {/* ── Top action bar ── */}
      <div style={{ flexShrink:0, padding:'14px 20px', borderBottom:'1px solid var(--border)',
        background:'var(--surface)', display:'flex', alignItems:'center', justifyContent:'space-between', gap:12 }}>
        <div>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)' }}>Cloud Security Posture — {cspm?.project_id || conn.account_id}</div>
          {cspm && <div style={{ fontSize:10.5, color:'var(--text3)', marginTop:2 }}>
            Last scan: {cspm.scanned_at ? format(new Date(cspm.scanned_at), 'MMM d, yyyy HH:mm') : '—'} · {cspm.scan_duration}
            {cspm.scc_enabled && <span style={{ color:'#34d399', marginLeft:8 }}>✓ SCC connected ({cspm.scc_findings||0} findings)</span>}
            {cspm.errors?.length > 0 && (
              <button onClick={() => setShowErrors(e => !e)}
                style={{ marginLeft:8, background:'rgba(251,146,60,0.1)', border:'1px solid rgba(251,146,60,0.25)',
                  color:'#fb923c', borderRadius:4, padding:'1px 7px', fontSize:10.5, cursor:'pointer', fontFamily:'inherit' }}>
                ⚠ {cspm.errors.length} check failed — click to see
              </button>
            )}
          </div>}
        </div>
        <div style={{ display:'flex', gap:8, alignItems:'center' }}>
          {cspm && (
            <button onClick={runAISummary} disabled={aiLoading}
              style={{ display:'flex', alignItems:'center', gap:5, fontSize:11.5, padding:'7px 13px',
                background:'rgba(139,92,246,0.1)', border:'1px solid rgba(139,92,246,0.25)',
                color:'#a78bfa', borderRadius:7, cursor:aiLoading?'wait':'pointer', fontFamily:'inherit', fontWeight:600 }}>
              <Sparkles size={12}/>{aiLoading ? 'Analysing…' : 'AI Summary'}
            </button>
          )}
          <button onClick={onRunScan} disabled={scanning}
            style={{ display:'flex', alignItems:'center', gap:6, fontSize:11.5, padding:'7px 14px',
              background: scanning ? 'var(--surface2)' : 'var(--accent)',
              color: scanning ? 'var(--text2)' : '#000',
              border:'none', borderRadius:7, cursor: scanning?'wait':'pointer', fontFamily:'inherit', fontWeight:700 }}>
            <RefreshCw size={12} style={scanning ? { animation:'spin 0.8s linear infinite' } : {}}/>
            {scanning ? 'Scanning…' : 'Run Scan'}
          </button>
        </div>
      </div>

      <div style={{ flex:1, overflow:'auto', padding:'16px 20px' }}>

        {/* ── Scan Errors Panel ── */}
        {showErrors && cspm?.errors?.length > 0 && (
          <div style={{ marginBottom:16, background:'rgba(251,146,60,0.06)', border:'1px solid rgba(251,146,60,0.25)', borderRadius:10, overflow:'hidden' }}>
            <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'10px 14px', borderBottom:'1px solid rgba(251,146,60,0.2)' }}>
              <div style={{ display:'flex', alignItems:'center', gap:7 }}>
                <span style={{ fontSize:12, fontWeight:700, color:'#fb923c' }}>⚠ Scan Check Failures</span>
                <span style={{ fontSize:10.5, color:'var(--text3)' }}>These checks could not run — usually missing IAM role or API not enabled</span>
              </div>
              <button onClick={() => setShowErrors(false)}
                style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', fontSize:16, padding:'0 4px', fontFamily:'inherit' }}>×</button>
            </div>
            {cspm.errors.map((err, i) => {
              const checkName = err.split(':')[0]
              const errMsg = err.slice(checkName.length + 1).trim()
              const is403 = errMsg.includes('403') || errMsg.includes('permission denied')
              const is404 = errMsg.includes('404') || errMsg.includes('not found')
  const requiredRoles = {
    kms:              'roles/cloudkms.viewer  +  enable cloudkms.googleapis.com API',
    vpc_flow_logs:    'roles/compute.networkViewer',
    dns_logging:      'roles/dns.reader  +  enable dns.googleapis.com API',
    sql:              'roles/cloudsql.viewer',
    storage:          'roles/storage.objectViewer',
    service_accounts: 'roles/iam.serviceAccountViewer',
    iam:              'roles/iam.securityReviewer',
    compute:          'roles/compute.viewer',
    audit_logging:    'roles/iam.securityReviewer',
    firewall:         'roles/compute.viewer',
    scc:              'roles/securitycenter.findingsViewer  +  enable securitycenter.googleapis.com API',
    gke:              'roles/container.viewer  +  enable container.googleapis.com API',
    bigquery:         'roles/bigquery.metadataViewer  +  enable bigquery.googleapis.com API',
    secret_manager:   'roles/secretmanager.viewer  +  enable secretmanager.googleapis.com API',
    org_policies:     'roles/orgpolicy.policyViewer',
    cloud_run:        'roles/run.viewer  +  enable run.googleapis.com API',
    artifact_registry:'roles/artifactregistry.reader  +  enable artifactregistry.googleapis.com API',
    cloud_functions:  'roles/cloudfunctions.viewer  +  enable cloudfunctions.googleapis.com API',
    pubsub:           'roles/pubsub.viewer  +  enable pubsub.googleapis.com API',
    org_iam:          'roles/resourcemanager.organizationViewer  (auto-granted when SCC is enabled)',
  }
              return (
                <div key={i} style={{ padding:'10px 14px', borderBottom: i < cspm.errors.length-1 ? '1px solid rgba(251,146,60,0.1)' : 'none' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                    <code style={{ fontSize:11, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:4, padding:'1px 6px', color:'#fb923c', fontFamily:'DM Mono, monospace' }}>{checkName}</code>
                    <span style={{ fontSize:10.5, color: is403 ? '#f87171' : is404 ? '#38bdf8' : '#fb923c' }}>
                      {is403 ? '403 Permission Denied' : is404 ? '404 Not Found / API disabled' : 'Error'}
                    </span>
                  </div>
                  <div style={{ fontSize:11, color:'var(--text3)', fontFamily:'DM Mono, monospace', marginBottom:6, wordBreak:'break-all' }}>{errMsg.slice(0, 200)}</div>
                  {requiredRoles[checkName] && (
                    <div style={{ display:'flex', alignItems:'center', gap:5, fontSize:10.5 }}>
                      <span style={{ color:'#34d399', fontWeight:600 }}>Fix:</span>
                      <code style={{ color:'var(--text2)', fontFamily:'DM Mono, monospace', background:'var(--surface2)', padding:'1px 6px', borderRadius:4 }}>
                        {requiredRoles[checkName]}
                      </code>
                    </div>
                  )}
                </div>
              )
            })}
            <div style={{ padding:'10px 14px', background:'rgba(0,0,0,0.2)', fontSize:11, color:'var(--text3)' }}>
              The service account needs <strong style={{ color:'var(--text2)' }}>roles/viewer</strong> or <strong style={{ color:'var(--text2)' }}>roles/security-reviewer</strong> at minimum.
              Checks that fail are skipped — other findings are still shown.
            </div>
          </div>
        )}

        {loading && (
          <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:200, color:'var(--text3)', gap:8 }}>
            <RefreshCw size={16} style={{ animation:'spin 0.8s linear infinite' }}/> Loading last scan…
          </div>
        )}

        {!loading && !cspm && !scanning && (
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:300, gap:12 }}>
            <Shield size={48} color="var(--border)" strokeWidth={1}/>
            <div style={{ fontSize:15, fontWeight:600, color:'var(--text2)' }}>No scan results yet</div>
            <div style={{ fontSize:12, color:'var(--text3)' }}>Click "Run Scan" to check your cloud security posture</div>
          </div>
        )}

        {cspm && !loading && (<>

          {/* ── Summary row ── */}
          <div style={{ display:'grid', gridTemplateColumns:'auto 1fr auto', gap:16, marginBottom:16, alignItems:'start' }}>

            {/* Risk score */}
            <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px 20px', display:'flex', flexDirection:'column', alignItems:'center', gap:8 }}>
              <RiskScoreGauge score={score}/>
              <div style={{ fontSize:10, color:'var(--text3)', textAlign:'center' }}>Risk Score</div>
            </div>

            {/* KPIs */}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:8 }}>
              {[
                { label:'Critical', value: cspm.critical, color:'#f87171' },
                { label:'High',     value: cspm.high,     color:'#fb923c' },
                { label:'Medium',   value: cspm.medium,   color:'#fbbf24' },
                { label:'Low',      value: cspm.low,      color:'#38bdf8' },
                { label:'Passed',   value: cspm.passed,   color:'#34d399' },
                { label:'Total',    value: cspm.total_findings, color:'var(--text2)' },
              ].map(k => (
                <div key={k.label} style={{ background:'var(--surface)', border:'1px solid var(--border)',
                  borderRadius:8, padding:'10px 12px', borderTop:`2px solid ${k.color}` }}>
                  <div style={{ fontSize:10, color:'var(--text3)', marginBottom:4, fontWeight:600, textTransform:'uppercase', letterSpacing:'0.06em' }}>{k.label}</div>
                  <div style={{ fontSize:22, fontWeight:700, color:k.color, fontFamily:'DM Mono, monospace' }}>{k.value||0}</div>
                </div>
              ))}
            </div>

            {/* Compliance + SCC status */}
            <div style={{ background:'var(--surface)', border:'1px solid var(--border)', borderRadius:12, padding:'16px', minWidth:220 }}>
              <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:10 }}>Compliance Status</div>
              <ComplianceBadges findings={allFindings}/>
              <div style={{ marginTop:12, paddingTop:10, borderTop:'1px solid var(--border)' }}>
                <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:6 }}>Security Command Center</div>
                {cspm.scc_enabled ? (
                  <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                    <span style={{ width:7, height:7, borderRadius:'50%', background:'#34d399', display:'inline-block' }}/>
                    <span style={{ fontSize:11, color:'#34d399', fontWeight:600 }}>Connected</span>
                    <span style={{ fontSize:10.5, color:'var(--text3)' }}>· {cspm.scc_findings||0} findings</span>
                  </div>
                ) : (
                  <div>
                    <div style={{ display:'flex', alignItems:'center', gap:6, marginBottom:4 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:'var(--text3)', display:'inline-block' }}/>
                      <span style={{ fontSize:11, color:'var(--text3)' }}>Not connected</span>
                    </div>
                    <div style={{ fontSize:10, color:'var(--text3)', lineHeight:1.5 }}>
                      Enable for 500+ GCP built-in checks, threat detection, and compliance posture.
                    </div>
                    <a href="https://console.cloud.google.com/security/command-center" target="_blank" rel="noopener noreferrer"
                      style={{ display:'inline-flex', alignItems:'center', gap:4, marginTop:6, fontSize:10.5,
                        color:'var(--accent)', textDecoration:'none' }}>
                      Enable SCC →
                    </a>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── AI Summary (if loaded) ── */}
          {aiSummary && (
            <div style={{ background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.2)', borderRadius:10, padding:'14px 16px', marginBottom:16 }}>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:8 }}>
                <div style={{ fontSize:10, fontWeight:700, color:'#a78bfa', textTransform:'uppercase', letterSpacing:'0.06em' }}>✦ AI Executive Summary</div>
                <button onClick={() => setAiSummary(null)} style={{ background:'none', border:'none', color:'var(--text3)', cursor:'pointer', padding:0 }}>
                  <X size={13}/>
                </button>
              </div>
              {aiSummary.executive_summary && (
                <p style={{ fontSize:12.5, color:'var(--text)', lineHeight:1.7, marginBottom:10 }}>{aiSummary.executive_summary}</p>
              )}
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
                {aiSummary.top_risks?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#f87171', fontWeight:600, marginBottom:5 }}>⚠ Top Risks</div>
                    {aiSummary.top_risks.map((r,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {r}</div>)}
                  </div>
                )}
                {aiSummary.immediate_actions?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#34d399', fontWeight:600, marginBottom:5 }}>✓ Immediate Actions</div>
                    {aiSummary.immediate_actions.map((a,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {a}</div>)}
                  </div>
                )}
                {aiSummary.positive_findings?.length > 0 && (
                  <div>
                    <div style={{ fontSize:10, color:'#38bdf8', fontWeight:600, marginBottom:5 }}>✦ Doing Well</div>
                    {aiSummary.positive_findings.map((p,i) => <div key={i} style={{ fontSize:11, color:'var(--text2)', marginBottom:3, lineHeight:1.4 }}>• {p}</div>)}
                  </div>
                )}
              </div>
              {aiSummary.compliance_notes && (
                <div style={{ marginTop:8, fontSize:11, color:'var(--text3)', fontStyle:'italic', borderTop:'1px solid rgba(139,92,246,0.15)', paddingTop:8 }}>
                  {aiSummary.compliance_notes}
                </div>
              )}
            </div>
          )}

          {/* ── Section nav ── */}
          <div style={{ display:'flex', gap:4, marginBottom:14, borderBottom:'1px solid var(--border)', paddingBottom:0 }}>
            {[
              { id:'findings',   label:'Findings',         icon: Shield,    count: allFindings.length },
              { id:'assets',     label:'Asset Inventory',  icon: Layers,    count: null },
              { id:'network',    label:'Network Exposure', icon: Wifi,      count: allFindings.filter(f=>f.category==='network').length },
              { id:'identity',   label:'Identity & Access',icon: Lock,      count: allFindings.filter(f=>f.category==='iam').length },
            ].map(({ id, label, icon: Icon, count }) => (
              <button key={id} onClick={() => setSection(id)}
                style={{ display:'flex', alignItems:'center', gap:5, padding:'7px 13px', fontSize:11.5,
                  background: section===id ? 'rgba(0,194,224,0.1)' : 'transparent',
                  color: section===id ? 'var(--accent)' : 'var(--text3)',
                  border:'none', borderBottom: section===id ? '2px solid var(--accent)' : '2px solid transparent',
                  cursor:'pointer', fontFamily:'inherit', fontWeight: section===id ? 600 : 400,
                  marginBottom:-1 }}>
                <Icon size={12}/>
                {label}
                {count !== null && count > 0 && (
                  <span style={{ fontSize:9.5, background:'rgba(0,194,224,0.15)', color:'var(--accent)',
                    borderRadius:10, padding:'0 5px', minWidth:16, textAlign:'center' }}>{count}</span>
                )}
              </button>
            ))}
          </div>

          {/* ── Findings section ── */}
          {section === 'findings' && (
            <div>
              {/* Filter bar */}
              <div style={{ display:'flex', gap:8, marginBottom:12, flexWrap:'wrap', alignItems:'center' }}>
                <div style={{ position:'relative', flex:1, minWidth:200 }}>
                  <Search size={11} style={{ position:'absolute', left:9, top:'50%', transform:'translateY(-50%)', color:'var(--text3)' }}/>
                  <input value={search} onChange={e => setSearch(e.target.value)}
                    placeholder="Search findings…"
                    style={{ width:'100%', background:'var(--surface)', border:'1px solid var(--border)',
                      borderRadius:7, paddingLeft:28, paddingRight:10, paddingTop:6, paddingBottom:6,
                      fontSize:11.5, color:'var(--text)', outline:'none', fontFamily:'inherit', boxSizing:'border-box' }}/>
                </div>
                <div style={{ display:'flex', gap:4 }}>
                  {['all','critical','high','medium','low'].map(s => (
                    <button key={s} onClick={() => setSevFilter(s)}
                      style={{ fontSize:10.5, padding:'4px 10px', borderRadius:6,
                        background: sevFilter===s ? (SEV_BG[s]||'rgba(0,194,224,0.1)') : 'var(--surface)',
                        border: `1px solid ${sevFilter===s ? (SEV_BORDER[s]||'rgba(0,194,224,0.3)') : 'var(--border)'}`,
                        color: sevFilter===s ? (SEV_COLOR[s]||'var(--accent)') : 'var(--text3)',
                        cursor:'pointer', fontFamily:'inherit', fontWeight: sevFilter===s ? 600 : 400 }}>
                      {s.charAt(0).toUpperCase()+s.slice(1)}
                    </button>
                  ))}
                </div>
                {categories.length > 0 && (
                  <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
                    style={{ fontSize:11, padding:'5px 8px', background:'var(--surface)', border:'1px solid var(--border)',
                      borderRadius:6, color:'var(--text2)', outline:'none', fontFamily:'inherit' }}>
                    <option value="all">All categories</option>
                    {categories.map(c => <option key={c} value={c}>{CAT_META[c]?.label || c}</option>)}
                  </select>
                )}
                <span style={{ fontSize:10.5, color:'var(--text3)', marginLeft:'auto' }}>
                  {filteredFindings.length} of {allFindings.length} findings
                </span>
              </div>

              {/* Findings grouped by severity */}
              {['critical','high','medium','low'].map(sev => {
                const group = filteredFindings.filter(f => f.severity === sev)
                if (!group.length) return null
                return (
                  <div key={sev} style={{ marginBottom:16 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
                      <span style={{ width:7, height:7, borderRadius:'50%', background:SEV_COLOR[sev], display:'inline-block', flexShrink:0 }}/>
                      <span style={{ fontSize:11.5, fontWeight:700, color:SEV_COLOR[sev], textTransform:'uppercase', letterSpacing:'0.07em' }}>
                        {sev} — {group.length} finding{group.length!==1?'s':''}
                      </span>
                    </div>
                    <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                      {group.map((f,i) => (
                        <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>
                      ))}
                    </div>
                  </div>
                )
              })}

              {filteredFindings.length === 0 && (
                <div style={{ textAlign:'center', padding:40, color:search||sevFilter!=='all' ? 'var(--text3)' : '#34d399', fontSize:13 }}>
                  {search||sevFilter!=='all' ? 'No findings match your filter' : '✓ No findings — your cloud posture looks clean!'}
                </div>
              )}
            </div>
          )}

          {/* ── Asset Inventory section ── */}
          {section === 'assets' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                Resources detected across your GCP project with outstanding security findings.
              </div>
              <AssetInventory findings={allFindings}/>
            </div>
          )}

          {/* ── Network Exposure section ── */}
          {section === 'network' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                Resources with network-level exposure — open firewall rules, public IPs, publicly accessible services.
              </div>
              <NetworkExposure findings={allFindings}/>
              <div style={{ marginTop:16 }}>
                <div style={{ fontSize:11, fontWeight:600, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>All Network Findings</div>
                <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                  {allFindings.filter(f => f.category === 'network').map((f,i) => (
                    <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── Identity & Access section ── */}
          {section === 'identity' && (
            <div>
              <div style={{ fontSize:12, color:'var(--text3)', marginBottom:12 }}>
                IAM misconfigurations, excessive permissions, service account key risks.
              </div>
              <IdentityRisk findings={allFindings}/>
              <div style={{ marginTop:16 }}>
                <div style={{ fontSize:11, fontWeight:600, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.06em', marginBottom:8 }}>All IAM Findings</div>
                <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                  {allFindings.filter(f => f.category === 'iam').map((f,i) => (
                    <FindingCard key={f.id||i} f={f} provider={conn.provider} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>
                  ))}
                </div>
              </div>
            </div>
          )}

        </>)}
      </div>
    </div>
  )
}

