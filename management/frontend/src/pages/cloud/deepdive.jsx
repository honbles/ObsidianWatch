import { useState } from 'react'
import { Search, Lock, Server, HardDrive, Key, Wifi, ExternalLink } from 'lucide-react'
import { FindingCard } from './cspm.jsx'

// ── Panel: Deep Dive ──────────────────────────────────────────────────────────
export function PanelDeepDive({ cspm, conn }) {
  const [section, setSection] = useState('iam')
  const all = cspm?.findings || []

  const iamFindings = all.filter(f => f.category === 'iam')
  const storageFindings = all.filter(f =>
    f.category === 'storage' ||
    ['gcs_bucket','bigquery_dataset','secret','storage_account'].includes(f.resource_type)
  )
  const computeFindings = all.filter(f =>
    f.category === 'compute' ||
    ['compute_instance','gke_cluster','gke_node_pool','virtual_machine','aks_cluster',
     'app_service','function_app','container_registry'].includes(f.resource_type)
  )
  const netFindings = all.filter(f =>
    f.category === 'network' ||
    ['firewall_rule','vpc_subnet','dns_policy','nsg','application_gateway'].includes(f.resource_type)
  )

  const isAzure = conn?.provider === 'azure'

  const iamGroups = isAzure ? {
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
    'Privilege Escalation Paths':         iamFindings.filter(f => f.mitre === 'T1548.005' || f.title?.includes('escalation') || f.title?.includes('impersonat')),
    'Admin Roles on External Identities': iamFindings.filter(f => f.title?.includes('Admin') && (f.title?.includes('external') || f.title?.includes('identity'))),
    'Old Service Account Keys':           iamFindings.filter(f => f.resource_type === 'service_account_key'),
    'Default SA with Broad Scope':        iamFindings.filter(f => f.title?.includes('Default service') || f.title?.includes('cloud-platform scope')),
    'Cross-Project SA Access':            iamFindings.filter(f => f.title?.includes('Cross-project')),
    'Other IAM Issues':                   iamFindings.filter(f => {
      const covered = ['allUsers','public','Primitive','Owner','Editor','T1548','Admin','service_account_key','Default service','cloud-platform','Cross-project']
      return !covered.some(k => (f.title||'').includes(k) || (f.mitre||'').includes(k))
    }),
  }

  const sections = [
    { id:'iam',     label:'IAM Explorer',     icon: Lock,      count: iamFindings.length,     desc:'Identity, access, privilege escalation paths' },
    { id:'storage', label:'Storage Explorer',  icon: HardDrive, count: storageFindings.length,
      desc: isAzure ? 'Storage accounts, SQL databases' : 'Buckets, BigQuery datasets, Secrets' },
    { id:'compute', label:'Compute Explorer',  icon: Server,    count: computeFindings.length,
      desc: isAzure ? 'VMs, AKS clusters, App Services, Functions' : 'Compute instances, GKE clusters, node pools' },
    { id:'network', label:'Network Explorer',  icon: Wifi,      count: netFindings.length,
      desc: isAzure ? 'NSGs, Application Gateways' : 'Firewall rules, subnets, DNS policies' },
  ]

  const renderGroup = (title, items) => items.length === 0 ? null : (
    <div key={title} style={{ marginBottom:18 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:8 }}>
        <span style={{ fontSize:11, fontWeight:700, color:'var(--text2)' }}>{title}</span>
        <span style={{ fontSize:10, background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:10, padding:'0 6px', color:'var(--text3)' }}>{items.length}</span>
      </div>
      <div style={{ display:'flex', flexDirection:'column', gap:5 }}>
        {items.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
      </div>
    </div>
  )

  return (
    <div style={{ height:'100%', display:'flex', overflow:'hidden' }}>
      {/* Left nav */}
      <div style={{ width:200, flexShrink:0, borderRight:'1px solid var(--border)', padding:'16px 10px', background:'var(--surface)', overflow:'auto' }}>
        <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:10, padding:'0 6px' }}>Explore by Type</div>
        {sections.map(({ id, label, icon: Icon, count, desc }) => (
          <button key={id} onClick={() => setSection(id)}
            style={{ display:'flex', flexDirection:'column', width:'100%', padding:'10px 10px', marginBottom:4,
              background: section===id ? 'rgba(0,194,224,0.1)' : 'transparent',
              border: `1px solid ${section===id ? 'rgba(0,194,224,0.3)' : 'transparent'}`,
              borderRadius:8, cursor:'pointer', textAlign:'left', fontFamily:'inherit' }}>
            <div style={{ display:'flex', alignItems:'center', gap:7, marginBottom:4 }}>
              <Icon size={12} color={section===id ? 'var(--accent)' : 'var(--text3)'}/>
              <span style={{ fontSize:11.5, fontWeight:600, color: section===id ? 'var(--accent)' : 'var(--text)' }}>{label}</span>
              {count > 0 && (
                <span style={{ marginLeft:'auto', fontSize:10, background: count>0 ? 'rgba(248,113,113,0.15)' : 'var(--surface2)',
                  color: count>0 ? '#f87171' : 'var(--text3)', border:`1px solid ${count>0 ? 'rgba(248,113,113,0.3)' : 'var(--border)'}`,
                  borderRadius:10, padding:'0 5px', fontFamily:'DM Mono,monospace' }}>{count}</span>
              )}
            </div>
            <span style={{ fontSize:10, color:'var(--text3)', lineHeight:1.4 }}>{desc}</span>
          </button>
        ))}

        {/* Quick console links */}
        <div style={{ marginTop:16, paddingTop:14, borderTop:'1px solid var(--border)' }}>
          <div style={{ fontSize:10, fontWeight:700, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.07em', marginBottom:8, padding:'0 6px' }}>
            {isAzure ? 'Azure Portal' : 'GCP Console'}
          </div>
          {isAzure ? [
            { label: 'IAM & Access Control', href: 'https://portal.azure.com/#view/Microsoft_Azure_AD/IAMMenuBlade/~/RoleAssignments' },
            { label: 'Security Center',       href: 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/Environment' },
            { label: 'Storage Accounts',      href: 'https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FstorageAccounts' },
            { label: 'Network Security Groups',href: 'https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Network%2FnetworkSecurityGroups' },
            { label: 'Key Vaults',            href: 'https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.KeyVault%2Fvaults' },
          ].map(({ label, href }) => (
            <a key={label} href={href} target="_blank" rel="noopener noreferrer"
              style={{ display:'flex', alignItems:'center', gap:6, padding:'7px 10px', fontSize:11,
                color:'var(--text3)', textDecoration:'none', borderRadius:6, marginBottom:2 }}
              onMouseEnter={e => e.currentTarget.style.color='var(--accent)'}
              onMouseLeave={e => e.currentTarget.style.color='var(--text3)'}>
              <ExternalLink size={10}/>{label}
            </a>
          )) : [
            { label: 'IAM & Admin',       href: `https://console.cloud.google.com/iam-admin/iam?project=${cspm?.project_id || conn?.account_id}` },
            { label: 'Firewall Rules',    href: `https://console.cloud.google.com/networking/firewalls?project=${cspm?.project_id || conn?.account_id}` },
            { label: 'Cloud Storage',     href: `https://console.cloud.google.com/storage/browser?project=${cspm?.project_id || conn?.account_id}` },
            { label: 'Compute Instances', href: `https://console.cloud.google.com/compute/instances?project=${cspm?.project_id || conn?.account_id}` },
            { label: 'Security Overview', href: `https://console.cloud.google.com/security/overview?project=${cspm?.project_id || conn?.account_id}` },
          ].map(({ label, href }) => (
            <a key={label} href={href} target="_blank" rel="noopener noreferrer"
              style={{ display:'flex', alignItems:'center', gap:6, padding:'7px 10px', fontSize:11,
                color:'var(--text3)', textDecoration:'none', borderRadius:6, marginBottom:2 }}
              onMouseEnter={e => e.currentTarget.style.color='var(--accent)'}
              onMouseLeave={e => e.currentTarget.style.color='var(--text3)'}>
              <ExternalLink size={10}/>{label}
            </a>
          ))}
        </div>
      </div>

      {/* Right: content */}
      <div style={{ flex:1, overflow:'auto', padding:'20px 22px' }}>
        {!cspm && (
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', height:220, color:'var(--text3)', gap:8 }}>
            <Search size={36} strokeWidth={1} color="var(--border)"/>
            <div style={{ fontSize:13 }}>Run a scan to explore findings in depth</div>
          </div>
        )}

        {cspm && section === 'iam' && (<>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:4 }}>IAM Explorer</div>
          <div style={{ fontSize:11, color:'var(--text3)', marginBottom:18 }}>
            Identity & access misconfigurations, privilege escalation paths, external grants
          </div>
          {iamFindings.length === 0
            ? <div style={{ fontSize:12, color:'#34d399', padding:'30px 0', textAlign:'center' }}>✓ No IAM findings — access looks well configured</div>
            : Object.entries(iamGroups).map(([title, items]) => renderGroup(title, items))
          }
        </>)}

        {cspm && section === 'storage' && (<>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:4 }}>Storage Explorer</div>
          <div style={{ fontSize:11, color:'var(--text3)', marginBottom:18 }}>
            {isAzure ? 'Storage accounts, SQL databases with security issues' : 'Cloud Storage buckets, BigQuery datasets, and Secrets with security issues'}
          </div>
          {storageFindings.length === 0
            ? <div style={{ fontSize:12, color:'#34d399', padding:'30px 0', textAlign:'center' }}>✓ No storage findings</div>
            : <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                {storageFindings.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
              </div>
          }
        </>)}

        {cspm && section === 'compute' && (<>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:4 }}>Compute Explorer</div>
          <div style={{ fontSize:11, color:'var(--text3)', marginBottom:18 }}>
            {isAzure ? 'Virtual Machines, AKS clusters, App Services, Function Apps, Container Registries' : 'Compute instances, GKE clusters, and node pool security configurations'}
          </div>
          {computeFindings.length === 0
            ? <div style={{ fontSize:12, color:'#34d399', padding:'30px 0', textAlign:'center' }}>✓ No compute findings</div>
            : <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                {computeFindings.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
              </div>
          }
        </>)}

        {cspm && section === 'network' && (<>
          <div style={{ fontSize:13, fontWeight:700, color:'var(--text)', marginBottom:4 }}>Network Explorer</div>
          <div style={{ fontSize:11, color:'var(--text3)', marginBottom:18 }}>
            {isAzure ? 'Network Security Groups, Application Gateways and network-level exposure' : 'Firewall rules, VPC subnets, DNS policies and network-level exposure'}
          </div>
          {netFindings.length === 0
            ? <div style={{ fontSize:12, color:'#34d399', padding:'30px 0', textAlign:'center' }}>✓ No network findings</div>
            : <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                {netFindings.map((f,i) => <FindingCard key={f.id||i} f={f} provider={conn?.provider || "gcp"} projectId={cspm?.project_id} subscriptionId={cspm?.subscription_id}/>)}
              </div>
          }
        </>)}
      </div>
    </div>
  )
}

