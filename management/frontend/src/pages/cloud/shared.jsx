import { Activity, Shield, Zap, Database, Lock, Server, HardDrive, Key, Wifi, AlertTriangle, Info, FileText } from 'lucide-react'
import { CloudEventsAlerts } from './events.jsx'

// ── Constants ─────────────────────────────────────────────────────────────────
export const PROVIDERS = {
  aws: {
    label: 'Amazon Web Services', color: 'text-orange-400',
    border: 'border-orange-800/40', bg: 'bg-orange-950/10',
    fields: [
      { key: 'access_key_id',     label: 'Access Key ID',     placeholder: 'AKIAIOSFODNN7EXAMPLE', secret: false },
      { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '••••••••', secret: true },
      { key: 'region',            label: 'Region',            placeholder: 'us-east-1', secret: false },
      { key: 'role_arn',          label: 'Role ARN to assume (optional, recommended)', placeholder: 'arn:aws:iam::123456789012:role/ObsidianWatchReadOnly', secret: false },
      { key: 'external_id',       label: 'External ID (optional)', placeholder: 'shared secret from the role trust policy', secret: true },
      { key: 'account_id',        label: 'Account ID (optional)', placeholder: '123456789012', secret: false },
    ],
    pulls: ['CloudTrail (LookupEvents API)', 'IAM activity', 'GuardDuty findings'],
  },
  azure: {
    label: 'Microsoft Azure', color: 'text-blue-400',
    border: 'border-blue-800/40', bg: 'bg-blue-950/10',
    fields: [
      { key: 'tenant_id',       label: 'Tenant ID',       placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
      { key: 'client_id',       label: 'Client ID',       placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx', secret: false },
      { key: 'client_secret',   label: 'Client Secret',   placeholder: '••••••••', secret: true },
      { key: 'subscription_id', label: 'Subscription ID(s)', placeholder: 'one ID, a comma-separated list, or * for all enabled subscriptions', secret: false },
      { key: 'workspace_id', label: 'Log Analytics workspace ID(s) (optional)', placeholder: 'workspace GUID(s) receiving Key Vault / AKS / Firewall / App Service diagnostic logs; app needs Log Analytics Reader', secret: false },
    ],
    pulls: ['Azure Activity Log', 'Entra ID sign-in + audit logs', 'Defender for Cloud alerts', 'Resource logs (Key Vault, AKS, Firewall, App Service) via Log Analytics'],
  },
  gcp: {
    label: 'Google Cloud Platform', color: 'text-green-400',
    border: 'border-green-800/40', bg: 'bg-green-950/10',
    fields: [
      { key: 'service_account', label: 'Service Account JSON or Workload Identity config', placeholder: '{ "type": "service_account", ... } or { "type": "external_account", ... } (keyless; token file under /var/run/secrets/)', secret: true, multiline: true },
      { key: 'project_id', label: 'Project ID(s) (optional)', placeholder: 'defaults to the service account project; a comma-separated list, or * to discover under the org/folder below', secret: false },
      { key: 'org_id',     label: 'Organization ID (optional)', placeholder: '123456789012 - with project_id = * syncs every active project in the org', secret: false },
      { key: 'folder_id',  label: 'Folder ID (optional)', placeholder: '987654321 - limits discovery to this folder tree', secret: false },
    ],
    pulls: ['Cloud Audit Logs', 'Admin Activity', 'Data Access logs', 'System Events'],
  },
}

export const PROVIDER_COLORS = { aws: 'text-orange-400', azure: 'text-blue-400', gcp: 'text-green-400' }

export const SEV_COLOR = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--warn)', low: 'var(--info)', info: 'var(--t2)' }

export const SEV_BG    = { critical: 'rgb(var(--crit-c) / 0.08)', high: 'rgb(var(--high-c) / 0.08)', medium: 'rgb(var(--warn-c) / 0.08)', low: 'rgb(var(--info-c) / 0.08)', info: 'rgb(var(--t2-c) / 0.06)' }

export const SEV_BORDER= { critical: 'rgb(var(--crit-c) / 0.25)', high: 'rgb(var(--high-c) / 0.25)', medium: 'rgb(var(--warn-c) / 0.25)', low: 'rgb(var(--info-c) / 0.25)', info: 'rgb(var(--t2-c) / 0.15)' }

// Category → icon + label mapping
export const CAT_META = {
  network:       { icon: Wifi,      label: 'Network',          color: 'var(--crit)' },
  iam:           { icon: Lock,      label: 'Identity & Access', color: 'var(--violet)' },
  storage:       { icon: HardDrive, label: 'Storage',          color: 'var(--info)' },
  compute:       { icon: Server,    label: 'Compute',          color: 'var(--high)' },
  sql:           { icon: Database,  label: 'Database',         color: 'var(--ok)' },
  logging:       { icon: FileText,  label: 'Logging',          color: 'var(--warn)' },
  kms:           { icon: Key,       label: 'KMS / Crypto',     color: 'var(--violet)' },
  threat:        { icon: Zap,       label: 'Threat Detection', color: 'var(--crit)' },
  vulnerability: { icon: AlertTriangle, label: 'Vulnerability', color: 'var(--high)' },
  security:      { icon: Shield,    label: 'Security',         color: 'var(--t2)' },
  default:       { icon: Shield,    label: 'Security',         color: 'var(--t2)' },
}

export const CIS_MAPPING = {
  // GCP sections
  network:             'CIS 3.x - Networking',
  iam:                 'CIS 1.x - Identity & Access Management',
  storage:             'CIS 5.x - Cloud Storage',
  compute:             'CIS 4.x - Virtual Machines',
  sql:                 'CIS 6.x - Cloud SQL',
  logging:             'CIS 2.x - Logging & Monitoring',
  kms:                 'CIS 1.x - IAM / KMS',
  cloud_run_service:   'CIS 4.x - Serverless Compute',
  artifact_registry:   'CIS 4.x - Container Registry',
  cloud_function:      'CIS 4.x - Serverless Compute',
  pubsub_topic:        'CIS 5.x - Messaging',
  pubsub_subscription: 'CIS 5.x - Messaging',
  org_iam_binding:     'CIS 1.x - Organization IAM',
  gke_cluster:         'CIS 4.x - Kubernetes / GKE',
  gke_node_pool:       'CIS 4.x - Kubernetes / GKE',
  // Azure sections
  nsg:                 'CIS 6.x - Networking',
  storage_account:     'CIS 3.x - Storage Accounts',
  virtual_machine:     'CIS 7.x - Virtual Machines',
  sql_server:          'CIS 4.x - Database Services',
  sql_database:        'CIS 4.x - Database Services',
  key_vault:           'CIS 8.x - Key Vault',
  aks_cluster:         'CIS 5.x - Containers',
  role_assignment:     'CIS 1.x - Identity & Access',
  classic_admin:       'CIS 1.x - Identity & Access',
  entra_tenant:        'CIS 1.x - Conditional Access',
  diagnostic_setting:  'CIS 5.x - Logging & Monitoring',
  defender_plan:       'CIS 2.x - Microsoft Defender',
  app_service:         'CIS 9.x - App Service',
  function_app:        'CIS 9.x - App Service',
  container_registry:  'CIS 5.x - Containers',
}

// ── Helpers ───────────────────────────────────────────────────────────────────
export function riskScore(cspm) {
  if (!cspm) return 0
  const w = { critical: 10, high: 5, medium: 2, low: 0.5 }
  const raw = (cspm.critical||0)*w.critical + (cspm.high||0)*w.high + (cspm.medium||0)*w.medium + (cspm.low||0)*w.low
  const total = (cspm.total_findings||0) + (cspm.passed||0)
  if (!total) return 0
  return Math.min(100, Math.round(raw / Math.max(total, 1) * 10))
}

export function riskLabel(score) {
  if (score >= 80) return { label: 'Critical Risk',   color: 'var(--crit)' }
  if (score >= 60) return { label: 'High Risk',       color: 'var(--high)' }
  if (score >= 40) return { label: 'Medium Risk',     color: 'var(--warn)' }
  if (score >= 20) return { label: 'Low Risk',        color: 'var(--info)' }
  return               { label: 'Minimal Risk',      color: 'var(--ok)' }
}

// ── CloudEventsAlerts - clickable event + alert rows with slide-out panels ────
export const SEV_LABELS = ['', 'Info', 'Low', 'Medium', 'High', 'Critical']

export const SEV_COLORS_CLS = ['', 'text-siem-muted', 'text-blue-400', 'text-yellow-400', 'text-orange-400', 'text-red-400']

export const RISK_COLORS_BLAST = { critical:'var(--crit)', high:'var(--high)', medium:'var(--warn)', low:'var(--info)', none:'var(--t3)' }

export const NODE_COLORS_BLAST  = {
  vm:'var(--info)', virtual_machine:'var(--info)', service_account:'var(--violet)', storage_bucket:'var(--warn)',
  storage_account:'var(--warn)', cloud_sql:'var(--ok)', sql_server:'var(--ok)', internet:'var(--crit)',
  network:'var(--t2)', firewall:'var(--high)', iam_role:'var(--magenta)', secret:'var(--teal)',
  key_vault:'var(--teal)', user:'var(--magenta)', principal:'var(--magenta)', default:'var(--t3)'
}

