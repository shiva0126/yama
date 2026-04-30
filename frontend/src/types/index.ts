// ============================================================
// Core AD Types
// ============================================================

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type FindingCategory =
  | 'Kerberos'
  | 'Account Security'
  | 'Privileged Access'
  | 'Group Policy'
  | 'Domain Controllers'
  | 'AD Structure'
  | 'Delegation'
  | 'Trusts'
  | 'PKI / Certificate Services'
  | 'NTLM & Authentication'
  | 'Persistence Mechanisms'

// ============================================================
// Scans
// ============================================================

export interface ScanJob {
  id: string
  agent_id: string
  domain: string
  status: ScanStatus
  progress: number
  overall_score?: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  total_findings: number
  snapshot_id?: string
  created_at: string
  started_at?: string
  completed_at?: string
  tasks?: ScanTask[]
}

export interface ScanTask {
  id: string
  type: string
  status: ScanStatus
  items_found: number
  error?: string
  started_at?: string
  completed_at?: string
}

export interface ScoreCard {
  overall_score: number
  category_scores: Record<string, number>
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  total_findings: number
  passed_checks: number
  total_checks: number
}

export interface ScanRequest {
  agent_id: string
  domain: string
  task_types?: string[]
}

// ============================================================
// Agents
// ============================================================

export interface CollectorAgent {
  id: string
  name: string
  hostname: string
  domain: string
  ip_address: string
  status: 'online' | 'offline' | 'busy'
  last_seen: string
  version: string
  capabilities: string[]
}

// ============================================================
// Inventory
// ============================================================

export interface ADUser {
  distinguished_name: string
  sam_account_name: string
  user_principal_name: string
  display_name: string
  domain: string
  enabled: boolean
  password_never_expires: boolean
  dont_require_preauth: boolean
  service_principal_names: string[]
  is_privileged: boolean
  is_service_account: boolean
  last_logon: string | null
  pwd_last_set: string | null
  admin_count: number
  privileged_groups: string[]
  member_of: string[]
}

export interface ADGroup {
  distinguished_name: string
  sam_account_name: string
  name: string
  description: string
  domain: string
  group_scope: string
  group_category: string
  members: string[]
  is_privileged: boolean
  privilege_level: string
  admin_count: number
}

export interface ADComputer {
  distinguished_name: string
  name: string
  dns_host_name: string
  domain: string
  operating_system: string
  operating_system_version: string
  enabled: boolean
  is_domain_controller: boolean
  laps_enabled: boolean
  trusted_for_delegation: boolean
  last_logon: string | null
}

export interface ADGPO {
  id: string
  name: string
  domain: string
  status: string
  is_linked: boolean
  linked_ous: Array<{ ou_dn: string; enabled: boolean; enforced: boolean }>
  sysvol_writable_by_nonadmin: boolean
  created: string
  modified: string
}

export interface ADDomainController {
  name: string
  host_name: string
  ip_address: string
  site: string
  domain: string
  operating_system: string
  is_read_only: boolean
  is_global_catalog: boolean
  fsmo_roles: string[]
  spooler_running: boolean
  smb_signing_required: boolean
  ldap_signing_required: boolean
}

// ============================================================
// Findings
// ============================================================

export interface Finding {
  id: string
  scan_id: string
  indicator_id: string
  name: string
  description: string
  severity: Severity
  category: FindingCategory
  risk_score: number
  affected_objects: AffectedObject[]
  remediation: string
  references: string[]
  mitre: string[]
  detected_at: string
  is_new: boolean
}

export interface AffectedObject {
  dn: string
  type: string
  name: string
  detail: string
}

export interface SecurityIndicator {
  id: string
  name: string
  description: string
  category: FindingCategory
  severity: Severity
  remediation: string
}

// ============================================================
// Agent Installation
// ============================================================

export type InstallStatus = 'pending' | 'running' | 'completed' | 'failed'

export interface InstallRequest {
  target_ip: string
  username: string
  password: string
  domain: string
  agent_name: string
  ssh_port?: number
  agent_port?: number
}

export interface InstallJob {
  id: string
  target_ip: string
  agent_name: string
  status: InstallStatus
  progress: number
  message: string
  agent_id?: string
  error?: string
  created_at: string
}

// ============================================================
// WebSocket
// ============================================================

export interface WSMessage {
  type: 'scan_progress' | 'scan_complete' | 'scan_error' | 'agent_status' | 'new_finding'
  payload: unknown
}

export interface ScanProgressPayload {
  scan_id: string
  progress: number
  message: string
}
