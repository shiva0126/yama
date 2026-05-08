import axios from 'axios'
import type {
  ScanJob, ScanRequest, CollectorAgent, Finding, ScoreCard,
  ADUser, ADGroup, ADComputer, ADGPO, ADDomainController, SecurityIndicator,
  InstallRequest, InstallJob, OverviewSummary,
  DefenseCatalogSummary, DefenseDetection, DefenseIncident, DefensePolicySummary,
  EvidenceBundle, EvidenceBundleRequest, ResponseAction,
  ADVulnerability, BulkDCInstallRequest, BulkDCInstallResponse, ServiceIdentity,
} from '../types'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('auth_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)

// ─── Defense API (defense-api:8098) ─────────────────────────────────────────
const defenseApiClient = axios.create({
  baseURL: import.meta.env.VITE_DEFENSE_API_BASE_URL || '/defense-api',
  headers: { 'Content-Type': 'application/json' },
})
defenseApiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ─── Evidence Ledger (evidence-ledger:8096) ──────────────────────────────────
const evidenceApiClient = axios.create({
  baseURL: import.meta.env.VITE_EVIDENCE_API_BASE_URL || '/evidence-api',
  headers: { 'Content-Type': 'application/json' },
})
evidenceApiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ─── Policy Engine (policy-engine:8097) ──────────────────────────────────────
const policyApiClient = axios.create({
  baseURL: import.meta.env.VITE_POLICY_API_BASE_URL || '/policy-api',
  headers: { 'Content-Type': 'application/json' },
})
policyApiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

// ============================================================
// Auth
// ============================================================
export const authApi = {
  login: (username: string, password: string) =>
    api.post<{ token: string; username: string }>('/auth/login', { username, password }),
}

// ============================================================
// Agents
// ============================================================
export const agentsApi = {
  list: () => api.get<{ agents: CollectorAgent[]; total: number }>('/agents'),
  get: (id: string) => api.get<CollectorAgent>(`/agents/${id}`),
  register: (data: { name: string; hostname: string; domain: string; ip_address?: string }) =>
    api.post<{ id: string; api_key: string }>('/agents', data),
  delete: (id: string) => api.delete(`/agents/${id}`),
  status: (id: string) => api.get<{ status: string; last_seen: string }>(`/agents/${id}/status`),
  install: (data: InstallRequest) =>
    api.post<{ job_id: string; message: string }>('/agents/install', data),
  installBulkDCs: (data: BulkDCInstallRequest) =>
    api.post<BulkDCInstallResponse>('/agents/install/bulk-dcs', data),
  listInstallJobs: () => api.get<{ jobs: InstallJob[] }>('/agents/install'),
  getInstallStatus: (jobId: string) => api.get<InstallJob>(`/agents/install/${jobId}`),
}

// ============================================================
// Scans
// ============================================================
export const scansApi = {
  list: () => api.get<{ scans: ScanJob[]; total: number }>('/scans'),
  get: (id: string) => api.get<ScanJob>(`/scans/${id}`),
  create: (data: ScanRequest) => api.post<ScanJob>('/scans', data),
  cancel: (id: string) => api.delete(`/scans/${id}`),
  getProgress: (id: string) => api.get<{ scan_id: string; progress: number; status: string }>(`/scans/${id}/progress`),
  getScoreCard: (id: string) => api.get<ScoreCard>(`/scans/${id}/scorecard`),
}

// ============================================================
// Inventory
// ============================================================
export const inventoryApi = {
  listSnapshots: () => api.get<{ snapshots: any[]; total: number }>('/inventory/snapshots'),
  getSnapshot: (id: string) => api.get(`/inventory/snapshots/${id}`),
  getUsers: (snapshotId: string, params?: Record<string, string>) =>
    api.get<{ items: ADUser[]; total: number }>(`/inventory/snapshots/${snapshotId}/users`, { params }),
  getGroups: (snapshotId: string, params?: Record<string, string>) =>
    api.get<{ items: ADGroup[]; total: number }>(`/inventory/snapshots/${snapshotId}/groups`, { params }),
  getComputers: (snapshotId: string, params?: Record<string, string>) =>
    api.get<{ items: ADComputer[]; total: number }>(`/inventory/snapshots/${snapshotId}/computers`, { params }),
  getGPOs: (snapshotId: string) =>
    api.get<{ items: ADGPO[]; total: number }>(`/inventory/snapshots/${snapshotId}/gpos`),
  getDomainControllers: (snapshotId: string) =>
    api.get<{ items: ADDomainController[]; total: number }>(`/inventory/snapshots/${snapshotId}/dcs`),
  getTopology: (snapshotId: string) => api.get(`/inventory/snapshots/${snapshotId}/topology`),
  getServiceIdentities: (snapshotId: string) =>
    api.get<{ items: ServiceIdentity[]; total: number }>(`/inventory/snapshots/${snapshotId}/service-identities`),
  getVulnerabilities: (snapshotId: string) =>
    api.get<{ items: ADVulnerability[]; total: number }>(`/inventory/snapshots/${snapshotId}/vulnerabilities`),
}

// ============================================================
// Findings
// ============================================================
export const findingsApi = {
  list: (params?: Record<string, string>) =>
    api.get<{ findings: Finding[]; total: number }>('/findings', { params }),
  get: (id: string) => api.get<Finding>(`/findings/${id}`),
  getByScan: (scanId: string) =>
    api.get<{ findings: Finding[]; total: number }>(`/findings/scan/${scanId}`),
  listIndicators: () =>
    api.get<{ indicators: SecurityIndicator[]; total: number }>('/findings/indicators'),
}

// ============================================================
// Overview
// ============================================================
export const overviewApi = {
  summary: () => api.get<OverviewSummary>('/overview/summary'),
}

// ============================================================
// Defense (defense-api:8098)
// ============================================================
export const defenseApi = {
  summary:    () => defenseApiClient.get<DefenseCatalogSummary>('/catalog/summary'),
  catalog:    () => defenseApiClient.get('/catalog'),
  incidents:  () =>
    defenseApiClient
      .get<{ incidents?: Array<Partial<DefenseIncident>> }>('/incidents')
      .then((r) => ({
        ...r,
        data: (r.data.incidents ?? []).map((incident) => ({
          id: incident.id ?? '',
          title: incident.title ?? 'Untitled incident',
          severity: (incident.severity ?? 'info') as DefenseIncident['severity'],
          confidence: incident.confidence ?? 'unknown',
          status: incident.status ?? 'open',
          primary_actor: incident.primary_actor ?? '',
          primary_target: incident.primary_target ?? '',
          opened_at: incident.opened_at ?? new Date().toISOString(),
          last_updated_at: incident.last_updated_at ?? incident.opened_at ?? new Date().toISOString(),
          detection_ids: incident.detection_ids ?? [],
          response_actions: incident.response_actions ?? [],
          metadata: incident.metadata ?? {},
        })),
      })),
  detections: () =>
    defenseApiClient
      .get<{ detections?: Array<Partial<DefenseDetection> & { detected_at?: string }> }>('/detections')
      .then((r) => ({
        ...r,
        data: (r.data.detections ?? []).map((detection) => ({
          id: detection.id ?? '',
          detector_id: detection.detector_id ?? '',
          title: detection.title ?? 'Untitled detection',
          confidence: detection.confidence ?? 'unknown',
          severity: (detection.severity ?? 'info') as DefenseDetection['severity'],
          occurred_at: detection.occurred_at ?? detection.detected_at ?? new Date().toISOString(),
          domain: detection.domain ?? '',
          source_host: detection.source_host ?? '',
          actor: detection.actor ?? '',
          target: detection.target ?? '',
          evidence_refs: detection.evidence_refs ?? [],
          metadata: detection.metadata ?? {},
        })),
      })),
  responses:  () =>
    defenseApiClient
      .get<{ actions?: Array<Partial<ResponseAction> & { created_at?: string }> }>('/responses')
      .then((r) => ({
        ...r,
        data: (r.data.actions ?? []).map((action) => ({
          id: action.id ?? '',
          incident_id: action.incident_id ?? '',
          action_type: action.action_type ?? '',
          mode: action.mode ?? 'approval-required',
          status: action.status ?? 'planned',
          target_type: action.target_type ?? '',
          target_value: action.target_value ?? '',
          result_summary: action.result_summary ?? '',
          rollback_data: action.rollback_data,
          executed_at: action.executed_at ?? action.created_at,
        })),
      })),
  agents:     () =>
    defenseApiClient
      .get<{ agents?: Array<Partial<CollectorAgent>> }>('/agents')
      .then((r) => ({
        ...r,
        data: (r.data.agents ?? []).map((agent) => ({
          id: agent.id ?? '',
          name: agent.name ?? agent.hostname ?? 'unknown',
          hostname: agent.hostname ?? '',
          domain: agent.domain ?? '',
          ip_address: agent.ip_address ?? '',
          port: agent.port,
          status: (agent.status as CollectorAgent['status']) ?? 'offline',
          last_seen: agent.last_seen ?? new Date().toISOString(),
          version: agent.version ?? '',
          capabilities: agent.capabilities ?? [],
          defense_mode: agent.defense_mode,
          defense_url: agent.defense_url,
        })),
      })),
  heartbeat:  (agentId: string, defenseUrl: string) =>
    defenseApiClient.post('/agent/heartbeat', { agent_id: agentId, defense_url: defenseUrl }),
  plan:       (incident: DefenseIncident) => defenseApiClient.post('/plan', incident),
}

// ============================================================
// Policy Engine (policy-engine:8097)
// ============================================================
export const policyApi = {
  get:            () => policyApiClient.get<DefensePolicySummary>('/policy'),
  listExclusions: () => policyApiClient.get('/policy/exclusion'),
  addExclusion:   (data: { scope_type: string; scope_value: string; reason: string; expires_at?: string; created_by: string }) =>
    policyApiClient.post('/policy/exclusion', data),
  deleteExclusion: (id: string) => policyApiClient.delete(`/policy/exclusion/${id}`),
  evaluate:       (data: { action_type: string; severity: string; confidence: string; target_value: string }) =>
    policyApiClient.post('/policy/evaluate', data),
}

// ============================================================
// Evidence Ledger (evidence-ledger:8096)
// ============================================================
export const evidenceApi = {
  list:   () =>
    evidenceApiClient
      .get<{ bundles?: Array<Partial<EvidenceBundle>>; total?: number }>('/evidence')
      .then((r) => ({
        ...r,
        data: {
          items: (r.data.bundles ?? []).map((bundle) => ({
            id: bundle.id ?? '',
            incident_id: bundle.incident_id ?? '',
            storage_key: bundle.storage_key ?? '',
            sha256: bundle.sha256 ?? '',
            content_type: bundle.content_type ?? 'application/json',
            size_bytes: bundle.size_bytes ?? 0,
            metadata: bundle.metadata ?? {},
            created_at: bundle.created_at,
          })),
          total: r.data.total ?? (r.data.bundles?.length ?? 0),
        },
      })),
  bundle: (payload: EvidenceBundleRequest) => evidenceApiClient.post<EvidenceBundle>('/evidence/bundle', payload),
}

// ============================================================
// Reports
// ============================================================
export const reportsApi = {
  list: () => api.get<{ reports: any[]; total: number }>('/reports'),
  generate: (scanId: string, format: 'html' | 'pdf' | 'json') =>
    api.post<{ id: string }>('/reports/generate', { scan_id: scanId, format }),
  get: (id: string) => api.get(`/reports/${id}`),
  download: (id: string) => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
}

export default api
