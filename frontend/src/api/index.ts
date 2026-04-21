import axios from 'axios'
import type {
  ScanJob, ScanRequest, CollectorAgent, Finding, ScoreCard,
  ADUser, ADGroup, ADComputer, ADGPO, ADDomainController, SecurityIndicator
} from '../types'

const BASE_URL = import.meta.env.VITE_API_BASE_URL || ''

const api = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
})

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Redirect on 401
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
// Reports
// ============================================================
export const reportsApi = {
  generate: (scanId: string, format: 'html' | 'pdf' | 'json') =>
    api.post<{ id: string }>('/reports/generate', { scan_id: scanId, format }),
  get: (id: string) => api.get(`/reports/${id}`),
  download: (id: string) => api.get(`/reports/${id}/download`, { responseType: 'blob' }),
}

export default api
