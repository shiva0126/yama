import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { format, formatDistanceToNow } from 'date-fns'
import { Activity, ChevronRight, Loader2, Play, Radar, Search, Server, StopCircle, X } from 'lucide-react'
import { agentsApi, findingsApi, inventoryApi, scansApi } from '../../api'
import { useScanStore } from '../../stores/scanStore'
import type { ADVulnerability, Finding, Severity } from '../../types'
import { ScoreGauge, SeverityDonut } from '../Charts'

const TASKS = [
  { id: 'topology',  label: 'Forest topology',   group: 'Core' },
  { id: 'users',     label: 'Identity inventory', group: 'Core' },
  { id: 'groups',    label: 'Group analysis',     group: 'Core' },
  { id: 'computers', label: 'Asset inventory',    group: 'Core' },
  { id: 'ous',       label: 'OU structure',       group: 'Core' },
  { id: 'gpos',      label: 'Policy analysis',    group: 'Security' },
  { id: 'dcinfo',    label: 'DC posture',         group: 'Security' },
  { id: 'kerberos',  label: 'Kerberos security',  group: 'Security' },
  { id: 'acls',      label: 'ACL analysis',       group: 'Security' },
  { id: 'trusts',    label: 'Trust review',       group: 'Security' },
  { id: 'adcs',      label: 'ADCS / PKI',         group: 'Security' },
  { id: 'sites',     label: 'Sites & services',   group: 'Security' },
  { id: 'fgpp',      label: 'FGPP review',        group: 'Security' },
  { id: 'service-identities', label: 'Service ID enumeration', group: 'Security' },
  { id: 'ad-vuln-scan',       label: 'AD vulnerability scan',  group: 'Security' },
]

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEV_BAR: Record<Severity, string> = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0284c7', info: '#64748b' }

export function Assess() {
  const [tab, setTab] = useState<'scan' | 'findings'>('scan')
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#f4f6f9' }}>
      <div className="tab-bar">
        <button className={`tab-item ${tab === 'scan' ? 'active' : ''}`} onClick={() => setTab('scan')}>
          <Play size={13} /> Assessment
        </button>
        <button className={`tab-item ${tab === 'findings' ? 'active' : ''}`} onClick={() => setTab('findings')}>
          <Activity size={13} /> Exposure Queue
        </button>
      </div>
      <div style={{ flex: 1, overflow: 'hidden' }}>
        {tab === 'scan' ? <ScanTab /> : <FindingsTab />}
      </div>

    </div>
  )
}

/* ─── Scan tab ──────────────────────────────────────── */
function ScanTab() {
  const qc = useQueryClient()
  const { setActiveScan } = useScanStore()
  const [domain, setDomain] = useState('')
  const [agentId, setAgentId] = useState('')
  const [fullScan, setFullScan] = useState(true)
  const [tasks, setTasks] = useState<string[]>([])
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [showBulkDCInstall, setShowBulkDCInstall] = useState(false)
  const [bulkCreds, setBulkCreds] = useState({
    username: '',
    password: '',
    domain: '',
    agent_name_prefix: 'DC-Agent',
  })
  const [bulkInstallSummary, setBulkInstallSummary] = useState<{ queued: number; total: number; skipped: number } | null>(null)

  const { data: agentsData } = useQuery({ queryKey: ['agents'], queryFn: () => agentsApi.list().then(r => r.data) })
  const { data: scansData } = useQuery({ queryKey: ['scans'], queryFn: () => scansApi.list().then(r => r.data), refetchInterval: 4000 })

  const agents = agentsData?.agents ?? []
  const scans  = scansData?.scans ?? []
  const runningScan = scans.find(s => s.status === 'running')
  const latestCompletedScan = scans.find(s => s.status === 'completed' && !!s.snapshot_id)
  const displayScan = activeScanId ? scans.find(s => s.id === activeScanId) : runningScan
  const snapshotId = displayScan?.snapshot_id ?? latestCompletedScan?.snapshot_id

  const { data: vulnerabilitiesData } = useQuery({
    queryKey: ['assessment-vulnerabilities', snapshotId],
    queryFn: () => inventoryApi.getVulnerabilities(snapshotId!).then(r => r.data),
    enabled: !!snapshotId,
    refetchInterval: 15_000,
  })
  const { data: serviceIdentitiesData } = useQuery({
    queryKey: ['assessment-service-identities', snapshotId],
    queryFn: () => inventoryApi.getServiceIdentities(snapshotId!).then(r => r.data),
    enabled: !!snapshotId,
    refetchInterval: 15_000,
  })

  const vulnerabilities = vulnerabilitiesData?.items ?? []
  const serviceIdentities = serviceIdentitiesData?.items ?? []

  const createScan = useMutation({
    mutationFn: () => scansApi.create({ agent_id: agentId, domain, task_types: fullScan ? [] : tasks }),
    onSuccess: (res) => {
      setActiveScanId(res.data.id)
      setActiveScan(res.data)
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })
  const cancelScan = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => { setActiveScanId(null); qc.invalidateQueries({ queryKey: ['scans'] }) },
  })
  const bulkInstallDCs = useMutation({
    mutationFn: () => agentsApi.installBulkDCs({
      snapshot_id: snapshotId!,
      username: bulkCreds.username,
      password: bulkCreds.password,
      domain: bulkCreds.domain || domain || latestCompletedScan?.domain || '',
      agent_name_prefix: bulkCreds.agent_name_prefix || 'DC-Agent',
    }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      qc.invalidateQueries({ queryKey: ['agents-install-jobs'] })
      setBulkInstallSummary({
        queued: res.data.queued_count,
        total: res.data.dc_count,
        skipped: res.data.skipped.length,
      })
      setShowBulkDCInstall(false)
      setBulkCreds((prev) => ({ ...prev, password: '' }))
    },
  })

  const toggleTask = (id: string) => setTasks(p => p.includes(id) ? p.filter(t => t !== id) : [...p, id])

  const vulnBySeverity = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    vulnerabilities.forEach((v) => {
      const sev = (v.severity || 'info').toLowerCase()
      counts[sev] = (counts[sev] ?? 0) + (v.count ?? 0)
    })
    return counts
  }, [vulnerabilities])

  const privilegedServiceAccounts = useMemo(
    () => serviceIdentities.filter((identity) => identity.is_privileged).length,
    [serviceIdentities],
  )

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>

      {/* Config panel */}
      <div style={{ width: 340, flexShrink: 0, background: '#fff', borderRight: '1px solid #e4e8ef', overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Target */}
        <div>
          <div className="section-label" style={{ marginBottom: 10 }}>Target</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#4b5c72', marginBottom: 5 }}>Agent</label>
              <select className="field" value={agentId} onChange={e => { setAgentId(e.target.value); const ag = agents.find(a => a.id === e.target.value); if (ag) setDomain(ag.domain) }}>
                <option value="">Select agent…</option>
                {agents.map(a => <option key={a.id} value={a.id}>{a.name} — {a.status}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: '#4b5c72', marginBottom: 5 }}>Domain</label>
              <input className="field" value={domain} onChange={e => setDomain(e.target.value)} placeholder="corp.local" />
            </div>
          </div>
        </div>

        {/* Scope */}
        <div>
          <div className="section-label" style={{ marginBottom: 10 }}>Scan scope</div>
          <label style={{
            display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', borderRadius: 7, cursor: 'pointer',
            background: fullScan ? '#eff6ff' : '#f9fafb',
            border: `1px solid ${fullScan ? '#bfdbfe' : '#e4e8ef'}`, marginBottom: 12,
          }}>
            <input type="checkbox" checked={fullScan} onChange={e => setFullScan(e.target.checked)} style={{ accentColor: '#2563eb', width: 14, height: 14 }} />
            <div>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>Full assessment</div>
              <div style={{ fontSize: 11, color: '#8a9ab5' }}>All {TASKS.length} collection tasks</div>
            </div>
          </label>

          {!fullScan && ['Core', 'Security'].map(group => (
            <div key={group} style={{ marginBottom: 12 }}>
              <div style={{ fontSize: 10, color: '#8a9ab5', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6 }}>{group}</div>
              {TASKS.filter(t => t.group === group).map(t => (
                <label key={t.id} style={{
                  display: 'flex', alignItems: 'center', gap: 9, padding: '7px 10px', borderRadius: 6, cursor: 'pointer',
                  background: tasks.includes(t.id) ? '#eff6ff' : 'transparent',
                  border: `1px solid ${tasks.includes(t.id) ? '#bfdbfe' : 'transparent'}`,
                  fontSize: 12, color: tasks.includes(t.id) ? '#1d4ed8' : '#4b5c72', marginBottom: 2,
                }}>
                  <input type="checkbox" checked={tasks.includes(t.id)} onChange={() => toggleTask(t.id)} style={{ accentColor: '#2563eb', flexShrink: 0 }} />
                  {t.label}
                </label>
              ))}
            </div>
          ))}
        </div>

        <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center', padding: '9px 0' }}
          disabled={!agentId || !domain || createScan.isPending || !!runningScan}
          onClick={() => createScan.mutate()}>
          {createScan.isPending ? <Loader2 size={13} className="spin" /> : <Play size={13} />}
          {runningScan ? 'Scan running…' : 'Launch assessment'}
        </button>

        <button
          className="btn btn-ghost"
          style={{ width: '100%', justifyContent: 'center', padding: '9px 0' }}
          disabled={!snapshotId}
          onClick={() => {
            setBulkCreds((prev) => ({ ...prev, domain: domain || latestCompletedScan?.domain || prev.domain }))
            setShowBulkDCInstall(true)
          }}
        >
          <Server size={13} />
          Install agents on mapped DCs
        </button>
        {!snapshotId && (
          <div style={{ fontSize: 11, color: '#8a9ab5' }}>
            Run one completed scan first, then bulk-install agents for all discovered DCs.
          </div>
        )}
        {bulkInstallSummary && (
          <div style={{ fontSize: 11, color: '#4b5c72', background: '#f8fafc', border: '1px solid #dbe2ea', borderRadius: 6, padding: '8px 10px' }}>
            DC bulk install queued: {bulkInstallSummary.queued}/{bulkInstallSummary.total}
            {bulkInstallSummary.skipped > 0 ? ` · skipped ${bulkInstallSummary.skipped}` : ''}
          </div>
        )}
      </div>

      {/* Right: progress + history */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: '#f4f6f9' }}>

        {/* Active scan progress */}
        {displayScan && (
          <div className="card" style={{ padding: 18, marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 600, color: '#0f1923' }}>{displayScan.domain}</div>
                <div style={{ fontSize: 12, color: '#8a9ab5' }}>
                  {displayScan.status === 'running' ? `${displayScan.progress ?? 0}% complete` : displayScan.status}
                </div>
              </div>
              {displayScan.status === 'running' && (
                <button className="btn btn-ghost" style={{ padding: '5px 10px', fontSize: 12 }} onClick={() => cancelScan.mutate(displayScan.id)}>
                  <StopCircle size={12} /> Stop
                </button>
              )}
            </div>
            <div className="progress-track">
              <div className={`progress-fill ${displayScan.status === 'completed' ? 'success' : ''}`}
                style={{ width: `${displayScan.status === 'completed' ? 100 : (displayScan.progress ?? 0)}%` }} />
            </div>
            {displayScan.status === 'completed' && (() => {
              const counts = {
                critical: (displayScan as any).critical_count ?? 0,
                high:     (displayScan as any).high_count     ?? 0,
                medium:   (displayScan as any).medium_count   ?? 0,
                low:      (displayScan as any).low_count      ?? 0,
                info:     (displayScan as any).info_count     ?? 0,
              }
              const total = Object.values(counts).reduce((a, b) => a + b, 0)
              const score = (displayScan as any).overall_score
              return (
                <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 20, paddingTop: 14, borderTop: '1px solid #f0f3f8' }}>
                  {score != null && <ScoreGauge score={score} size={100} />}
                  <SeverityDonut counts={counts} size={84} />
                  <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {(['critical', 'high', 'medium', 'low'] as Severity[]).map(s => {
                      const c = counts[s]
                      if (c === 0) return null
                      return (
                        <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: SEV_BAR[s], flexShrink: 0 }} />
                          <span style={{ fontSize: 11, color: '#4b5c72', flex: 1, textTransform: 'capitalize' }}>{s}</span>
                          <div style={{ width: 80, height: 5, background: '#e4e8ef', borderRadius: 3, overflow: 'hidden' }}>
                            <div style={{ height: '100%', background: SEV_BAR[s], borderRadius: 3, width: total > 0 ? `${(c / total) * 100}%` : '0%' }} />
                          </div>
                          <span style={{ fontSize: 11, fontWeight: 700, color: SEV_BAR[s], minWidth: 20, textAlign: 'right' }}>{c}</span>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })()}
          </div>
        )}

        {/* AD vulnerability and service identity posture */}
        <div className="section-label" style={{ marginBottom: 10 }}>AD vulnerability posture</div>
        {!snapshotId ? (
          <div style={{ color: '#8a9ab5', fontSize: 13, marginBottom: 20 }}>
            Complete an assessment to populate vulnerability and service identity analysis.
          </div>
        ) : (
          <div className="card" style={{ padding: 16, marginBottom: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 14 }}>
              <div style={{ border: '1px solid #fecaca', background: '#fef2f2', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#dc2626', lineHeight: 1 }}>{vulnBySeverity.critical}</div>
                <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 4 }}>Critical</div>
              </div>
              <div style={{ border: '1px solid #fed7aa', background: '#fff7ed', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#ea580c', lineHeight: 1 }}>{vulnBySeverity.high}</div>
                <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 4 }}>High</div>
              </div>
              <div style={{ border: '1px solid #fde68a', background: '#fffbeb', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#d97706', lineHeight: 1 }}>{vulnBySeverity.medium}</div>
                <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 4 }}>Medium</div>
              </div>
              <div style={{ border: '1px solid #d1d9e6', background: '#f8fafc', borderRadius: 8, padding: '10px 12px' }}>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#0f1923', lineHeight: 1 }}>{serviceIdentities.length}</div>
                <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginTop: 4 }}>Service IDs</div>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 14 }}>
              <div style={{ border: '1px solid #e4e8ef', borderRadius: 8, padding: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
                  Top vulnerability findings
                </div>
                {(vulnerabilities as ADVulnerability[]).length === 0 ? (
                  <div style={{ fontSize: 12, color: '#8a9ab5' }}>No vulnerability telemetry yet</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {[...vulnerabilities]
                      .sort((a, b) => {
                        const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
                        return ((rank[a.severity] ?? 5) - (rank[b.severity] ?? 5)) || (b.count - a.count)
                      })
                      .slice(0, 6)
                      .map((v) => (
                        <div key={v.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span className={`sev sev-${v.severity}`}>{v.severity}</span>
                          <span style={{ fontSize: 12, color: '#0f1923', flex: 1 }}>{v.title}</span>
                          <span style={{ fontSize: 11, fontWeight: 700, color: '#4b5c72' }}>{v.count}</span>
                        </div>
                      ))}
                  </div>
                )}
              </div>

              <div style={{ border: '1px solid #e4e8ef', borderRadius: 8, padding: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                  <Radar size={13} color="#2563eb" />
                  <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                    Service identity risk
                  </div>
                </div>
                <div style={{ marginBottom: 8, fontSize: 12, color: '#4b5c72' }}>
                  Privileged service accounts
                </div>
                <div style={{ fontSize: 30, fontWeight: 800, color: privilegedServiceAccounts > 0 ? '#dc2626' : '#16a34a', lineHeight: 1 }}>
                  {privilegedServiceAccounts}
                </div>
                <div style={{ height: 6, background: '#e4e8ef', borderRadius: 3, overflow: 'hidden', marginTop: 12 }}>
                  <div
                    style={{
                      width: `${serviceIdentities.length > 0 ? (privilegedServiceAccounts / serviceIdentities.length) * 100 : 0}%`,
                      height: '100%',
                      background: privilegedServiceAccounts > 0 ? '#dc2626' : '#16a34a',
                    }}
                  />
                </div>
                <div style={{ marginTop: 8, fontSize: 11, color: '#8a9ab5' }}>
                  {serviceIdentities.length} service identities enumerated
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Scan history */}
        <div className="section-label" style={{ marginBottom: 10 }}>Scan history</div>
        {scans.length === 0
          ? <div style={{ color: '#8a9ab5', fontSize: 13 }}>No scans yet — launch an assessment</div>
          : <div className="card" style={{ overflow: 'hidden' }}>
            <table className="data-table">
              <thead><tr><th>Domain</th><th>Status</th><th>Score</th><th>Findings</th><th>Date</th></tr></thead>
              <tbody>
                {scans.slice(0, 20).map(scan => (
                  <tr key={scan.id}>
                    <td className="primary">{scan.domain}</td>
                    <td>
                      <span className={`badge badge-${scan.status === 'completed' ? 'ok' : scan.status === 'running' ? 'info' : scan.status === 'failed' ? 'error' : 'neutral'}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td style={{ fontWeight: 700, color: scan.overall_score != null ? (scan.overall_score >= 70 ? '#16a34a' : scan.overall_score >= 40 ? '#d97706' : '#dc2626') : '#8a9ab5' }}>
                      {scan.overall_score ?? '—'}
                    </td>
                    <td>
                      {scan.status === 'completed' && (
                        <span style={{ fontSize: 12 }}>
                          <span style={{ color: '#dc2626', fontWeight: 600 }}>{scan.critical_count}C</span>
                          {' '}<span style={{ color: '#ea580c' }}>{scan.high_count}H</span>
                          {' '}<span style={{ color: '#d97706' }}>{scan.medium_count}M</span>
                        </span>
                      )}
                    </td>
                    <td style={{ color: '#8a9ab5', fontSize: 12 }}>
                      {scan.completed_at ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true }) : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        }
      </div>

      {showBulkDCInstall && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(15,25,35,0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 60,
            backdropFilter: 'blur(2px)',
          }}
          onClick={() => setShowBulkDCInstall(false)}
        >
          <div
            style={{
              width: 440,
              borderRadius: 12,
              background: '#ffffff',
              border: '1px solid #e4e8ef',
              padding: 22,
              boxShadow: '0 20px 60px rgba(15,25,35,0.18)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#0f1923' }}>Install Agents On All DCs</div>
                <div style={{ fontSize: 12, color: '#8a9ab5', marginTop: 4 }}>
                  Snapshot: {snapshotId} · Targeting mapped domain controllers
                </div>
              </div>
              <button className="btn-icon" onClick={() => setShowBulkDCInstall(false)}>
                <X size={14} />
              </button>
            </div>

            <div style={{ display: 'grid', gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', marginBottom: 6, display: 'block' }}>Domain admin username</label>
                <input
                  className="field"
                  value={bulkCreds.username}
                  onChange={(e) => setBulkCreds((prev) => ({ ...prev, username: e.target.value }))}
                  placeholder="Administrator"
                />
              </div>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', marginBottom: 6, display: 'block' }}>Password</label>
                <input
                  type="password"
                  className="field"
                  value={bulkCreds.password}
                  onChange={(e) => setBulkCreds((prev) => ({ ...prev, password: e.target.value }))}
                  placeholder="••••••••"
                />
              </div>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', marginBottom: 6, display: 'block' }}>Domain</label>
                <input
                  className="field"
                  value={bulkCreds.domain}
                  onChange={(e) => setBulkCreds((prev) => ({ ...prev, domain: e.target.value }))}
                  placeholder="corp.local"
                />
              </div>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', marginBottom: 6, display: 'block' }}>Agent name prefix</label>
                <input
                  className="field"
                  value={bulkCreds.agent_name_prefix}
                  onChange={(e) => setBulkCreds((prev) => ({ ...prev, agent_name_prefix: e.target.value }))}
                  placeholder="DC-Agent"
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 16 }}>
              <div style={{ fontSize: 11, color: '#8a9ab5', maxWidth: 260 }}>
                This queues one installer job per domain controller discovered in the selected snapshot.
              </div>
              <button
                className="btn btn-primary"
                disabled={!bulkCreds.username || !bulkCreds.password || !bulkCreds.domain || bulkInstallDCs.isPending || !snapshotId}
                onClick={() => bulkInstallDCs.mutate()}
              >
                {bulkInstallDCs.isPending ? <Loader2 size={13} className="spin" /> : <Server size={13} />}
                Queue installs
              </button>
            </div>

            {bulkInstallDCs.isError && (
              <div style={{ marginTop: 12, fontSize: 12, color: '#b91c1c', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 7, padding: '8px 10px' }}>
                Bulk install request failed. Check snapshot coverage, credentials, and resolver reachability.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

/* ─── Findings tab ──────────────────────────────────── */
function FindingsTab() {
  const [selectedScan, setSelectedScan] = useState('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const { data: scansData } = useQuery({ queryKey: ['scans'], queryFn: () => scansApi.list().then(r => r.data) })

  const completedScans = scansData?.scans?.filter(s => s.status === 'completed') ?? []

  // Auto-select the latest completed scan on first load
  const latestScanId = completedScans[0]?.id ?? ''
  const effectiveScan = selectedScan || latestScanId

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['findings', effectiveScan],
    queryFn: () => effectiveScan ? findingsApi.getByScan(effectiveScan).then(r => r.data) : findingsApi.list().then(r => r.data),
  })

  // Fetch full finding detail when one is selected
  const { data: fullFinding, isLoading: detailLoading } = useQuery({
    queryKey: ['finding-detail', selectedId],
    queryFn: () => findingsApi.get(selectedId!).then(r => r.data),
    enabled: !!selectedId,
  })

  const findings = findingsData?.findings ?? []

  const filtered = useMemo(() => {
    let list = [...findings]
    if (severity) list = list.filter(f => f.severity === severity)
    if (search) { const q = search.toLowerCase(); list = list.filter(f => f.name.toLowerCase().includes(q) || f.category.toLowerCase().includes(q)) }
    return list.sort((a, b) => { const o: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }; return (o[a.severity] ?? 5) - (o[b.severity] ?? 5) })
  }, [findings, severity, search])

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {}
    findings.forEach(f => { c[f.severity] = (c[f.severity] ?? 0) + 1 })
    return c
  }, [findings])

  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Severity summary strip */}
        {findings.length > 0 && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 20, padding: '10px 20px',
            background: '#ffffff', borderBottom: '1px solid #e4e8ef', flexShrink: 0,
          }}>
            <SeverityDonut counts={sevCounts} size={72} />
            <div style={{ display: 'flex', gap: 16 }}>
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(s => {
                const c = sevCounts[s] ?? 0
                return (
                  <button key={s} onClick={() => setSeverity(severity === s ? '' : s)} style={{
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
                    padding: '6px 10px', borderRadius: 8, cursor: 'pointer', border: 'none',
                    background: severity === s ? `${SEV_BAR[s]}14` : '#f4f6f9',
                    outline: severity === s ? `1px solid ${SEV_BAR[s]}44` : 'none',
                    transition: 'all 0.12s',
                  }}>
                    <div style={{ fontSize: 18, fontWeight: 800, color: c > 0 ? SEV_BAR[s] : '#d1d9e6', lineHeight: 1, letterSpacing: '-0.02em' }}>{c}</div>
                    <div style={{ fontSize: 9, fontWeight: 700, color: c > 0 ? SEV_BAR[s] : '#c0cad6', textTransform: 'capitalize', letterSpacing: '0.04em' }}>{s}</div>
                  </button>
                )
              })}
            </div>
            {(severity || search) && (
              <button className="btn btn-ghost" style={{ fontSize: 11, padding: '4px 10px', marginLeft: 'auto' }}
                onClick={() => { setSeverity(''); setSearch('') }}>
                Clear filters
              </button>
            )}
          </div>
        )}

        {/* Filter bar */}
        <div style={{
          padding: '10px 20px', background: '#fff', borderBottom: '1px solid #e4e8ef',
          display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap',
        }}>
          <select className="field" style={{ width: 220, flexShrink: 0 }} value={effectiveScan} onChange={e => setSelectedScan(e.target.value)}>
            <option value="">All scans</option>
            {completedScans.map(s => <option key={s.id} value={s.id}>{s.domain} — {s.completed_at ? format(new Date(s.completed_at), 'MMM d') : ''}</option>)}
          </select>

          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {(['', ...SEV_ORDER] as (Severity | '')[]).map(s => (
              <button key={s} onClick={() => setSeverity(s)} style={{
                padding: '4px 10px', borderRadius: 20, cursor: 'pointer', fontSize: 11, fontWeight: 600, transition: 'all 0.12s',
                background: severity === s ? (s ? `${SEV_BAR[s as Severity]}18` : '#1e40af') : '#f4f6f9',
                color: severity === s ? (s ? SEV_BAR[s as Severity] : '#fff') : '#8a9ab5',
                border: severity === s ? `1px solid ${s ? `${SEV_BAR[s as Severity]}40` : '#1e40af'}` : '1px solid #e4e8ef',
              }}>{s || 'All'}</button>
            ))}
          </div>

          <div style={{ position: 'relative', flex: 1, minWidth: 160 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#8a9ab5', pointerEvents: 'none' }} />
            <input className="field" style={{ paddingLeft: 30 }} placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          <div style={{ fontSize: 12, color: '#8a9ab5', whiteSpace: 'nowrap', fontWeight: 500 }}>
            {filtered.length} {filtered.length === 1 ? 'finding' : 'findings'}
          </div>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflowY: 'auto', background: '#f4f6f9' }}>
          {isLoading ? (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 3 }}>
              {[...Array(10)].map((_, i) => <div key={i} className="skeleton" style={{ height: 42 }} />)}
            </div>
          ) : filtered.length === 0 ? (
            <div style={{ padding: 60, textAlign: 'center', color: '#8a9ab5', fontSize: 13 }}>
              {findings.length === 0 ? 'No findings — run an assessment first' : 'No findings match this filter'}
            </div>
          ) : (
            <div className="card" style={{ margin: 16, overflow: 'hidden' }}>
              <table className="data-table">
                <thead><tr><th>Severity</th><th>Finding</th><th>Category</th><th>Objects affected</th><th style={{ width: 30 }}></th></tr></thead>
                <tbody>
                  {filtered.map(f => (
                    <tr key={f.id} onClick={() => setSelectedId(f.id)} style={{ background: selectedId === f.id ? '#f0f6ff' : undefined }}>
                      <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                      <td className="primary">{f.name}</td>
                      <td>{f.category}</td>
                      <td style={{ color: '#8a9ab5' }}>{f.affected_objects?.length ?? 0}</td>
                      <td><ChevronRight size={14} color="#c4cdd8" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Detail drawer */}
      {selectedId && (
        <div style={{ width: 380, flexShrink: 0, background: '#fff', borderLeft: '1px solid #e4e8ef', overflowY: 'auto', display: 'flex', flexDirection: 'column' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #e4e8ef', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            {fullFinding && <span className={`sev sev-${fullFinding.severity}`}>{fullFinding.severity}</span>}
            <button className="btn-icon" onClick={() => setSelectedId(null)}><X size={15} /></button>
          </div>
          {detailLoading ? (
            <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 28 }} />)}
            </div>
          ) : fullFinding ? (
            <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div>
                <div style={{ fontSize: 15, fontWeight: 700, color: '#0f1923', marginBottom: 6 }}>{fullFinding.name}</div>
                <div style={{ fontSize: 12.5, color: '#4b5c72', lineHeight: 1.65 }}>{fullFinding.description}</div>
              </div>
              {fullFinding.affected_objects?.length > 0 && (
                <div>
                  <div className="section-label" style={{ marginBottom: 8 }}>Affected objects ({fullFinding.affected_objects.length})</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                    {fullFinding.affected_objects.slice(0, 10).map((obj, i) => (
                      <div key={i} style={{ fontSize: 11.5, color: '#4b5c72', background: '#f4f6f9', padding: '6px 10px', borderRadius: 5, fontFamily: 'monospace', border: '1px solid #e4e8ef' }}>
                        {obj.name || obj.dn}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {fullFinding.remediation && (
                <div>
                  <div className="section-label" style={{ marginBottom: 8 }}>Remediation</div>
                  <div style={{ fontSize: 12.5, color: '#4b5c72', lineHeight: 1.65, background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: 7, padding: '10px 12px' }}>
                    {fullFinding.remediation}
                  </div>
                </div>
              )}
              {fullFinding.mitre?.length > 0 && (
                <div>
                  <div className="section-label" style={{ marginBottom: 8 }}>MITRE ATT&CK</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                    {fullFinding.mitre.map(m => (
                      <span key={m} style={{ fontSize: 11, padding: '3px 8px', borderRadius: 4, background: '#eff6ff', color: '#1d4ed8', border: '1px solid #bfdbfe', fontWeight: 600 }}>{m}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}
