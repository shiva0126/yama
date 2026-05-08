import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { AlertTriangle, FileArchive, Flame, Shield, Zap } from 'lucide-react'
import { defenseApi, evidenceApi } from '../../api'
import type { CollectorAgent, DefenseDetection, DefenseIncident, EvidenceBundle, ResponseAction, Severity } from '../../types'
import { CategoryBars } from '../Charts'

type Tab = 'active' | 'incidents' | 'catalog' | 'response' | 'evidence'

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0891b2', info: '#8a9ab5',
}
const SEV_BG: Record<string, string> = {
  critical: '#fef2f2', high: '#fff7ed', medium: '#fffbeb', low: '#ecfeff', info: '#f8fafc',
}

export function Defend() {
  const [tab, setTab] = useState<Tab>('active')

  const { data: summary } = useQuery({
    queryKey: ['defense-summary'],
    queryFn: () => defenseApi.summary().then(r => r.data),
    refetchInterval: 30_000,
  })
  const { data: incidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then(r => r.data),
    refetchInterval: 15_000,
  })
  const { data: detections } = useQuery({
    queryKey: ['defense-detections'],
    queryFn: () => defenseApi.detections().then(r => r.data),
    refetchInterval: 15_000,
  })
  const { data: catalog } = useQuery({
    queryKey: ['defense-catalog'],
    queryFn: () => defenseApi.catalog().then(r => r.data),
    enabled: tab === 'catalog',
  })
  const { data: responses } = useQuery({
    queryKey: ['defense-responses'],
    queryFn: () => defenseApi.responses().then(r => r.data),
    refetchInterval: 15_000,
  })
  const { data: defenseAgents } = useQuery({
    queryKey: ['defense-agents'],
    queryFn: () => defenseApi.agents().then(r => r.data),
    refetchInterval: 15_000,
  })
  const { data: evidence } = useQuery({
    queryKey: ['defense-evidence'],
    queryFn: () => evidenceApi.list().then(r => r.data),
    refetchInterval: 20_000,
  })

  const openIncidents = incidents?.filter(i => i.status === 'open') ?? []

  const tabs: { id: Tab; label: string; icon: JSX.Element; count?: number }[] = [
    { id: 'active',    label: 'Active',    icon: <Zap size={13} />,           count: openIncidents.length },
    { id: 'incidents', label: 'Incidents', icon: <AlertTriangle size={13} />, count: incidents?.length },
    { id: 'catalog',   label: 'Catalog',   icon: <Flame size={13} />,         count: summary?.detector_count },
    { id: 'response',  label: 'Response',  icon: <Shield size={13} />,        count: responses?.length },
    { id: 'evidence',  label: 'Evidence',  icon: <FileArchive size={13} />,   count: evidence?.total },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#f4f6f9' }}>
      {/* Tab bar */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid #e4e8ef',
        padding: '0 24px', background: '#ffffff', flexShrink: 0,
      }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '12px 16px', fontSize: 13, fontWeight: 500,
              background: 'none', border: 'none', cursor: 'pointer',
              borderBottom: tab === t.id ? '2px solid #2563eb' : '2px solid transparent',
              color: tab === t.id ? '#2563eb' : '#4b5c72',
              marginBottom: -1, transition: 'color 0.15s',
            }}
          >
            <span style={{ opacity: 0.8 }}>{t.icon}</span>
            {t.label}
            {t.count != null && t.count > 0 && (
              <span style={{
                fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10,
                background: t.id === 'active' && openIncidents.length > 0 ? '#fef2f2' : '#eff6ff',
                color: t.id === 'active' && openIncidents.length > 0 ? '#dc2626' : '#2563eb',
              }}>
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflow: 'hidden' }}>
        {tab === 'active'    && <ActiveTab    incidents={openIncidents} detections={detections ?? []} />}
        {tab === 'incidents' && <IncidentsTab incidents={incidents ?? []} />}
        {tab === 'catalog'   && <CatalogTab   catalog={catalog} summary={summary} />}
        {tab === 'response'  && <ResponseTab  summary={summary} responses={responses ?? []} agents={defenseAgents ?? []} />}
        {tab === 'evidence'  && <EvidenceTab  bundles={evidence?.items ?? []} />}
      </div>
    </div>
  )
}

/* ─── Active tab ───────────────────────────────────────── */
function ActiveTab({ incidents, detections }: { incidents: DefenseIncident[]; detections: DefenseDetection[] }) {
  return (
    <div style={{ display: 'flex', height: '100%', overflow: 'hidden' }}>
      {/* Incident queue */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', borderRight: '1px solid #e4e8ef' }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 14 }}>
          Open incidents
        </div>
        {incidents.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '60px 0', color: '#8a9ab5' }}>
            <Shield size={36} style={{ opacity: 0.25, margin: '0 auto 12px', display: 'block', color: '#2563eb' }} />
            <div style={{ fontSize: 13, fontWeight: 500, color: '#4b5c72', marginBottom: 4 }}>All clear</div>
            <div style={{ fontSize: 12 }}>No active incidents detected</div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {incidents.map(inc => <IncidentCard key={inc.id} incident={inc} />)}
          </div>
        )}
      </div>

      {/* Detection stream */}
      <div style={{ width: 320, flexShrink: 0, overflowY: 'auto', padding: '20px 16px', background: '#f9fafb' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 14 }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%', background: '#dc2626', flexShrink: 0,
            boxShadow: '0 0 0 3px rgba(220,38,38,0.2)',
          }} />
          <span style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Detection stream
          </span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {detections.length === 0 ? (
            <div style={{ color: '#8a9ab5', fontSize: 12, padding: '12px 0' }}>No recent detections</div>
          ) : detections.map(d => (
            <div key={d.id} style={{
              padding: '10px 12px', borderRadius: 8,
              background: '#ffffff',
              border: '1px solid #e4e8ef',
              boxShadow: '0 1px 3px rgba(15,25,35,0.04)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <span className={`sev sev-${d.severity}`}>{d.severity}</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#0f1923', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {d.title}
                </span>
              </div>
              <div style={{ fontSize: 10, color: '#8a9ab5' }}>
                {d.actor} → {d.target} · {formatDistanceToNow(new Date(d.occurred_at), { addSuffix: true })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function IncidentCard({ incident }: { incident: DefenseIncident }) {
  const sev = incident.severity as string
  return (
    <div style={{
      padding: '14px 16px', borderRadius: 10,
      background: SEV_BG[sev] ?? '#ffffff',
      border: `1px solid ${SEV_COLOR[sev] ? SEV_COLOR[sev] + '33' : '#e4e8ef'}`,
      boxShadow: '0 1px 4px rgba(15,25,35,0.05)',
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span className={`sev sev-${incident.severity}`}>{incident.severity}</span>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>{incident.title}</span>
          </div>
          <div style={{ fontSize: 11, color: '#4b5c72', marginBottom: 3 }}>
            {incident.primary_actor} → {incident.primary_target}
          </div>
          <div style={{ fontSize: 10, color: '#8a9ab5' }}>
            {formatDistanceToNow(new Date(incident.opened_at), { addSuffix: true })} ·{' '}
            {incident.detection_ids?.length ?? 0} detection{incident.detection_ids?.length !== 1 ? 's' : ''}
          </div>
        </div>
        <button className="btn btn-danger" style={{ padding: '5px 12px', fontSize: 11, flexShrink: 0 }}>Respond</button>
      </div>
    </div>
  )
}

/* ─── Incidents tab ────────────────────────────────────── */
function IncidentsTab({ incidents }: { incidents: DefenseIncident[] }) {
  const [filter, setFilter] = useState<Severity | ''>('')
  const filtered = filter ? incidents.filter(i => i.severity === filter) : incidents

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{
        padding: '10px 24px', borderBottom: '1px solid #e4e8ef',
        display: 'flex', gap: 6, alignItems: 'center', background: '#ffffff', flexShrink: 0,
      }}>
        {(['', 'critical', 'high', 'medium', 'low'] as (Severity | '')[]).map(s => (
          <button key={s} onClick={() => setFilter(s)} style={{
            padding: '5px 12px', borderRadius: 6, border: `1px solid ${filter === s ? (s ? SEV_COLOR[s] + '66' : '#b8c4d9') : '#e4e8ef'}`,
            cursor: 'pointer', fontSize: 11, fontWeight: 600,
            background: filter === s ? (s ? SEV_BG[s] : '#f0f3f8') : '#ffffff',
            color: filter === s ? (s ? SEV_COLOR[s] : '#0f1923') : '#4b5c72',
            transition: 'all 0.15s',
          }}>
            {s ? s.charAt(0).toUpperCase() + s.slice(1) : 'All'}
          </button>
        ))}
        <span style={{ fontSize: 12, color: '#8a9ab5', marginLeft: 6 }}>
          {filtered.length} incident{filtered.length !== 1 ? 's' : ''}
        </span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        <table className="data-table">
          <thead>
            <tr><th>Severity</th><th>Title</th><th>Actor → Target</th><th>Status</th><th>Detections</th><th>Opened</th></tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: '40px 0', color: '#8a9ab5', fontSize: 13 }}>No incidents</td></tr>
            ) : filtered.map(inc => (
              <tr key={inc.id}>
                <td><span className={`sev sev-${inc.severity}`}>{inc.severity}</span></td>
                <td style={{ fontWeight: 500, color: '#0f1923' }}>{inc.title}</td>
                <td style={{ color: '#4b5c72', fontSize: 12 }}>{inc.primary_actor} → {inc.primary_target}</td>
                <td>
                  <span style={{
                    fontSize: 11, fontWeight: 600, textTransform: 'capitalize',
                    color: inc.status === 'open' ? '#dc2626' : '#16a34a',
                  }}>
                    {inc.status}
                  </span>
                </td>
                <td style={{ color: '#4b5c72' }}>{inc.detection_ids?.length ?? 0}</td>
                <td style={{ fontSize: 12, color: '#8a9ab5' }}>
                  {formatDistanceToNow(new Date(inc.opened_at), { addSuffix: true })}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/* ─── Catalog tab ──────────────────────────────────────── */
function CatalogTab({ catalog, summary }: { catalog: any; summary: any }) {
  if (!catalog) return (
    <div style={{ padding: '24px' }}>
      {[...Array(5)].map((_, i) => <div key={i} className="skeleton" style={{ height: 60, marginBottom: 8 }} />)}
    </div>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Stats strip */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 0, borderBottom: '1px solid #e4e8ef', flexShrink: 0, background: '#ffffff',
      }}>
        {[
          { label: 'Families',   value: summary?.family_count ?? 0,     color: '#2563eb' },
          { label: 'Detectors',  value: summary?.detector_count ?? 0,   color: '#0f1923' },
          { label: 'Critical',   value: summary?.critical_count ?? 0,   color: '#dc2626' },
          { label: 'Demo ready', value: summary?.demo_ready_count ?? 0, color: '#16a34a' },
        ].map((s, i) => (
          <div key={s.label} style={{
            padding: '18px 24px', textAlign: 'center',
            borderRight: i < 3 ? '1px solid #e4e8ef' : 'none',
          }}>
            <div style={{ fontSize: 26, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</div>
            <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600, marginTop: 4 }}>{s.label}</div>
          </div>
        ))}
      </div>

      {/* Family breakdown */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
          Attack families
        </div>
        <div className="card" style={{ padding: '18px 20px' }}>
          <CategoryBars
            data={Object.entries(summary?.by_family ?? {}).map(([name, count]) => ({
              name,
              count: count as number,
              color: '#2563eb',
            }))}
          />
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 16 }}>
          {Object.entries(summary?.by_family ?? {}).map(([family, count]) => (
            <div key={family} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 14px', background: '#ffffff',
              border: '1px solid #e4e8ef', borderRadius: 8,
            }}>
              <div style={{ fontSize: 13, color: '#0f1923', fontWeight: 500 }}>{family}</div>
              <span style={{ fontSize: 12, color: '#4b5c72', fontWeight: 600 }}>
                {count as number}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

/* ─── Response tab ─────────────────────────────────────── */
function ResponseTab({ summary, responses, agents }: { summary: any; responses: ResponseAction[]; agents: CollectorAgent[] }) {
  const profiles = Object.entries(summary?.response_profiles ?? {})
  const onlineAgents = agents.filter((agent) => agent.status === 'online').length
  return (
    <div style={{ padding: '24px' }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
        Response profiles
      </div>
      {profiles.length === 0 ? (
        <div style={{ color: '#8a9ab5', fontSize: 13 }}>No response profiles defined</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
          {profiles.map(([profile, count]) => (
            <div key={profile} style={{
              padding: '16px', background: '#ffffff',
              border: '1px solid #e4e8ef', borderRadius: 10,
              boxShadow: '0 1px 3px rgba(15,25,35,0.04)',
            }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: '#0f1923', marginBottom: 5, textTransform: 'capitalize' }}>
                {profile.replace(/_/g, ' ')}
              </div>
              <div style={{ fontSize: 12, color: '#8a9ab5' }}>
                {count as number} detector{(count as number) !== 1 ? 's' : ''}
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', margin: '24px 0 10px' }}>
        Action execution · {onlineAgents}/{agents.length} agents online
      </div>
      {responses.length === 0 ? (
        <div style={{ color: '#8a9ab5', fontSize: 13 }}>No response actions planned yet</div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr><th>Action</th><th>Target</th><th>Mode</th><th>Status</th><th>Executed</th></tr>
            </thead>
            <tbody>
              {responses.slice(0, 50).map(action => (
                <tr key={action.id}>
                  <td style={{ color: '#0f1923', fontWeight: 500 }}>{action.action_type}</td>
                  <td style={{ color: '#4b5c72', fontFamily: 'monospace', fontSize: 11 }}>{action.target_value || '—'}</td>
                  <td style={{ color: '#4b5c72', textTransform: 'capitalize' }}>{action.mode}</td>
                  <td style={{ textTransform: 'capitalize' }}>
                    <span className={`badge ${action.status === 'completed' ? 'badge-ok' : action.status === 'failed' ? 'badge-error' : action.status === 'executing' ? 'badge-info' : 'badge-neutral'}`}>
                      {action.status}
                    </span>
                  </td>
                  <td style={{ color: '#8a9ab5', fontSize: 12 }}>
                    {action.executed_at ? formatDistanceToNow(new Date(action.executed_at), { addSuffix: true }) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/* ─── Evidence tab ─────────────────────────────────────── */
function EvidenceTab({ bundles }: { bundles: EvidenceBundle[] }) {
  return (
    <div style={{ padding: '24px' }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 16 }}>
        Evidence bundles
      </div>
      {bundles.length === 0 ? (
        <div style={{ color: '#8a9ab5', fontSize: 13 }}>No evidence collected yet</div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="data-table">
            <thead>
              <tr><th>Incident</th><th>Storage key</th><th>Size</th><th>SHA256</th><th>Created</th></tr>
            </thead>
            <tbody>
              {bundles.slice(0, 100).map(bundle => (
                <tr key={bundle.id}>
                  <td style={{ fontFamily: 'monospace', fontSize: 11, color: '#0f1923', fontWeight: 500 }}>{bundle.incident_id || '—'}</td>
                  <td style={{ color: '#4b5c72', fontFamily: 'monospace', fontSize: 11 }}>{bundle.storage_key}</td>
                  <td style={{ color: '#4b5c72' }}>{bundle.size_bytes} B</td>
                  <td style={{ color: '#8a9ab5', fontFamily: 'monospace', fontSize: 11 }}>{bundle.sha256.slice(0, 12)}…</td>
                  <td style={{ fontSize: 12, color: '#8a9ab5' }}>
                    {bundle.created_at ? formatDistanceToNow(new Date(bundle.created_at), { addSuffix: true }) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
