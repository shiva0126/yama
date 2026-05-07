import { useEffect, useState, type ReactNode, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import ReactFlow, {
  Background, BackgroundVariant, Controls, MiniMap,
  useEdgesState, useNodesState, type Edge, type Node,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { formatDistanceToNow } from 'date-fns'
import { AlertTriangle, Maximize2, Radio, Server, Shield, Wifi, WifiOff, X, Zap } from 'lucide-react'
import { agentsApi, defenseApi, inventoryApi, overviewApi, scansApi } from '../../api'
import type { CollectorAgent, DefenseIncident } from '../../types'
import { ScoreGauge, SeverityDonut } from '../Charts'
import { useTheme } from '../../contexts/ThemeContext'

/* ─── Topology builder ──────────────────────────────────── */
function buildGraph(
  topo: any,
  agents: CollectorAgent[],
  incidents: DefenseIncident[],
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []
  const hasThreat = incidents.length > 0

  nodes.push({
    id: 'domain', type: 'default', position: { x: 320, y: 20 },
    data: { label: topo.domain?.fqdn ?? topo.domain?.name ?? 'Domain' },
    style: {
      background: hasThreat ? 'rgba(220,38,38,0.18)' : 'rgba(37,99,235,0.2)',
      border: `2px solid ${hasThreat ? 'rgba(220,38,38,0.55)' : 'rgba(37,99,235,0.6)'}`,
      color: '#e2ecf6', borderRadius: 10, padding: '10px 22px',
      fontSize: 13, fontWeight: 700, minWidth: 150, textAlign: 'center',
    },
  })

  ;(topo.sites ?? []).forEach((site: any, si: number) => {
    const siteId = `site-${si}`
    nodes.push({
      id: siteId, type: 'default', position: { x: si * 340, y: 140 },
      data: { label: site.name ?? `Site ${si + 1}` },
      style: {
        background: '#142236', border: '1px solid rgba(255,255,255,0.12)',
        color: '#8ba0b8', borderRadius: 8, padding: '7px 14px', fontSize: 12,
      },
    })
    edges.push({ id: `d-${siteId}`, source: 'domain', target: siteId, style: { stroke: 'rgba(255,255,255,0.15)' } })
    ;(site.domain_controllers ?? []).forEach((dc: any, di: number) => {
      const dcId = `dc-${si}-${di}`
      nodes.push({
        id: dcId, type: 'default',
        position: { x: si * 340 + di * 180 - ((site.domain_controllers.length - 1) * 90), y: 270 },
        data: { label: dc.host_name ?? dc.name ?? 'DC' },
        style: {
          background: dc.is_global_catalog ? 'rgba(37,99,235,0.15)' : '#0d1826',
          border: `1px solid ${dc.is_global_catalog ? 'rgba(59,130,246,0.4)' : 'rgba(255,255,255,0.1)'}`,
          color: dc.is_global_catalog ? '#93c5fd' : '#6b8299',
          borderRadius: 7, padding: '6px 12px', fontSize: 11,
        },
      })
      edges.push({ id: `s-${dcId}`, source: siteId, target: dcId, style: { stroke: 'rgba(255,255,255,0.08)' } })
    })
  })

  agents.forEach((ag, ai) => {
    const online = ag.status === 'online'
    const agId = `ag-${ai}`
    nodes.push({
      id: agId, type: 'default', position: { x: 680 + ai * 160, y: 20 },
      data: { label: ag.name ?? ag.hostname },
      style: {
        background: online ? 'rgba(22,163,74,0.14)' : 'rgba(220,38,38,0.1)',
        border: `1px solid ${online ? 'rgba(22,163,74,0.4)' : 'rgba(220,38,38,0.3)'}`,
        color: online ? '#86efac' : '#fca5a5', borderRadius: 7, padding: '6px 12px', fontSize: 11,
      },
    })
    edges.push({
      id: `ag-${agId}`, source: 'domain', target: agId,
      style: { stroke: online ? 'rgba(22,163,74,0.4)' : 'rgba(220,38,38,0.25)', strokeDasharray: '5 3' },
    })
  })

  return { nodes, edges }
}

/* ─── Main component ─────────────────────────────────────── */
export function Overview() {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [mapExpanded, setMapExpanded] = useState(false)
  const { theme } = useTheme()
  const isDarkMap = theme.mapStyle === 'dark'

  const { data: overview }  = useQuery({ queryKey: ['overview'],          queryFn: () => overviewApi.summary().then(r => r.data),  refetchInterval: 15_000 })
  const { data: scansData } = useQuery({ queryKey: ['scans'],             queryFn: () => scansApi.list().then(r => r.data),        refetchInterval: 15_000 })
  const { data: agentsData }= useQuery({ queryKey: ['agents'],            queryFn: () => agentsApi.list().then(r => r.data),       refetchInterval: 10_000 })
  const { data: defSummary }= useQuery({ queryKey: ['defense-summary'],   queryFn: () => defenseApi.summary().then(r => r.data),   refetchInterval: 30_000 })
  const { data: incidents } = useQuery({ queryKey: ['defense-incidents'], queryFn: () => defenseApi.incidents().then(r => r.data), refetchInterval: 15_000 })

  const latestScan     = scansData?.scans?.find(s => s.status === 'completed')
  const { data: topo } = useQuery({
    queryKey: ['topology', latestScan?.snapshot_id],
    queryFn:  () => inventoryApi.getTopology(latestScan!.snapshot_id!).then(r => r.data),
    enabled:  !!latestScan?.snapshot_id,
  })

  useEffect(() => {
    if (!topo) return
    const { nodes: n, edges: e } = buildGraph(topo, agentsData?.agents ?? [], incidents ?? [])
    setNodes(n); setEdges(e)
  }, [topo, agentsData, incidents, setNodes, setEdges])

  const agents      = agentsData?.agents ?? []
  const online      = agents.filter(a => a.status === 'online').length
  const score       = latestScan?.overall_score ?? overview?.scans?.latest_completed?.overall_score
  const critCount   = latestScan?.critical_count ?? overview?.findings?.critical ?? 0
  const activeInc   = (incidents ?? []).filter(i => i.status === 'open').length
  const scoreColor  = score == null ? '#8a9ab5' : score >= 70 ? '#16a34a' : score >= 40 ? '#d97706' : '#dc2626'

  const sev = {
    critical: latestScan?.critical_count ?? 0,
    high:     latestScan?.high_count     ?? 0,
    medium:   latestScan?.medium_count   ?? 0,
    low:      latestScan?.low_count      ?? 0,
    info:     latestScan?.info_count     ?? 0,
  }
  const totalFindings = Object.values(sev).reduce((a, b) => a + b, 0)

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', background: '#f4f6f9' }}>

      {/* ── KPI row ──────────────────────────────────────── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 0, flexShrink: 0,
        borderBottom: '1px solid #e4e8ef', background: '#ffffff',
      }}>
        {/* Security Score */}
        <KpiCard border="left: 3px solid #2563eb">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <Shield size={14} color="#2563eb" />
            <span style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Security Score
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <ScoreGauge score={score ?? 0} size={96} />
            <div>
              <div style={{ fontSize: 11, color: '#4b5c72', marginBottom: 2 }}>
                {latestScan ? `Assessed ${formatDistanceToNow(new Date(latestScan.completed_at!), { addSuffix: true })}` : 'No assessment yet'}
              </div>
              <div style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                fontSize: 11, fontWeight: 600, padding: '3px 8px', borderRadius: 5,
                background: score == null ? '#f4f6f9' : score >= 70 ? '#f0fdf4' : score >= 40 ? '#fffbeb' : '#fef2f2',
                color: scoreColor,
                border: `1px solid ${score == null ? '#e4e8ef' : score >= 70 ? '#bbf7d0' : score >= 40 ? '#fde68a' : '#fecaca'}`,
              }}>
                {score == null ? 'Not assessed' : score >= 70 ? 'Healthy' : score >= 40 ? 'At risk' : 'Critical'}
              </div>
            </div>
          </div>
        </KpiCard>

        {/* Critical Exposures */}
        <KpiCard border={`left: 3px solid ${critCount > 0 ? '#dc2626' : '#e4e8ef'}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <AlertTriangle size={14} color={critCount > 0 ? '#dc2626' : '#8a9ab5'} />
            <span style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Exposures
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            {totalFindings > 0
              ? <SeverityDonut counts={sev} size={72} />
              : (
                <div style={{
                  width: 72, height: 72, borderRadius: '50%',
                  background: '#f0fdf4', border: '2px solid #bbf7d0',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexShrink: 0,
                }}>
                  <span style={{ fontSize: 11, fontWeight: 700, color: '#16a34a' }}>Clean</span>
                </div>
              )}
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 32, fontWeight: 800, color: critCount > 0 ? '#dc2626' : '#16a34a', letterSpacing: '-0.03em', lineHeight: 1 }}>
                {critCount}
              </div>
              <div style={{ fontSize: 11, color: '#8a9ab5', marginTop: 4 }}>critical</div>
              {totalFindings > 0 && (
                <div style={{ fontSize: 11, color: '#4b5c72', marginTop: 2 }}>{totalFindings} total</div>
              )}
            </div>
          </div>
        </KpiCard>

        {/* Active Incidents */}
        <KpiCard border={`left: 3px solid ${activeInc > 0 ? '#dc2626' : '#e4e8ef'}`}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Zap size={14} color={activeInc > 0 ? '#dc2626' : '#8a9ab5'} />
              <span style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Incidents
              </span>
            </div>
            {activeInc > 0 && (
              <span style={{ fontSize: 9, fontWeight: 700, color: '#dc2626', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 4, padding: '2px 7px', letterSpacing: '0.06em' }}>
                LIVE
              </span>
            )}
          </div>
          <div style={{ fontSize: 44, fontWeight: 800, color: activeInc > 0 ? '#dc2626' : '#16a34a', letterSpacing: '-0.04em', lineHeight: 1, marginBottom: 6 }}>
            {activeInc}
          </div>
          <div style={{ fontSize: 11, color: '#8a9ab5' }}>
            {defSummary?.detector_count ?? 0} detectors armed
          </div>
          {activeInc === 0 && (
            <div style={{ fontSize: 11, fontWeight: 600, color: '#16a34a', marginTop: 4 }}>All clear</div>
          )}
        </KpiCard>

        {/* Agents */}
        <KpiCard border={`left: 3px solid ${agents.length === 0 ? '#e4e8ef' : online === agents.length ? '#16a34a' : '#d97706'}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <Radio size={14} color={agents.length === 0 ? '#8a9ab5' : online === agents.length ? '#16a34a' : '#d97706'} />
            <span style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
              Agents
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 4, marginBottom: 8 }}>
            <span style={{ fontSize: 44, fontWeight: 800, color: '#0f1923', letterSpacing: '-0.04em', lineHeight: 1 }}>{online}</span>
            <span style={{ fontSize: 18, fontWeight: 500, color: '#8a9ab5' }}>/ {agents.length}</span>
          </div>
          {agents.length > 0 ? (
            <>
              <div style={{ height: 6, background: '#e4e8ef', borderRadius: 3, overflow: 'hidden', marginBottom: 6 }}>
                <div style={{
                  height: '100%', borderRadius: 3, transition: 'width 0.5s',
                  background: online === agents.length ? '#16a34a' : '#d97706',
                  width: `${(online / agents.length) * 100}%`,
                }} />
              </div>
              <div style={{ fontSize: 11, color: '#8a9ab5' }}>
                {online === agents.length ? 'All agents online' : `${agents.length - online} offline`}
              </div>
            </>
          ) : (
            <div style={{ fontSize: 11, color: '#8a9ab5' }}>No agents deployed</div>
          )}
        </KpiCard>
      </div>

      {/* ── Main area: left content + right panel ─────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', gap: 0 }}>

        {/* Map section */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: 20, gap: 16 }}>

          {/* Map card */}
          <div style={{
            flex: 1, borderRadius: 10, overflow: 'hidden',
            border: '1px solid #e4e8ef',
            boxShadow: '0 1px 4px rgba(15,25,35,0.06)',
            position: 'relative', display: 'flex', flexDirection: 'column',
            minHeight: 0,
          }}>
            {/* Map header */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 16px', background: '#ffffff', borderBottom: '1px solid #e4e8ef',
              flexShrink: 0,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: topo ? '#16a34a' : '#d97706' }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: '#0f1923' }}>AD Topology Map</span>
                {latestScan && (
                  <span style={{ fontSize: 11, color: '#8a9ab5' }}>
                    — {latestScan.domain}
                  </span>
                )}
              </div>
              <button
                onClick={() => setMapExpanded(true)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8a9ab5', padding: 4, display: 'flex' }}
                title="Expand map"
              >
                <Maximize2 size={13} />
              </button>
            </div>

            {/* Map canvas */}
            <div style={{ flex: 1, minHeight: 0 }} className={isDarkMap ? 'reactflow-dark' : ''}>
              {!topo ? (
                <div style={{
                  height: '100%', display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center', gap: 14,
                  background: isDarkMap ? '#07101a' : '#f8fafc',
                }}>
                  <Server size={40} style={{ opacity: 0.2, color: isDarkMap ? '#2563eb' : '#94a3b8' }} />
                  <div style={{ fontSize: 14, fontWeight: 600, color: isDarkMap ? '#1e3a5f' : '#64748b' }}>
                    {latestScan ? 'Building topology…' : 'No assessment data'}
                  </div>
                  <div style={{ fontSize: 12, color: isDarkMap ? '#12253a' : '#94a3b8', maxWidth: 260, textAlign: 'center' }}>
                    Run an assessment to visualise your AD topology
                  </div>
                </div>
              ) : (
                <ReactFlow
                  nodes={nodes} edges={edges}
                  onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                  fitView fitViewOptions={{ padding: 0.2 }}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background variant={BackgroundVariant.Dots} color="rgba(255,255,255,0.03)" gap={28} size={1} />
                  <Controls showInteractive={false} />
                  <MiniMap nodeColor={n => n.id.startsWith('ag') ? '#22c55e' : n.id === 'domain' ? '#2563eb' : '#1e3a5f'} maskColor="rgba(7,16,26,0.7)" />
                </ReactFlow>
              )}
            </div>
          </div>
        </div>

        {/* ── Right panel — white ──────────────────────── */}
        <div style={{
          width: 300, flexShrink: 0, overflowY: 'auto',
          borderLeft: '1px solid #e4e8ef',
          background: '#f4f6f9',
          padding: 16, display: 'flex', flexDirection: 'column', gap: 14,
        }}>

          {/* Exposure breakdown */}
          {totalFindings > 0 && (
            <div style={{ background: '#fff', border: '1px solid #e4e8ef', borderRadius: 10, padding: 16, boxShadow: '0 1px 3px rgba(15,25,35,0.04)' }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 14 }}>
                Exposure breakdown
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                <SeverityDonut counts={sev} size={88} />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 7 }}>
                  {(['critical', 'high', 'medium', 'low'] as const).map(s => {
                    const COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#0284c7' }
                    const c = sev[s]
                    if (!c) return null
                    return (
                      <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <span style={{ width: 7, height: 7, borderRadius: '50%', background: COLORS[s], flexShrink: 0 }} />
                        <span style={{ fontSize: 11, color: '#4b5c72', flex: 1, textTransform: 'capitalize' }}>{s}</span>
                        <div style={{ width: 48, height: 4, background: '#e4e8ef', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ height: '100%', background: COLORS[s], width: `${(c / totalFindings) * 100}%` }} />
                        </div>
                        <span style={{ fontSize: 11, fontWeight: 700, color: COLORS[s], minWidth: 20, textAlign: 'right' }}>{c}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Agent fleet */}
          <div style={{ background: '#fff', border: '1px solid #e4e8ef', borderRadius: 10, padding: 16, boxShadow: '0 1px 3px rgba(15,25,35,0.04)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Agent fleet
              </div>
              <span style={{ fontSize: 11, fontWeight: 600, color: online === agents.length && agents.length > 0 ? '#16a34a' : '#8a9ab5' }}>
                {online}/{agents.length}
              </span>
            </div>
            {agents.length === 0 ? (
              <div style={{ fontSize: 12, color: '#8a9ab5', padding: '8px 0' }}>No agents registered</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {agents.map(ag => (
                  <div key={ag.id} style={{
                    display: 'flex', alignItems: 'center', gap: 9,
                    padding: '8px 10px', borderRadius: 7,
                    background: '#f9fafb', border: '1px solid #e4e8ef',
                  }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: 7, flexShrink: 0,
                      background: ag.status === 'online' ? '#f0fdf4' : '#fef2f2',
                      border: `1px solid ${ag.status === 'online' ? '#bbf7d0' : '#fecaca'}`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                    }}>
                      {ag.status === 'online'
                        ? <Wifi size={12} color="#16a34a" />
                        : <WifiOff size={12} color="#dc2626" />}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, fontWeight: 500, color: '#0f1923', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ag.name ?? ag.hostname}
                      </div>
                      <div style={{ fontSize: 10, color: '#8a9ab5' }}>{ag.domain}</div>
                    </div>
                    <div style={{
                      fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
                      color: ag.status === 'online' ? '#16a34a' : '#dc2626',
                    }}>
                      {ag.status}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Live incident feed */}
          <div style={{ background: '#fff', border: '1px solid #e4e8ef', borderRadius: 10, padding: 16, boxShadow: '0 1px 3px rgba(15,25,35,0.04)', flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                Live incidents
              </div>
              {activeInc > 0 && (
                <div style={{
                  width: 7, height: 7, borderRadius: '50%', background: '#dc2626',
                  boxShadow: '0 0 0 3px rgba(220,38,38,0.2)',
                }} />
              )}
            </div>
            {!incidents || incidents.length === 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '20px 0', gap: 8 }}>
                <Shield size={28} color="#16a34a" style={{ opacity: 0.4 }} />
                <div style={{ fontSize: 12, color: '#8a9ab5', fontWeight: 500 }}>No active incidents</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {incidents.slice(0, 6).map(inc => (
                  <div key={inc.id} style={{
                    padding: '10px 12px', borderRadius: 8,
                    background: '#fef2f2', border: '1px solid #fecaca',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span className={`sev sev-${inc.severity}`}>{inc.severity}</span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#0f1923', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {inc.title}
                      </span>
                    </div>
                    <div style={{ fontSize: 10, color: '#4b5c72' }}>
                      {inc.primary_actor} → {inc.primary_target}
                    </div>
                    <div style={{ fontSize: 10, color: '#8a9ab5', marginTop: 2 }}>
                      {formatDistanceToNow(new Date(inc.opened_at), { addSuffix: true })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Fullscreen map overlay ──────────────────────── */}
      {mapExpanded && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 100,
          display: 'flex', flexDirection: 'column',
          background: '#07101a',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 20px', background: 'rgba(13,24,38,0.95)',
            borderBottom: '1px solid rgba(255,255,255,0.07)', flexShrink: 0,
          }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: '#e2ecf6' }}>AD Topology — {latestScan?.domain}</span>
            <button onClick={() => setMapExpanded(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b8299', padding: 4, display: 'flex' }}>
              <X size={18} />
            </button>
          </div>
          <div style={{ flex: 1 }} className="reactflow-dark">
            {topo && (
              <ReactFlow
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                fitView fitViewOptions={{ padding: 0.15 }}
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} color="rgba(255,255,255,0.03)" gap={28} size={1} />
                <Controls />
                <MiniMap nodeColor={n => n.id.startsWith('ag') ? '#22c55e' : n.id === 'domain' ? '#2563eb' : '#1e3a5f'} maskColor="rgba(7,16,26,0.7)" />
              </ReactFlow>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function KpiCard({ children, border }: { children: ReactNode; border: string }) {
  return (
    <div style={{
      padding: '18px 22px',
      borderRight: '1px solid #e4e8ef',
      display: 'flex', flexDirection: 'column',
      borderLeft: border.startsWith('left:') ? border.replace('left:', '').trim() : undefined,
    }}>
      {children}
    </div>
  )
}
