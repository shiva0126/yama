import { useEffect, useMemo, useState, type ReactNode } from 'react'
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

type NodeHeartbeat = 'online' | 'offline' | 'unmanaged'

function normalizeHost(value?: string) {
  if (!value) return ''
  return value.toLowerCase().trim().replace(/\.$/, '')
}

function hostAliases(value?: string): string[] {
  const v = normalizeHost(value)
  if (!v) return []
  const short = v.split('.')[0]
  return short && short !== v ? [v, short] : [v]
}

function buildAgentHeartbeatIndex(agents: CollectorAgent[]) {
  const index = new Map<string, NodeHeartbeat>()
  const setStatus = (key: string, status: NodeHeartbeat) => {
    if (!key || status === 'unmanaged') return
    const current = index.get(key)
    if (!current || (current === 'offline' && status === 'online')) {
      index.set(key, status)
    }
  }

  agents.forEach((agent) => {
    const status: NodeHeartbeat = agent.status === 'online' ? 'online' : 'offline'
    ;[...(hostAliases(agent.hostname)), ...(hostAliases(agent.name)), ...(hostAliases(agent.ip_address))].forEach((key) => {
      setStatus(key, status)
    })
  })

  return index
}

function resolveDCHeartbeat(dc: any, agentIndex: Map<string, NodeHeartbeat>): NodeHeartbeat {
  const dcNode = normalizeDCRecord(dc)
  const candidates = [
    ...hostAliases(dcNode.host_name),
    ...hostAliases(dcNode.name),
    ...hostAliases(dcNode.ip_address),
  ]
  for (const key of candidates) {
    const status = agentIndex.get(key)
    if (status) return status
  }
  return 'unmanaged'
}

function normalizeDCRecord(dc: any): { name?: string; host_name?: string; ip_address?: string; is_global_catalog?: boolean } {
  if (typeof dc === 'string') {
    return { name: dc, host_name: dc }
  }
  if (!dc || typeof dc !== 'object') {
    return {}
  }
  return dc
}

/* ─── Topology builder ──────────────────────────────────── */
function buildGraph(
  topo: any,
  agents: CollectorAgent[],
  incidents: DefenseIncident[],
  mapStyle: 'dark' | 'light',
): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []
  const hasThreat = incidents.length > 0
  const dark = mapStyle === 'dark'
  const agentIndex = buildAgentHeartbeatIndex(agents)

  const colors = dark
    ? {
        domainBg: hasThreat ? 'rgba(220,38,38,0.18)' : 'rgba(37,99,235,0.2)',
        domainBorder: hasThreat ? 'rgba(220,38,38,0.55)' : 'rgba(37,99,235,0.6)',
        domainText: '#e2ecf6',
        siteBg: '#142236',
        siteBorder: '1px solid rgba(255,255,255,0.12)',
        siteText: '#8ba0b8',
        siteEdge: 'rgba(255,255,255,0.15)',
        dcBg: '#0d1826',
        dcGcBg: 'rgba(37,99,235,0.15)',
        dcBorder: 'rgba(255,255,255,0.1)',
        dcGcBorder: 'rgba(59,130,246,0.4)',
        dcText: '#6b8299',
        dcGcText: '#93c5fd',
        dcEdge: 'rgba(255,255,255,0.08)',
        dcOnlineBg: 'rgba(22,163,74,0.15)',
        dcOnlineBorder: 'rgba(22,163,74,0.45)',
        dcOnlineText: '#86efac',
        dcOfflineBg: 'rgba(220,38,38,0.14)',
        dcOfflineBorder: 'rgba(220,38,38,0.4)',
        dcOfflineText: '#fca5a5',
        agOnlineBg: 'rgba(22,163,74,0.14)',
        agOnlineBorder: 'rgba(22,163,74,0.4)',
        agOnlineText: '#86efac',
        agOfflineBg: 'rgba(220,38,38,0.1)',
        agOfflineBorder: 'rgba(220,38,38,0.3)',
        agOfflineText: '#fca5a5',
        agOnlineEdge: 'rgba(22,163,74,0.4)',
        agOfflineEdge: 'rgba(220,38,38,0.25)',
      }
    : {
        domainBg: hasThreat ? '#fee2e2' : '#dbeafe',
        domainBorder: hasThreat ? '#f87171' : '#60a5fa',
        domainText: '#1e293b',
        siteBg: '#f8fafc',
        siteBorder: '1px solid #cbd5e1',
        siteText: '#334155',
        siteEdge: '#cbd5e1',
        dcBg: '#ffffff',
        dcGcBg: '#dcfce7',
        dcBorder: '#cbd5e1',
        dcGcBorder: '#86efac',
        dcText: '#334155',
        dcGcText: '#166534',
        dcEdge: '#dbe2ea',
        dcOnlineBg: '#dcfce7',
        dcOnlineBorder: '#86efac',
        dcOnlineText: '#166534',
        dcOfflineBg: '#fee2e2',
        dcOfflineBorder: '#fca5a5',
        dcOfflineText: '#b91c1c',
        agOnlineBg: '#dcfce7',
        agOnlineBorder: '#86efac',
        agOnlineText: '#166534',
        agOfflineBg: '#fee2e2',
        agOfflineBorder: '#fca5a5',
        agOfflineText: '#b91c1c',
        agOnlineEdge: '#86efac',
        agOfflineEdge: '#fca5a5',
      }

  nodes.push({
    id: 'domain', type: 'default', position: { x: 320, y: 20 },
    data: { label: topo.domain?.fqdn ?? topo.domain?.name ?? 'Domain' },
    style: {
      background: colors.domainBg,
      border: `2px solid ${colors.domainBorder}`,
      color: colors.domainText, borderRadius: 10, padding: '10px 22px',
      fontSize: 13, fontWeight: 700, minWidth: 150, textAlign: 'center',
    },
  })

  ;(topo.sites ?? []).forEach((site: any, si: number) => {
    const siteId = `site-${si}`
    nodes.push({
      id: siteId, type: 'default', position: { x: si * 340, y: 140 },
      data: { label: site.name ?? `Site ${si + 1}` },
      style: {
        background: colors.siteBg, border: colors.siteBorder,
        color: colors.siteText, borderRadius: 8, padding: '7px 14px', fontSize: 12,
      },
    })
    edges.push({ id: `d-${siteId}`, source: 'domain', target: siteId, style: { stroke: colors.siteEdge } })
    ;(site.domain_controllers ?? []).forEach((dc: any, di: number) => {
      const dcNode = normalizeDCRecord(dc)
      const dcId = `dc-${si}-${di}`
      const heartbeat = resolveDCHeartbeat(dc, agentIndex)
      const dcLabel = dcNode.host_name ?? dcNode.name ?? 'DC'
      nodes.push({
        id: dcId, type: 'default',
        position: { x: si * 340 + di * 180 - ((site.domain_controllers.length - 1) * 90), y: 270 },
        data: {
          label: heartbeat === 'unmanaged'
            ? dcLabel
            : `${dcLabel} (${heartbeat})`,
        },
        style: {
          background: heartbeat === 'online'
            ? colors.dcOnlineBg
            : heartbeat === 'offline'
              ? colors.dcOfflineBg
              : (dc.is_global_catalog ? colors.dcGcBg : colors.dcBg),
          border: `1px solid ${
            heartbeat === 'online'
              ? colors.dcOnlineBorder
              : heartbeat === 'offline'
                ? colors.dcOfflineBorder
                : (dcNode.is_global_catalog ? colors.dcGcBorder : colors.dcBorder)
          }`,
          color: heartbeat === 'online'
            ? colors.dcOnlineText
            : heartbeat === 'offline'
              ? colors.dcOfflineText
              : (dcNode.is_global_catalog ? colors.dcGcText : colors.dcText),
          borderRadius: 7, padding: '6px 12px', fontSize: 11,
          boxShadow: heartbeat === 'online'
            ? (dark ? '0 0 0 3px rgba(22,163,74,0.18)' : '0 0 0 3px rgba(22,163,74,0.12)')
            : 'none',
        },
      })
      edges.push({
        id: `s-${dcId}`,
        source: siteId,
        target: dcId,
        style: {
          stroke: heartbeat === 'online'
            ? colors.dcOnlineBorder
            : heartbeat === 'offline'
              ? colors.dcOfflineBorder
              : colors.dcEdge,
        },
      })
    })
  })

  agents.forEach((ag, ai) => {
    const online = ag.status === 'online'
    const agId = `ag-${ai}`
    nodes.push({
      id: agId, type: 'default', position: { x: 680 + ai * 160, y: 20 },
      data: { label: ag.name ?? ag.hostname },
      style: {
        background: online ? colors.agOnlineBg : colors.agOfflineBg,
        border: `1px solid ${online ? colors.agOnlineBorder : colors.agOfflineBorder}`,
        color: online ? colors.agOnlineText : colors.agOfflineText, borderRadius: 7, padding: '6px 12px', fontSize: 11,
        boxShadow: online
          ? (dark ? '0 0 0 3px rgba(22,163,74,0.16)' : '0 0 0 3px rgba(22,163,74,0.12)')
          : 'none',
      },
    })
    edges.push({
      id: `ag-${agId}`, source: 'domain', target: agId,
      style: { stroke: online ? colors.agOnlineEdge : colors.agOfflineEdge, strokeDasharray: '5 3' },
    })
  })

  return { nodes, edges }
}

/* ─── Main component ─────────────────────────────────────── */
export function Overview() {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const [mapExpanded, setMapExpanded] = useState(false)
  const { theme, setTheme } = useTheme()
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
    const { nodes: n, edges: e } = buildGraph(topo, agentsData?.agents ?? [], incidents ?? [], theme.mapStyle)
    setNodes(n); setEdges(e)
  }, [topo, agentsData, incidents, setNodes, setEdges, theme.mapStyle])

  const agents      = agentsData?.agents ?? []
  const online      = agents.filter(a => a.status === 'online').length
  const offline     = agents.length - online
  const dcCoverage = useMemo(() => {
    const index = buildAgentHeartbeatIndex(agents)
    const seen = new Set<string>()
    const counters = { total: 0, online: 0, offline: 0, unmanaged: 0 }
    const sites = (topo as any)?.sites ?? []
    const fromSites = sites.flatMap((site: any) => site?.domain_controllers ?? [])
    const fromSummary = (topo as any)?.domain_controllers ?? []
    const all = [...fromSites, ...fromSummary]

    all.forEach((dc: any) => {
      const dcNode = normalizeDCRecord(dc)
      const id = normalizeHost(dcNode.host_name) || normalizeHost(dcNode.name) || normalizeHost(dcNode.ip_address)
      if (!id || seen.has(id)) return
      seen.add(id)
      counters.total++
      const hb = resolveDCHeartbeat(dcNode, index)
      if (hb === 'online') counters.online++
      else if (hb === 'offline') counters.offline++
      else counters.unmanaged++
    })

    return counters
  }, [agents, topo])

  const dcCount = dcCoverage.total
  const coveragePct = dcCount > 0 ? Math.min(100, Math.round((dcCoverage.online / dcCount) * 100)) : 0
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
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  onClick={() => setTheme({ mapStyle: 'light' })}
                  style={{
                    border: `1px solid ${!isDarkMap ? '#93c5fd' : '#dbe2ea'}`,
                    background: !isDarkMap ? '#eff6ff' : '#ffffff',
                    color: !isDarkMap ? '#1d4ed8' : '#64748b',
                    borderRadius: 5,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    padding: '3px 7px',
                    cursor: 'pointer',
                  }}
                >
                  light
                </button>
                <button
                  onClick={() => setTheme({ mapStyle: 'dark' })}
                  style={{
                    border: `1px solid ${isDarkMap ? '#60a5fa' : '#dbe2ea'}`,
                    background: isDarkMap ? '#dbeafe' : '#ffffff',
                    color: isDarkMap ? '#1d4ed8' : '#64748b',
                    borderRadius: 5,
                    fontSize: 10,
                    fontWeight: 700,
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    padding: '3px 7px',
                    cursor: 'pointer',
                  }}
                >
                  dark
                </button>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: '#16a34a',
                  background: '#f0fdf4',
                  border: '1px solid #bbf7d0',
                  borderRadius: 5,
                  padding: '3px 7px',
                }}>
                  {online} online
                </span>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: '#64748b',
                  background: '#f8fafc',
                  border: '1px solid #dbe2ea',
                  borderRadius: 5,
                  padding: '3px 7px',
                }}>
                  {offline} offline
                </span>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  color: '#1d4ed8',
                  background: '#eff6ff',
                  border: '1px solid #bfdbfe',
                  borderRadius: 5,
                  padding: '3px 7px',
                }}>
                  {dcCoverage.online}/{dcCoverage.total} dc covered
                </span>
                <button
                  onClick={() => setMapExpanded(true)}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8a9ab5', padding: 4, display: 'flex' }}
                  title="Expand map"
                >
                  <Maximize2 size={13} />
                </button>
              </div>
            </div>

            {/* Map canvas */}
            <div style={{ flex: 1, minHeight: 0 }} className={isDarkMap ? 'reactflow-dark' : 'reactflow-light'}>
              {!topo ? (
                <div style={{
                  height: '100%', display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center', gap: 14,
                  background: isDarkMap ? '#07101a' : '#f8fafc',
                }}>
                  <Server size={40} style={{ opacity: 0.2, color: isDarkMap ? '#2563eb' : '#94a3b8' }} />
                  <div style={{ fontSize: 14, fontWeight: 600, color: isDarkMap ? '#9db8d5' : '#64748b' }}>
                    {latestScan ? 'Building topology…' : 'No assessment data'}
                  </div>
                  <div style={{ fontSize: 12, color: isDarkMap ? '#6b8299' : '#94a3b8', maxWidth: 260, textAlign: 'center' }}>
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
                  <Background
                    variant={BackgroundVariant.Dots}
                    color={isDarkMap ? 'rgba(255,255,255,0.03)' : 'rgba(100,116,139,0.12)'}
                    gap={28}
                    size={1}
                  />
                  <Controls showInteractive={false} />
                  <MiniMap
                    nodeColor={(n) => (typeof n.style?.background === 'string' ? n.style.background : '#94a3b8')}
                    maskColor={isDarkMap ? 'rgba(7,16,26,0.7)' : 'rgba(226,232,240,0.8)'}
                  />
                </ReactFlow>
              )}
            </div>
          </div>

          <div style={{
            borderRadius: 10,
            border: '1px solid #e4e8ef',
            background: '#ffffff',
            boxShadow: '0 1px 4px rgba(15,25,35,0.04)',
            padding: '12px 16px',
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
              <div>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                  DC coverage by active agents
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 6 }}>
                  <span style={{ fontSize: 22, fontWeight: 800, color: coveragePct >= 70 ? '#16a34a' : coveragePct >= 40 ? '#d97706' : '#dc2626', lineHeight: 1 }}>
                    {coveragePct}%
                  </span>
                  <span style={{ fontSize: 12, color: '#8a9ab5' }}>{dcCoverage.online}/{dcCount || 0} mapped</span>
                </div>
                <div style={{ height: 7, background: '#e4e8ef', borderRadius: 999, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${coveragePct}%`, background: coveragePct >= 70 ? '#16a34a' : coveragePct >= 40 ? '#d97706' : '#dc2626' }} />
                </div>
                <div style={{ marginTop: 7, fontSize: 11, color: '#8a9ab5' }}>
                  {dcCoverage.offline} with offline heartbeat · {dcCoverage.unmanaged} without agent
                </div>
              </div>

              <div>
                <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
                  Live incident pressure
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', height: 48 }}>
                  {([
                    { label: 'C', value: sev.critical, color: '#dc2626' },
                    { label: 'H', value: sev.high, color: '#ea580c' },
                    { label: 'M', value: sev.medium, color: '#d97706' },
                    { label: 'L', value: sev.low, color: '#0284c7' },
                  ]).map((item) => {
                    const max = Math.max(sev.critical, sev.high, sev.medium, sev.low, 1)
                    const h = Math.max(8, Math.round((item.value / max) * 44))
                    return (
                      <div key={item.label} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                        <div style={{ width: 14, height: h, borderRadius: 4, background: item.color }} />
                        <div style={{ fontSize: 9, color: '#8a9ab5', fontWeight: 700 }}>{item.label}</div>
                      </div>
                    )
                  })}
                </div>
              </div>
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
          background: isDarkMap ? '#07101a' : '#f8fafc',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 20px',
            background: isDarkMap ? 'rgba(13,24,38,0.95)' : 'rgba(255,255,255,0.95)',
            borderBottom: isDarkMap ? '1px solid rgba(255,255,255,0.07)' : '1px solid #e4e8ef',
            flexShrink: 0,
          }}>
            <span style={{ fontSize: 13, fontWeight: 600, color: isDarkMap ? '#e2ecf6' : '#0f1923' }}>AD Topology — {latestScan?.domain}</span>
            <button onClick={() => setMapExpanded(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: isDarkMap ? '#6b8299' : '#64748b', padding: 4, display: 'flex' }}>
              <X size={18} />
            </button>
          </div>
          <div style={{ flex: 1 }} className={isDarkMap ? 'reactflow-dark' : 'reactflow-light'}>
            {topo && (
              <ReactFlow
                nodes={nodes} edges={edges}
                onNodesChange={onNodesChange} onEdgesChange={onEdgesChange}
                fitView fitViewOptions={{ padding: 0.15 }}
                proOptions={{ hideAttribution: true }}
              >
                <Background
                  variant={BackgroundVariant.Dots}
                  color={isDarkMap ? 'rgba(255,255,255,0.03)' : 'rgba(100,116,139,0.12)'}
                  gap={28}
                  size={1}
                />
                <Controls />
                <MiniMap
                  nodeColor={(n) => (typeof n.style?.background === 'string' ? n.style.background : '#94a3b8')}
                  maskColor={isDarkMap ? 'rgba(7,16,26,0.7)' : 'rgba(226,232,240,0.8)'}
                />
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
