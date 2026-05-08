import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
} from 'reactflow'
import 'reactflow/dist/style.css'
import { AlertTriangle, Network, Server, Shield, Users } from 'lucide-react'
import { agentsApi, inventoryApi, scansApi } from '../../api'
import { useTheme } from '../../contexts/ThemeContext'
import type { CollectorAgent } from '../../types'

type NodeHeartbeat = 'online' | 'offline' | 'unmanaged'

function normalizeHost(value?: string) {
  if (!value) return ''
  return value.toLowerCase().trim().replace(/\.$/, '')
}

function hostAliases(value?: string): string[] {
  const normalized = normalizeHost(value)
  if (!normalized) return []
  const short = normalized.split('.')[0]
  return short && short !== normalized ? [normalized, short] : [normalized]
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
    ;[...hostAliases(agent.hostname), ...hostAliases(agent.name), ...hostAliases(agent.ip_address)].forEach((key) => {
      setStatus(key, status)
    })
  })

  return index
}

function resolveDCHeartbeat(dc: any, agentIndex: Map<string, NodeHeartbeat>): NodeHeartbeat {
  const dcNode = normalizeDCRecord(dc)
  const keys = [...hostAliases(dcNode?.name), ...hostAliases(dcNode?.host_name), ...hostAliases(dcNode?.ip_address)]
  for (const key of keys) {
    const status = agentIndex.get(key)
    if (status) return status
  }
  return 'unmanaged'
}

function normalizeDCRecord(dc: any): { name?: string; host_name?: string; ip_address?: string; operating_system?: string; is_global_catalog?: boolean } {
  if (typeof dc === 'string') {
    return { name: dc, host_name: dc }
  }
  if (!dc || typeof dc !== 'object') {
    return {}
  }
  return dc
}

export function Topology() {
  const { theme, setTheme } = useTheme()
  const isDarkMap = theme.mapStyle === 'dark'
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const latestScan = scansData?.scans?.find((scan) => scan.status === 'completed')
  const snapshotId = latestScan?.snapshot_id
  const scansLoading = scansData === undefined

  const { data: topologyData } = useQuery({
    queryKey: ['topology', snapshotId],
    queryFn: () => (snapshotId ? inventoryApi.getTopology(snapshotId).then((r) => r.data) : null),
    enabled: !!snapshotId,
  })
  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then((r) => r.data),
    refetchInterval: 10_000,
  })

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useEffect(() => {
    if (!topologyData) return
    const graph = buildGraph(topologyData, agentsData?.agents ?? [], theme.mapStyle)
    setNodes(graph.nodes)
    setEdges(graph.edges)
  }, [agentsData?.agents, setEdges, setNodes, theme.mapStyle, topologyData])

  const summary = topologyData?.summary
  const topologyLoading = topologyData === undefined && !!snapshotId
  const sites: any[] = topologyData?.sites ?? []
  const machineAccountQuota: number = topologyData?.machine_account_quota ?? 0
  const recycleBinEnabled: boolean = topologyData?.recycle_bin_enabled ?? false
  const certTemplates: any[] = topologyData?.cert_templates ?? []
  const vulnerableTemplates = certTemplates.filter(
    (template) =>
      template.vulnerable_esc1 ||
      template.vulnerable_esc2 ||
      template.vulnerable_esc3 ||
      template.vulnerable_esc4 ||
      template.vulnerable_esc6 ||
      template.vulnerable_esc7
  ).length
  const dcHeartbeat = (() => {
    const index = buildAgentHeartbeatIndex(agentsData?.agents ?? [])
    const result = { online: 0, offline: 0, unmanaged: 0, total: 0 }
    ;(topologyData?.domain_controllers ?? []).forEach((dc: any) => {
      const dcNode = normalizeDCRecord(dc)
      result.total++
      const status = resolveDCHeartbeat(dcNode, index)
      if (status === 'online') result.online++
      else if (status === 'offline') result.offline++
      else result.unmanaged++
    })
    return result
  })()

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <p className="label">Forest topology</p>
        <h2 className="mt-2 text-2xl font-semibold text-white">Topology</h2>

        {topologyLoading ? (
          <p className="mt-4 text-sm text-slate-400">Loading topology data…</p>
        ) : summary ? (
          <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <SummaryCard icon={Server} label="Domain controllers" value={summary.dc_count} />
            <SummaryCard icon={Users} label="User identities" value={summary.user_count} />
            <SummaryCard icon={Network} label="Computer objects" value={summary.computer_count} />
            <SummaryCard icon={Shield} label="Security groups" value={summary.group_count} />
          </div>
        ) : null}
      </section>

      <section className="flex flex-wrap gap-3">
        <RiskBadge
          label={scansLoading ? 'Machine account quota: loading' : `Machine account quota: ${machineAccountQuota}`}
          tone={scansLoading ? 'neutral' : machineAccountQuota > 0 ? 'danger' : 'success'}
        />
        <RiskBadge
          label={scansLoading ? 'Recycle Bin: loading' : `Recycle Bin: ${recycleBinEnabled ? 'enabled' : 'disabled'}`}
          tone={scansLoading ? 'neutral' : recycleBinEnabled ? 'success' : 'warning'}
        />
        <RiskBadge
          label={scansLoading ? 'Vulnerable ADCS templates: loading' : `Vulnerable ADCS templates: ${vulnerableTemplates}`}
          tone={scansLoading ? 'neutral' : vulnerableTemplates > 0 ? 'danger' : 'neutral'}
        />
        <RiskBadge label={scansLoading ? 'Sites mapped: loading' : `Sites mapped: ${sites.length}`} tone="neutral" />
        <RiskBadge
          label={scansLoading ? 'DC heartbeat: loading' : `DC heartbeat online: ${dcHeartbeat.online}/${dcHeartbeat.total}`}
          tone={scansLoading ? 'neutral' : dcHeartbeat.total > 0 && dcHeartbeat.online < dcHeartbeat.total ? 'warning' : 'success'}
        />
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-white/8 px-6 py-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="label">Directory graph</p>
              <h3 className="mt-1 text-lg font-semibold text-white">Forest and controller map</h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setTheme({ mapStyle: 'light' })}
                className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${
                  isDarkMap
                    ? 'border-slate-200/15 bg-white/[0.03] text-slate-300'
                    : 'border-sky-300/50 bg-sky-400/15 text-sky-100'
                }`}
              >
                light
              </button>
              <button
                type="button"
                onClick={() => setTheme({ mapStyle: 'dark' })}
                className={`rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${
                  isDarkMap
                    ? 'border-sky-300/50 bg-sky-400/15 text-sky-100'
                    : 'border-slate-200/15 bg-white/[0.03] text-slate-300'
                }`}
              >
                dark
              </button>
              <span className="rounded-full border border-emerald-300/30 bg-emerald-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-emerald-200">
                {dcHeartbeat.online} online
              </span>
              <span className="rounded-full border border-rose-300/30 bg-rose-400/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.12em] text-rose-200">
                {dcHeartbeat.offline} offline
              </span>
            </div>
          </div>
        </div>
        <div className="h-[620px]">
          {scansLoading ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-500">Loading assessment snapshots…</div>
          ) : !snapshotId ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-500">No completed assessment data available.</div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              className={isDarkMap ? 'reactflow-dark' : 'reactflow-light'}
            >
              <Background color={isDarkMap ? 'rgba(124, 154, 190, 0.12)' : 'rgba(100,116,139,0.15)'} gap={24} />
              <Controls />
              <MiniMap
                className={isDarkMap ? '!bg-[#0b1628]' : '!bg-white'}
                nodeColor={(node) => (typeof node.style?.background === 'string' ? node.style.background : '#1b2b40')}
              />
            </ReactFlow>
          )}
        </div>
      </section>

      {sites.length > 0 && (
        <section className="panel overflow-hidden">
          <div className="border-b border-white/8 px-6 py-4">
            <p className="label">Site inventory</p>
            <h3 className="mt-1 text-lg font-semibold text-white">Sites and controller distribution</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-white/8 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                <tr>
                  <th className="px-6 py-3 font-medium">Site</th>
                  <th className="px-6 py-3 font-medium">Controllers</th>
                  <th className="px-6 py-3 font-medium">Subnets</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/6">
                {sites.map((site: any, index: number) => (
                  <tr key={`${site.name}-${index}`} className="hover:bg-white/[0.03]">
                    <td className="px-6 py-4 font-medium text-white">{site.name}</td>
                    <td className="px-6 py-4 text-slate-300">{(site.dcs ?? []).join(', ') || '—'}</td>
                    <td className="px-6 py-4 text-slate-400">{(site.subnets ?? []).join(', ') || 'No subnets defined'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}

function buildGraph(data: any, agents: CollectorAgent[], mapStyle: 'dark' | 'light'): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []
  const dark = mapStyle === 'dark'
  const agentIndex = buildAgentHeartbeatIndex(agents)
  const colors = dark
    ? {
        domainBg: 'rgba(36, 82, 146, 0.62)',
        domainBorder: 'rgba(78, 161, 255, 0.28)',
        domainText: '#f8fbff',
        siteBg: 'rgba(20, 34, 55, 0.92)',
        siteBorder: 'rgba(124, 154, 190, 0.18)',
        siteText: '#dbe7f7',
        siteEdge: 'rgba(124, 154, 190, 0.4)',
        dcBg: 'rgba(18, 31, 49, 0.94)',
        dcGcBg: 'rgba(18, 61, 57, 0.9)',
        dcBorder: 'rgba(78, 161, 255, 0.18)',
        dcGcBorder: 'rgba(115, 224, 192, 0.28)',
        dcText: '#ecf3ff',
        siteLink: 'rgba(244, 201, 107, 0.72)',
        siteLinkText: '#d8b56b',
        dcOnlineBg: 'rgba(22,163,74,0.15)',
        dcOnlineBorder: 'rgba(22,163,74,0.48)',
        dcOnlineText: '#86efac',
        dcOfflineBg: 'rgba(220,38,38,0.15)',
        dcOfflineBorder: 'rgba(220,38,38,0.44)',
        dcOfflineText: '#fca5a5',
      }
    : {
        domainBg: '#dbeafe',
        domainBorder: '#93c5fd',
        domainText: '#0f172a',
        siteBg: '#f8fafc',
        siteBorder: '#cbd5e1',
        siteText: '#334155',
        siteEdge: '#cbd5e1',
        dcBg: '#ffffff',
        dcGcBg: '#dcfce7',
        dcBorder: '#d1d9e6',
        dcGcBorder: '#86efac',
        dcText: '#0f172a',
        siteLink: '#f59e0b',
        siteLinkText: '#b45309',
        dcOnlineBg: '#dcfce7',
        dcOnlineBorder: '#86efac',
        dcOnlineText: '#166534',
        dcOfflineBg: '#fee2e2',
        dcOfflineBorder: '#fca5a5',
        dcOfflineText: '#b91c1c',
      }

  const domain = data.domain
  const sites: any[] = data.sites ?? []
  const dcs: any[] = data.domain_controllers ?? []
  const siteLinks: any[] = data.site_links ?? []

  if (!domain) return { nodes, edges }

  nodes.push({
    id: 'domain',
    position: { x: 440, y: 40 },
    data: { label: domain },
    style: {
      minWidth: 220,
      padding: '14px 18px',
      borderRadius: '18px',
      color: colors.domainText,
      border: `1px solid ${colors.domainBorder}`,
      background: colors.domainBg,
      textAlign: 'center',
      fontWeight: 700,
      fontSize: '13px',
    },
  })

  const sitePositions = new Map<string, { x: number; y: number }>()
  sites.forEach((site: any, index: number) => {
    const x = 120 + index * 280
    const y = 210
    sitePositions.set(site.name, { x, y })
    nodes.push({
      id: `site:${site.name}`,
      position: { x, y },
      data: { label: `${site.name}\n${(site.dcs ?? []).length} controller(s)` },
      style: {
        minWidth: 180,
        padding: '12px 14px',
        borderRadius: '16px',
        color: colors.siteText,
        border: `1px solid ${colors.siteBorder}`,
        background: colors.siteBg,
        fontSize: '11px',
        lineHeight: 1.4,
        textAlign: 'center',
      },
    })
    edges.push({
      id: `domain-site-${site.name}`,
      source: 'domain',
      target: `site:${site.name}`,
      style: { stroke: colors.siteEdge, strokeDasharray: '6 3' },
    })
  })

  dcs.forEach((dc: any, index: number) => {
    const dcNode = normalizeDCRecord(dc)
    const site = sites.find((entry: any) => (entry.dcs ?? []).includes(dcNode.name))
    const parent = site ? `site:${site.name}` : 'domain'
    const position = sitePositions.get(site?.name ?? '')
    const x = position ? position.x - 32 + ((site.dcs ?? []).indexOf(dcNode.name) || 0) * 110 : 180 + index * 130
    const y = position ? 370 : 190
    const heartbeat = resolveDCHeartbeat(dcNode, agentIndex)
    const label = heartbeat === 'unmanaged'
      ? `${dcNode.name ?? 'DC'}\n${dcNode.operating_system ?? 'Domain Controller'}`
      : `${dcNode.name ?? 'DC'} (${heartbeat})\n${dcNode.operating_system ?? 'Domain Controller'}`
    nodes.push({
      id: `dc:${dcNode.name ?? index}`,
      position: { x, y },
      data: { label },
      style: {
        minWidth: 150,
        padding: '10px 12px',
        borderRadius: '14px',
        color: heartbeat === 'online'
          ? colors.dcOnlineText
          : heartbeat === 'offline'
            ? colors.dcOfflineText
            : colors.dcText,
        border: `1px solid ${
          heartbeat === 'online'
            ? colors.dcOnlineBorder
            : heartbeat === 'offline'
              ? colors.dcOfflineBorder
              : (dcNode.is_global_catalog ? colors.dcGcBorder : colors.dcBorder)
        }`,
        background: heartbeat === 'online'
          ? colors.dcOnlineBg
          : heartbeat === 'offline'
            ? colors.dcOfflineBg
            : (dcNode.is_global_catalog ? colors.dcGcBg : colors.dcBg),
        fontSize: '10px',
        lineHeight: 1.5,
        textAlign: 'center',
        boxShadow: heartbeat === 'online'
          ? (dark ? '0 0 0 3px rgba(22,163,74,0.18)' : '0 0 0 3px rgba(22,163,74,0.1)')
          : 'none',
      },
    })
    edges.push({
      id: `${parent}-${dcNode.name ?? index}`,
      source: parent,
      target: `dc:${dcNode.name ?? index}`,
      style: {
        stroke: heartbeat === 'online'
          ? colors.dcOnlineBorder
          : heartbeat === 'offline'
            ? colors.dcOfflineBorder
            : (dcNode.is_global_catalog ? colors.dcGcBorder : colors.dcBorder),
        strokeWidth: 1.6,
      },
    })
  })

  siteLinks.forEach((link: any, index: number) => {
    const linkedSites: string[] = link.sites ?? []
    for (let i = 0; i < linkedSites.length - 1; i += 1) {
      edges.push({
        id: `site-link-${index}-${i}`,
        source: `site:${linkedSites[i]}`,
        target: `site:${linkedSites[i + 1]}`,
        label: `${link.name} · cost ${link.cost ?? '?'}`,
        style: { stroke: colors.siteLink, strokeDasharray: '5 3' },
        labelStyle: { fill: colors.siteLinkText, fontSize: 9 },
      })
    }
  })

  return { nodes, edges }
}

function SummaryCard({ icon: Icon, label, value }: { icon: typeof Server; label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/8 bg-white/[0.02] text-sky-200">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
          <p className="mt-1 text-2xl font-semibold text-white">{value}</p>
        </div>
      </div>
    </div>
  )
}

function RiskBadge({
  label,
  tone,
}: {
  label: string
  tone: 'danger' | 'warning' | 'success' | 'neutral'
}) {
  const styles: Record<string, string> = {
    danger: 'border-red-400/18 bg-red-400/10 text-red-200',
    warning: 'border-amber-400/18 bg-amber-400/10 text-amber-200',
    success: 'border-emerald-400/18 bg-emerald-400/10 text-emerald-200',
    neutral: 'border-white/8 bg-white/[0.03] text-slate-300',
  }

  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-medium ${styles[tone]}`}>
      {tone === 'danger' ? <AlertTriangle className="h-4 w-4" /> : <Shield className="h-4 w-4" />}
      {label}
    </span>
  )
}
