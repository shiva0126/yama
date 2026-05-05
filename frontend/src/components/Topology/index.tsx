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
import { inventoryApi, scansApi } from '../../api'

export function Topology() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const latestScan = scansData?.scans?.find((scan) => scan.status === 'completed')
  const snapshotId = latestScan?.snapshot_id

  const { data: topologyData } = useQuery({
    queryKey: ['topology', snapshotId],
    queryFn: () => (snapshotId ? inventoryApi.getTopology(snapshotId).then((r) => r.data) : null),
    enabled: !!snapshotId,
  })

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useEffect(() => {
    if (!topologyData) return
    const graph = buildGraph(topologyData)
    setNodes(graph.nodes)
    setEdges(graph.edges)
  }, [setEdges, setNodes, topologyData])

  const summary = topologyData?.summary
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

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <p className="label">Forest topology</p>
        <h2 className="mt-2 text-2xl font-semibold text-white">Topology</h2>

        {summary && (
          <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <SummaryCard icon={Server} label="Domain controllers" value={summary.dc_count} />
            <SummaryCard icon={Users} label="User identities" value={summary.user_count} />
            <SummaryCard icon={Network} label="Computer objects" value={summary.computer_count} />
            <SummaryCard icon={Shield} label="Security groups" value={summary.group_count} />
          </div>
        )}
      </section>

      <section className="flex flex-wrap gap-3">
        <RiskBadge
          label={`Machine account quota: ${machineAccountQuota}`}
          tone={machineAccountQuota > 0 ? 'danger' : 'success'}
        />
        <RiskBadge
          label={`Recycle Bin: ${recycleBinEnabled ? 'enabled' : 'disabled'}`}
          tone={recycleBinEnabled ? 'success' : 'warning'}
        />
        <RiskBadge
          label={`Vulnerable ADCS templates: ${vulnerableTemplates}`}
          tone={vulnerableTemplates > 0 ? 'danger' : 'neutral'}
        />
        <RiskBadge label={`Sites mapped: ${sites.length}`} tone="neutral" />
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-white/8 px-6 py-4">
          <p className="label">Directory graph</p>
          <h3 className="mt-1 text-lg font-semibold text-white">Forest and controller map</h3>
        </div>
        <div className="h-[620px]">
          {!snapshotId ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-500">No topology data available.</div>
          ) : (
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              fitView
              className="bg-[#06101d]"
            >
              <Background color="rgba(124, 154, 190, 0.12)" gap={24} />
              <Controls className="!border-white/8 !bg-[#0b1628]" />
              <MiniMap
                className="!bg-[#0b1628]"
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

function buildGraph(data: any): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = []
  const edges: Edge[] = []

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
      color: '#f8fbff',
      border: '1px solid rgba(78, 161, 255, 0.28)',
      background: 'rgba(36, 82, 146, 0.62)',
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
        color: '#dbe7f7',
        border: '1px solid rgba(124, 154, 190, 0.18)',
        background: 'rgba(20, 34, 55, 0.92)',
        fontSize: '11px',
        lineHeight: 1.4,
        textAlign: 'center',
      },
    })
    edges.push({
      id: `domain-site-${site.name}`,
      source: 'domain',
      target: `site:${site.name}`,
      style: { stroke: 'rgba(124, 154, 190, 0.4)', strokeDasharray: '6 3' },
    })
  })

  dcs.forEach((dc: any, index: number) => {
    const site = sites.find((entry: any) => (entry.dcs ?? []).includes(dc.name))
    const parent = site ? `site:${site.name}` : 'domain'
    const position = sitePositions.get(site?.name ?? '')
    const x = position ? position.x - 32 + ((site.dcs ?? []).indexOf(dc.name) || 0) * 110 : 180 + index * 130
    const y = position ? 370 : 190
    nodes.push({
      id: `dc:${dc.name}`,
      position: { x, y },
      data: { label: `${dc.name}\n${dc.operating_system ?? 'Domain Controller'}` },
      style: {
        minWidth: 150,
        padding: '10px 12px',
        borderRadius: '14px',
        color: '#ecf3ff',
        border: `1px solid ${dc.is_global_catalog ? 'rgba(115, 224, 192, 0.28)' : 'rgba(78, 161, 255, 0.18)'}`,
        background: dc.is_global_catalog ? 'rgba(18, 61, 57, 0.9)' : 'rgba(18, 31, 49, 0.94)',
        fontSize: '10px',
        lineHeight: 1.5,
        textAlign: 'center',
      },
    })
    edges.push({
      id: `${parent}-${dc.name}`,
      source: parent,
      target: `dc:${dc.name}`,
      style: {
        stroke: dc.is_global_catalog ? 'rgba(115, 224, 192, 0.55)' : 'rgba(78, 161, 255, 0.5)',
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
        style: { stroke: 'rgba(244, 201, 107, 0.72)', strokeDasharray: '5 3' },
        labelStyle: { fill: '#d8b56b', fontSize: 9 },
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
