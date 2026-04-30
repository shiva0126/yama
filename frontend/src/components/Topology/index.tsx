import { useQuery } from '@tanstack/react-query'
import { scansApi, inventoryApi } from '../../api'
import ReactFlow, {
  Background, Controls, MiniMap, useNodesState, useEdgesState,
  type Node, type Edge
} from 'reactflow'
import 'reactflow/dist/style.css'
import { useEffect } from 'react'
import { Server, Users, Monitor, Shield, AlertTriangle } from 'lucide-react'

export function Topology() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const latestScan = scansData?.scans?.find(s => s.status === 'completed')
  const snapshotId = latestScan?.snapshot_id

  const { data: topoData } = useQuery({
    queryKey: ['topology', snapshotId],
    queryFn: () => snapshotId ? inventoryApi.getTopology(snapshotId).then(r => r.data) : null,
    enabled: !!snapshotId,
  })

  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])

  useEffect(() => {
    if (!topoData) return
    const { newNodes, newEdges } = buildGraph(topoData)
    setNodes(newNodes)
    setEdges(newEdges)
  }, [topoData])

  const summary = topoData?.summary
  const sites: any[] = topoData?.sites ?? []
  const maq: number = topoData?.machine_account_quota ?? 0
  const recycleBin: boolean = topoData?.recycle_bin_enabled ?? false
  const certTemplates: any[] = topoData?.cert_templates ?? []
  const escCount = certTemplates.filter((t: any) => t.vulnerable_esc1 || t.vulnerable_esc2 || t.vulnerable_esc3).length

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-semibold text-white">Topology</h1>
        <p className="text-gray-400 text-sm mt-1">AD forest structure, sites, and infrastructure map</p>
      </div>

      {/* Summary bar */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <SummaryCard icon={Server} label="Domain Controllers" value={summary.dc_count} color="blue" />
          <SummaryCard icon={Users} label="User Accounts" value={summary.user_count} color="violet" />
          <SummaryCard icon={Monitor} label="Computers" value={summary.computer_count} color="emerald" />
          <SummaryCard icon={Shield} label="Groups" value={summary.group_count} color="amber" />
        </div>
      )}

      {/* Risk flags */}
      {topoData && (
        <div className="flex flex-wrap gap-2">
          <RiskBadge label={`Machine Account Quota: ${maq}`} bad={maq > 0} good={maq === 0} />
          <RiskBadge label="AD Recycle Bin" bad={!recycleBin} good={recycleBin} badText="Disabled" goodText="Enabled" />
          {escCount > 0 && (
            <RiskBadge label={`ADCS: ${escCount} vulnerable template(s)`} bad />
          )}
          {sites.length > 0 && (
            <span className="text-xs px-2 py-1 rounded-full bg-gray-800 text-gray-400 border border-gray-700">
              {sites.length} site{sites.length > 1 ? 's' : ''}
            </span>
          )}
        </div>
      )}

      {/* Main graph */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden" style={{ height: 560 }}>
        {!snapshotId ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            Run a scan to view the topology
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            className="bg-gray-950"
          >
            <Background color="#1f2937" gap={24} />
            <Controls className="bg-gray-800 border-gray-700" />
            <MiniMap className="bg-gray-800" nodeColor={n => n.style?.background as string ?? '#8b5cf6'} />
          </ReactFlow>
        )}
      </div>

      {/* Sites table */}
      {sites.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800">
            <h2 className="text-sm font-semibold text-white">Sites &amp; Services</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs border-b border-gray-800">
                <th className="px-4 py-2 text-left font-medium">Site</th>
                <th className="px-4 py-2 text-left font-medium">Domain Controllers</th>
                <th className="px-4 py-2 text-left font-medium">Subnets</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {sites.map((site: any, i: number) => (
                <tr key={i} className="hover:bg-gray-800/50">
                  <td className="px-4 py-2 text-white font-mono text-xs">{site.name}</td>
                  <td className="px-4 py-2 text-gray-300 text-xs">{(site.dcs ?? []).join(', ') || '—'}</td>
                  <td className="px-4 py-2 text-gray-400 text-xs">{(site.subnets ?? []).join(', ') || 'No subnets defined'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ============================================================
// Graph builder
// ============================================================

function buildGraph(data: any): { newNodes: Node[]; newEdges: Edge[] } {
  const newNodes: Node[] = []
  const newEdges: Edge[] = []

  const domain: string = data.domain ?? ''
  const dcs: any[] = data.domain_controllers ?? []
  const sites: any[] = data.sites ?? []
  const siteLinks: any[] = data.site_links ?? []

  if (!domain) return { newNodes, newEdges }

  // Domain node (center)
  newNodes.push({
    id: 'domain',
    type: 'default',
    position: { x: 380, y: 40 },
    data: { label: `${domain}` },
    style: {
      background: '#1e3a5f', color: 'white',
      border: '2px solid #3b82f6', borderRadius: 10,
      padding: '10px 20px', fontWeight: 600, fontSize: 13,
      minWidth: 200, textAlign: 'center',
    },
  })

  // Site nodes
  const siteX: Record<string, number> = {}
  sites.forEach((site: any, i: number) => {
    const x = 80 + i * 280
    const y = 180
    siteX[site.name] = x + 100
    newNodes.push({
      id: `site:${site.name}`,
      type: 'default',
      position: { x, y },
      data: { label: `📍 ${site.name}\n${(site.dcs ?? []).length} DC(s)` },
      style: {
        background: '#1f2937', color: '#d1d5db',
        border: '1px solid #4b5563', borderRadius: 8,
        padding: '8px 14px', fontSize: 11, minWidth: 160,
      },
    })
    newEdges.push({
      id: `domain-site-${i}`,
      source: 'domain',
      target: `site:${site.name}`,
      style: { stroke: '#4b5563', strokeDasharray: '4 2' },
    })
  })

  // DC nodes
  const dcsBySite: Record<string, string[]> = {}
  sites.forEach((s: any) => {
    (s.dcs ?? []).forEach((dc: string) => {
      if (!dcsBySite[s.name]) dcsBySite[s.name] = []
      dcsBySite[s.name].push(dc)
    })
  })

  // DCs not in any site
  const assignedDCs = new Set(Object.values(dcsBySite).flat())
  const unassigned = dcs.filter(dc => !assignedDCs.has(dc.name))

  dcs.forEach((dc: any, i: number) => {
    const siteName = Object.keys(dcsBySite).find(s => dcsBySite[s].includes(dc.name))
    const baseX = siteName && siteX[siteName] != null ? siteX[siteName] - 60 + (dcsBySite[siteName]?.indexOf(dc.name) ?? 0) * 130 : 200 + i * 150
    const y = siteName ? 340 : 200
    const isGC = dc.is_global_catalog
    newNodes.push({
      id: `dc:${dc.name}`,
      type: 'default',
      position: { x: baseX, y },
      data: { label: `🖥 ${dc.name}${isGC ? ' (GC)' : ''}\n${dc.operating_system?.replace('Windows Server ', 'WS ') ?? ''}` },
      style: {
        background: isGC ? '#1a2e1a' : '#1e1a2e', color: '#e5e7eb',
        border: `1px solid ${isGC ? '#16a34a' : '#7c3aed'}`, borderRadius: 8,
        padding: '6px 12px', fontSize: 10, minWidth: 140,
      },
    })
    const parent = siteName ? `site:${siteName}` : 'domain'
    newEdges.push({
      id: `${parent}-dc-${dc.name}`,
      source: parent,
      target: `dc:${dc.name}`,
      style: { stroke: isGC ? '#16a34a' : '#7c3aed', strokeWidth: 1.5 },
    })
  })

  // Site link edges
  siteLinks.forEach((link: any, i: number) => {
    const sites2: string[] = link.sites ?? []
    for (let j = 0; j < sites2.length - 1; j++) {
      newEdges.push({
        id: `sitelink-${i}-${j}`,
        source: `site:${sites2[j]}`,
        target: `site:${sites2[j + 1]}`,
        label: `${link.name} (cost: ${link.cost ?? '?'})`,
        animated: false,
        style: { stroke: '#f59e0b', strokeDasharray: '6 3' },
        labelStyle: { fill: '#f59e0b', fontSize: 9 },
      })
    }
  })

  return { newNodes, newEdges }
}

// ============================================================
// Small UI components
// ============================================================

function SummaryCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    blue: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    violet: 'text-violet-400 bg-violet-500/10 border-violet-500/20',
    emerald: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
    amber: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  }
  return (
    <div className={`rounded-xl border p-4 ${colorMap[color]}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4" />
        <span className="text-xs text-gray-400">{label}</span>
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  )
}

function RiskBadge({ label, bad = false, good = false, badText, goodText }: {
  label: string; bad?: boolean; good?: boolean; badText?: string; goodText?: string;
}) {
  if (good) {
    return (
      <span className="flex items-center gap-1 text-xs px-2 py-1 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
        ✓ {goodText ? `${label}: ${goodText}` : label}
      </span>
    )
  }
  if (bad) {
    return (
      <span className="flex items-center gap-1 text-xs px-2 py-1 rounded-full bg-red-500/10 text-red-400 border border-red-500/20">
        <AlertTriangle className="w-3 h-3" />
        {badText ? `${label}: ${badText}` : label}
      </span>
    )
  }
  return null
}
