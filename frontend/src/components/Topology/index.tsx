import { useQuery } from '@tanstack/react-query'
import { scansApi, inventoryApi } from '../../api'
import ReactFlow, {
  Background, Controls, MiniMap, useNodesState, useEdgesState,
  type Node, type Edge
} from 'reactflow'
import 'reactflow/dist/style.css'
import { useEffect } from 'react'

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

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold text-white">Topology</h1>
        <p className="text-gray-400 text-sm mt-1">AD forest and domain trust visualization</p>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden" style={{ height: 600 }}>
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
            <Background color="#374151" gap={20} />
            <Controls className="bg-gray-800 border-gray-700" />
            <MiniMap className="bg-gray-800" nodeColor="#8b5cf6" />
          </ReactFlow>
        )}
      </div>
    </div>
  )
}

function buildGraph(data: any): { newNodes: Node[]; newEdges: Edge[] } {
  const newNodes: Node[] = []
  const newEdges: Edge[] = []

  const forest = data.forest || {}

  // Forest node
  if (forest.name) {
    newNodes.push({
      id: `forest:${forest.name}`,
      type: 'default',
      position: { x: 400, y: 50 },
      data: { label: `🌲 ${forest.name} (Forest)` },
      style: { background: '#4c1d95', color: 'white', border: '1px solid #7c3aed', borderRadius: 8, padding: '8px 16px' },
    })
  }

  // Domain nodes
  const domains = data.domains || []
  domains.forEach((domain: any, i: number) => {
    const x = 150 + i * 300
    const y = 200
    newNodes.push({
      id: `domain:${domain.name}`,
      type: 'default',
      position: { x, y },
      data: {
        label: `🏢 ${domain.name}\nDCs: ${domain.domain_controllers?.length ?? 0}`,
      },
      style: { background: '#1e3a5f', color: 'white', border: '1px solid #3b82f6', borderRadius: 8, padding: '8px 16px', fontSize: 11 },
    })

    if (forest.name) {
      newEdges.push({
        id: `forest-${domain.name}`,
        source: `forest:${forest.name}`,
        target: `domain:${domain.name}`,
        style: { stroke: '#6b7280' },
      })
    }
  })

  // Trust edges
  const trusts = data.trusts || forest.trusts || []
  trusts.forEach((trust: any, i: number) => {
    const srcId = `domain:${trust.source_domain}`
    const tgtId = `domain:${trust.target_domain}`
    newEdges.push({
      id: `trust-${i}`,
      source: srcId,
      target: tgtId,
      label: trust.trust_direction,
      animated: true,
      style: { stroke: '#f59e0b' },
      labelStyle: { fill: '#f59e0b', fontSize: 10 },
      markerEnd: trust.trust_direction === 'Bidirectional' ? undefined : 'arrowclosed',
    })
  })

  return { newNodes, newEdges }
}
