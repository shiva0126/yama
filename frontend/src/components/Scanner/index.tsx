import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { agentsApi, scansApi } from '../../api'
import { useScanStore } from '../../stores/scanStore'
import { Play, RefreshCw, X, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import clsx from 'clsx'
import type { ScanJob } from '../../types'

const TASK_TYPES = [
  { id: 'topology',  label: 'Forest Topology',       desc: 'Domains, trusts, sites', group: 'Core' },
  { id: 'users',     label: 'Users',                 desc: 'All user accounts', group: 'Core' },
  { id: 'groups',    label: 'Groups',                desc: 'Security groups & nesting', group: 'Core' },
  { id: 'computers', label: 'Computers',             desc: 'Workstations & servers', group: 'Core' },
  { id: 'gpos',      label: 'Group Policy',          desc: 'GPO settings & links', group: 'Core' },
  { id: 'dcinfo',    label: 'Domain Controllers',    desc: 'DC health & services', group: 'Core' },
  { id: 'kerberos',  label: 'Kerberos Config',       desc: 'krbtgt, encryption types', group: 'Security' },
  { id: 'acls',      label: 'ACL Analysis',          desc: 'Dangerous permissions', group: 'Security' },
  { id: 'trusts',    label: 'Trust Relationships',   desc: 'Forest & domain trusts', group: 'Security' },
  { id: 'adcs',      label: 'ADCS / PKI',            desc: 'Certificate templates, ESC vulns', group: 'Security' },
  { id: 'sites',     label: 'Sites & Services',      desc: 'AD sites, subnets, MAQ, RecycleBin', group: 'Security' },
  { id: 'fgpp',      label: 'Fine-Grained Passwords',desc: 'Password Settings Objects', group: 'Security' },
  { id: 'ous',       label: 'OUs',                   desc: 'Organizational units', group: 'Core' },
]

export function Scanner() {
  const qc = useQueryClient()
  const { setActiveScan } = useScanStore()
  const [selectedAgent, setSelectedAgent] = useState('')
  const [domain, setDomain] = useState('')
  const [selectedTasks, setSelectedTasks] = useState<string[]>([])
  const [allTasks, setAllTasks] = useState(true)

  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then(r => r.data),
  })

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
    refetchInterval: 5_000,
  })

  const createScan = useMutation({
    mutationFn: () => scansApi.create({
      agent_id: selectedAgent,
      domain,
      task_types: allTasks ? [] : selectedTasks,
    }).then(r => r.data),
    onSuccess: (scan: ScanJob) => {
      setActiveScan(scan)
      qc.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const cancelScan = useMutation({
    mutationFn: (id: string) => scansApi.cancel(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })

  const agents = agentsData?.agents ?? []
  const scans  = scansData?.scans ?? []

  const toggleTask = (id: string) => {
    setSelectedTasks(prev =>
      prev.includes(id) ? prev.filter(t => t !== id) : [...prev, id]
    )
  }

  const canStart = selectedAgent && domain && (allTasks || selectedTasks.length > 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Scanner</h1>
        <p className="text-gray-400 text-sm mt-1">Configure and launch AD assessment scans</p>
      </div>

      <div className="grid grid-cols-2 gap-6">
        {/* Scan configuration */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
          <h2 className="text-sm font-semibold text-gray-300">New Scan</h2>

          {/* Agent selection */}
          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">Collector Agent</label>
            {agents.length === 0 ? (
              <p className="text-sm text-gray-500">No agents registered. Deploy the collector agent on a domain-joined machine.</p>
            ) : (
              <select
                value={selectedAgent}
                onChange={e => {
                  setSelectedAgent(e.target.value)
                  const agent = agents.find(a => a.id === e.target.value)
                  if (agent) setDomain(agent.domain)
                }}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
              >
                <option value="">Select an agent...</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.name} ({a.hostname}) — {a.status === 'online' ? '🟢' : '🔴'}
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Domain */}
          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">Target Domain</label>
            <input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              placeholder="corp.example.com"
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
            />
          </div>

          {/* Task selection */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs text-gray-400">Collection Modules</label>
              <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={allTasks}
                  onChange={e => setAllTasks(e.target.checked)}
                  className="rounded"
                />
                All modules
              </label>
            </div>
            {!allTasks && (
              <div className="space-y-3 mt-2">
                {(['Core', 'Security'] as const).map(group => (
                  <div key={group}>
                    <p className="text-xs text-gray-600 uppercase tracking-wider mb-1.5">{group}</p>
                    <div className="grid grid-cols-2 gap-2">
                      {TASK_TYPES.filter(t => t.group === group).map(task => (
                        <label
                          key={task.id}
                          className={clsx(
                            'flex items-start gap-2 p-2 rounded-lg border cursor-pointer transition-colors text-xs',
                            selectedTasks.includes(task.id)
                              ? 'border-violet-500/50 bg-violet-500/10'
                              : 'border-gray-700 hover:border-gray-600'
                          )}
                        >
                          <input
                            type="checkbox"
                            checked={selectedTasks.includes(task.id)}
                            onChange={() => toggleTask(task.id)}
                            className="mt-0.5"
                          />
                          <div>
                            <p className="text-white font-medium">{task.label}</p>
                            <p className="text-gray-500">{task.desc}</p>
                          </div>
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <button
            disabled={!canStart || createScan.isPending}
            onClick={() => createScan.mutate()}
            className={clsx(
              'w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors',
              canStart && !createScan.isPending
                ? 'bg-violet-600 hover:bg-violet-500 text-white'
                : 'bg-gray-800 text-gray-500 cursor-not-allowed'
            )}
          >
            {createScan.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> Starting...</>
            ) : (
              <><Play className="w-4 h-4" /> Start Scan</>
            )}
          </button>
        </div>

        {/* Recent scans */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Scan History</h2>
          <div className="space-y-2">
            {scans.slice(0, 8).map(scan => (
              <ScanRow key={scan.id} scan={scan} onCancel={() => cancelScan.mutate(scan.id)} />
            ))}
            {scans.length === 0 && (
              <p className="text-gray-500 text-sm text-center py-6">No scans yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function ScanRow({ scan, onCancel }: { scan: ScanJob; onCancel: () => void }) {
  const statusIcon = {
    pending:   <Loader2 className="w-4 h-4 text-gray-400" />,
    running:   <Loader2 className="w-4 h-4 text-violet-400 animate-spin" />,
    completed: <CheckCircle2 className="w-4 h-4 text-emerald-400" />,
    failed:    <XCircle className="w-4 h-4 text-red-400" />,
    cancelled: <XCircle className="w-4 h-4 text-gray-500" />,
  }[scan.status]

  return (
    <div className="flex items-center gap-3 p-3 bg-gray-800/50 rounded-lg">
      {statusIcon}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-white font-medium truncate">{scan.domain}</p>
        <p className="text-xs text-gray-500">
          {scan.status === 'running' ? (
            <span className="text-violet-400">{scan.progress}% complete</span>
          ) : (
            scan.total_findings !== undefined ? `${scan.total_findings} findings` : scan.status
          )}
        </p>
      </div>
      {scan.status === 'running' && (
        <button
          onClick={onCancel}
          className="p-1 text-gray-400 hover:text-red-400 transition-colors"
          title="Cancel scan"
        >
          <X className="w-4 h-4" />
        </button>
      )}
      {scan.overall_score !== undefined && (
        <span className={clsx(
          'text-xs font-bold',
          scan.overall_score >= 80 ? 'text-emerald-400' :
          scan.overall_score >= 60 ? 'text-amber-400' : 'text-red-400'
        )}>
          {scan.overall_score}
        </span>
      )}
    </div>
  )
}
