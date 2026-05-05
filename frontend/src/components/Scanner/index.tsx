import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, Loader2, Play, Radar, StopCircle } from 'lucide-react'
import clsx from 'clsx'
import { agentsApi, scansApi } from '../../api'
import { useScanStore } from '../../stores/scanStore'
import type { ScanJob } from '../../types'

const taskCatalog = [
  { id: 'topology', label: 'Forest topology', description: 'Domains, trusts, sites, and relationship mapping', group: 'Core' },
  { id: 'users', label: 'Identity inventory', description: 'User accounts, privilege flags, stale accounts', group: 'Core' },
  { id: 'groups', label: 'Group analysis', description: 'Nested groups, privileged memberships, role hygiene', group: 'Core' },
  { id: 'computers', label: 'Asset inventory', description: 'Workstations, servers, stale computers, delegation state', group: 'Core' },
  { id: 'gpos', label: 'Policy analysis', description: 'GPO linkage, SYSVOL exposure, policy configuration', group: 'Security' },
  { id: 'dcinfo', label: 'Controller posture', description: 'Domain controller operating state and security controls', group: 'Security' },
  { id: 'kerberos', label: 'Kerberos security', description: 'Kerberos configuration, pre-auth, encryption risk', group: 'Security' },
  { id: 'acls', label: 'ACL analysis', description: 'Dangerous rights, write exposure, abuseable permissions', group: 'Security' },
  { id: 'trusts', label: 'Trust review', description: 'Cross-domain trust posture and attack bridging paths', group: 'Security' },
  { id: 'adcs', label: 'ADCS and PKI', description: 'Certificate authorities, templates, ESC attack exposure', group: 'Security' },
  { id: 'sites', label: 'Sites and services', description: 'Machine account quota, recycle bin, service structure', group: 'Security' },
  { id: 'fgpp', label: 'FGPP review', description: 'Fine-grained password settings and enforcement drift', group: 'Security' },
  { id: 'ous', label: 'OU structure', description: 'Organizational units, scoping, and governance boundaries', group: 'Core' },
]

export function Scanner() {
  const qc = useQueryClient()
  const { setActiveScan } = useScanStore()

  const [selectedAgent, setSelectedAgent] = useState('')
  const [domain, setDomain] = useState('')
  const [selectedTasks, setSelectedTasks] = useState<string[]>([])
  const [runFullAssessment, setRunFullAssessment] = useState(true)

  const { data: agentsData } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then((r) => r.data),
    refetchInterval: 15000,
  })

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
    refetchInterval: 5000,
  })

  const createScan = useMutation({
    mutationFn: () =>
      scansApi
        .create({
          agent_id: selectedAgent,
          domain,
          task_types: runFullAssessment ? [] : selectedTasks,
        })
        .then((r) => r.data),
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
  const scans = scansData?.scans ?? []
  const completedScans = scans.filter((scan) => scan.status === 'completed')
  const coverageSummary = useMemo(() => {
    const count = runFullAssessment ? taskCatalog.length : selectedTasks.length
    const securityCount = taskCatalog.filter((task) => task.group === 'Security').length
    return {
      count,
      securityCount,
      lastScore: completedScans[0]?.overall_score ?? null,
    }
  }, [completedScans, runFullAssessment, selectedTasks])

  const canStart = Boolean(selectedAgent && domain && (runFullAssessment || selectedTasks.length > 0))

  const toggleTask = (id: string) => {
    setSelectedTasks((prev) => (prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]))
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
        <div className="panel-strong p-6">
          <p className="label">Assessment planning</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Assessment scope</h2>

          <div className="mt-6 grid gap-4 md:grid-cols-3">
            <AssessmentMetric label="Modules in scope" value={coverageSummary.count} detail="Current run plan" />
            <AssessmentMetric label="Security modules" value={coverageSummary.securityCount} detail="Analysis set" />
            <AssessmentMetric
              label="Latest score"
              value={coverageSummary.lastScore ?? '—'}
              detail="Most recent completed run"
            />
          </div>
        </div>

        <div className="panel p-6">
          <p className="label">Execution model</p>
          <div className="mt-4 grid gap-3">
            <ModeCard
              active={runFullAssessment}
              title="Full domain assessment"
              description="Run all collection and analysis modules."
              onClick={() => setRunFullAssessment(true)}
            />
            <ModeCard
              active={!runFullAssessment}
              title="Targeted assessment"
              description="Run only selected modules."
              onClick={() => setRunFullAssessment(false)}
            />
          </div>
        </div>
      </section>

      <section className="grid gap-6 2xl:grid-cols-[1.15fr_0.85fr]">
        <div className="panel p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="label">Launch assessment</p>
              <h3 className="mt-2 text-lg font-semibold text-white">Collector, target domain, and module selection</h3>
            </div>
            <Radar className="h-5 w-5 text-sky-300" />
          </div>

          <div className="mt-5 grid gap-4 md:grid-cols-2">
            <div>
              <label className="label">Collector agent</label>
              <select
                value={selectedAgent}
                onChange={(e) => {
                  setSelectedAgent(e.target.value)
                  const agent = agents.find((item) => item.id === e.target.value)
                  if (agent) setDomain(agent.domain)
                }}
                className="select mt-2"
              >
                <option value="">Select collector</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name} · {agent.hostname} · {agent.status}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="label">Target domain</label>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="corp.example.com"
                className="input mt-2"
              />
            </div>
          </div>

          <div className="mt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="label">Modules</p>
                <p className="mt-1 text-sm text-slate-400">Choose the assessment surfaces to collect and analyze.</p>
              </div>
              {!runFullAssessment && (
                <span className="chip border-sky-400/16 bg-sky-400/8 text-sky-200">{selectedTasks.length} selected</span>
              )}
            </div>

            <div className="mt-4 grid gap-3 xl:grid-cols-2">
              {taskCatalog.map((task) => {
                const selected = runFullAssessment || selectedTasks.includes(task.id)
                return (
                  <button
                    key={task.id}
                    type="button"
                    disabled={runFullAssessment}
                    onClick={() => toggleTask(task.id)}
                    className={clsx(
                      'rounded-2xl border p-4 text-left transition',
                      selected
                        ? 'border-sky-400/22 bg-sky-400/10'
                        : 'border-white/8 bg-white/[0.02] hover:border-white/16 hover:bg-white/[0.04]',
                      runFullAssessment && 'cursor-default'
                    )}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-white">{task.label}</p>
                        <p className="mt-1 text-xs uppercase tracking-[0.16em] text-slate-500">{task.group}</p>
                      </div>
                      <CheckCircle2 className={clsx('h-4 w-4', selected ? 'text-sky-300' : 'text-slate-600')} />
                    </div>
                    <p className="mt-3 text-sm leading-6 text-slate-400">{task.description}</p>
                  </button>
                )
              })}
            </div>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <button disabled={!canStart || createScan.isPending} onClick={() => createScan.mutate()} className="btn-primary">
              {createScan.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start assessment
            </button>
            <span className="text-sm text-slate-500">
              {canStart ? 'Assessment configuration is complete.' : 'Select an agent and target domain to begin.'}
            </span>
          </div>
        </div>

        <div className="grid gap-6">
          <div className="panel p-6">
            <p className="label">Collector availability</p>
            <div className="mt-4 space-y-3">
              {agents.length === 0 ? (
                <p className="text-sm text-slate-500">No collectors have been registered yet.</p>
              ) : (
                agents.map((agent) => (
                  <div key={agent.id} className="rounded-2xl border border-white/8 bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <p className="text-sm font-semibold text-white">{agent.name}</p>
                        <p className="mt-1 text-xs text-slate-500">
                          {agent.hostname} · {agent.domain}
                        </p>
                      </div>
                      <span
                        className={clsx(
                          'chip',
                          agent.status === 'online'
                            ? 'border-emerald-400/18 bg-emerald-400/10 text-emerald-300'
                            : agent.status === 'busy'
                              ? 'border-sky-400/18 bg-sky-400/10 text-sky-200'
                              : 'border-slate-500/20 bg-slate-500/10 text-slate-400'
                        )}
                      >
                        {agent.status}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel overflow-hidden">
            <div className="border-b border-white/8 px-6 py-4">
              <p className="label">Assessment ledger</p>
              <h3 className="mt-1 text-lg font-semibold text-white">Recent runs and execution status</h3>
            </div>
            <div className="divide-y divide-white/6">
              {scans.length === 0 ? (
                <div className="px-6 py-12 text-sm text-slate-500">No assessments have been executed yet.</div>
              ) : (
                scans.slice(0, 8).map((scan) => (
                  <ScanRow
                    key={scan.id}
                    scan={scan}
                    onCancel={() => cancelScan.mutate(scan.id)}
                    isCancelling={cancelScan.isPending}
                  />
                ))
              )}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

function AssessmentMetric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
      <p className="mt-2 text-sm text-slate-400">{detail}</p>
    </div>
  )
}

function ModeCard({
  active,
  title,
  description,
  onClick,
}: {
  active: boolean
  title: string
  description: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={clsx(
        'rounded-2xl border p-4 text-left transition',
        active ? 'border-sky-400/24 bg-sky-400/10' : 'border-white/8 bg-white/[0.02] hover:border-white/16'
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-semibold text-white">{title}</p>
        <CheckCircle2 className={clsx('h-4 w-4', active ? 'text-sky-300' : 'text-slate-600')} />
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-400">{description}</p>
    </button>
  )
}

function ScanRow({
  scan,
  onCancel,
  isCancelling,
}: {
  scan: ScanJob
  onCancel: () => void
  isCancelling: boolean
}) {
  const scoreTone =
    (scan.overall_score ?? 0) >= 80 ? 'text-emerald-300' : (scan.overall_score ?? 0) >= 60 ? 'text-amber-300' : 'text-red-300'

  return (
    <div className="flex items-center gap-4 px-6 py-4">
      <div
        className={clsx(
          'h-2.5 w-2.5 rounded-full',
          scan.status === 'running'
            ? 'bg-sky-400'
            : scan.status === 'completed'
              ? 'bg-emerald-400'
              : scan.status === 'failed'
                ? 'bg-red-400'
                : 'bg-slate-500'
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <p className="text-sm font-semibold text-white">{scan.domain}</p>
          <span className="chip px-2.5 py-0.5">{scan.status}</span>
        </div>
        <p className="mt-1 text-xs text-slate-500">
          {scan.status === 'running' ? `${scan.progress}% complete` : `${scan.total_findings ?? 0} findings recorded`}
        </p>
      </div>
      {scan.status === 'running' ? (
        <button onClick={onCancel} disabled={isCancelling} className="btn-secondary px-3 py-2">
          {isCancelling ? <Loader2 className="h-4 w-4 animate-spin" /> : <StopCircle className="h-4 w-4" />}
        </button>
      ) : (
        <div className="text-right">
          <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Score</p>
          <p className={clsx('mt-1 text-sm font-semibold', scoreTone)}>{scan.overall_score ?? '—'}</p>
        </div>
      )}
    </div>
  )
}
