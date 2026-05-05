import { useEffect, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import {
  Download,
  Loader2,
  Network,
  Server,
  Trash2,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react'
import { agentsApi } from '../../api'
import type { InstallJob, InstallRequest } from '../../types'

export function Agents() {
  const qc = useQueryClient()
  const [showInstall, setShowInstall] = useState(false)

  const { data: agentsData, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then((r) => r.data),
    refetchInterval: 10000,
  })

  const deleteAgent = useMutation({
    mutationFn: (id: string) => agentsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const agents = agentsData?.agents ?? []
  const online = agents.filter((agent) => agent.status === 'online').length

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="label">Agent fleet</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Collectors</h2>
          </div>
          <button onClick={() => setShowInstall(true)} className="btn-primary">
            <Download className="h-4 w-4" />
            Install collector
          </button>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <FleetMetric label="Registered collectors" value={agents.length} />
          <FleetMetric label="Online collectors" value={online} />
          <FleetMetric label="Offline collectors" value={agents.length - online} />
        </div>
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-white/8 px-6 py-4">
          <p className="label">Collector inventory</p>
          <h3 className="mt-1 text-lg font-semibold text-white">Current registered agents</h3>
        </div>

        {isLoading ? (
          <div className="px-6 py-12 text-center text-sm text-slate-500">Loading collector fleet…</div>
        ) : agents.length === 0 ? (
          <div className="px-6 py-14 text-center">
            <Server className="mx-auto h-10 w-10 text-slate-600" />
            <p className="mt-4 text-sm font-medium text-slate-300">No collectors registered yet.</p>
            <p className="mt-2 text-sm text-slate-500">Deploy a domain-joined collector to start assessment operations.</p>
          </div>
        ) : (
          <div className="divide-y divide-white/6">
            {agents.map((agent) => (
              <div key={agent.id} className="flex flex-wrap items-center gap-4 px-6 py-4">
                <div
                  className={clsx(
                    'flex h-10 w-10 items-center justify-center rounded-xl border',
                    agent.status === 'online'
                      ? 'border-emerald-400/18 bg-emerald-400/10 text-emerald-300'
                      : 'border-slate-500/16 bg-slate-500/10 text-slate-400'
                  )}
                >
                  {agent.status === 'online' ? <Wifi className="h-4 w-4" /> : <WifiOff className="h-4 w-4" />}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-sm font-semibold text-white">{agent.name}</p>
                    <span
                      className={clsx(
                        'chip capitalize',
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
                  <p className="mt-1 text-xs text-slate-500">
                    {agent.hostname} · {agent.ip_address} · {agent.domain}
                  </p>
                </div>

                <div className="min-w-[180px] text-sm text-slate-400">
                  <p>Version {agent.version || '—'}</p>
                  <p className="mt-1 text-xs text-slate-500">
                    {agent.last_seen ? `Last seen ${new Date(agent.last_seen).toLocaleString()}` : 'No heartbeat yet'}
                  </p>
                </div>

                <button
                  onClick={() => deleteAgent.mutate(agent.id)}
                  className="btn-secondary px-3 py-2 text-red-200 hover:text-red-100"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      {showInstall && <InstallModal onClose={() => setShowInstall(false)} />}
    </div>
  )
}

function InstallModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState<InstallRequest>({
    target_ip: '',
    username: '',
    password: '',
    domain: '',
    agent_name: '',
    ssh_port: 22,
    agent_port: 9090,
  })
  const [jobId, setJobId] = useState<string | null>(null)
  const [job, setJob] = useState<InstallJob | null>(null)

  const install = useMutation({
    mutationFn: () => agentsApi.install(form).then((r) => r.data),
    onSuccess: (payload) => setJobId(payload.job_id),
  })

  useEffect(() => {
    if (!jobId) return
    const timer = setInterval(async () => {
      try {
        const response = await agentsApi.getInstallStatus(jobId)
        setJob(response.data)
        if (response.data.status === 'completed' || response.data.status === 'failed') {
          clearInterval(timer)
          qc.invalidateQueries({ queryKey: ['agents'] })
        }
      } catch {
        clearInterval(timer)
      }
    }, 2000)

    return () => clearInterval(timer)
  }, [jobId, qc])

  const updateField = (key: keyof InstallRequest, value: string | number) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-sm">
      <div className="panel-strong w-full max-w-2xl">
        <div className="flex items-center justify-between border-b border-white/8 px-6 py-5">
          <div>
            <p className="label">Collector installation</p>
            <h3 className="mt-1 text-lg font-semibold text-white">Deploy a new Windows collector over SSH</h3>
          </div>
          <button onClick={onClose} className="btn-secondary px-3 py-2">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-5 px-6 py-6">
          {!jobId ? (
            <>
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Target IP or hostname">
                  <input value={form.target_ip} onChange={(e) => updateField('target_ip', e.target.value)} className="input" />
                </Field>
                <Field label="Agent name">
                  <input value={form.agent_name} onChange={(e) => updateField('agent_name', e.target.value)} className="input" />
                </Field>
                <Field label="Windows username">
                  <input value={form.username} onChange={(e) => updateField('username', e.target.value)} className="input" />
                </Field>
                <Field label="Password">
                  <input type="password" value={form.password} onChange={(e) => updateField('password', e.target.value)} className="input" />
                </Field>
                <Field label="Directory domain">
                  <input value={form.domain} onChange={(e) => updateField('domain', e.target.value)} className="input" />
                </Field>
                <div className="grid grid-cols-2 gap-4">
                  <Field label="SSH port">
                    <input type="number" value={form.ssh_port} onChange={(e) => updateField('ssh_port', Number(e.target.value))} className="input" />
                  </Field>
                  <Field label="Agent port">
                    <input type="number" value={form.agent_port} onChange={(e) => updateField('agent_port', Number(e.target.value))} className="input" />
                  </Field>
                </div>
              </div>

              <div className="rounded-2xl border border-amber-400/18 bg-amber-400/10 p-4 text-sm leading-6 text-amber-100">
                Use a domain-joined Windows host with reachable SSH and credentials that can install the service.
              </div>

              <div className="flex items-center gap-3">
                <button onClick={() => install.mutate()} disabled={install.isPending} className="btn-primary">
                  {install.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                  Start installation
                </button>
                <button onClick={onClose} className="btn-secondary">
                  Cancel
                </button>
              </div>
            </>
          ) : (
            <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-5">
              <p className="label">Install job</p>
              <h4 className="mt-2 text-lg font-semibold text-white">{job?.agent_name || form.agent_name}</h4>
              <p className="mt-2 text-sm text-slate-400">{job?.message || 'Waiting for installer status…'}</p>
              <div className="mt-5 h-2 overflow-hidden rounded-full bg-slate-900/80">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-sky-500 to-cyan-300"
                  style={{ width: `${job?.progress ?? 12}%` }}
                />
              </div>
              <div className="mt-4 flex items-center justify-between text-sm">
                <span className="capitalize text-slate-300">{job?.status || 'pending'}</span>
                <span className="text-slate-500">{job?.progress ?? 0}%</span>
              </div>
              {job?.error && <p className="mt-3 text-sm text-red-300">{job.error}</p>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      <div className="mt-2">{children}</div>
    </label>
  )
}

function FleetMetric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  )
}
