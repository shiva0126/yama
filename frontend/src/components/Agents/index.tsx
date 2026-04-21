import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { agentsApi } from '../../api'
import type { InstallJob, InstallRequest } from '../../types'
import {
  Server, Plus, Trash2, Wifi, WifiOff, Download,
  Loader2, CheckCircle2, XCircle, X, ChevronRight,
} from 'lucide-react'
import clsx from 'clsx'

export function Agents() {
  const [showInstall, setShowInstall] = useState(false)
  const qc = useQueryClient()

  const { data: agentsData, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then(r => r.data),
    refetchInterval: 10_000,
  })

  const deleteAgent = useMutation({
    mutationFn: (id: string) => agentsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const agents = agentsData?.agents ?? []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Agents</h1>
          <p className="text-gray-400 text-sm mt-1">
            Manage collector agents deployed on domain-joined Windows machines
          </p>
        </div>
        <button
          onClick={() => setShowInstall(true)}
          className="flex items-center gap-2 px-4 py-2 bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          <Download className="w-4 h-4" />
          Install Agent
        </button>
      </div>

      {/* Agent list */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-300">Registered Agents</h2>
          <span className="text-xs text-gray-500">{agents.length} agent{agents.length !== 1 ? 's' : ''}</span>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-violet-400 animate-spin" />
          </div>
        ) : agents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-center px-6">
            <Server className="w-10 h-10 text-gray-700 mb-3" />
            <p className="text-gray-400 font-medium">No agents registered</p>
            <p className="text-gray-600 text-sm mt-1">
              Click <span className="text-violet-400">Install Agent</span> to deploy one on a domain-joined Windows machine.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {agents.map(agent => (
              <div key={agent.id} className="flex items-center gap-4 px-6 py-4 hover:bg-gray-800/40 transition-colors">
                <div className={clsx(
                  'flex-shrink-0 w-8 h-8 rounded-lg flex items-center justify-center',
                  agent.status === 'online' ? 'bg-emerald-500/15' : 'bg-gray-800',
                )}>
                  {agent.status === 'online'
                    ? <Wifi className="w-4 h-4 text-emerald-400" />
                    : <WifiOff className="w-4 h-4 text-gray-500" />
                  }
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium text-white">{agent.name}</p>
                    <StatusBadge status={agent.status} />
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {agent.hostname} · {agent.ip_address} · {agent.domain}
                  </p>
                </div>

                <div className="text-right hidden md:block">
                  <p className="text-xs text-gray-500">v{agent.version || '—'}</p>
                  <p className="text-xs text-gray-600 mt-0.5">
                    {agent.last_seen ? `Seen ${new Date(agent.last_seen).toLocaleTimeString()}` : 'Never seen'}
                  </p>
                </div>

                <button
                  onClick={() => deleteAgent.mutate(agent.id)}
                  className="p-1.5 text-gray-600 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                  title="Remove agent"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* How to manually register */}
      <ManualRegisterPanel />

      {showInstall && (
        <InstallModal
          onClose={() => {
            setShowInstall(false)
            qc.invalidateQueries({ queryKey: ['agents'] })
          }}
        />
      )}
    </div>
  )
}

// ============================================================
// Install Modal
// ============================================================

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
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const install = useMutation({
    mutationFn: () => agentsApi.install(form).then(r => r.data),
    onSuccess: (data) => {
      setJobId(data.job_id)
    },
  })

  // Poll job status once we have a job ID
  useEffect(() => {
    if (!jobId) return
    pollRef.current = setInterval(async () => {
      try {
        const res = await agentsApi.getInstallStatus(jobId)
        setJob(res.data)
        if (res.data.status === 'completed' || res.data.status === 'failed') {
          clearInterval(pollRef.current!)
          if (res.data.status === 'completed') {
            qc.invalidateQueries({ queryKey: ['agents'] })
          }
        }
      } catch {}
    }, 2000)
    return () => clearInterval(pollRef.current!)
  }, [jobId, qc])

  const set = (k: keyof InstallRequest, v: string | number) =>
    setForm(f => ({ ...f, [k]: v }))

  const isRunning = install.isPending || (job && job.status === 'running' || job?.status === 'pending')
  const isDone = job?.status === 'completed' || job?.status === 'failed'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg bg-gray-900 border border-gray-700 rounded-2xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-violet-500/15 rounded-lg flex items-center justify-center">
              <Download className="w-4 h-4 text-violet-400" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Install Collector Agent</h2>
              <p className="text-xs text-gray-500">Deploy via SSH to a domain-joined Windows machine</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 text-gray-500 hover:text-white transition-colors rounded">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {!jobId ? (
            <>
              {/* Form */}
              <div className="grid grid-cols-2 gap-4">
                <Field label="Target IP / Hostname" required>
                  <input
                    value={form.target_ip}
                    onChange={e => set('target_ip', e.target.value)}
                    placeholder="192.168.1.10"
                    className="input"
                  />
                </Field>
                <Field label="Agent Name" required>
                  <input
                    value={form.agent_name}
                    onChange={e => set('agent_name', e.target.value)}
                    placeholder="DC01-Collector"
                    className="input"
                  />
                </Field>
                <Field label="Windows Username" required>
                  <input
                    value={form.username}
                    onChange={e => set('username', e.target.value)}
                    placeholder="Administrator"
                    autoComplete="off"
                    className="input"
                  />
                </Field>
                <Field label="Password" required>
                  <input
                    type="password"
                    value={form.password}
                    onChange={e => set('password', e.target.value)}
                    autoComplete="new-password"
                    className="input"
                  />
                </Field>
                <Field label="AD Domain" required>
                  <input
                    value={form.domain}
                    onChange={e => set('domain', e.target.value)}
                    placeholder="corp.example.com"
                    className="input"
                  />
                </Field>
                <div className="grid grid-cols-2 gap-2">
                  <Field label="SSH Port">
                    <input
                      type="number"
                      value={form.ssh_port}
                      onChange={e => set('ssh_port', Number(e.target.value))}
                      className="input"
                    />
                  </Field>
                  <Field label="Agent Port">
                    <input
                      type="number"
                      value={form.agent_port}
                      onChange={e => set('agent_port', Number(e.target.value))}
                      className="input"
                    />
                  </Field>
                </div>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/25 rounded-lg px-4 py-3 text-xs text-amber-300 space-y-1">
                <p className="font-medium">Prerequisites</p>
                <ul className="list-disc list-inside space-y-0.5 text-amber-400/80">
                  <li>OpenSSH server enabled on the target machine</li>
                  <li>Agent binary built: <code className="font-mono">make build-agent</code></li>
                  <li>TCP {form.agent_port} open in Windows Firewall after install</li>
                </ul>
              </div>

              {install.isError && (
                <p className="text-sm text-red-400">
                  {(install.error as any)?.response?.data?.error ?? 'Failed to start installation'}
                </p>
              )}

              <button
                disabled={!form.target_ip || !form.username || !form.password || !form.domain || !form.agent_name}
                onClick={() => install.mutate()}
                className={clsx(
                  'w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors',
                  form.target_ip && form.username && form.password && form.domain && form.agent_name
                    ? 'bg-violet-600 hover:bg-violet-500 text-white'
                    : 'bg-gray-800 text-gray-500 cursor-not-allowed',
                )}
              >
                {install.isPending
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting installation...</>
                  : <><Download className="w-4 h-4" /> Install Agent</>
                }
              </button>
            </>
          ) : (
            /* Progress view */
            <div className="space-y-5">
              <ProgressBar progress={job?.progress ?? 0} status={job?.status ?? 'pending'} />

              <div className="space-y-2">
                <StepLog job={job} />
              </div>

              {job?.status === 'completed' && (
                <div className="bg-emerald-500/10 border border-emerald-500/25 rounded-lg px-4 py-3 text-sm text-emerald-300 flex items-start gap-3">
                  <CheckCircle2 className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium">Agent installed successfully</p>
                    <p className="text-emerald-400/70 text-xs mt-0.5">
                      The agent is running and has been registered. You can now start scans.
                    </p>
                  </div>
                </div>
              )}

              {job?.status === 'failed' && (
                <div className="bg-red-500/10 border border-red-500/25 rounded-lg px-4 py-3 text-sm text-red-300 flex items-start gap-3">
                  <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium">Installation failed</p>
                    <p className="text-red-400/70 text-xs mt-1">{job.error}</p>
                  </div>
                </div>
              )}

              <div className="flex gap-3">
                {isDone && (
                  <button
                    onClick={onClose}
                    className="flex-1 py-2.5 bg-violet-600 hover:bg-violet-500 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    Done
                  </button>
                )}
                {job?.status === 'failed' && (
                  <button
                    onClick={() => { setJobId(null); setJob(null) }}
                    className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm font-medium rounded-lg transition-colors"
                  >
                    Try Again
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ============================================================
// Sub-components
// ============================================================

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-xs text-gray-400 mb-1.5 block">
        {label}{required && <span className="text-red-400 ml-0.5">*</span>}
      </label>
      {children}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    online:  'bg-emerald-500/15 text-emerald-400',
    offline: 'bg-gray-800 text-gray-500',
    busy:    'bg-amber-500/15 text-amber-400',
  }
  return (
    <span className={clsx('text-xs px-2 py-0.5 rounded-full font-medium', map[status] ?? 'bg-gray-800 text-gray-500')}>
      {status}
    </span>
  )
}

function ProgressBar({ progress, status }: { progress: number; status: string }) {
  const color = status === 'completed' ? 'bg-emerald-500'
    : status === 'failed' ? 'bg-red-500'
    : 'bg-violet-500'

  return (
    <div>
      <div className="flex justify-between text-xs text-gray-400 mb-1.5">
        <span>Installation progress</span>
        <span>{progress}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={clsx('h-full rounded-full transition-all duration-500', color,
            status === 'running' && progress < 100 ? 'animate-pulse' : ''
          )}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  )
}

const STEPS = [
  { at: 5,  label: 'Locating agent binary' },
  { at: 10, label: 'Connecting via SSH' },
  { at: 20, label: 'Creating installation directory' },
  { at: 35, label: 'Uploading agent binary' },
  { at: 65, label: 'Removing previous installation' },
  { at: 70, label: 'Installing Windows service' },
  { at: 80, label: 'Starting service' },
  { at: 88, label: 'Waiting for agent to come online' },
  { at: 95, label: 'Registering agent' },
  { at: 100, label: 'Complete' },
]

function StepLog({ job }: { job: InstallJob | null }) {
  if (!job) return null
  const progress = job.progress

  return (
    <div className="space-y-1">
      {STEPS.map(step => {
        const done = progress > step.at || (job.status === 'completed' && progress >= step.at)
        const active = job.status === 'running' && progress >= step.at &&
          (STEPS.find(s => s.at > step.at)?.at ?? 101) > progress
        const failed = job.status === 'failed' && active

        return (
          <div key={step.at} className={clsx(
            'flex items-center gap-2.5 text-xs py-1',
            done ? 'text-gray-400' : active ? 'text-white' : 'text-gray-600',
          )}>
            {done && !active ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 flex-shrink-0" />
            ) : active && !failed ? (
              <Loader2 className="w-3.5 h-3.5 text-violet-400 animate-spin flex-shrink-0" />
            ) : failed ? (
              <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
            ) : (
              <ChevronRight className="w-3.5 h-3.5 flex-shrink-0" />
            )}
            {step.label}
          </div>
        )
      })}
    </div>
  )
}

function ManualRegisterPanel() {
  const [open, setOpen] = useState(false)
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', hostname: '', domain: '', ip_address: '' })
  const [result, setResult] = useState<{ api_key: string } | null>(null)

  const register = useMutation({
    mutationFn: () => agentsApi.register(form).then(r => r.data),
    onSuccess: (data) => {
      setResult(data)
      qc.invalidateQueries({ queryKey: ['agents'] })
    },
  })

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-300 transition-colors"
      >
        <Plus className="w-4 h-4" />
        Register agent manually
      </button>
    )
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-300">Manual Registration</h3>
        <button onClick={() => setOpen(false)} className="text-gray-600 hover:text-gray-400">
          <X className="w-4 h-4" />
        </button>
      </div>

      {result ? (
        <div className="space-y-3">
          <p className="text-sm text-emerald-400">Agent registered. Copy the API key — it won't be shown again.</p>
          <div className="bg-gray-800 rounded-lg px-4 py-3">
            <p className="text-xs text-gray-500 mb-1">API Key</p>
            <code className="text-sm text-violet-300 break-all font-mono">{result.api_key}</code>
          </div>
          <button
            onClick={() => { setResult(null); setForm({ name: '', hostname: '', domain: '', ip_address: '' }) }}
            className="text-sm text-gray-400 hover:text-white transition-colors"
          >
            Register another
          </button>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3">
            {(['name', 'hostname', 'domain', 'ip_address'] as const).map(k => (
              <div key={k}>
                <label className="text-xs text-gray-500 mb-1 block capitalize">{k.replace('_', ' ')}</label>
                <input
                  value={form[k]}
                  onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
                  className="input"
                />
              </div>
            ))}
          </div>
          <button
            disabled={!form.name || !form.hostname || !form.domain || register.isPending}
            onClick={() => register.mutate()}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-sm text-white rounded-lg transition-colors disabled:opacity-50"
          >
            {register.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            Register
          </button>
        </>
      )}
    </div>
  )
}
