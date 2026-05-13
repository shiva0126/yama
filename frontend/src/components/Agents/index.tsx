import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { CheckCircle, Loader2, Plus, Server, Trash2, Wifi, WifiOff, X, XCircle } from 'lucide-react'
import { agentsApi } from '../../api'
import type { InstallJob, InstallRequest } from '../../types'

export function Agents() {
  const qc = useQueryClient()
  const [showInstall, setShowInstall] = useState(false)
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [form, setForm] = useState<InstallRequest>({
    target_ip: '', username: '', password: '', domain: '', agent_name: '',
  })

  const { data, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list().then(r => r.data),
    refetchInterval: 10_000,
  })

  const { data: jobData } = useQuery({
    queryKey: ['install-job', activeJobId],
    queryFn: () => agentsApi.getInstallStatus(activeJobId!).then(r => r.data),
    enabled: !!activeJobId,
    refetchInterval: (q) => {
      const status = q.state.data?.status
      return status === 'completed' || status === 'failed' ? false : 2000
    },
  })

  const { data: jobsData } = useQuery({
    queryKey: ['agents-install-jobs'],
    queryFn: () => agentsApi.listInstallJobs().then(r => r.data),
    refetchInterval: 15_000,
  })

  const recentJobs: InstallJob[] = jobsData?.jobs ?? []

  const deleteAgent = useMutation({
    mutationFn: (id: string) => agentsApi.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agents'] }),
  })

  const install = useMutation({
    mutationFn: () => agentsApi.install(form),
    onSuccess: (res) => {
      setActiveJobId(res.data.job_id)
      setShowInstall(false)
      setForm({ target_ip: '', username: '', password: '', domain: '', agent_name: '' })
      qc.invalidateQueries({ queryKey: ['agents-install-jobs'] })
    },
  })

  const agents = data?.agents ?? []
  const online = agents.filter(a => a.status === 'online').length

  const statusColor = (s: string) => s === 'online' ? '#16a34a' : s === 'busy' ? '#d97706' : '#dc2626'
  const statusBg   = (s: string) => s === 'online' ? '#f0fdf4' : s === 'busy' ? '#fffbeb' : '#fef2f2'
  const statusBd   = (s: string) => s === 'online' ? '#bbf7d0' : s === 'busy' ? '#fde68a' : '#fecaca'

  return (
    <div className="page-content">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div className="page-title">Agents</div>
          <div style={{ fontSize: 12, color: '#8a9ab5', marginTop: 3 }}>
            {agents.length === 0
              ? 'No agents registered'
              : `${online} online · ${agents.length - online} offline · ${agents.length} total`}
          </div>
        </div>
        <button className="btn btn-primary" onClick={() => setShowInstall(true)}>
          <Plus size={14} /> Deploy agent
        </button>
      </div>

      {/* Summary strip */}
      {agents.length > 0 && (
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 20,
        }}>
          {[
            { label: 'Online',  value: online,                         color: '#16a34a', bg: '#f0fdf4', bd: '#bbf7d0' },
            { label: 'Offline', value: agents.length - online,         color: '#dc2626', bg: '#fef2f2', bd: '#fecaca' },
            { label: 'Total',   value: agents.length,                  color: '#0f1923', bg: '#ffffff', bd: '#e4e8ef' },
          ].map(s => (
            <div key={s.label} className="card" style={{ padding: '14px 18px', borderTop: `3px solid ${s.color}` }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 10, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600, marginTop: 2 }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Active install job progress */}
      {activeJobId && jobData && (
        <div style={{
          marginBottom: 20, padding: '14px 18px', borderRadius: 10,
          background: jobData.status === 'completed' ? '#f0fdf4' : jobData.status === 'failed' ? '#fef2f2' : '#eff6ff',
          border: `1px solid ${jobData.status === 'completed' ? '#bbf7d0' : jobData.status === 'failed' ? '#fecaca' : '#bfdbfe'}`,
          display: 'flex', alignItems: 'center', gap: 14,
        }}>
          {jobData.status === 'completed'
            ? <CheckCircle size={18} color="#16a34a" />
            : jobData.status === 'failed'
            ? <XCircle size={18} color="#dc2626" />
            : <Loader2 size={18} color="#2563eb" className="spin" />}
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>
              {jobData.status === 'completed' ? 'Agent installed successfully' : jobData.status === 'failed' ? 'Installation failed' : `Installing on ${jobData.target_ip}…`}
            </div>
            <div style={{ fontSize: 11, color: '#4b5c72', marginTop: 2 }}>{jobData.message || jobData.error || ''}</div>
            {jobData.status === 'running' && (
              <div style={{ marginTop: 8, height: 4, background: '#dbeafe', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', background: '#2563eb', borderRadius: 2, width: `${jobData.progress ?? 0}%`, transition: 'width 0.4s' }} />
              </div>
            )}
          </div>
          {(jobData.status === 'completed' || jobData.status === 'failed') && (
            <button className="btn-icon" onClick={() => setActiveJobId(null)}><X size={14} /></button>
          )}
        </div>
      )}

      {/* Recent install jobs */}
      {recentJobs.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div className="section-label" style={{ marginBottom: 8 }}>Recent installs</div>
          <div className="card" style={{ overflow: 'hidden' }}>
            <table className="data-table">
              <thead><tr><th>Agent</th><th>Target</th><th>Status</th><th>Message</th></tr></thead>
              <tbody>
                {recentJobs.slice(0, 5).map(job => (
                  <tr key={job.id} onClick={() => setActiveJobId(job.id)} style={{ cursor: 'pointer' }}>
                    <td className="primary">{job.agent_name}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11 }}>{job.target_ip}</td>
                    <td>
                      <span className={`badge badge-${job.status === 'completed' ? 'ok' : job.status === 'failed' ? 'error' : 'info'}`}>
                        {job.status}
                      </span>
                    </td>
                    <td style={{ color: '#8a9ab5', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {job.message || job.error || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Agent cards */}
      {isLoading ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 110 }} />)}
        </div>
      ) : agents.length === 0 ? (
        <div className="card" style={{ padding: '60px 0', textAlign: 'center' }}>
          <Server size={40} style={{ opacity: 0.2, margin: '0 auto 14px', display: 'block', color: '#2563eb' }} />
          <div style={{ fontSize: 14, fontWeight: 500, color: '#4b5c72', marginBottom: 6 }}>No agents deployed</div>
          <div style={{ fontSize: 12, color: '#8a9ab5', maxWidth: 320, margin: '0 auto' }}>
            Deploy an agent on a domain-joined Windows host to begin assessments
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 12 }}>
          {agents.map(agent => (
            <div key={agent.id} className="card" style={{
              padding: '16px',
              borderLeft: `3px solid ${statusColor(agent.status)}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', flex: 1, minWidth: 0 }}>
                  <div style={{
                    width: 36, height: 36, borderRadius: 8, flexShrink: 0,
                    background: statusBg(agent.status), border: `1px solid ${statusBd(agent.status)}`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {agent.status === 'online'
                      ? <Wifi size={16} style={{ color: statusColor(agent.status) }} />
                      : <WifiOff size={16} style={{ color: statusColor(agent.status) }} />
                    }
                  </div>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: '#0f1923', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {agent.name}
                    </div>
                    <div style={{ fontSize: 11, color: '#8a9ab5', marginTop: 1 }}>{agent.domain}</div>
                  </div>
                </div>
                <button
                  className="btn btn-ghost"
                  style={{ padding: '5px 7px', flexShrink: 0, color: '#8a9ab5' }}
                  onClick={() => { if (confirm(`Remove ${agent.name}?`)) deleteAgent.mutate(agent.id) }}
                >
                  <Trash2 size={13} />
                </button>
              </div>

              <div style={{
                marginTop: 14, paddingTop: 12,
                borderTop: '1px solid #f0f3f8',
                display: 'flex', gap: 0, fontSize: 11,
              }}>
                <div style={{ flex: 1 }}>
                  <div style={{ color: '#8a9ab5', marginBottom: 2 }}>IP Address</div>
                  <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#0f1923', fontWeight: 500 }}>
                    {agent.ip_address || '—'}
                  </div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: '#8a9ab5', marginBottom: 2 }}>Version</div>
                  <div style={{ color: '#0f1923', fontWeight: 500 }}>{agent.version || '—'}</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ color: '#8a9ab5', marginBottom: 2 }}>Status</div>
                  <div style={{ fontWeight: 600, color: statusColor(agent.status), textTransform: 'capitalize' }}>
                    {agent.status === 'online'
                      ? 'Online'
                      : formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true })}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Deploy modal */}
      {showInstall && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(15,25,35,0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50,
          backdropFilter: 'blur(2px)',
        }} onClick={() => setShowInstall(false)}>
          <div style={{
            background: '#ffffff',
            border: '1px solid #e4e8ef',
            borderRadius: 14, padding: 28, width: 440,
            boxShadow: '0 20px 60px rgba(15,25,35,0.18)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22 }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: '#0f1923' }}>Deploy agent</div>
              <button onClick={() => setShowInstall(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8a9ab5', padding: 4 }}>
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {([
                { key: 'agent_name', label: 'Agent name', placeholder: 'DC-Agent-01' },
                { key: 'target_ip',  label: 'Target IP',  placeholder: '192.168.1.10' },
                { key: 'domain',     label: 'Domain',     placeholder: 'corp.local' },
                { key: 'username',   label: 'Username',   placeholder: 'Administrator' },
                { key: 'password',   label: 'Password',   placeholder: '••••••••', type: 'password' },
              ] as const).map(f => (
                <div key={f.key}>
                  <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                    {f.label}
                  </label>
                  <input
                    className="field"
                    type={(f as any).type ?? 'text'}
                    placeholder={f.placeholder}
                    value={(form as any)[f.key]}
                    onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                  />
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10, marginTop: 24, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setShowInstall(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                disabled={!form.agent_name || !form.target_ip || !form.domain || !form.username || !form.password || install.isPending}
                onClick={() => install.mutate()}
              >
                {install.isPending ? <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} /> : <Plus size={13} />}
                Deploy
              </button>
            </div>

            {install.isError && (
              <div style={{ marginTop: 14, fontSize: 12, color: '#dc2626', background: '#fef2f2', padding: '10px 14px', borderRadius: 7, border: '1px solid #fecaca' }}>
                Deployment failed — check target connectivity and credentials
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
