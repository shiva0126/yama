import { Link, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { format, formatDistanceToNow } from 'date-fns'
import { ArrowRight, BrainCircuit, ShieldAlert, ShieldCheck, Workflow } from 'lucide-react'
import clsx from 'clsx'
import { overviewApi } from '../../api'
import type { ComponentType } from 'react'
import type { ScanJob } from '../../types'

const severityTone: Record<string, string> = {
  critical: 'border-red-500/20 bg-red-500/10 text-red-200',
  high: 'border-orange-500/20 bg-orange-500/10 text-orange-200',
  medium: 'border-amber-500/20 bg-amber-500/10 text-amber-200',
  low: 'border-sky-500/20 bg-sky-500/10 text-sky-200',
  info: 'border-slate-500/20 bg-slate-500/10 text-slate-300',
}

export function Dashboard() {
  const navigate = useNavigate()

  const { data, isLoading } = useQuery({
    queryKey: ['overview-summary'],
    queryFn: () => overviewApi.summary().then((r) => r.data),
    refetchInterval: 15_000,
  })

  const latestScan = data?.scans.latest_completed ?? null
  const recentScans = data?.scans.recent ?? []
  const recentReports = data?.reports.recent ?? []
  const topFindings = data?.findings.top ?? []
  const metricsLoading = isLoading || data === undefined

  return (
    <div className="space-y-6">
      <section className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <div className="panel-strong overflow-hidden">
          <div className="border-b border-slate-200/80 px-6 py-5">
            <p className="label">Executive posture</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Active Directory risk command center</h2>
            <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600">
              A high-density operational view for analysts and CISOs. The focus is current exposure, deltas, collector health, and
              unresolved attack paths.
            </p>
          </div>

          <div className="grid gap-4 px-6 py-6 md:grid-cols-2 xl:grid-cols-4">
            <MetricCard
              icon={ShieldCheck}
              title="Protection index"
              value={metricsLoading ? 'Loading' : (latestScan?.overall_score ?? '—')}
              detail={metricsLoading ? 'Loading assessment summary…' : (latestScan?.completed_at ? `Last completed ${formatDistanceToNow(new Date(latestScan.completed_at), { addSuffix: true })}` : 'No completed assessment yet')}
            />
            <MetricCard
              icon={ShieldAlert}
              title="Critical exposures"
              value={metricsLoading ? 'Loading' : (data?.findings.critical ?? 0)}
              detail={metricsLoading ? 'Loading exposure counts…' : `${data?.findings.new ?? 0} new since the latest scan`}
              tone="danger"
            />
            <MetricCard
              icon={BrainCircuit}
              title="Coverage"
              value={metricsLoading ? 'Loading' : (data?.findings.coverage.percentage ?? 0)}
              suffix="%"
              detail={metricsLoading ? 'Loading coverage data…' : `${data?.findings.coverage.covered ?? 0}/${data?.findings.coverage.total ?? 0} indicators hit`}
              tone="info"
            />
            <MetricCard
              icon={Workflow}
              title="Collectors online"
              value={metricsLoading ? 'Loading' : (data?.collectors.online ?? 0)}
              detail={metricsLoading ? 'Loading collector health…' : `${data?.collectors.stale ?? 0} stale / ${data?.collectors.offline ?? 0} offline`}
              tone="success"
            />
          </div>
        </div>

        <div className="panel p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="label">Operational state</p>
              <h3 className="mt-2 text-xl font-semibold text-slate-950">Current assessment posture</h3>
              <p className="mt-1 text-sm text-slate-600">
                {metricsLoading ? 'Loading current posture…' : `${latestScan?.domain ?? 'No active domain'} ${latestScan?.completed_at ? `• ${format(new Date(latestScan.completed_at), 'MMM d, yyyy HH:mm')}` : ''}`}
              </p>
            </div>
            <button onClick={() => navigate('/scanner')} className="btn-secondary">
              Start assessment
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>

          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            <CompactStat label="Running scans" value={data?.scans.running ?? 0} />
            <CompactStat label="Completed scans" value={data?.scans.completed ?? 0} />
            <CompactStat label="High findings" value={data?.findings.high ?? 0} />
            <CompactStat label="Reports generated" value={data?.reports.total ?? 0} />
          </div>

          <div className="mt-6 rounded-3xl border border-slate-200 bg-slate-50 p-5">
            <p className="label">Leadership view</p>
            <div className="mt-3 flex items-end justify-between gap-4">
              <div>
                <p className="text-5xl font-semibold tracking-tight text-slate-950">{metricsLoading ? 'Loading' : (latestScan?.overall_score ?? '—')}</p>
                <p className="mt-2 text-sm text-slate-600">
                  {metricsLoading ? 'Loading leadership summary…' : 'Protection index for the most recent completed assessment'}
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Latest report</p>
                <p className="mt-1 text-sm font-medium text-slate-900">{metricsLoading ? 'Loading' : (recentReports[0]?.domain ?? '—')}</p>
                <p className="mt-1 text-xs text-slate-500">
                  {metricsLoading
                    ? 'Loading report history…'
                    : recentReports[0]?.generated_at
                      ? formatDistanceToNow(new Date(recentReports[0].generated_at), { addSuffix: true })
                      : 'No report generated yet'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-6 2xl:grid-cols-[1.15fr_0.85fr]">
        <div className="panel overflow-hidden">
            <div className="flex items-center justify-between border-b border-slate-200/80 px-6 py-4">
            <div>
              <p className="label">Analyst queue</p>
              <h3 className="mt-1 text-lg font-semibold text-slate-950">Top exposures requiring review</h3>
            </div>
            <Link to="/findings" className="btn-ghost">
              Open exposure queue
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
          {isLoading ? (
            <div className="px-6 py-12 text-sm text-slate-500">Loading overview…</div>
          ) : topFindings.length === 0 ? (
            <div className="px-6 py-12 text-sm text-slate-500">No findings available for the latest assessment.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-slate-200 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-6 py-3 font-medium">Finding</th>
                    <th className="px-6 py-3 font-medium">Severity</th>
                    <th className="px-6 py-3 font-medium">Risk</th>
                    <th className="px-6 py-3 font-medium">Objects</th>
                    <th className="px-6 py-3 font-medium">Detected</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/80">
                  {topFindings.map((finding) => (
                    <tr key={finding.id} className="hover:bg-slate-50">
                      <td className="px-6 py-4">
                        <div className="min-w-0">
                          <p className="font-medium text-slate-950">{finding.name}</p>
                          <p className="mt-1 line-clamp-2 text-xs leading-6 text-slate-600">{finding.description}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', severityTone[finding.severity])}>
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 font-semibold text-slate-950">{finding.risk_score}</td>
                      <td className="px-6 py-4 text-slate-600">{finding.affected_objects.length}</td>
                      <td className="px-6 py-4 text-slate-600">
                        {formatDistanceToNow(new Date(finding.detected_at), { addSuffix: true })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="grid gap-6">
          <div className="panel p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="label">Collector health</p>
                <h3 className="mt-1 text-lg font-semibold text-slate-950">Fleet readiness</h3>
              </div>
              <span className="chip">
                {data?.collectors.total ?? 0} total
              </span>
            </div>
            <div className="mt-5 space-y-3">
              {metricsLoading ? (
                <p className="text-sm text-slate-500">Loading collector inventory…</p>
              ) : (data?.collectors.recent ?? []).length === 0 ? (
                <p className="text-sm text-slate-500">No collectors registered yet.</p>
              ) : (
                (data?.collectors.recent ?? []).map((agent) => (
                  <div key={agent.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-950">{agent.name}</p>
                        <p className="mt-1 text-xs text-slate-600">{agent.hostname} · {agent.domain}</p>
                      </div>
                      <span className="chip capitalize">{agent.status}</span>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">
                      Last seen {agent.last_seen ? formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : 'unknown'}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="label">Recent scans</p>
                <h3 className="mt-1 text-lg font-semibold text-slate-950">Assessment timeline</h3>
              </div>
              <Link to="/scanner" className="btn-ghost">
                New run
                <ArrowRight className="h-4 w-4" />
              </Link>
            </div>

            <div className="mt-5 space-y-3">
              {metricsLoading ? (
                <p className="text-sm text-slate-500">Loading recent assessments…</p>
              ) : recentScans.length === 0 ? (
                <p className="text-sm text-slate-500">No assessments have been executed yet.</p>
              ) : (
                recentScans.slice(0, 4).map((scan) => (
                  <ScanItem key={scan.id} scan={scan} />
                ))
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="panel p-6">
          <p className="label">Coverage</p>
          <h3 className="mt-2 text-lg font-semibold text-slate-950">Indicator coverage and new exposure load</h3>
          <div className="mt-5 space-y-4">
            <MiniProgress label="Coverage" value={data?.findings.coverage.percentage ?? 0} tone="blue" />
            <MiniProgress label="Critical" value={Math.min(100, (data?.findings.critical ?? 0) * 8)} tone="red" />
            <MiniProgress label="High" value={Math.min(100, (data?.findings.high ?? 0) * 5)} tone="amber" />
          </div>
        </div>

        <div className="panel p-6">
          <p className="label">Reports</p>
          <h3 className="mt-2 text-lg font-semibold text-slate-950">Latest evidence packages</h3>
          <div className="mt-5 space-y-3">
            {metricsLoading ? (
              <p className="text-sm text-slate-500">Loading reports…</p>
            ) : recentReports.length === 0 ? (
              <p className="text-sm text-slate-500">No reports generated yet.</p>
            ) : (
              recentReports.slice(0, 4).map((report) => (
                <div key={report.id} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-950">{report.domain}</p>
                    <p className="mt-1 text-xs text-slate-600">
                      {report.format.toUpperCase()} · score {report.score}
                    </p>
                  </div>
                  <p className="text-xs text-slate-500">
                    {formatDistanceToNow(new Date(report.generated_at), { addSuffix: true })}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </section>
    </div>
  )
}

function MetricCard({
  icon: Icon,
  title,
  value,
  detail,
  suffix = '',
  tone = 'default',
}: {
  icon: ComponentType<{ className?: string }>
  title: string
  value: number | string
  detail: string
  suffix?: string
  tone?: 'default' | 'danger' | 'info' | 'success'
}) {
  const toneClass =
    tone === 'danger'
      ? 'border-red-200 bg-red-50 text-red-700'
      : tone === 'info'
        ? 'border-sky-200 bg-sky-50 text-sky-700'
        : tone === 'success'
          ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
          : 'border-slate-200 bg-white text-slate-700'

  return (
    <div className="rounded-3xl border border-slate-200 bg-white p-4 shadow-[0_8px_24px_rgba(15,23,42,0.04)]">
      <div className={clsx('flex h-11 w-11 items-center justify-center rounded-2xl border', toneClass)}>
        <Icon className="h-5 w-5" />
      </div>
      <p className="mt-4 text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</p>
      <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">
        {value}
        {suffix}
      </p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{detail}</p>
    </div>
  )
}

function CompactStat({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-slate-950">{value}</p>
    </div>
  )
}

function MiniProgress({ label, value, tone }: { label: string; value: number; tone: 'blue' | 'red' | 'amber' }) {
  const color =
    tone === 'red'
      ? 'from-red-500 to-red-400'
      : tone === 'amber'
        ? 'from-amber-500 to-orange-400'
        : 'from-sky-600 to-cyan-500'

  return (
    <div>
      <div className="flex items-center justify-between text-xs uppercase tracking-[0.16em] text-slate-500">
        <span>{label}</span>
        <span>{value}%</span>
      </div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-200">
        <div className={clsx('h-full rounded-full bg-gradient-to-r', color)} style={{ width: `${value}%` }} />
      </div>
    </div>
  )
}

function ScanItem({ scan }: { scan: ScanJob }) {
  return (
    <Link to={`/findings?scan_id=${scan.id}`} className="block rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 transition hover:border-slate-300 hover:bg-white">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-950">{scan.domain}</p>
          <p className="mt-1 text-xs text-slate-600">
            {scan.status} · {scan.total_findings} findings
          </p>
        </div>
        <div className="text-right">
          <p className="text-sm font-semibold text-slate-950">{scan.overall_score ?? '—'}</p>
          <p className="mt-1 text-xs text-slate-500">
            {scan.completed_at ? formatDistanceToNow(new Date(scan.completed_at), { addSuffix: true }) : 'Pending'}
          </p>
        </div>
      </div>
    </Link>
  )
}
