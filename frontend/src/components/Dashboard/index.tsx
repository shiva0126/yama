import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { format } from 'date-fns'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { ArrowRight, BadgeAlert, Blocks, Bot, ShieldAlert, ShieldEllipsis, Target } from 'lucide-react'
import { findingsApi, scansApi } from '../../api'
import { ScoreGauge } from './ScoreGauge'
import type { Finding, SecurityIndicator } from '../../types'

const severityPalette: Record<string, string> = {
  critical: '#ff6b6b',
  high: '#ff9c54',
  medium: '#f4c96b',
  low: '#5ea9ff',
  info: '#6b7b90',
}

const categoryTone: Record<string, string> = {
  Kerberos: '#8bbdff',
  'Privileged Access': '#ff8a7a',
  'PKI / Certificate Services': '#73e0c0',
  Delegation: '#76c0ff',
  Trusts: '#f4c96b',
  'NTLM & Authentication': '#ff9c54',
  'Persistence Mechanisms': '#d38bff',
  'Group Policy': '#91a7ff',
  'Domain Controllers': '#6fd0e4',
  'AD Structure': '#8ca8c7',
  'Account Security': '#ffb36d',
}

export function Dashboard() {
  const navigate = useNavigate()

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
    refetchInterval: 10000,
  })

  const scans = scansData?.scans ?? []
  const completedScans = scans.filter((scan) => scan.status === 'completed')
  const latestScan = completedScans[0]
  const previousScan = completedScans[1]
  const runningScan = scans.find((scan) => scan.status === 'running')

  const { data: findingsData } = useQuery({
    queryKey: ['findings', latestScan?.id],
    queryFn: () => (latestScan ? findingsApi.getByScan(latestScan.id).then((r) => r.data) : null),
    enabled: !!latestScan,
  })

  const { data: indicatorsData } = useQuery({
    queryKey: ['indicator-catalog'],
    queryFn: () => findingsApi.listIndicators().then((r) => r.data),
  })

  const findings = findingsData?.findings ?? []
  const indicators = indicatorsData?.indicators ?? []

  const postureDelta =
    latestScan?.overall_score != null && previousScan?.overall_score != null
      ? latestScan.overall_score - previousScan.overall_score
      : null

  const {
    priorityFindings,
    severityData,
    categoryData,
    trendData,
    attackCoverage,
    topAffectedObjects,
  } = useMemo(() => {
    const priority = [...findings]
      .sort((a, b) => {
        if (a.severity === b.severity) return b.risk_score - a.risk_score
        return severityRank(b.severity) - severityRank(a.severity)
      })
      .slice(0, 6)

    const severityCounts = ['critical', 'high', 'medium', 'low', 'info'].map((severity) => ({
      name: severityLabel(severity),
      key: severity,
      value: findings.filter((finding) => finding.severity === severity).length,
      color: severityPalette[severity],
    }))

    const categoryMap = new Map<string, { total: number; weighted: number }>()
    findings.forEach((finding) => {
      const existing = categoryMap.get(finding.category) ?? { total: 0, weighted: 0 }
      existing.total += 1
      existing.weighted += severityRank(finding.severity) * 10 + finding.risk_score
      categoryMap.set(finding.category, existing)
    })

    const categoryEntries = [...categoryMap.entries()]
      .map(([name, value]) => ({
        name,
        total: value.total,
        weighted: value.weighted,
        color: categoryTone[name] ?? '#7c9ec6',
      }))
      .sort((a, b) => b.weighted - a.weighted)
      .slice(0, 7)

    const trend = [...completedScans]
      .reverse()
      .slice(-8)
      .map((scan) => ({
        date: scan.completed_at ? format(new Date(scan.completed_at), 'MMM d') : 'Pending',
        score: scan.overall_score ?? 0,
        critical: scan.critical_count ?? 0,
        high: scan.high_count ?? 0,
      }))

    const covered = new Set(findings.map((finding) => finding.indicator_id)).size
    const coverage = indicators.length > 0 ? Math.round((covered / indicators.length) * 100) : 0

    const objectMap = new Map<string, { label: string; count: number }>()
    findings.forEach((finding) => {
      finding.affected_objects?.slice(0, 5).forEach((object) => {
        const key = `${object.type}:${object.name}`
        const current = objectMap.get(key) ?? { label: `${object.type} · ${object.name}`, count: 0 }
        current.count += 1
        objectMap.set(key, current)
      })
    })

    const objects = [...objectMap.values()].sort((a, b) => b.count - a.count).slice(0, 5)

    return {
      priorityFindings: priority,
      severityData: severityCounts,
      categoryData: categoryEntries,
      trendData: trend,
      attackCoverage: { covered, total: indicators.length, percentage: coverage },
      topAffectedObjects: objects,
    }
  }, [completedScans, findings, indicators])

  return (
    <div className="space-y-6">
      <section className="grid gap-6 xl:grid-cols-[1.45fr_0.95fr]">
        <div className="panel-strong overflow-hidden">
          <div className="border-b border-white/8 px-6 py-5">
            <p className="label">Overview</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-white">Security posture</h2>
          </div>

          <div className="grid gap-4 px-6 py-6 md:grid-cols-2 2xl:grid-cols-4">
            <MetricCard
              icon={ShieldEllipsis}
              title="Protection index"
              value={latestScan?.overall_score ?? '—'}
              suffix="/100"
              detail={postureDelta == null ? 'Awaiting historical baseline' : `${postureDelta >= 0 ? '+' : ''}${postureDelta} vs prior run`}
            />
            <MetricCard
              icon={BadgeAlert}
              title="Critical exposures"
              value={latestScan?.critical_count ?? 0}
              detail="Immediate attack enablers"
              tone="danger"
            />
            <MetricCard
              icon={Target}
              title="Attack classes covered"
              value={attackCoverage.covered}
              suffix={attackCoverage.total ? `/${attackCoverage.total}` : ''}
              detail={`${attackCoverage.percentage}% of current indicator catalog hit in latest dataset`}
              tone="info"
            />
            <MetricCard
              icon={Bot}
              title="Collector state"
              value={runningScan ? 'Live' : 'Idle'}
              detail={runningScan ? `${runningScan.domain} at ${runningScan.progress}%` : 'No active assessment execution'}
              tone={runningScan ? 'success' : 'default'}
            />
          </div>
        </div>

        <div className="panel p-6">
          <div className="flex items-start justify-between">
            <div>
              <p className="label">Latest operation</p>
              <h3 className="mt-2 text-xl font-semibold text-white">{latestScan?.domain ?? 'No completed assessment'}</h3>
              <p className="mt-1 text-sm text-slate-400">
                {latestScan?.completed_at
                  ? `Completed ${format(new Date(latestScan.completed_at), 'MMM d, yyyy • HH:mm')}`
                  : 'No completed assessment available.'}
              </p>
            </div>
            <button onClick={() => navigate('/scanner')} className="btn-secondary">
              Open Assessment
            </button>
          </div>

          <div className="mt-6 flex items-center justify-center">
            <ScoreGauge score={latestScan?.overall_score ?? 0} />
          </div>

          <div className="mt-6 grid gap-3 md:grid-cols-2">
            <CompactStat label="Critical" value={latestScan?.critical_count ?? 0} tone="critical" />
            <CompactStat label="High" value={latestScan?.high_count ?? 0} tone="high" />
            <CompactStat label="Medium" value={latestScan?.medium_count ?? 0} tone="medium" />
            <CompactStat label="Total findings" value={latestScan?.total_findings ?? 0} tone="neutral" />
          </div>
        </div>
      </section>

      <section className="grid gap-6 2xl:grid-cols-[1.2fr_0.8fr]">
        <div className="panel p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="label">Posture trend</p>
              <h3 className="mt-2 text-lg font-semibold text-white">Security score versus severe exposure load</h3>
            </div>
            <button onClick={() => navigate('/reports')} className="btn-ghost text-sky-300">
              Review reports
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-5 h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <defs>
                  <linearGradient id="scoreFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#4ea1ff" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#4ea1ff" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="criticalFill" x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0%" stopColor="#ff6b6b" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="#ff6b6b" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.06)" vertical={false} />
                <XAxis dataKey="date" stroke="#73839a" tickLine={false} axisLine={false} />
                <YAxis stroke="#73839a" tickLine={false} axisLine={false} width={36} />
                <Tooltip
                  contentStyle={{
                    background: 'rgba(7, 17, 31, 0.96)',
                    border: '1px solid rgba(124, 154, 190, 0.16)',
                    borderRadius: 16,
                    color: '#e8eef8',
                  }}
                />
                <Area type="monotone" dataKey="score" stroke="#4ea1ff" fill="url(#scoreFill)" strokeWidth={2.5} />
                <Area type="monotone" dataKey="critical" stroke="#ff6b6b" fill="url(#criticalFill)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="grid gap-6">
          <div className="panel p-6">
            <p className="label">Severity profile</p>
            <h3 className="mt-2 text-lg font-semibold text-white">Latest exposure mix</h3>
            <div className="mt-4 grid items-center gap-4 lg:grid-cols-[0.9fr_1.1fr]">
              <div className="h-[220px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      innerRadius={58}
                      outerRadius={84}
                      paddingAngle={3}
                      stroke="rgba(7, 17, 31, 0.8)"
                    >
                      {severityData.map((entry) => (
                        <Cell key={entry.key} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: 'rgba(7, 17, 31, 0.96)',
                        border: '1px solid rgba(124, 154, 190, 0.16)',
                        borderRadius: 16,
                        color: '#e8eef8',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-3">
                {severityData.map((entry) => (
                  <div key={entry.key} className="flex items-center justify-between rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                      <span className="text-sm text-slate-300">{entry.name}</span>
                    </div>
                    <span className="text-sm font-semibold text-white">{entry.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="panel p-6">
            <p className="label">Attack pressure</p>
            <h3 className="mt-2 text-lg font-semibold text-white">Most exposed control domains</h3>
            <div className="mt-4 h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={categoryData} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 24 }}>
                  <CartesianGrid stroke="rgba(255,255,255,0.05)" horizontal={false} />
                  <XAxis type="number" stroke="#73839a" axisLine={false} tickLine={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#73839a"
                    axisLine={false}
                    tickLine={false}
                    width={120}
                    tick={{ fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      background: 'rgba(7, 17, 31, 0.96)',
                      border: '1px solid rgba(124, 154, 190, 0.16)',
                      borderRadius: 16,
                      color: '#e8eef8',
                    }}
                  />
                  <Bar dataKey="weighted" radius={[0, 8, 8, 0]}>
                    {categoryData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.15fr_0.85fr]">
        <div className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/8 px-6 py-4">
            <div>
              <p className="label">Priority queue</p>
              <h3 className="mt-1 text-lg font-semibold text-white">Highest-priority exposures from the latest assessment</h3>
            </div>
            <button onClick={() => navigate('/findings')} className="btn-secondary">
              Open Exposure
            </button>
          </div>

          <div className="divide-y divide-white/6">
            {priorityFindings.length === 0 ? (
              <div className="px-6 py-14 text-center text-sm text-slate-500">No findings available yet.</div>
            ) : (
              priorityFindings.map((finding) => (
                <button
                  key={finding.id}
                  onClick={() => navigate('/findings')}
                  className="flex w-full items-start gap-4 px-6 py-4 text-left transition hover:bg-white/[0.03]"
                >
                  <div
                    className="mt-1 h-2.5 w-2.5 rounded-full"
                    style={{ backgroundColor: severityPalette[finding.severity] }}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-white">{finding.name}</span>
                      <span className="chip px-2.5 py-0.5" style={{ color: severityPalette[finding.severity] }}>
                        {severityLabel(finding.severity)}
                      </span>
                      <span className="text-xs uppercase tracking-[0.16em] text-slate-500">{finding.indicator_id}</span>
                    </div>
                    <p className="mt-2 line-clamp-2 text-sm leading-6 text-slate-400">{finding.description}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Risk</p>
                    <p className="mt-1 text-lg font-semibold text-white">{finding.risk_score}</p>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        <div className="grid gap-6">
          <div className="panel p-6">
            <p className="label">Affected surface</p>
            <h3 className="mt-2 text-lg font-semibold text-white">Objects appearing most often across findings</h3>
            <div className="mt-4 space-y-3">
              {topAffectedObjects.length === 0 ? (
                <p className="text-sm text-slate-500">No affected-object telemetry available yet.</p>
              ) : (
                topAffectedObjects.map((object) => (
                  <div key={object.label} className="flex items-center justify-between rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
                    <div className="flex items-center gap-3">
                      <Blocks className="h-4 w-4 text-slate-500" />
                      <span className="text-sm text-slate-300">{object.label}</span>
                    </div>
                    <span className="text-sm font-semibold text-white">{object.count}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="panel p-6">
            <p className="label">Run ledger</p>
            <h3 className="mt-2 text-lg font-semibold text-white">Recent assessments</h3>
            <div className="mt-4 space-y-3">
              {completedScans.slice(0, 5).map((scan) => (
                <div key={scan.id} className="rounded-2xl border border-white/6 bg-white/[0.02] px-4 py-3">
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-sm font-semibold text-white">{scan.domain}</p>
                      <p className="mt-1 text-xs text-slate-500">
                        {scan.completed_at ? format(new Date(scan.completed_at), 'MMM d, yyyy • HH:mm') : 'Pending'}
                      </p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Score</p>
                      <p className="text-sm font-semibold text-white">{scan.overall_score ?? '—'}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

function severityRank(severity: string) {
  switch (severity) {
    case 'critical':
      return 5
    case 'high':
      return 4
    case 'medium':
      return 3
    case 'low':
      return 2
    default:
      return 1
  }
}

function severityLabel(severity: string) {
  return severity.charAt(0).toUpperCase() + severity.slice(1)
}

function MetricCard({
  icon: Icon,
  title,
  value,
  suffix,
  detail,
  tone = 'default',
}: {
  icon: typeof ShieldAlert
  title: string
  value: string | number
  suffix?: string
  detail: string
  tone?: 'default' | 'danger' | 'info' | 'success'
}) {
  const toneStyles: Record<string, string> = {
    default: 'border-white/8 bg-white/[0.02] text-slate-300',
    danger: 'border-red-400/18 bg-red-400/8 text-red-200',
    info: 'border-sky-400/18 bg-sky-400/8 text-sky-200',
    success: 'border-emerald-400/18 bg-emerald-400/8 text-emerald-200',
  }

  return (
    <div className={`rounded-2xl border p-4 ${toneStyles[tone]}`}>
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/8 bg-black/10">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{title}</p>
          <p className="mt-1 text-2xl font-semibold text-white">
            {value}
            {suffix ? <span className="ml-1 text-base text-slate-500">{suffix}</span> : null}
          </p>
        </div>
      </div>
      <p className="mt-3 text-sm text-slate-400">{detail}</p>
    </div>
  )
}

function CompactStat({
  label,
  value,
  tone,
}: {
  label: string
  value: string | number
  tone: 'critical' | 'high' | 'medium' | 'neutral'
}) {
  const styles: Record<string, string> = {
    critical: 'border-red-400/16 bg-red-400/8 text-red-200',
    high: 'border-orange-400/16 bg-orange-400/8 text-orange-200',
    medium: 'border-amber-400/16 bg-amber-400/8 text-amber-200',
    neutral: 'border-white/8 bg-white/[0.02] text-slate-200',
  }

  return (
    <div className={`rounded-2xl border px-4 py-3 ${styles[tone]}`}>
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-semibold text-white">{value}</p>
    </div>
  )
}
