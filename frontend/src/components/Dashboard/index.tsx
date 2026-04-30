import { useQuery } from '@tanstack/react-query'
import { scansApi, findingsApi } from '../../api'
import { ScoreGauge } from './ScoreGauge'
import { Shield, AlertTriangle, Server, TrendingUp, TrendingDown, Minus, Activity, ChevronRight } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import clsx from 'clsx'
import { format } from 'date-fns'
import { useNavigate } from 'react-router-dom'
import type { ScanJob, Finding } from '../../types'

const SEVERITY_COLORS = {
  critical: { bg: 'bg-red-500',    text: 'text-red-400',    light: 'bg-red-500/10 border-red-500/20' },
  high:     { bg: 'bg-orange-500', text: 'text-orange-400', light: 'bg-orange-500/10 border-orange-500/20' },
  medium:   { bg: 'bg-amber-500',  text: 'text-amber-400',  light: 'bg-amber-500/10 border-amber-500/20' },
  low:      { bg: 'bg-blue-500',   text: 'text-blue-400',   light: 'bg-blue-500/10 border-blue-500/20' },
  info:     { bg: 'bg-gray-500',   text: 'text-gray-400',   light: 'bg-gray-500/10 border-gray-500/20' },
}

const CATEGORY_ICONS: Record<string, string> = {
  'Kerberos': '🎟',
  'Account Security': '👤',
  'Privileged Access': '👑',
  'Group Policy': '📋',
  'Domain Controllers': '🖥',
  'AD Structure': '🏗',
  'Delegation': '🔗',
  'Trusts': '🤝',
  'PKI / Certificate Services': '🔐',
  'NTLM & Authentication': '🔑',
  'Persistence Mechanisms': '🕷',
}

export function Dashboard() {
  const navigate = useNavigate()

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
    refetchInterval: 10_000,
  })

  const scans = scansData?.scans ?? []
  const completedScans = scans.filter(s => s.status === 'completed')
  const latestScan = completedScans[0]
  const prevScan = completedScans[1]

  const { data: findingsData } = useQuery({
    queryKey: ['findings', latestScan?.id],
    queryFn: () => latestScan ? findingsApi.getByScan(latestScan.id).then(r => r.data) : null,
    enabled: !!latestScan,
  })

  const findings = findingsData?.findings ?? []
  const criticalFindings = findings.filter(f => f.severity === 'critical').slice(0, 5)
  const highFindings     = findings.filter(f => f.severity === 'high').slice(0, 5)
  const topFindings      = [...criticalFindings, ...highFindings].slice(0, 6)

  // Score delta vs previous scan
  const scoreDelta = latestScan && prevScan && latestScan.overall_score != null && prevScan.overall_score != null
    ? latestScan.overall_score - prevScan.overall_score : null

  // Trend data — last 10 completed scans oldest→newest
  const trendData = [...completedScans].reverse().slice(-10).map(s => ({
    date: format(new Date(s.completed_at!), 'MMM d'),
    score: s.overall_score ?? 0,
    findings: s.total_findings ?? 0,
    critical: s.critical_count ?? 0,
    high: s.high_count ?? 0,
  }))

  // Category breakdown from findings
  const catMap: Record<string, { critical: number; high: number; medium: number; low: number; total: number }> = {}
  for (const f of findings) {
    if (!catMap[f.category]) catMap[f.category] = { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    catMap[f.category][f.severity as 'critical' | 'high' | 'medium' | 'low']++
    catMap[f.category].total++
  }

  const runningScan = scans.find(s => s.status === 'running')

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Dashboard</h1>
          <p className="text-gray-400 text-sm mt-0.5">
            {latestScan ? `Last scan: ${latestScan.domain} · ${format(new Date(latestScan.completed_at!), 'MMM d, yyyy HH:mm')}` : 'No scans yet'}
          </p>
        </div>
        {runningScan && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-violet-500/10 border border-violet-500/30 rounded-lg">
            <Activity className="w-4 h-4 text-violet-400 animate-pulse" />
            <span className="text-xs text-violet-400 font-medium">Scan in progress — {runningScan.progress}%</span>
          </div>
        )}
      </div>

      {/* Stat cards row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Security Score"
          value={latestScan?.overall_score ?? '—'}
          suffix="/100"
          delta={scoreDelta}
          icon={<Shield className="w-5 h-5" />}
          color="violet"
        />
        <StatCard
          label="Critical Findings"
          value={latestScan?.critical_count ?? '—'}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={latestScan?.critical_count ? 'red' : 'green'}
          good={latestScan?.critical_count === 0}
        />
        <StatCard
          label="High Findings"
          value={latestScan?.high_count ?? '—'}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={latestScan?.high_count ? 'orange' : 'green'}
        />
        <StatCard
          label="Total Scans"
          value={completedScans.length}
          icon={<Server className="w-5 h-5" />}
          color="blue"
          sub={`${scans.filter(s => s.status === 'running').length > 0 ? '1 running' : 'none running'}`}
        />
      </div>

      {/* Score + trend row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Gauge */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col items-center justify-center">
          <p className="text-xs font-medium text-gray-400 mb-3 self-start">Security Score</p>
          <ScoreGauge score={latestScan?.overall_score ?? 0} />
          {scoreDelta !== null && (
            <div className={clsx('flex items-center gap-1 text-xs mt-3 font-medium',
              scoreDelta > 0 ? 'text-emerald-400' : scoreDelta < 0 ? 'text-red-400' : 'text-gray-400')}>
              {scoreDelta > 0 ? <TrendingUp className="w-3.5 h-3.5" /> : scoreDelta < 0 ? <TrendingDown className="w-3.5 h-3.5" /> : <Minus className="w-3.5 h-3.5" />}
              {scoreDelta > 0 ? '+' : ''}{scoreDelta} vs previous scan
            </div>
          )}
        </div>

        {/* Score trend chart */}
        <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-xl p-6">
          <p className="text-xs font-medium text-gray-400 mb-4">Score Trend (last {trendData.length} scans)</p>
          {trendData.length < 2 ? (
            <div className="flex items-center justify-center h-40 text-gray-600 text-sm">
              Need 2+ completed scans to show trend
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="date" tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} width={28} />
                <Tooltip
                  contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
                  labelStyle={{ color: '#9ca3af', fontSize: 11 }}
                  itemStyle={{ fontSize: 12 }}
                />
                <Line type="monotone" dataKey="score" stroke="#8b5cf6" strokeWidth={2} dot={{ fill: '#8b5cf6', r: 3 }} name="Score" />
                <Line type="monotone" dataKey="findings" stroke="#f59e0b" strokeWidth={2} dot={{ fill: '#f59e0b', r: 3 }} name="Findings" />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Findings severity summary + category health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity breakdown */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <p className="text-xs font-medium text-gray-400 mb-4">Findings Breakdown</p>
          <div className="space-y-2.5">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
              const count = latestScan?.[`${sev}_count` as keyof ScanJob] as number ?? 0
              const total = latestScan?.total_findings ?? 1
              const pct   = total > 0 ? Math.round((count / total) * 100) : 0
              const c     = SEVERITY_COLORS[sev]
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-16 capitalize">{sev}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-2 overflow-hidden">
                    <div className={clsx('h-full rounded-full transition-all', c.bg)} style={{ width: `${pct}%` }} />
                  </div>
                  <span className={clsx('text-sm font-semibold w-6 text-right', c.text)}>{count}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Category health grid */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <p className="text-xs font-medium text-gray-400 mb-4">Risk by Category</p>
          {Object.keys(catMap).length === 0 ? (
            <p className="text-gray-600 text-sm text-center pt-6">No findings to display</p>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              {Object.entries(catMap).sort((a, b) => b[1].total - a[1].total).map(([cat, counts]) => (
                <button
                  key={cat}
                  onClick={() => navigate(`/findings?category=${encodeURIComponent(cat)}`)}
                  className="flex items-center gap-2 p-2.5 bg-gray-800 hover:bg-gray-700 rounded-lg text-left transition-colors group"
                >
                  <span className="text-base">{CATEGORY_ICONS[cat] ?? '🔍'}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-white font-medium truncate">{cat}</p>
                    <div className="flex items-center gap-1 mt-0.5">
                      {counts.critical > 0 && <span className="text-red-400 text-xs font-semibold">{counts.critical}C</span>}
                      {counts.high > 0 && <span className="text-orange-400 text-xs">{counts.high}H</span>}
                      {counts.medium > 0 && <span className="text-amber-400 text-xs">{counts.medium}M</span>}
                      {counts.low > 0 && <span className="text-blue-400 text-xs">{counts.low}L</span>}
                    </div>
                  </div>
                  <ChevronRight className="w-3.5 h-3.5 text-gray-600 group-hover:text-gray-400" />
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Top priority findings */}
      {topFindings.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-800 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Top Priority Findings</h2>
            <button
              onClick={() => navigate('/findings')}
              className="text-xs text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1"
            >
              View all <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="divide-y divide-gray-800">
            {topFindings.map(f => (
              <TopFindingRow key={f.id} finding={f} />
            ))}
          </div>
        </div>
      )}

      {/* Recent scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-gray-800 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-white">Scan History</h2>
          <button onClick={() => navigate('/scanner')} className="text-xs text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1">
            Run new scan <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs border-b border-gray-800">
                <th className="px-4 py-2.5 text-left font-medium">Domain</th>
                <th className="px-4 py-2.5 text-left font-medium">Date</th>
                <th className="px-4 py-2.5 text-left font-medium">Score</th>
                <th className="px-4 py-2.5 text-left font-medium">Findings</th>
                <th className="px-4 py-2.5 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {scans.slice(0, 8).map(s => (
                <ScanRow key={s.id} scan={s} onClick={() => navigate(`/findings?scan_id=${s.id}`)} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, suffix, delta, icon, color, good, sub }: {
  label: string; value: number | string; suffix?: string; delta?: number | null
  icon: React.ReactNode; color: string; good?: boolean; sub?: string
}) {
  const colorMap: Record<string, { border: string; icon: string; text: string }> = {
    violet: { border: 'border-violet-500/20', icon: 'text-violet-400 bg-violet-500/10', text: 'text-violet-400' },
    red:    { border: 'border-red-500/20',    icon: 'text-red-400 bg-red-500/10',       text: 'text-red-400' },
    orange: { border: 'border-orange-500/20', icon: 'text-orange-400 bg-orange-500/10', text: 'text-orange-400' },
    green:  { border: 'border-emerald-500/20',icon: 'text-emerald-400 bg-emerald-500/10',text: 'text-emerald-400' },
    blue:   { border: 'border-blue-500/20',   icon: 'text-blue-400 bg-blue-500/10',     text: 'text-blue-400' },
  }
  const c = colorMap[good ? 'green' : color] ?? colorMap.blue

  return (
    <div className={clsx('bg-gray-900 border rounded-xl p-5', c.border)}>
      <div className="flex items-start justify-between mb-3">
        <p className="text-xs text-gray-400">{label}</p>
        <div className={clsx('p-1.5 rounded-lg', c.icon)}>{icon}</div>
      </div>
      <div className="flex items-end gap-1">
        <span className="text-3xl font-bold text-white">{value}</span>
        {suffix && <span className="text-sm text-gray-500 mb-1">{suffix}</span>}
      </div>
      {sub && <p className="text-xs text-gray-500 mt-1">{sub}</p>}
      {delta != null && (
        <p className={clsx('text-xs mt-1 flex items-center gap-0.5',
          delta > 0 ? 'text-emerald-400' : delta < 0 ? 'text-red-400' : 'text-gray-500')}>
          {delta > 0 ? <TrendingUp className="w-3 h-3" /> : delta < 0 ? <TrendingDown className="w-3 h-3" /> : null}
          {delta > 0 ? '+' : ''}{delta} from last scan
        </p>
      )}
    </div>
  )
}

function TopFindingRow({ finding }: { finding: Finding }) {
  const sev = finding.severity
  const c   = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.info
  return (
    <div className="px-5 py-3.5 flex items-center gap-4 hover:bg-gray-800/40 transition-colors">
      <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-medium flex-shrink-0', c.light, c.text)}>
        {sev}
      </span>
      <span className="text-xs font-mono text-gray-500 w-14 flex-shrink-0">{finding.indicator_id}</span>
      <span className="text-sm text-white flex-1 min-w-0 truncate">{finding.name}</span>
      <span className="text-xs text-gray-500 flex-shrink-0">{finding.category}</span>
      {finding.mitre?.length > 0 && (
        <span className="text-xs font-mono text-gray-600">{finding.mitre[0]}</span>
      )}
    </div>
  )
}

function ScanRow({ scan, onClick }: { scan: ScanJob; onClick: () => void }) {
  const statusColors: Record<string, string> = {
    completed: 'text-emerald-400',
    running:   'text-violet-400',
    failed:    'text-red-400',
    pending:   'text-gray-400',
    cancelled: 'text-gray-500',
  }
  const score = scan.overall_score
  const scoreColor = score == null ? 'text-gray-500'
    : score >= 80 ? 'text-emerald-400'
    : score >= 60 ? 'text-amber-400'
    : score >= 40 ? 'text-orange-400'
    : 'text-red-400'

  return (
    <tr className="hover:bg-gray-800/40 cursor-pointer transition-colors" onClick={onClick}>
      <td className="px-4 py-3 font-mono text-xs text-white">{scan.domain}</td>
      <td className="px-4 py-3 text-xs text-gray-400">
        {scan.completed_at ? format(new Date(scan.completed_at), 'MMM d, yyyy HH:mm') : '—'}
      </td>
      <td className={clsx('px-4 py-3 text-sm font-bold', scoreColor)}>
        {score != null ? score : '—'}
      </td>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2 text-xs">
          {scan.critical_count > 0 && <span className="text-red-400 font-semibold">{scan.critical_count}C</span>}
          {scan.high_count > 0 && <span className="text-orange-400">{scan.high_count}H</span>}
          {scan.medium_count > 0 && <span className="text-amber-400">{scan.medium_count}M</span>}
          {scan.low_count > 0 && <span className="text-blue-400">{scan.low_count}L</span>}
          {scan.total_findings === 0 && <span className="text-gray-500">None</span>}
        </div>
      </td>
      <td className={clsx('px-4 py-3 text-xs capitalize font-medium', statusColors[scan.status] ?? 'text-gray-400')}>
        {scan.status}
        {scan.status === 'running' && ` — ${scan.progress}%`}
      </td>
    </tr>
  )
}
