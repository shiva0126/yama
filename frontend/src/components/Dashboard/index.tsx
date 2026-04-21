import { useQuery } from '@tanstack/react-query'
import { scansApi, findingsApi } from '../../api'
import { ScoreGauge } from './ScoreGauge'
import { SeverityBreakdown } from './SeverityBreakdown'
import { RecentScans } from './RecentScans'
import { CategoryChart } from './CategoryChart'
import { StatCard } from './StatCard'
import { Shield, Users, Server, AlertTriangle } from 'lucide-react'
import type { ScanJob } from '../../types'

export function Dashboard() {
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
    refetchInterval: 10_000,
  })

  const scans = scansData?.scans ?? []
  const latestScan = scans.find(s => s.status === 'completed')

  const { data: findingsData } = useQuery({
    queryKey: ['findings', latestScan?.id],
    queryFn: () => latestScan ? findingsApi.getByScan(latestScan.id).then(r => r.data) : null,
    enabled: !!latestScan,
  })

  const findings = findingsData?.findings ?? []

  const stats = [
    { label: 'Overall Score', value: latestScan?.overall_score ?? '—', icon: Shield, color: 'violet', suffix: '/100' },
    { label: 'Total Findings', value: latestScan?.total_findings ?? '—', icon: AlertTriangle, color: 'red' },
    { label: 'Critical Issues', value: latestScan?.critical_count ?? '—', icon: AlertTriangle, color: 'red' },
    { label: 'Scans Run', value: scans.length, icon: Server, color: 'blue' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Dashboard</h1>
        <p className="text-gray-400 text-sm mt-1">Active Directory security posture overview</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        {stats.map((stat) => (
          <StatCard key={stat.label} {...stat} />
        ))}
      </div>

      {/* Main panels */}
      <div className="grid grid-cols-3 gap-6">
        {/* Score gauge */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Security Score</h2>
          <ScoreGauge score={latestScan?.overall_score ?? 0} />
        </div>

        {/* Severity breakdown */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Findings by Severity</h2>
          <SeverityBreakdown scan={latestScan} />
        </div>

        {/* Category chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
          <h2 className="text-sm font-medium text-gray-400 mb-4">Findings by Category</h2>
          <CategoryChart findings={findings} />
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        <h2 className="text-sm font-medium text-gray-400 mb-4">Recent Scans</h2>
        <RecentScans scans={scans.slice(0, 10)} />
      </div>
    </div>
  )
}
