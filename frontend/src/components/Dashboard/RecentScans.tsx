import { formatDistanceToNow } from 'date-fns'
import { Link } from 'react-router-dom'
import clsx from 'clsx'
import type { ScanJob } from '../../types'

interface Props {
  scans: ScanJob[]
}

const statusConfig = {
  pending:   { label: 'Pending',   classes: 'bg-gray-700 text-gray-300' },
  running:   { label: 'Running',   classes: 'bg-violet-500/20 text-violet-400' },
  completed: { label: 'Completed', classes: 'bg-emerald-500/20 text-emerald-400' },
  failed:    { label: 'Failed',    classes: 'bg-red-500/20 text-red-400' },
  cancelled: { label: 'Cancelled', classes: 'bg-gray-700 text-gray-400' },
}

function ScoreBar({ score }: { score?: number }) {
  if (score == null) return <span className="text-gray-500 text-xs">—</span>
  const color = score >= 80 ? 'bg-emerald-500' : score >= 60 ? 'bg-amber-500' : score >= 40 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-gray-800 rounded-full">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-400">{score}</span>
    </div>
  )
}

export function RecentScans({ scans }: Props) {
  if (scans.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <p className="text-sm">No scans yet. Go to Scanner to start your first scan.</p>
      </div>
    )
  }

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-gray-500 text-left border-b border-gray-800">
          <th className="pb-2 font-medium">Domain</th>
          <th className="pb-2 font-medium">Status</th>
          <th className="pb-2 font-medium">Score</th>
          <th className="pb-2 font-medium">Findings</th>
          <th className="pb-2 font-medium">Started</th>
          <th className="pb-2 font-medium"></th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-800">
        {scans.map((scan) => {
          const cfg = statusConfig[scan.status]
          return (
            <tr key={scan.id} className="hover:bg-gray-800/50 transition-colors">
              <td className="py-3 font-medium text-white">{scan.domain}</td>
              <td className="py-3">
                <span className={clsx('text-xs px-2 py-1 rounded-full font-medium', cfg.classes)}>
                  {cfg.label}
                </span>
                {scan.status === 'running' && (
                  <span className="ml-2 text-xs text-violet-400">{scan.progress}%</span>
                )}
              </td>
              <td className="py-3">
                <ScoreBar score={scan.overall_score} />
              </td>
              <td className="py-3">
                <div className="flex items-center gap-2 text-xs">
                  {scan.critical_count > 0 && (
                    <span className="text-red-400">{scan.critical_count}C</span>
                  )}
                  {scan.high_count > 0 && (
                    <span className="text-orange-400">{scan.high_count}H</span>
                  )}
                  {scan.medium_count > 0 && (
                    <span className="text-amber-400">{scan.medium_count}M</span>
                  )}
                </div>
              </td>
              <td className="py-3 text-gray-400">
                {scan.started_at
                  ? formatDistanceToNow(new Date(scan.started_at), { addSuffix: true })
                  : '—'}
              </td>
              <td className="py-3">
                {scan.status === 'completed' && (
                  <Link
                    to={`/findings?scan_id=${scan.id}`}
                    className="text-violet-400 hover:text-violet-300 text-xs font-medium"
                  >
                    View →
                  </Link>
                )}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
