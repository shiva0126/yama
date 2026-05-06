import type { ScanJob } from '../../types'

const SEVERITY_CONFIG = [
  { key: 'critical_count', label: 'Critical', color: '#ef4444', bg: 'bg-red-500/20', text: 'text-red-400' },
  { key: 'high_count',     label: 'High',     color: '#f97316', bg: 'bg-orange-500/20', text: 'text-orange-400' },
  { key: 'medium_count',   label: 'Medium',   color: '#f59e0b', bg: 'bg-amber-500/20', text: 'text-amber-400' },
  { key: 'low_count',      label: 'Low',      color: '#3b82f6', bg: 'bg-blue-500/20', text: 'text-blue-400' },
  { key: 'info_count',     label: 'Info',     color: '#6b7280', bg: 'bg-gray-500/20', text: 'text-gray-400' },
] as const

interface Props {
  scan: ScanJob | undefined
}

export function SeverityBreakdown({ scan }: Props) {
  if (!scan) {
    return <p className="text-gray-500 text-sm">No scan data yet.</p>
  }

  const total = scan.total_findings || 1

  return (
    <div className="space-y-3">
      {SEVERITY_CONFIG.map(({ key, label, color, bg, text }) => {
        const count = scan[key] as number ?? 0
        const pct   = Math.round((count / total) * 100)
        return (
          <div key={key} className="space-y-1">
            <div className="flex items-center justify-between">
              <span className={`text-xs font-medium ${text}`}>{label}</span>
              <span className="text-xs text-gray-400">{count}</span>
            </div>
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{ width: `${pct}%`, backgroundColor: color }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}
