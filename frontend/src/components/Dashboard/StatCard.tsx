import type { LucideIcon } from 'lucide-react'

interface Props {
  label: string
  value: number | string
  icon: LucideIcon
  color: string
  suffix?: string
}

const colorMap: Record<string, string> = {
  violet: 'text-violet-400 bg-violet-500/20',
  red:    'text-red-400 bg-red-500/20',
  blue:   'text-blue-400 bg-blue-500/20',
  green:  'text-emerald-400 bg-emerald-500/20',
}

export function StatCard({ label, value, icon: Icon, color, suffix }: Props) {
  const cls = colorMap[color] || colorMap.violet
  const [textCls, bgCls] = cls.split(' ')
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-gray-400 text-xs font-medium">{label}</p>
          <p className="text-2xl font-bold text-white mt-1">
            {value}{suffix && <span className="text-sm text-gray-400 ml-1">{suffix}</span>}
          </p>
        </div>
        <div className={`p-2 rounded-lg ${bgCls}`}>
          <Icon className={`w-5 h-5 ${textCls}`} />
        </div>
      </div>
    </div>
  )
}
