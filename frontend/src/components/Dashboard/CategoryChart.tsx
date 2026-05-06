import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import type { Finding } from '../../types'

interface Props {
  findings: Finding[]
}

export function CategoryChart({ findings }: Props) {
  if (findings.length === 0) {
    return <p className="text-gray-500 text-sm">No findings yet.</p>
  }

  // Count findings by category
  const counts: Record<string, number> = {}
  for (const f of findings) {
    counts[f.category] = (counts[f.category] ?? 0) + 1
  }

  const data = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({
      name: name.replace('Domain Controllers', 'DCs').replace('Account Security', 'Accounts').replace('Privileged Access', 'Privileged'),
      count,
    }))

  const COLORS = ['#ef4444', '#f97316', '#f59e0b', '#8b5cf6', '#3b82f6', '#10b981', '#6b7280', '#ec4899']

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ left: 0, right: 10 }}>
        <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} />
        <YAxis type="category" dataKey="name" width={75} tick={{ fill: '#9ca3af', fontSize: 10 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: 8 }}
          labelStyle={{ color: '#f3f4f6' }}
          itemStyle={{ color: '#d1d5db' }}
        />
        <Bar dataKey="count" radius={4}>
          {data.map((_, i) => (
            <Cell key={i} fill={COLORS[i % COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
