import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Tooltip } from 'recharts'

const SEV_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#0284c7',
  info:     '#94a3b8',
}

/* ── Score gauge (half-donut) ─────────────────────────── */
export function ScoreGauge({ score, size = 130 }: { score: number; size?: number }) {
  const clamp = Math.min(100, Math.max(0, score))
  const color = clamp >= 70 ? '#16a34a' : clamp >= 40 ? '#d97706' : '#dc2626'
  const bg = clamp >= 70 ? '#f0fdf4' : clamp >= 40 ? '#fffbeb' : '#fef2f2'
  const data = [
    { value: clamp,       fill: color },
    { value: 100 - clamp, fill: '#e4e8ef' },
  ]
  const cx = size / 2
  const cy = size * 0.54

  return (
    <div style={{ position: 'relative', width: size, height: size * 0.6, flexShrink: 0 }}>
      <PieChart width={size} height={size * 0.6}>
        <Pie
          data={data}
          cx={cx} cy={cy}
          startAngle={180} endAngle={0}
          innerRadius={size * 0.28} outerRadius={size * 0.44}
          dataKey="value"
          stroke="none"
          isAnimationActive
        >
          {data.map((d, i) => <Cell key={i} fill={d.fill} />)}
        </Pie>
      </PieChart>
      {/* Score text overlay */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center',
      }}>
        <div style={{ fontSize: size * 0.24, fontWeight: 800, color, lineHeight: 1, letterSpacing: '-0.03em' }}>
          {clamp}
        </div>
        <div style={{ fontSize: 9, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>
          / 100
        </div>
      </div>
    </div>
  )
}

/* ── Severity donut ───────────────────────────────────── */
export function SeverityDonut({
  counts, size = 96,
}: {
  counts: Partial<Record<string, number>>; size?: number
}) {
  const SEV = ['critical', 'high', 'medium', 'low', 'info'] as const
  const data = SEV.map(s => ({ name: s, value: counts[s] ?? 0 })).filter(d => d.value > 0)
  const total = data.reduce((a, d) => a + d.value, 0)
  if (total === 0) return (
    <div style={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <span style={{ fontSize: 11, color: '#8a9ab5' }}>No findings</span>
    </div>
  )

  return (
    <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
      <PieChart width={size} height={size}>
        <Pie
          data={data} cx={size / 2} cy={size / 2}
          innerRadius={size * 0.30} outerRadius={size * 0.46}
          dataKey="value" stroke="none" isAnimationActive
        >
          {data.map((d, i) => <Cell key={i} fill={SEV_COLORS[d.name] ?? '#94a3b8'} />)}
        </Pie>
        <Tooltip
          formatter={(v: number, name: string) => [`${v}`, name]}
          contentStyle={{ background: '#fff', border: '1px solid #e4e8ef', borderRadius: 6, fontSize: 11 }}
        />
      </PieChart>
      {/* Total in center */}
      <div style={{
        position: 'absolute', inset: 0,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ fontSize: size * 0.22, fontWeight: 700, color: '#0f1923', lineHeight: 1 }}>{total}</div>
        <div style={{ fontSize: 8, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>total</div>
      </div>
    </div>
  )
}

/* ── Horizontal severity bars (no library) ────────────── */
export function SeverityBars({
  counts, total,
}: {
  counts: Partial<Record<string, number>>; total: number
}) {
  const SEV = [
    { key: 'critical', label: 'C', color: '#dc2626' },
    { key: 'high',     label: 'H', color: '#ea580c' },
    { key: 'medium',   label: 'M', color: '#d97706' },
    { key: 'low',      label: 'L', color: '#0284c7' },
    { key: 'info',     label: 'I', color: '#94a3b8' },
  ] as const

  if (total === 0) return null

  return (
    <div style={{ display: 'flex', gap: 3, alignItems: 'flex-end', height: 36 }}>
      {SEV.map(({ key, label, color }) => {
        const count = counts[key] ?? 0
        const pct = count / total
        const h = Math.max(4, Math.round(pct * 32))
        return (
          <div key={key} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, flex: 1 }} title={`${key}: ${count}`}>
            <div style={{ fontSize: 9, fontWeight: 700, color, lineHeight: 1 }}>{count > 0 ? count : ''}</div>
            <div style={{ width: '100%', height: h, background: color, borderRadius: '2px 2px 0 0', opacity: count === 0 ? 0.15 : 1 }} />
            <div style={{ fontSize: 8, fontWeight: 700, color, letterSpacing: '0.04em' }}>{label}</div>
          </div>
        )
      })}
    </div>
  )
}

/* ── Category bar chart ───────────────────────────────── */
export function CategoryBars({ data }: { data: { name: string; count: number; color?: string }[] }) {
  const max = Math.max(...data.map(d => d.count), 1)
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
      {data.map((d, i) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 110, fontSize: 11, color: '#4b5c72', textAlign: 'right', flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {d.name}
          </div>
          <div style={{ flex: 1, height: 7, background: '#e4e8ef', borderRadius: 4, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 4,
              background: d.color ?? '#2563eb',
              width: `${(d.count / max) * 100}%`,
              transition: 'width 0.5s ease',
            }} />
          </div>
          <div style={{ width: 28, fontSize: 11, fontWeight: 600, color: '#0f1923', flexShrink: 0 }}>{d.count}</div>
        </div>
      ))}
    </div>
  )
}

/* ── Mini sparkline (trend) ───────────────────────────── */
export function MiniTrend({ values, color = '#2563eb', height = 36, width = 80 }: {
  values: number[]; color?: string; height?: number; width?: number
}) {
  if (!values.length) return null
  const max = Math.max(...values, 1)
  const pts = values.map((v, i) => {
    const x = (i / Math.max(values.length - 1, 1)) * (width - 4) + 2
    const y = height - 4 - ((v / max) * (height - 8))
    return `${x},${y}`
  }).join(' ')

  return (
    <svg width={width} height={height} style={{ overflow: 'visible', flexShrink: 0 }}>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <polyline
        points={`2,${height} ${pts} ${width - 2},${height}`}
        fill={color} fillOpacity="0.08" stroke="none"
      />
    </svg>
  )
}

/* ── KPI delta badge ──────────────────────────────────── */
export function Delta({ value, invert = false }: { value: number; invert?: boolean }) {
  if (value === 0) return <span style={{ fontSize: 11, color: '#8a9ab5' }}>—</span>
  const good = invert ? value < 0 : value > 0
  const color = good ? '#16a34a' : '#dc2626'
  const arrow = value > 0 ? '↑' : '↓'
  return (
    <span style={{ fontSize: 11, fontWeight: 600, color }}>
      {arrow} {Math.abs(value)}
    </span>
  )
}
