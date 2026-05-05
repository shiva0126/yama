import { RadialBar, RadialBarChart, PolarAngleAxis, ResponsiveContainer } from 'recharts'

interface Props {
  score: number
}

function scoreColor(score: number) {
  if (score >= 85) return '#73e0c0'
  if (score >= 70) return '#4ea1ff'
  if (score >= 50) return '#f4c96b'
  return '#ff6b6b'
}

function scoreLabel(score: number) {
  if (score >= 85) return 'Controlled'
  if (score >= 70) return 'Stable'
  if (score >= 50) return 'At risk'
  return 'Exposed'
}

export function ScoreGauge({ score }: Props) {
  const color = scoreColor(score)

  return (
    <div className="flex flex-col items-center">
      <div className="relative h-56 w-56">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%"
            cy="50%"
            data={[{ value: score, fill: color }]}
            innerRadius="62%"
            outerRadius="84%"
            barSize={16}
            startAngle={210}
            endAngle={-30}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} tick={false} angleAxisId={0} />
            <RadialBar background={{ fill: 'rgba(255,255,255,0.08)' }} dataKey="value" angleAxisId={0} cornerRadius={16} />
          </RadialBarChart>
        </ResponsiveContainer>

        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">Protection index</p>
          <span className="mt-2 text-5xl font-semibold text-white">{score}</span>
          <span className="mt-1 text-sm font-medium" style={{ color }}>
            {scoreLabel(score)}
          </span>
        </div>
      </div>
    </div>
  )
}
