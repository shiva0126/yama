import { RadialBarChart, RadialBar, PolarAngleAxis, ResponsiveContainer } from 'recharts'
import clsx from 'clsx'

interface Props {
  score: number
}

function scoreColor(score: number) {
  if (score >= 80) return '#10b981' // green
  if (score >= 60) return '#f59e0b' // amber
  if (score >= 40) return '#f97316' // orange
  return '#ef4444'                  // red
}

function scoreLabel(score: number) {
  if (score >= 80) return 'Good'
  if (score >= 60) return 'Fair'
  if (score >= 40) return 'Poor'
  return 'Critical'
}

export function ScoreGauge({ score }: Props) {
  const color = scoreColor(score)
  const data = [{ value: score, fill: color }]

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-48 h-48">
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart
            cx="50%"
            cy="50%"
            innerRadius="60%"
            outerRadius="80%"
            barSize={12}
            data={data}
            startAngle={180}
            endAngle={0}
          >
            <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
            <RadialBar background={{ fill: '#1f2937' }} dataKey="value" angleAxisId={0} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold text-white">{score}</span>
          <span className="text-xs text-gray-400">out of 100</span>
        </div>
      </div>
      <span
        className="mt-2 text-sm font-semibold px-3 py-1 rounded-full"
        style={{ color, backgroundColor: color + '20' }}
      >
        {scoreLabel(score)}
      </span>
    </div>
  )
}
