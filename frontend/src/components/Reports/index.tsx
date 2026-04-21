import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { scansApi, reportsApi } from '../../api'
import { FileText, Download, Loader2 } from 'lucide-react'

export function Reports() {
  const [selectedScan, setSelectedScan] = useState('')
  const [format, setFormat] = useState<'html' | 'pdf' | 'json'>('html')

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const completedScans = scansData?.scans?.filter(s => s.status === 'completed') ?? []

  const generate = useMutation({
    mutationFn: () => reportsApi.generate(selectedScan, format).then(r => r.data),
    onSuccess: async (data: { id: string }) => {
      const resp = await reportsApi.download(data.id)
      const blob = new Blob([resp.data], {
        type: format === 'json' ? 'application/json' : format === 'html' ? 'text/html' : 'application/pdf'
      })
      const url = URL.createObjectURL(blob)
      const a   = document.createElement('a')
      a.href    = url
      a.download = `ad-assessment-report.${format}`
      a.click()
      URL.revokeObjectURL(url)
    },
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Reports</h1>
        <p className="text-gray-400 text-sm mt-1">Generate and download assessment reports</p>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 max-w-lg space-y-5">
        <div>
          <label className="text-xs text-gray-400 mb-1.5 block">Select Scan</label>
          <select
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
          >
            <option value="">Choose a completed scan...</option>
            {completedScans.map(s => (
              <option key={s.id} value={s.id}>
                {s.domain} — {new Date(s.completed_at!).toLocaleDateString()} — Score: {s.overall_score}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="text-xs text-gray-400 mb-1.5 block">Format</label>
          <div className="flex gap-2">
            {(['html', 'pdf', 'json'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFormat(f)}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                  format === f ? 'bg-violet-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-white'
                }`}
              >
                {f.toUpperCase()}
              </button>
            ))}
          </div>
        </div>

        <button
          disabled={!selectedScan || generate.isPending}
          onClick={() => generate.mutate()}
          className="flex items-center gap-2 px-5 py-2.5 bg-violet-600 hover:bg-violet-500 disabled:bg-gray-800 disabled:text-gray-500 text-white rounded-lg text-sm font-medium transition-colors"
        >
          {generate.isPending ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>
          ) : (
            <><Download className="w-4 h-4" /> Generate & Download</>
          )}
        </button>
      </div>
    </div>
  )
}
