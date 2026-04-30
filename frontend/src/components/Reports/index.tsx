import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansApi, reportsApi } from '../../api'
import { FileText, Download, Loader2, FileJson, FileCode, RefreshCw, CheckCircle2 } from 'lucide-react'
import clsx from 'clsx'

const FORMAT_INFO = {
  html: { label: 'HTML', icon: FileCode, desc: 'Interactive report for browser viewing' },
  pdf:  { label: 'PDF',  icon: FileText, desc: 'Print-ready formatted document' },
  json: { label: 'JSON', icon: FileJson, desc: 'Machine-readable structured data' },
} as const

export function Reports() {
  const qc = useQueryClient()
  const [selectedScan, setSelectedScan] = useState('')
  const [format, setFormat] = useState<'html' | 'pdf' | 'json'>('html')
  const [generating, setGenerating] = useState(false)

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const { data: reportsData, isLoading: reportsLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.list().then(r => r.data),
    refetchInterval: 10_000,
  })

  const completedScans = scansData?.scans?.filter(s => s.status === 'completed') ?? []
  const reports: any[] = reportsData?.reports ?? []

  const generate = useMutation({
    mutationFn: () => reportsApi.generate(selectedScan, format).then(r => r.data),
    onMutate: () => setGenerating(true),
    onSuccess: async (data: { id: string }) => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      const resp = await reportsApi.download(data.id)
      const mimeTypes = { json: 'application/json', html: 'text/html', pdf: 'application/pdf' }
      const blob = new Blob([resp.data], { type: mimeTypes[format] })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `ad-assessment-${selectedScan.slice(0, 8)}.${format}`
      a.click()
      URL.revokeObjectURL(url)
    },
    onSettled: () => setGenerating(false),
  })

  const downloadReport = async (id: string, fmt: string) => {
    const resp = await reportsApi.download(id)
    const mimeTypes: Record<string, string> = { json: 'application/json', html: 'text/html', pdf: 'application/pdf' }
    const blob = new Blob([resp.data], { type: mimeTypes[fmt] ?? 'application/octet-stream' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `report-${id.slice(0, 8)}.${fmt}`
    a.click()
    URL.revokeObjectURL(url)
  }

  const selectedScanObj = completedScans.find(s => s.id === selectedScan)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Reports</h1>
          <p className="text-gray-400 text-sm mt-1">Generate and download AD assessment reports</p>
        </div>
        <span className="text-xs text-gray-500">{reports.length} report{reports.length !== 1 ? 's' : ''} generated</span>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Generator panel */}
        <div className="col-span-1 space-y-5">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-5">
            <h2 className="text-sm font-semibold text-gray-300">Generate Report</h2>

            {/* Scan selector */}
            <div>
              <label className="text-xs text-gray-400 mb-1.5 block">Select Scan</label>
              {completedScans.length === 0 ? (
                <p className="text-sm text-gray-500">No completed scans available.</p>
              ) : (
                <select
                  value={selectedScan}
                  onChange={e => setSelectedScan(e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
                >
                  <option value="">Choose a scan...</option>
                  {completedScans.map(s => (
                    <option key={s.id} value={s.id}>
                      {s.domain} — {new Date(s.completed_at!).toLocaleDateString()} — Score: {s.overall_score ?? '—'}
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Scan summary */}
            {selectedScanObj && (
              <div className="bg-gray-800/50 rounded-lg p-3 space-y-1 text-xs">
                <div className="flex justify-between text-gray-400">
                  <span>Domain</span><span className="text-white font-mono">{selectedScanObj.domain}</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Score</span>
                  <span className={clsx('font-bold', (selectedScanObj.overall_score ?? 0) >= 80 ? 'text-emerald-400' : (selectedScanObj.overall_score ?? 0) >= 60 ? 'text-amber-400' : 'text-red-400')}>
                    {selectedScanObj.overall_score ?? '—'}
                  </span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Findings</span><span className="text-white">{selectedScanObj.total_findings}</span>
                </div>
                <div className="flex justify-between text-gray-400">
                  <span>Critical</span><span className="text-red-400 font-medium">{selectedScanObj.critical_count}</span>
                </div>
              </div>
            )}

            {/* Format picker */}
            <div>
              <label className="text-xs text-gray-400 mb-2 block">Output Format</label>
              <div className="space-y-2">
                {(Object.entries(FORMAT_INFO) as [string, typeof FORMAT_INFO[keyof typeof FORMAT_INFO]][]).map(([key, info]) => {
                  const Icon = info.icon
                  const isSelected = format === key
                  return (
                    <button
                      key={key}
                      onClick={() => setFormat(key as 'html' | 'pdf' | 'json')}
                      className={clsx(
                        'w-full flex items-center gap-3 p-3 rounded-lg border text-left transition-colors',
                        isSelected ? 'border-violet-500/50 bg-violet-500/10' : 'border-gray-700 hover:border-gray-600'
                      )}
                    >
                      <Icon className={clsx('w-4 h-4 flex-shrink-0', isSelected ? 'text-violet-400' : 'text-gray-400')} />
                      <div>
                        <p className={clsx('text-xs font-medium', isSelected ? 'text-white' : 'text-gray-300')}>{info.label}</p>
                        <p className="text-xs text-gray-500">{info.desc}</p>
                      </div>
                      {isSelected && <CheckCircle2 className="w-3.5 h-3.5 text-violet-400 ml-auto" />}
                    </button>
                  )
                })}
              </div>
            </div>

            <button
              disabled={!selectedScan || generating}
              onClick={() => generate.mutate()}
              className={clsx(
                'w-full flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-medium transition-colors',
                selectedScan && !generating
                  ? 'bg-violet-600 hover:bg-violet-500 text-white'
                  : 'bg-gray-800 text-gray-500 cursor-not-allowed'
              )}
            >
              {generating ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Generating...</>
              ) : (
                <><Download className="w-4 h-4" /> Generate & Download</>
              )}
            </button>
          </div>
        </div>

        {/* Report history */}
        <div className="col-span-2">
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-800 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-gray-300">Report History</h2>
              <button
                onClick={() => qc.invalidateQueries({ queryKey: ['reports'] })}
                className="p-1.5 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
            </div>

            {reportsLoading ? (
              <div className="flex items-center justify-center h-32 text-gray-500 text-sm">
                <Loader2 className="w-4 h-4 animate-spin mr-2" /> Loading...
              </div>
            ) : reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-40 text-gray-500 space-y-2">
                <FileText className="w-8 h-8 opacity-30" />
                <p className="text-sm">No reports generated yet.</p>
              </div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
                    <th className="px-5 py-3 font-medium">Domain</th>
                    <th className="px-5 py-3 font-medium">Format</th>
                    <th className="px-5 py-3 font-medium">Score</th>
                    <th className="px-5 py-3 font-medium">Generated</th>
                    <th className="px-5 py-3 font-medium"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {reports.map((rep: any) => (
                    <tr key={rep.id} className="hover:bg-gray-800/50 transition-colors">
                      <td className="px-5 py-3 font-mono text-xs text-white">{rep.domain}</td>
                      <td className="px-5 py-3">
                        <span className={clsx('text-xs px-2 py-0.5 rounded font-mono uppercase',
                          rep.format === 'html' ? 'bg-blue-500/20 text-blue-400' :
                          rep.format === 'pdf'  ? 'bg-red-500/20 text-red-400' :
                          'bg-amber-500/20 text-amber-400'
                        )}>
                          {rep.format}
                        </span>
                      </td>
                      <td className="px-5 py-3">
                        <span className={clsx('text-sm font-bold',
                          rep.score >= 80 ? 'text-emerald-400' : rep.score >= 60 ? 'text-amber-400' : 'text-red-400'
                        )}>
                          {rep.score}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-xs text-gray-400">
                        {rep.generated_at ? new Date(rep.generated_at).toLocaleString() : '—'}
                      </td>
                      <td className="px-5 py-3">
                        <button
                          onClick={() => downloadReport(rep.id, rep.format)}
                          className="flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300 transition-colors"
                        >
                          <Download className="w-3.5 h-3.5" /> Download
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
