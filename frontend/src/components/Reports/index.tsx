import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import clsx from 'clsx'
import { CheckCircle2, Download, FileCode2, FileJson2, FileText, Loader2, RefreshCw } from 'lucide-react'
import { reportsApi, scansApi } from '../../api'

const formatInfo = {
  html: {
    label: 'HTML',
    icon: FileCode2,
    description: 'Browser report.',
  },
  pdf: {
    label: 'PDF',
    icon: FileText,
    description: 'Portable document.',
  },
  json: {
    label: 'JSON',
    icon: FileJson2,
    description: 'Structured export.',
  },
} as const

export function Reports() {
  const qc = useQueryClient()
  const [selectedScan, setSelectedScan] = useState('')
  const [format, setFormat] = useState<'html' | 'pdf' | 'json'>('html')

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.list().then((r) => r.data),
    refetchInterval: 10000,
  })

  const completedScans = scansData?.scans?.filter((scan) => scan.status === 'completed') ?? []
  const reports = reportsData?.reports ?? []
  const selectedScanObject = completedScans.find((scan) => scan.id === selectedScan)

  const generate = useMutation({
    mutationFn: () => reportsApi.generate(selectedScan, format).then((r) => r.data),
    onSuccess: async (payload: { id: string }) => {
      qc.invalidateQueries({ queryKey: ['reports'] })
      const response = await reportsApi.download(payload.id)
      const blob = new Blob([response.data], {
        type:
          format === 'json'
            ? 'application/json'
            : format === 'pdf'
              ? 'application/pdf'
              : 'text/html',
      })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `yama-report-${selectedScan.slice(0, 8)}.${format}`
      link.click()
      URL.revokeObjectURL(url)
    },
  })

  const downloadReport = async (id: string, exportFormat: 'html' | 'pdf' | 'json') => {
    const response = await reportsApi.download(id)
    const blob = new Blob([response.data], {
      type:
        exportFormat === 'json'
          ? 'application/json'
          : exportFormat === 'pdf'
            ? 'application/pdf'
            : 'text/html',
    })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `yama-report-${id.slice(0, 8)}.${exportFormat}`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <p className="label">Reporting</p>
        <h2 className="mt-2 text-2xl font-semibold text-white">Exports</h2>
      </section>

      <section className="grid gap-6 2xl:grid-cols-[0.95fr_1.05fr]">
        <div className="panel p-6">
          <p className="label">Generate report</p>
          <h3 className="mt-2 text-lg font-semibold text-white">Run and format</h3>

          <div className="mt-5 space-y-5">
            <div>
              <label className="label">Assessment run</label>
              <select value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)} className="select mt-2">
                <option value="">Select completed run</option>
                {completedScans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.domain} · {scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : 'Pending'}
                  </option>
                ))}
              </select>
            </div>

            {selectedScanObject && (
              <div className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
                <div className="grid gap-3 sm:grid-cols-2">
                  <InfoLine label="Domain" value={selectedScanObject.domain} />
                  <InfoLine label="Protection index" value={selectedScanObject.overall_score ?? '—'} />
                  <InfoLine label="Critical findings" value={selectedScanObject.critical_count} />
                  <InfoLine label="Total findings" value={selectedScanObject.total_findings} />
                </div>
              </div>
            )}

            <div>
              <label className="label">Output format</label>
              <div className="mt-3 space-y-3">
                {(Object.entries(formatInfo) as Array<[keyof typeof formatInfo, (typeof formatInfo)[keyof typeof formatInfo]]>).map(
                  ([key, item]) => {
                    const Icon = item.icon
                    const active = format === key
                    return (
                      <button
                        key={key}
                        onClick={() => setFormat(key)}
                        className={clsx(
                          'flex w-full items-start gap-3 rounded-2xl border p-4 text-left transition',
                          active ? 'border-sky-400/22 bg-sky-400/10' : 'border-white/8 bg-white/[0.02] hover:border-white/16'
                        )}
                      >
                        <div
                          className={clsx(
                            'flex h-10 w-10 items-center justify-center rounded-xl border',
                            active ? 'border-sky-400/18 bg-sky-400/10 text-sky-200' : 'border-white/8 bg-white/[0.03] text-slate-500'
                          )}
                        >
                          <Icon className="h-4 w-4" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-3">
                            <p className="text-sm font-semibold text-white">{item.label}</p>
                            {active && <CheckCircle2 className="h-4 w-4 text-sky-200" />}
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-400">{item.description}</p>
                        </div>
                      </button>
                    )
                  }
                )}
              </div>
            </div>

            <button disabled={!selectedScan || generate.isPending} onClick={() => generate.mutate()} className="btn-primary">
              {generate.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
              Generate and download
            </button>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <div className="flex items-center justify-between border-b border-white/8 px-6 py-4">
            <div>
              <p className="label">Report ledger</p>
              <h3 className="mt-1 text-lg font-semibold text-white">Generated exports</h3>
            </div>
            <button onClick={() => qc.invalidateQueries({ queryKey: ['reports'] })} className="btn-secondary px-3 py-2">
              <RefreshCw className="h-4 w-4" />
            </button>
          </div>

          {isLoading ? (
            <div className="px-6 py-12 text-center text-sm text-slate-500">Loading report history…</div>
          ) : reports.length === 0 ? (
            <div className="px-6 py-12 text-center text-sm text-slate-500">No reports have been generated yet.</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-white/8 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-6 py-3 font-medium">Domain</th>
                    <th className="px-6 py-3 font-medium">Format</th>
                    <th className="px-6 py-3 font-medium">Score</th>
                    <th className="px-6 py-3 font-medium">Generated</th>
                    <th className="px-6 py-3 font-medium" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/6">
                  {reports.map((report: any) => (
                    <tr key={report.id} className="hover:bg-white/[0.03]">
                      <td className="px-6 py-4 font-medium text-white">{report.domain}</td>
                      <td className="px-6 py-4">
                        <span className="chip uppercase">{report.format}</span>
                      </td>
                      <td className="px-6 py-4 text-slate-300">{report.score}</td>
                      <td className="px-6 py-4 text-slate-400">
                        {report.generated_at ? new Date(report.generated_at).toLocaleString() : '—'}
                      </td>
                      <td className="px-6 py-4">
                        <button onClick={() => downloadReport(report.id, report.format)} className="btn-secondary px-3 py-2">
                          <Download className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}

function InfoLine({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-white">{value}</p>
    </div>
  )
}
