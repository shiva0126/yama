import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import { Filter, Search, ShieldAlert, ArrowRight } from 'lucide-react'
import { findingsApi, scansApi } from '../../api'
import type { Finding, Severity } from '../../types'

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

const severityConfig: Record<Severity, { label: string; tone: string; dot: string; weight: number }> = {
  critical: { label: 'Critical', tone: 'border-red-200 bg-red-50 text-red-700', dot: 'bg-red-500', weight: 5 },
  high: { label: 'High', tone: 'border-orange-200 bg-orange-50 text-orange-700', dot: 'bg-orange-500', weight: 4 },
  medium: { label: 'Medium', tone: 'border-amber-200 bg-amber-50 text-amber-700', dot: 'bg-amber-500', weight: 3 },
  low: { label: 'Low', tone: 'border-sky-200 bg-sky-50 text-sky-700', dot: 'bg-sky-500', weight: 2 },
  info: { label: 'Info', tone: 'border-slate-200 bg-slate-50 text-slate-700', dot: 'bg-slate-500', weight: 1 },
}

type SortKey = 'severity' | 'risk_score' | 'name' | 'detected_at'

export function Findings() {
  const [searchParams] = useSearchParams()
  const scanIdFromURL = searchParams.get('scan_id') ?? ''
  const categoryFromURL = searchParams.get('category') ?? ''

  const [selectedScan, setSelectedScan] = useState(scanIdFromURL)
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | ''>('')
  const [selectedCategory, setSelectedCategory] = useState(categoryFromURL)
  const [search, setSearch] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null)

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['findings', selectedScan],
    queryFn: () => findingsApi.list(selectedScan ? { scan_id: selectedScan } : undefined).then((r) => r.data),
  })

  const scans = scansData?.scans?.filter((scan) => scan.status === 'completed') ?? []
  const allFindings = findingsData?.findings ?? []
  const categories = useMemo(() => [...new Set(allFindings.map((finding) => finding.category))].sort((a, b) => a.localeCompare(b)), [allFindings])

  const filtered = useMemo(() => {
    let list = [...allFindings]
    if (selectedSeverity) list = list.filter((finding) => finding.severity === selectedSeverity)
    if (selectedCategory) list = list.filter((finding) => finding.category === selectedCategory)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter((finding) =>
        [
          finding.name,
          finding.description,
          finding.indicator_id,
          finding.category,
          ...finding.affected_objects.map((item) => `${item.type} ${item.name} ${item.detail}`),
        ]
          .join(' ')
          .toLowerCase()
          .includes(q)
      )
    }

    return list.sort((a, b) => {
      switch (sortKey) {
        case 'risk_score':
          return b.risk_score - a.risk_score
        case 'name':
          return a.name.localeCompare(b.name)
        case 'detected_at':
          return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime()
        default:
          return severityConfig[b.severity].weight - severityConfig[a.severity].weight || b.risk_score - a.risk_score
      }
    })
  }, [allFindings, search, selectedCategory, selectedSeverity, sortKey])

  const selectedFinding = filtered.find((finding) => finding.id === selectedFindingId) ?? filtered[0] ?? null

  const summary = {
    critical: filtered.filter((finding) => finding.severity === 'critical').length,
    high: filtered.filter((finding) => finding.severity === 'high').length,
    newCount: filtered.filter((finding) => finding.is_new).length,
  }

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="label">Exposure queue</p>
            <h2 className="mt-2 text-2xl font-semibold text-slate-950">Findings triage</h2>
            <p className="mt-2 max-w-2xl text-sm leading-7 text-slate-600">
              Sort and filter by operational priority. This view is built for analyst triage, not browsing.
            </p>
          </div>
          <div className="grid min-w-[280px] gap-3 sm:grid-cols-3">
            <SummaryBox label="Critical" value={summary.critical} tone="critical" />
            <SummaryBox label="High" value={summary.high} tone="high" />
            <SummaryBox label="New" value={summary.newCount} tone="neutral" />
          </div>
        </div>
      </section>

      <section className="panel p-6">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[260px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search finding, indicator, object, category"
              className="input pl-10"
            />
          </div>

          <select value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)} className="select min-w-[220px]">
            <option value="">All assessments</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.domain} · {scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : 'Pending'}
              </option>
            ))}
          </select>

          <select value={selectedCategory} onChange={(e) => setSelectedCategory(e.target.value)} className="select min-w-[220px]">
            <option value="">All categories</option>
            {categories.map((category) => (
              <option key={category} value={category}>
                {category}
              </option>
            ))}
          </select>

          <select value={sortKey} onChange={(e) => setSortKey(e.target.value as SortKey)} className="select min-w-[180px]">
            <option value="severity">Sort by severity</option>
            <option value="risk_score">Sort by risk score</option>
            <option value="detected_at">Sort by detection time</option>
            <option value="name">Sort by name</option>
          </select>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <span className="chip">
            <Filter className="h-3.5 w-3.5" />
            Severity
          </span>
          {severityOrder.map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity((prev) => (prev === severity ? '' : severity))}
              className={clsx(
                'rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.14em] transition',
                selectedSeverity === severity
                  ? severityConfig[severity].tone
                  : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50'
              )}
            >
              {severityConfig[severity].label}
            </button>
          ))}
          {(selectedSeverity || selectedCategory || selectedScan || search) && (
            <button
              onClick={() => {
                setSelectedSeverity('')
                setSelectedCategory('')
                setSelectedScan('')
                setSearch('')
              }}
              className="btn-secondary px-3 py-2 text-xs"
            >
              Clear filters
            </button>
          )}
        </div>
      </section>

      {isLoading ? (
        <div className="panel p-12 text-center text-sm text-slate-500">Loading exposure data...</div>
      ) : filtered.length === 0 ? (
        <div className="panel p-12 text-center">
          <ShieldAlert className="mx-auto h-10 w-10 text-slate-600" />
          <p className="mt-4 text-sm font-medium text-slate-900">No findings matched the current filter set.</p>
          <p className="mt-2 text-sm text-slate-500">Adjust the filter criteria or run another assessment.</p>
        </div>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1.25fr_0.75fr]">
          <section className="panel overflow-hidden">
            <div className="border-b border-slate-200/80 px-6 py-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="label">Queue</p>
                  <h3 className="mt-1 text-lg font-semibold text-slate-950">{filtered.length} findings</h3>
                </div>
                <span className="chip">{selectedCategory || 'All categories'}</span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-b border-slate-200 text-left text-xs uppercase tracking-[0.16em] text-slate-500">
                  <tr>
                    <th className="px-6 py-3 font-medium">Finding</th>
                    <th className="px-6 py-3 font-medium">Severity</th>
                    <th className="px-6 py-3 font-medium">Risk</th>
                    <th className="px-6 py-3 font-medium">Objects</th>
                    <th className="px-6 py-3 font-medium">Detected</th>
                    <th className="px-6 py-3 font-medium" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/80">
                  {filtered.map((finding) => (
                    <tr
                      key={finding.id}
                      className={clsx('cursor-pointer hover:bg-slate-50', selectedFinding?.id === finding.id && 'bg-slate-50')}
                      onClick={() => setSelectedFindingId(finding.id)}
                    >
                      <td className="px-6 py-4">
                        <div className="min-w-0">
                          <p className="font-medium text-slate-950">{finding.name}</p>
                          <p className="mt-1 line-clamp-2 text-xs leading-6 text-slate-600">{finding.description}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <span className={clsx('h-2.5 w-2.5 rounded-full', severityConfig[finding.severity].dot)} />
                          <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', severityConfig[finding.severity].tone)}>
                            {severityConfig[finding.severity].label}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 font-semibold text-slate-950">{finding.risk_score}</td>
                      <td className="px-6 py-4 text-slate-600">{finding.affected_objects.length}</td>
                      <td className="px-6 py-4 text-slate-600">{new Date(finding.detected_at).toLocaleString()}</td>
                      <td className="px-6 py-4 text-right text-slate-500">
                        <ArrowRight className="inline h-4 w-4" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <aside className="panel p-6">
            {selectedFinding ? <FindingDetail finding={selectedFinding} /> : <p className="text-sm text-slate-500">Select a finding to inspect evidence and remediation.</p>}
          </aside>
        </div>
      )}
    </div>
  )
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="space-y-5">
      <div>
        <p className="label">{finding.category}</p>
        <h3 className="mt-2 text-xl font-semibold text-slate-950">{finding.name}</h3>
        <p className="mt-3 text-sm leading-7 text-slate-600">{finding.description}</p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <InfoCard label="Risk score" value={finding.risk_score} />
        <InfoCard label="Objects" value={finding.affected_objects.length} />
        <InfoCard label="Indicator" value={finding.indicator_id} />
        <InfoCard label="Status" value={finding.is_new ? 'New' : 'Existing'} />
      </div>

      <div>
        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Affected objects</p>
        <div className="mt-3 space-y-2">
          {finding.affected_objects.slice(0, 5).map((object) => (
            <div key={`${object.dn}-${object.name}`} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <p className="text-sm font-medium text-slate-950">{object.name}</p>
              <p className="mt-1 text-xs text-slate-600">{object.type} · {object.detail || object.dn}</p>
            </div>
          ))}
        </div>
      </div>

      <div>
        <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Remediation</p>
        <p className="mt-3 text-sm leading-7 text-slate-600">{finding.remediation}</p>
      </div>

      {finding.mitre.length > 0 && (
        <div>
          <p className="text-xs uppercase tracking-[0.16em] text-slate-500">MITRE</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {finding.mitre.map((item) => (
              <span key={item} className="chip">
                {item}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function SummaryBox({ label, value, tone }: { label: string; value: number; tone: 'critical' | 'high' | 'neutral' }) {
  const toneClass =
    tone === 'critical'
      ? 'border-red-200 bg-red-50 text-red-700'
      : tone === 'high'
        ? 'border-orange-200 bg-orange-50 text-orange-700'
        : 'border-slate-200 bg-white text-slate-700'

  return (
    <div className={clsx('rounded-2xl border p-4', toneClass)}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] opacity-80">{label}</p>
      <p className="mt-2 text-2xl font-semibold">{value}</p>
    </div>
  )
}

function InfoCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-base font-semibold text-slate-950">{value}</p>
    </div>
  )
}
