import { useMemo, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import clsx from 'clsx'
import { Filter, Search, ShieldAlert } from 'lucide-react'
import { findingsApi, scansApi } from '../../api'
import type { Finding, Severity } from '../../types'

const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const severityConfig: Record<Severity, { label: string; classes: string; dot: string; score: number }> = {
  critical: {
    label: 'Critical',
    classes: 'border-red-400/20 bg-red-400/10 text-red-200',
    dot: 'bg-red-400',
    score: 5,
  },
  high: {
    label: 'High',
    classes: 'border-orange-400/20 bg-orange-400/10 text-orange-200',
    dot: 'bg-orange-400',
    score: 4,
  },
  medium: {
    label: 'Medium',
    classes: 'border-amber-400/20 bg-amber-400/10 text-amber-200',
    dot: 'bg-amber-400',
    score: 3,
  },
  low: {
    label: 'Low',
    classes: 'border-sky-400/20 bg-sky-400/10 text-sky-200',
    dot: 'bg-sky-400',
    score: 2,
  },
  info: {
    label: 'Info',
    classes: 'border-slate-500/18 bg-slate-500/10 text-slate-300',
    dot: 'bg-slate-500',
    score: 1,
  },
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
  const [expandedId, setExpandedId] = useState<string | null>(null)

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

  const categories = useMemo(
    () => [...new Set(allFindings.map((finding) => finding.category))].sort((a, b) => a.localeCompare(b)),
    [allFindings]
  )

  const filtered = useMemo(() => {
    let list = [...allFindings]
    if (selectedSeverity) list = list.filter((finding) => finding.severity === selectedSeverity)
    if (selectedCategory) list = list.filter((finding) => finding.category === selectedCategory)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(
        (finding) =>
          finding.name.toLowerCase().includes(q) ||
          finding.description.toLowerCase().includes(q) ||
          finding.indicator_id.toLowerCase().includes(q) ||
          finding.affected_objects.some((object) => `${object.type} ${object.name} ${object.detail}`.toLowerCase().includes(q))
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
          return severityConfig[b.severity].score - severityConfig[a.severity].score || b.risk_score - a.risk_score
      }
    })
  }, [allFindings, search, selectedCategory, selectedSeverity, selectedScan, sortKey])

  const grouped = useMemo(() => {
    const map = new Map<string, Finding[]>()
    filtered.forEach((finding) => {
      const items = map.get(finding.category) ?? []
      items.push(finding)
      map.set(finding.category, items)
    })
    return [...map.entries()]
  }, [filtered])

  const summary = {
    critical: filtered.filter((finding) => finding.severity === 'critical').length,
    high: filtered.filter((finding) => finding.severity === 'high').length,
    categories: new Set(filtered.map((finding) => finding.category)).size,
  }

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="label">Exposure analysis</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Findings</h2>
          </div>
          <div className="grid min-w-[280px] gap-3 sm:grid-cols-3">
            <SummaryBox label="Critical" value={summary.critical} tone="critical" />
            <SummaryBox label="High" value={summary.high} tone="high" />
            <SummaryBox label="Categories" value={summary.categories} tone="neutral" />
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
              placeholder="Search findings, indicator IDs, affected objects"
              className="input pl-10"
            />
          </div>

          <select value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)} className="select min-w-[200px]">
            <option value="">All assessments</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                {scan.domain}
              </option>
            ))}
          </select>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="select min-w-[220px]"
          >
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
            Severity filter
          </span>
          {severityOrder.map((severity) => (
            <button
              key={severity}
              onClick={() => setSelectedSeverity((prev) => (prev === severity ? '' : severity))}
              className={clsx(
                'rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.14em] transition',
                selectedSeverity === severity
                  ? severityConfig[severity].classes
                  : 'border-white/8 bg-white/[0.02] text-slate-400 hover:border-white/16 hover:text-slate-200'
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
        <div className="panel p-12 text-center text-sm text-slate-500">Loading exposure data…</div>
      ) : filtered.length === 0 ? (
        <div className="panel p-12 text-center">
          <ShieldAlert className="mx-auto h-10 w-10 text-slate-600" />
          <p className="mt-4 text-sm font-medium text-slate-300">No findings matched the current filter set.</p>
          <p className="mt-2 text-sm text-slate-500">Adjust the filter criteria or run another assessment.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {grouped.map(([category, items]) => (
            <section key={category} className="panel overflow-hidden">
              <div className="flex items-center justify-between border-b border-white/8 px-6 py-4">
                <div>
                  <p className="label">{category}</p>
                  <h3 className="mt-1 text-lg font-semibold text-white">{items.length} findings in this attack surface</h3>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {severityOrder.map((severity) => {
                    const count = items.filter((item) => item.severity === severity).length
                    if (!count) return null
                    return (
                      <span key={severity} className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', severityConfig[severity].classes)}>
                        {count} {severity}
                      </span>
                    )
                  })}
                </div>
              </div>

              <div className="divide-y divide-white/6">
                {items.map((finding) => (
                  <article key={finding.id} className="px-6 py-5">
                    <button
                      type="button"
                      onClick={() => setExpandedId((prev) => (prev === finding.id ? null : finding.id))}
                      className="w-full text-left"
                    >
                      <div className="flex flex-wrap items-start justify-between gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={clsx('h-2.5 w-2.5 rounded-full', severityConfig[finding.severity].dot)} />
                            <span className="text-lg font-semibold text-white">{finding.name}</span>
                            <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', severityConfig[finding.severity].classes)}>
                              {severityConfig[finding.severity].label}
                            </span>
                            <span className="text-xs uppercase tracking-[0.16em] text-slate-500">{finding.indicator_id}</span>
                          </div>
                          <p className="mt-3 text-sm leading-7 text-slate-400">{finding.description}</p>
                        </div>

                        <div className="grid min-w-[180px] gap-3 text-right sm:grid-cols-2 sm:text-left">
                          <div>
                            <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Risk score</p>
                            <p className="mt-1 text-xl font-semibold text-white">{finding.risk_score}</p>
                          </div>
                          <div>
                            <p className="text-xs uppercase tracking-[0.16em] text-slate-500">Affected objects</p>
                            <p className="mt-1 text-xl font-semibold text-white">{finding.affected_objects.length}</p>
                          </div>
                        </div>
                      </div>
                    </button>

                    {expandedId === finding.id && (
                      <div className="mt-5 grid gap-5 xl:grid-cols-[1fr_1fr_0.8fr]">
                        <DetailPanel title="Affected objects">
                          <div className="space-y-3">
                            {finding.affected_objects.length === 0 ? (
                              <p className="text-sm text-slate-500">No object list provided.</p>
                            ) : (
                              finding.affected_objects.map((object, index) => (
                                <div key={`${object.name}-${index}`} className="rounded-2xl border border-white/8 bg-white/[0.02] px-4 py-3">
                                  <p className="text-sm font-semibold text-white">
                                    {object.type} · {object.name}
                                  </p>
                                  <p className="mt-2 text-sm leading-6 text-slate-400">{object.detail}</p>
                                </div>
                              ))
                            )}
                          </div>
                        </DetailPanel>

                        <DetailPanel title="Remediation">
                          <p className="text-sm leading-7 text-slate-300">{finding.remediation}</p>
                        </DetailPanel>

                        <DetailPanel title="References and mapping">
                          <div className="space-y-4">
                            <div>
                              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">MITRE</p>
                              <div className="mt-2 flex flex-wrap gap-2">
                                {finding.mitre.length > 0 ? (
                                  finding.mitre.map((entry) => <span key={entry} className="chip">{entry}</span>)
                                ) : (
                                  <span className="text-sm text-slate-500">No ATT&amp;CK mapping</span>
                                )}
                              </div>
                            </div>
                            <div>
                              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">References</p>
                              <div className="mt-2 space-y-2">
                                {finding.references.length > 0 ? (
                                  finding.references.map((reference) => (
                                    <p key={reference} className="break-all text-sm text-sky-200">
                                      {reference}
                                    </p>
                                  ))
                                ) : (
                                  <span className="text-sm text-slate-500">No references provided</span>
                                )}
                              </div>
                            </div>
                          </div>
                        </DetailPanel>
                      </div>
                    )}
                  </article>
                ))}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  )
}

function SummaryBox({ label, value, tone }: { label: string; value: number; tone: 'critical' | 'high' | 'neutral' }) {
  const styles: Record<string, string> = {
    critical: 'border-red-400/18 bg-red-400/10 text-red-200',
    high: 'border-orange-400/18 bg-orange-400/10 text-orange-200',
    neutral: 'border-white/8 bg-white/[0.03] text-slate-200',
  }

  return (
    <div className={clsx('rounded-2xl border p-4', styles[tone])}>
      <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
    </div>
  )
}

function DetailPanel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-2xl border border-white/8 bg-white/[0.02] p-4">
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">{title}</p>
      <div className="mt-4">{children}</div>
    </div>
  )
}
