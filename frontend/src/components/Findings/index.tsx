import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { findingsApi, scansApi } from '../../api'
import { ChevronDown, ChevronRight, ExternalLink, ShieldAlert, Search, SlidersHorizontal } from 'lucide-react'
import clsx from 'clsx'
import type { Finding, Severity } from '../../types'

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const SEVERITY_CONFIG: Record<Severity, { label: string; classes: string; bar: string; score: number }> = {
  critical: { label: 'Critical', classes: 'bg-red-500/15 text-red-400 border-red-500/40',     bar: 'bg-red-500',    score: 4 },
  high:     { label: 'High',     classes: 'bg-orange-500/15 text-orange-400 border-orange-500/40', bar: 'bg-orange-500', score: 3 },
  medium:   { label: 'Medium',   classes: 'bg-amber-500/15 text-amber-400 border-amber-500/40', bar: 'bg-amber-500',  score: 2 },
  low:      { label: 'Low',      classes: 'bg-blue-500/15 text-blue-400 border-blue-500/40',   bar: 'bg-blue-500',   score: 1 },
  info:     { label: 'Info',     classes: 'bg-gray-500/15 text-gray-400 border-gray-500/40',   bar: 'bg-gray-500',   score: 0 },
}

const ALL_CATEGORIES = [
  'Kerberos', 'Account Security', 'Privileged Access', 'Group Policy',
  'Domain Controllers', 'AD Structure', 'Delegation', 'Trusts',
  'PKI / Certificate Services', 'NTLM & Authentication', 'Persistence Mechanisms',
]

type SortKey = 'severity' | 'risk_score' | 'name' | 'detected_at'

export function Findings() {
  const [searchParams] = useSearchParams()
  const scanIdFromURL = searchParams.get('scan_id') ?? ''
  const catFromURL    = searchParams.get('category') ?? ''

  const [selectedScan, setSelectedScan]     = useState(scanIdFromURL)
  const [filterSeverity, setFilterSeverity] = useState<Severity | ''>('')
  const [filterCategory, setFilterCategory] = useState(catFromURL)
  const [search, setSearch]                 = useState('')
  const [sortKey, setSortKey]               = useState<SortKey>('severity')
  const [groupMode, setGroupMode]           = useState(true)
  const [expanded, setExpanded]             = useState<string | null>(null)

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['findings', selectedScan],
    queryFn: () => {
      const params: Record<string, string> = {}
      if (selectedScan) params.scan_id = selectedScan
      return findingsApi.list(params).then(r => r.data)
    },
  })

  const scans = scansData?.scans?.filter(s => s.status === 'completed') ?? []

  const findings: Finding[] = useMemo(() => {
    let list = findingsData?.findings ?? []
    if (filterSeverity) list = list.filter(f => f.severity === filterSeverity)
    if (filterCategory) list = list.filter(f => f.category === filterCategory)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(f =>
        f.name.toLowerCase().includes(q) ||
        f.description.toLowerCase().includes(q) ||
        f.indicator_id.toLowerCase().includes(q) ||
        f.affected_objects?.some(o => (o.name ?? '').toLowerCase().includes(q))
      )
    }
    list = [...list].sort((a, b) => {
      if (sortKey === 'severity') return (SEVERITY_CONFIG[b.severity]?.score ?? 0) - (SEVERITY_CONFIG[a.severity]?.score ?? 0)
      if (sortKey === 'risk_score') return b.risk_score - a.risk_score
      if (sortKey === 'name') return a.name.localeCompare(b.name)
      if (sortKey === 'detected_at') return new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime()
      return 0
    })
    return list
  }, [findingsData, filterSeverity, filterCategory, search, sortKey])

  const grouped = useMemo(() => {
    const m: Record<string, Finding[]> = {}
    for (const f of findings) {
      if (!m[f.category]) m[f.category] = []
      m[f.category].push(f)
    }
    return m
  }, [findings])

  const total = findingsData?.findings?.length ?? 0

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Findings</h1>
          <p className="text-gray-400 text-sm mt-0.5">
            {findings.length} of {total} findings
            {filterSeverity || filterCategory || search ? ' (filtered)' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setGroupMode(g => !g)}
            className={clsx('flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors',
              groupMode ? 'bg-violet-600 border-violet-500 text-white' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white')}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            Grouped
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search findings, objects..."
            className="bg-gray-800 border border-gray-700 rounded-lg pl-8 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none w-56"
          />
        </div>

        {/* Scan */}
        <select
          value={selectedScan}
          onChange={e => setSelectedScan(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
        >
          <option value="">All scans</option>
          {scans.map(s => (
            <option key={s.id} value={s.id}>{s.domain} — {new Date(s.completed_at!).toLocaleDateString()}</option>
          ))}
        </select>

        {/* Severity chips */}
        <div className="flex gap-1">
          {SEVERITY_ORDER.map(sev => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(v => v === sev ? '' : sev)}
              className={clsx('px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors capitalize',
                filterSeverity === sev ? SEVERITY_CONFIG[sev].classes : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-white')}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Category */}
        <select
          value={filterCategory}
          onChange={e => setFilterCategory(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
        >
          <option value="">All categories</option>
          {ALL_CATEGORIES.map(cat => <option key={cat} value={cat}>{cat}</option>)}
        </select>

        {/* Sort */}
        <select
          value={sortKey}
          onChange={e => setSortKey(e.target.value as SortKey)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
        >
          <option value="severity">Sort: Severity</option>
          <option value="risk_score">Sort: Risk Score</option>
          <option value="name">Sort: Name</option>
          <option value="detected_at">Sort: Date</option>
        </select>

        {(filterSeverity || filterCategory || search) && (
          <button
            onClick={() => { setFilterSeverity(''); setFilterCategory(''); setSearch('') }}
            className="text-xs text-gray-400 hover:text-white px-2 py-1.5 rounded-lg bg-gray-800 border border-gray-700"
          >
            Clear filters
          </button>
        )}
      </div>

      {isLoading && (
        <div className="text-center py-12 text-gray-500">Loading findings...</div>
      )}

      {!isLoading && findings.length === 0 && (
        <div className="text-center py-16 bg-gray-900 border border-gray-800 rounded-xl">
          <ShieldAlert className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 font-medium">No findings found</p>
          <p className="text-gray-600 text-sm mt-1">
            {total > 0 ? 'Try adjusting your filters.' : 'Run a scan to see security findings.'}
          </p>
        </div>
      )}

      {/* Grouped view */}
      {groupMode && !isLoading && findings.length > 0 && (
        <div className="space-y-3">
          {Object.entries(grouped).map(([category, catFindings]) => (
            <div key={category} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-white">{category}</h3>
                <div className="flex items-center gap-2">
                  {(['critical', 'high', 'medium', 'low'] as Severity[]).map(sev => {
                    const n = catFindings.filter(f => f.severity === sev).length
                    if (!n) return null
                    return <span key={sev} className={clsx('text-xs font-semibold', SEVERITY_CONFIG[sev].classes, 'px-1.5 py-0.5 rounded border')}>{n} {sev}</span>
                  })}
                </div>
              </div>
              <div className="divide-y divide-gray-800">
                {catFindings.map(f => (
                  <FindingRow key={f.id} finding={f} isExpanded={expanded === f.id} onToggle={() => setExpanded(p => p === f.id ? null : f.id)} />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Flat table view */}
      {!groupMode && !isLoading && findings.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs border-b border-gray-800">
                <th className="px-4 py-3 text-left font-medium w-14">ID</th>
                <th className="px-4 py-3 text-left font-medium w-20">Severity</th>
                <th className="px-4 py-3 text-left font-medium">Name</th>
                <th className="px-4 py-3 text-left font-medium">Category</th>
                <th className="px-4 py-3 text-right font-medium w-16">Risk</th>
                <th className="px-4 py-3 text-right font-medium w-16">Objects</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {findings.map(f => (
                <tr
                  key={f.id}
                  className="hover:bg-gray-800/50 cursor-pointer transition-colors"
                  onClick={() => setExpanded(p => p === f.id ? null : f.id)}
                >
                  <td className="px-4 py-3 font-mono text-xs text-gray-500">{f.indicator_id}</td>
                  <td className="px-4 py-3">
                    <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-medium capitalize', SEVERITY_CONFIG[f.severity]?.classes)}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white font-medium">{f.name}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{f.category}</td>
                  <td className="px-4 py-3 text-right">
                    <RiskBar score={f.risk_score} />
                  </td>
                  <td className="px-4 py-3 text-right text-gray-500 text-xs">{f.affected_objects?.length ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function FindingRow({ finding, isExpanded, onToggle }: {
  finding: Finding; isExpanded: boolean; onToggle: () => void
}) {
  const sev = SEVERITY_CONFIG[finding.severity]
  return (
    <div>
      <button className="w-full text-left px-5 py-3.5 hover:bg-gray-800/50 transition-colors flex items-center gap-3" onClick={onToggle}>
        {isExpanded ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />}
        <span className="text-xs font-mono text-gray-500 w-14 flex-shrink-0">{finding.indicator_id}</span>
        <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-medium flex-shrink-0', sev.classes)}>{sev.label}</span>
        <span className="text-sm text-white font-medium flex-1 min-w-0 truncate">{finding.name}</span>
        <RiskBar score={finding.risk_score} />
        <span className="text-xs text-gray-500 flex-shrink-0 w-16 text-right">
          {finding.affected_objects?.length ?? 0} obj{(finding.affected_objects?.length ?? 0) !== 1 ? 's' : ''}
        </span>
      </button>

      {isExpanded && (
        <div className="px-14 pb-5 pt-2 space-y-4 bg-gray-800/20 border-t border-gray-800">
          {/* Description */}
          <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Affected objects */}
            {finding.affected_objects?.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Affected Objects ({finding.affected_objects.length})</h4>
                <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
                  {finding.affected_objects.map((obj, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs bg-gray-800 rounded-lg px-3 py-2">
                      <span className="text-gray-500 font-medium w-14 flex-shrink-0">{obj.type}</span>
                      <span className="text-white font-mono flex-1">{obj.name}</span>
                      {obj.detail && <span className="text-gray-500 text-right">{obj.detail}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Remediation */}
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Remediation</h4>
              <p className="text-sm text-gray-300 leading-relaxed bg-gray-800 rounded-lg p-3">{finding.remediation}</p>
            </div>
          </div>

          {/* Footer: MITRE + References */}
          <div className="flex flex-wrap items-center gap-3 pt-1">
            {finding.mitre?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {finding.mitre.map(t => (
                  <a
                    key={t}
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs bg-gray-800 border border-gray-700 text-violet-400 hover:text-violet-300 px-2 py-1 rounded font-mono transition-colors"
                  >
                    {t} <ExternalLink className="w-2.5 h-2.5" />
                  </a>
                ))}
              </div>
            )}
            {finding.references?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {finding.references.map((ref, i) => (
                  <a
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 text-xs text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Reference {i + 1}
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function RiskBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 40 ? 'bg-amber-500' : 'bg-blue-500'
  return (
    <div className="flex items-center gap-1.5 flex-shrink-0">
      <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div className={clsx('h-full rounded-full', color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-500 w-6 text-right">{score}</span>
    </div>
  )
}
