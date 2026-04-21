import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { findingsApi, scansApi } from '../../api'
import { ChevronDown, ChevronRight, ExternalLink, ShieldAlert } from 'lucide-react'
import clsx from 'clsx'
import type { Finding, Severity, FindingCategory } from '../../types'

const SEVERITY_CONFIG: Record<Severity, { label: string; classes: string; dot: string }> = {
  critical: { label: 'Critical', classes: 'bg-red-500/20 text-red-400 border-red-500/40', dot: 'bg-red-500' },
  high:     { label: 'High',     classes: 'bg-orange-500/20 text-orange-400 border-orange-500/40', dot: 'bg-orange-500' },
  medium:   { label: 'Medium',   classes: 'bg-amber-500/20 text-amber-400 border-amber-500/40', dot: 'bg-amber-500' },
  low:      { label: 'Low',      classes: 'bg-blue-500/20 text-blue-400 border-blue-500/40', dot: 'bg-blue-500' },
  info:     { label: 'Info',     classes: 'bg-gray-500/20 text-gray-400 border-gray-500/40', dot: 'bg-gray-500' },
}

const CATEGORIES: FindingCategory[] = [
  'Kerberos', 'Account Security', 'Privileged Access',
  'Group Policy', 'Domain Controllers', 'AD Structure', 'Delegation', 'Trusts'
]

export function Findings() {
  const [searchParams] = useSearchParams()
  const scanIdFromURL = searchParams.get('scan_id')

  const [selectedScan, setSelectedScan] = useState(scanIdFromURL || '')
  const [filterSeverity, setFilterSeverity] = useState<Severity | ''>('')
  const [filterCategory, setFilterCategory] = useState<FindingCategory | ''>('')
  const [expanded, setExpanded] = useState<string | null>(null)

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const { data: findingsData, isLoading } = useQuery({
    queryKey: ['findings', selectedScan, filterSeverity, filterCategory],
    queryFn: () => {
      const params: Record<string, string> = {}
      if (selectedScan) params.scan_id = selectedScan
      if (filterSeverity) params.severity = filterSeverity
      return findingsApi.list(params).then(r => r.data)
    },
  })

  const scans    = scansData?.scans?.filter(s => s.status === 'completed') ?? []
  let findings   = findingsData?.findings ?? []

  if (filterSeverity) findings = findings.filter(f => f.severity === filterSeverity)
  if (filterCategory) findings = findings.filter(f => f.category === filterCategory)

  // Group by category
  const grouped: Record<string, Finding[]> = {}
  for (const f of findings) {
    if (!grouped[f.category]) grouped[f.category] = []
    grouped[f.category].push(f)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-white">Findings</h1>
        <p className="text-gray-400 text-sm mt-1">{findings.length} security findings</p>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
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

        <select
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value as Severity | '')}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
        >
          <option value="">All severities</option>
          {(Object.keys(SEVERITY_CONFIG) as Severity[]).map(s => (
            <option key={s} value={s}>{SEVERITY_CONFIG[s].label}</option>
          ))}
        </select>

        <select
          value={filterCategory}
          onChange={e => setFilterCategory(e.target.value as FindingCategory | '')}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
        >
          <option value="">All categories</option>
          {CATEGORIES.map(cat => (
            <option key={cat} value={cat}>{cat}</option>
          ))}
        </select>
      </div>

      {isLoading && (
        <div className="text-center py-12 text-gray-500">Loading findings...</div>
      )}

      {!isLoading && findings.length === 0 && (
        <div className="text-center py-12">
          <ShieldAlert className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400">No findings found.</p>
          <p className="text-gray-600 text-sm mt-1">Run a scan to see security findings.</p>
        </div>
      )}

      {/* Grouped findings */}
      <div className="space-y-4">
        {Object.entries(grouped).map(([category, catFindings]) => (
          <div key={category} className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">{category}</h3>
              <span className="text-xs text-gray-400">{catFindings.length} finding{catFindings.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="divide-y divide-gray-800">
              {catFindings.map(finding => (
                <FindingRow
                  key={finding.id}
                  finding={finding}
                  isExpanded={expanded === finding.id}
                  onToggle={() => setExpanded(prev => prev === finding.id ? null : finding.id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function FindingRow({ finding, isExpanded, onToggle }: {
  finding: Finding
  isExpanded: boolean
  onToggle: () => void
}) {
  const sev = SEVERITY_CONFIG[finding.severity]

  return (
    <div>
      <button
        className="w-full text-left px-5 py-3.5 hover:bg-gray-800/50 transition-colors flex items-center gap-3"
        onClick={onToggle}
      >
        {isExpanded ? (
          <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
        )}

        <span className="text-xs font-mono text-gray-500 w-12 flex-shrink-0">{finding.indicator_id}</span>

        <span className={clsx('text-xs px-2 py-0.5 rounded-full border font-medium flex-shrink-0', sev.classes)}>
          {sev.label}
        </span>

        <span className="text-sm text-white font-medium flex-1 min-w-0 truncate">{finding.name}</span>

        <span className="text-xs text-gray-500 flex-shrink-0">
          {finding.affected_objects?.length ?? 0} object{(finding.affected_objects?.length ?? 0) !== 1 ? 's' : ''}
        </span>
      </button>

      {isExpanded && (
        <div className="px-5 pb-5 pt-1 space-y-4 bg-gray-800/30">
          <p className="text-sm text-gray-300 leading-relaxed">{finding.description}</p>

          {/* Affected objects */}
          {finding.affected_objects?.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">Affected Objects</h4>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {finding.affected_objects.map((obj, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs bg-gray-800 rounded px-3 py-2">
                    <span className="text-gray-500 font-medium w-16 flex-shrink-0">{obj.type}</span>
                    <span className="text-white font-mono">{obj.name}</span>
                    {obj.detail && <span className="text-gray-500 ml-2">{obj.detail}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">Remediation</h4>
            <p className="text-sm text-gray-300">{finding.remediation}</p>
          </div>

          {/* MITRE */}
          {finding.mitre?.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {finding.mitre.map(t => (
                <span key={t} className="text-xs bg-gray-800 border border-gray-700 text-gray-400 px-2 py-1 rounded font-mono">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
