import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import clsx from 'clsx'
import type { ADComputer } from '../../types'

type SortField = 'name' | 'os' | 'status' | 'last_logon' | 'risk'
type SortDir = 'asc' | 'desc'

function SortHeader({ label, field, current, dir, onClick }: {
  label: string; field: SortField; current: SortField; dir: SortDir; onClick: (f: SortField) => void
}) {
  const active = current === field
  return (
    <th className="px-4 py-3 font-medium cursor-pointer select-none hover:text-gray-300 transition-colors" onClick={() => onClick(field)}>
      <span className="flex items-center gap-1">
        {label}
        {active ? (dir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />) : <ChevronsUpDown className="w-3 h-3 opacity-40" />}
      </span>
    </th>
  )
}

export function ComputersTable({ snapshotId }: { snapshotId: string }) {
  const [search, setSearch] = useState('')
  const [filterDCOnly, setFilterDCOnly] = useState(false)
  const [filterNoLAPS, setFilterNoLAPS] = useState(false)
  const [sortField, setSortField] = useState<SortField>('risk')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'computers', snapshotId],
    queryFn: () => inventoryApi.getComputers(snapshotId).then(r => r.data),
  })

  const computers: ADComputer[] = data?.items ?? []

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = computers.filter(c => {
      const q = search.toLowerCase()
      if (search && !(c.name ?? '').toLowerCase().includes(q) && !(c.dns_host_name ?? '').toLowerCase().includes(q)) return false
      if (filterDCOnly && !c.is_domain_controller) return false
      if (filterNoLAPS && (c.laps_enabled || c.is_domain_controller)) return false
      return true
    })
    return [...list].sort((a, b) => {
      let cmp = 0
      if (sortField === 'name') cmp = (a.name ?? '').localeCompare(b.name ?? '')
      else if (sortField === 'os') cmp = (a.operating_system ?? '').localeCompare(b.operating_system ?? '')
      else if (sortField === 'status') cmp = (a.enabled ? 1 : 0) - (b.enabled ? 1 : 0)
      else if (sortField === 'last_logon') cmp = (a.last_logon ?? '').localeCompare(b.last_logon ?? '')
      else if (sortField === 'risk') {
        const ra = (a.trusted_for_delegation ? 3 : 0) + (!a.laps_enabled && !a.is_domain_controller ? 2 : 0) + (!a.enabled ? 1 : 0)
        const rb = (b.trusted_for_delegation ? 3 : 0) + (!b.laps_enabled && !b.is_domain_controller ? 2 : 0) + (!b.enabled ? 1 : 0)
        cmp = ra - rb
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [computers, search, filterDCOnly, filterNoLAPS, sortField, sortDir])

  return (
    <div>
      <div className="flex items-center gap-3 p-4 border-b border-gray-800 flex-wrap">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search computers..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none" />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={filterDCOnly} onChange={e => setFilterDCOnly(e.target.checked)} className="rounded" />
          DCs only
        </label>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={filterNoLAPS} onChange={e => setFilterNoLAPS(e.target.checked)} className="rounded" />
          No LAPS
        </label>
        <span className="text-xs text-gray-500 ml-auto whitespace-nowrap">{filtered.length} / {computers.length}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              <SortHeader label="Name" field="name" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="OS" field="os" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Status" field="status" current={sortField} dir={sortDir} onClick={toggleSort} />
              <th className="px-4 py-3 font-medium">Flags</th>
              <SortHeader label="Last Logon" field="last_logon" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Risk" field="risk" current={sortField} dir={sortDir} onClick={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && <tr><td colSpan={6} className="text-center py-8 text-gray-500">Loading...</td></tr>}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={6} className="text-center py-8 text-gray-500">No computers found.</td></tr>}
            {filtered.map((c, i) => (
              <tr key={i} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-2.5">
                  <p className="font-medium text-white font-mono text-xs">{c.name}</p>
                  <p className="text-gray-500 text-xs">{c.dns_host_name}</p>
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-300">{c.operating_system || '—'}</td>
                <td className="px-4 py-2.5">
                  <span className={clsx('text-xs px-2 py-0.5 rounded-full', c.enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-400')}>
                    {c.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex flex-wrap gap-1">
                    {c.is_domain_controller && <span className="text-xs bg-violet-500/20 text-violet-400 px-1.5 py-0.5 rounded">DC</span>}
                    {!c.laps_enabled && !c.is_domain_controller && <span className="text-xs bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">No LAPS</span>}
                    {c.trusted_for_delegation && <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">Unconstrained</span>}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-400">
                  {c.last_logon ? new Date(c.last_logon).toLocaleDateString() : '—'}
                </td>
                <td className="px-4 py-2.5">
                  {(c.trusted_for_delegation || (!c.laps_enabled && !c.is_domain_controller)) && (
                    <span className={clsx('text-xs font-medium', c.trusted_for_delegation ? 'text-red-400' : 'text-amber-400')}>
                      {c.trusted_for_delegation ? 'High' : 'Med'}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
