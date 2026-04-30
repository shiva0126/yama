import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import clsx from 'clsx'
import type { ADGPO } from '../../types'

type SortField = 'name' | 'links' | 'status' | 'modified' | 'risk'
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

export function GPOsTable({ snapshotId }: { snapshotId: string }) {
  const [search, setSearch] = useState('')
  const [filterRiskyOnly, setFilterRiskyOnly] = useState(false)
  const [sortField, setSortField] = useState<SortField>('risk')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'gpos', snapshotId],
    queryFn: () => inventoryApi.getGPOs(snapshotId).then(r => r.data),
  })

  const gpos: ADGPO[] = data?.items ?? []

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = gpos.filter(g => {
      if (search && !(g.name ?? '').toLowerCase().includes(search.toLowerCase())) return false
      if (filterRiskyOnly && !g.sysvol_writable_by_nonadmin && g.is_linked) return false
      return true
    })
    return [...list].sort((a, b) => {
      let cmp = 0
      if (sortField === 'name') cmp = (a.name ?? '').localeCompare(b.name ?? '')
      else if (sortField === 'links') cmp = (a.linked_ous?.length ?? 0) - (b.linked_ous?.length ?? 0)
      else if (sortField === 'status') cmp = (a.status ?? '').localeCompare(b.status ?? '')
      else if (sortField === 'modified') cmp = (a.modified ?? '').localeCompare(b.modified ?? '')
      else if (sortField === 'risk') {
        const ra = (a.sysvol_writable_by_nonadmin ? 3 : 0) + (!a.is_linked ? 1 : 0)
        const rb = (b.sysvol_writable_by_nonadmin ? 3 : 0) + (!b.is_linked ? 1 : 0)
        cmp = ra - rb
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [gpos, search, filterRiskyOnly, sortField, sortDir])

  return (
    <div>
      <div className="flex items-center gap-3 p-4 border-b border-gray-800">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search GPOs..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none" />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={filterRiskyOnly} onChange={e => setFilterRiskyOnly(e.target.checked)} className="rounded" />
          Risky only
        </label>
        <span className="text-xs text-gray-500 ml-auto whitespace-nowrap">{filtered.length} / {gpos.length}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              <SortHeader label="GPO Name" field="name" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Status" field="status" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Links" field="links" current={sortField} dir={sortDir} onClick={toggleSort} />
              <th className="px-4 py-3 font-medium">Flags</th>
              <SortHeader label="Modified" field="modified" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Risk" field="risk" current={sortField} dir={sortDir} onClick={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && <tr><td colSpan={6} className="text-center py-8 text-gray-500">Loading...</td></tr>}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={6} className="text-center py-8 text-gray-500">No GPOs found.</td></tr>}
            {filtered.map((gpo, i) => (
              <tr key={i} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-2.5 font-medium text-white text-sm">{gpo.name}</td>
                <td className="px-4 py-2.5 text-xs text-gray-400">{gpo.status}</td>
                <td className="px-4 py-2.5 text-xs text-gray-300">
                  {gpo.linked_ous?.length ?? 0} OU{gpo.linked_ous?.length !== 1 ? 's' : ''}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex gap-1">
                    {!gpo.is_linked && <span className="text-xs bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded">Unlinked</span>}
                    {gpo.sysvol_writable_by_nonadmin && <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">SYSVOL Write</span>}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-400">
                  {gpo.modified ? new Date(gpo.modified).toLocaleDateString() : '—'}
                </td>
                <td className="px-4 py-2.5">
                  {gpo.sysvol_writable_by_nonadmin && <span className="text-xs font-medium text-red-400">High</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
