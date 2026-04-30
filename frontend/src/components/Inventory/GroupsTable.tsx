import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import clsx from 'clsx'
import type { ADGroup } from '../../types'

type SortField = 'name' | 'members' | 'scope' | 'privilege'
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

export function GroupsTable({ snapshotId }: { snapshotId: string }) {
  const [search, setSearch] = useState('')
  const [filterPrivileged, setFilterPrivileged] = useState(false)
  const [sortField, setSortField] = useState<SortField>('members')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'groups', snapshotId],
    queryFn: () => inventoryApi.getGroups(snapshotId).then(r => r.data),
  })

  const groups: ADGroup[] = data?.items ?? []

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = groups.filter(g => {
      if (search && !(g.name ?? '').toLowerCase().includes(search.toLowerCase()) && !(g.description ?? '').toLowerCase().includes(search.toLowerCase())) return false
      if (filterPrivileged && !g.is_privileged) return false
      return true
    })
    return [...list].sort((a, b) => {
      let cmp = 0
      if (sortField === 'name') cmp = (a.name ?? '').localeCompare(b.name ?? '')
      else if (sortField === 'members') cmp = (a.members?.length ?? 0) - (b.members?.length ?? 0)
      else if (sortField === 'scope') cmp = (a.group_scope ?? '').localeCompare(b.group_scope ?? '')
      else if (sortField === 'privilege') cmp = (a.is_privileged ? 1 : 0) - (b.is_privileged ? 1 : 0)
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [groups, search, filterPrivileged, sortField, sortDir])

  return (
    <div>
      <div className="flex items-center gap-3 p-4 border-b border-gray-800">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search groups..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none" />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={filterPrivileged} onChange={e => setFilterPrivileged(e.target.checked)} className="rounded" />
          Privileged only
        </label>
        <span className="text-xs text-gray-500 ml-auto whitespace-nowrap">{filtered.length} / {groups.length}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              <SortHeader label="Group Name" field="name" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Scope" field="scope" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Members" field="members" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Privilege" field="privilege" current={sortField} dir={sortDir} onClick={toggleSort} />
              <th className="px-4 py-3 font-medium">Description</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && <tr><td colSpan={5} className="text-center py-8 text-gray-500">Loading...</td></tr>}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={5} className="text-center py-8 text-gray-500">No groups found.</td></tr>}
            {filtered.map((g, i) => (
              <tr key={i} className="hover:bg-gray-800/50 transition-colors">
                <td className="px-4 py-2.5 font-medium text-white text-sm">{g.name}</td>
                <td className="px-4 py-2.5 text-xs text-gray-400">{g.group_scope}</td>
                <td className="px-4 py-2.5 text-xs">
                  <span className={clsx('font-mono', g.members?.length > 50 ? 'text-amber-400' : 'text-gray-300')}>{g.members?.length ?? 0}</span>
                </td>
                <td className="px-4 py-2.5">
                  {g.is_privileged && <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">Privileged</span>}
                  {g.privilege_level && g.privilege_level !== 'none' && !g.is_privileged && (
                    <span className="text-xs bg-amber-500/20 text-amber-400 px-2 py-0.5 rounded-full">{g.privilege_level}</span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs text-gray-500 max-w-xs truncate">{g.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
