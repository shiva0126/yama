import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import clsx from 'clsx'
import type { ADDomainController } from '../../types'

type SortField = 'name' | 'ip' | 'os' | 'site' | 'risk'
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

export function DCsTable({ snapshotId }: { snapshotId: string }) {
  const [search, setSearch] = useState('')
  const [sortField, setSortField] = useState<SortField>('risk')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'dcs', snapshotId],
    queryFn: () => inventoryApi.getDomainControllers(snapshotId).then(r => r.data),
  })

  const dcs: ADDomainController[] = data?.items ?? []

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = dcs.filter(d => {
      const q = search.toLowerCase()
      if (search && !(d.name ?? '').toLowerCase().includes(q) && !(d.host_name ?? '').toLowerCase().includes(q)) return false
      return true
    })
    return [...list].sort((a, b) => {
      let cmp = 0
      if (sortField === 'name') cmp = (a.name ?? '').localeCompare(b.name ?? '')
      else if (sortField === 'ip') cmp = (a.ip_address ?? '').localeCompare(b.ip_address ?? '')
      else if (sortField === 'os') cmp = (a.operating_system ?? '').localeCompare(b.operating_system ?? '')
      else if (sortField === 'site') cmp = (a.site ?? '').localeCompare(b.site ?? '')
      else if (sortField === 'risk') {
        const ra = (a.spooler_running ? 3 : 0) + (!a.smb_signing_required ? 2 : 0) + (!a.ldap_signing_required ? 1 : 0)
        const rb = (b.spooler_running ? 3 : 0) + (!b.smb_signing_required ? 2 : 0) + (!b.ldap_signing_required ? 1 : 0)
        cmp = ra - rb
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [dcs, search, sortField, sortDir])

  return (
    <div>
      <div className="flex items-center gap-3 p-4 border-b border-gray-800">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search DCs..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none" />
        </div>
        <span className="text-xs text-gray-500 ml-auto whitespace-nowrap">{filtered.length} / {dcs.length}</span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              <SortHeader label="DC Name" field="name" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="IP" field="ip" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="OS" field="os" current={sortField} dir={sortDir} onClick={toggleSort} />
              <SortHeader label="Site" field="site" current={sortField} dir={sortDir} onClick={toggleSort} />
              <th className="px-4 py-3 font-medium">FSMO Roles</th>
              <th className="px-4 py-3 font-medium">Security Flags</th>
              <SortHeader label="Risk" field="risk" current={sortField} dir={sortDir} onClick={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && <tr><td colSpan={7} className="text-center py-8 text-gray-500">Loading...</td></tr>}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={7} className="text-center py-8 text-gray-500">No DCs found.</td></tr>}
            {filtered.map((dc, i) => {
              const riskScore = (dc.spooler_running ? 3 : 0) + (!dc.smb_signing_required ? 2 : 0) + (!dc.ldap_signing_required ? 1 : 0)
              return (
                <tr key={i} className="hover:bg-gray-800/50 transition-colors">
                  <td className="px-4 py-2.5">
                    <p className="font-mono text-xs text-white">{dc.name}</p>
                    <div className="flex gap-1 mt-0.5">
                      {dc.is_read_only && <span className="text-xs text-gray-500">RODC</span>}
                      {dc.is_global_catalog && <span className="text-xs text-violet-400">GC</span>}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-gray-400">{dc.ip_address || '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-300">{dc.operating_system}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-400">{dc.site || '—'}</td>
                  <td className="px-4 py-2.5 text-xs text-gray-400">{dc.fsmo_roles?.join(', ') || '—'}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {dc.spooler_running && <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">Spooler</span>}
                      {!dc.smb_signing_required && <span className="text-xs bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">No SMB Sign</span>}
                      {!dc.ldap_signing_required && <span className="text-xs bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">No LDAP Sign</span>}
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    {riskScore > 0 && (
                      <span className={clsx('text-xs font-medium', riskScore >= 3 ? 'text-red-400' : riskScore >= 2 ? 'text-orange-400' : 'text-amber-400')}>
                        {riskScore >= 3 ? 'High' : riskScore >= 2 ? 'Med' : 'Low'}
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
