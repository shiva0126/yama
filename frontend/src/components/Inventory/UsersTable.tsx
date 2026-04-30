import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search, ChevronUp, ChevronDown, ChevronsUpDown } from 'lucide-react'
import clsx from 'clsx'
import type { ADUser } from '../../types'

type SortField = 'sam_account_name' | 'display_name' | 'last_logon' | 'pwd_last_set' | 'risk'
type SortDir = 'asc' | 'desc'

function SortHeader({ label, field, current, dir, onClick }: {
  label: string; field: SortField; current: SortField; dir: SortDir; onClick: (f: SortField) => void
}) {
  const active = current === field
  return (
    <th
      className="px-4 py-3 font-medium cursor-pointer select-none hover:text-gray-300 transition-colors"
      onClick={() => onClick(field)}
    >
      <span className="flex items-center gap-1">
        {label}
        {active ? (dir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />) : <ChevronsUpDown className="w-3 h-3 opacity-40" />}
      </span>
    </th>
  )
}

export function UsersTable({ snapshotId }: { snapshotId: string }) {
  const [search, setSearch] = useState('')
  const [filterPrivileged, setFilterPrivileged] = useState(false)
  const [sortField, setSortField] = useState<SortField>('risk')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'users', snapshotId],
    queryFn: () => inventoryApi.getUsers(snapshotId).then(r => r.data),
    enabled: !!snapshotId,
  })

  const users: ADUser[] = data?.items ?? []

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDir('desc') }
  }

  const filtered = useMemo(() => {
    let list = users.filter(u => {
      if (search) {
        const q = search.toLowerCase()
        const matchName = (u.sam_account_name ?? '').toLowerCase().includes(q)
        const matchDisplay = (u.display_name ?? '').toLowerCase().includes(q)
        if (!matchName && !matchDisplay) return false
      }
      if (filterPrivileged && !u.is_privileged) return false
      return true
    })

    list = [...list].sort((a, b) => {
      let cmp = 0
      if (sortField === 'sam_account_name') cmp = (a.sam_account_name ?? '').localeCompare(b.sam_account_name ?? '')
      else if (sortField === 'display_name') cmp = (a.display_name ?? '').localeCompare(b.display_name ?? '')
      else if (sortField === 'last_logon') cmp = (a.last_logon ?? '').localeCompare(b.last_logon ?? '')
      else if (sortField === 'pwd_last_set') cmp = (a.pwd_last_set ?? '').localeCompare(b.pwd_last_set ?? '')
      else if (sortField === 'risk') {
        const riskA = (a.is_privileged ? 4 : 0) + (a.dont_require_preauth ? 3 : 0) + (a.service_principal_names?.length > 0 ? 2 : 0) + (a.password_never_expires ? 1 : 0)
        const riskB = (b.is_privileged ? 4 : 0) + (b.dont_require_preauth ? 3 : 0) + (b.service_principal_names?.length > 0 ? 2 : 0) + (b.password_never_expires ? 1 : 0)
        cmp = riskA - riskB
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
    return list
  }, [users, search, filterPrivileged, sortField, sortDir])

  const sp: { label: string; field: SortField } [] = [
    { label: 'Username', field: 'sam_account_name' },
    { label: 'Display Name', field: 'display_name' },
    { label: 'Last Logon', field: 'last_logon' },
    { label: 'Pwd Last Set', field: 'pwd_last_set' },
    { label: 'Risk', field: 'risk' },
  ]

  return (
    <div>
      <div className="flex items-center gap-3 p-4 border-b border-gray-800">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search users..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
          />
        </div>
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer whitespace-nowrap">
          <input type="checkbox" checked={filterPrivileged} onChange={e => setFilterPrivileged(e.target.checked)} className="rounded" />
          Privileged only
        </label>
        <span className="text-xs text-gray-500 ml-auto whitespace-nowrap">{filtered.length} / {users.length}</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              {sp.map(({ label, field }) => (
                <SortHeader key={field} label={label} field={field} current={sortField} dir={sortDir} onClick={toggleSort} />
              ))}
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Flags</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && <tr><td colSpan={7} className="text-center py-8 text-gray-500">Loading...</td></tr>}
            {!isLoading && filtered.length === 0 && <tr><td colSpan={7} className="text-center py-8 text-gray-500">No users found.</td></tr>}
            {filtered.map((user, i) => <UserRow key={i} user={user} />)}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function UserRow({ user }: { user: ADUser }) {
  const flags = []
  if (user.is_privileged) flags.push({ label: 'Admin', cls: 'bg-red-500/20 text-red-400' })
  if (user.dont_require_preauth) flags.push({ label: 'AS-REP', cls: 'bg-orange-500/20 text-orange-400' })
  if (user.service_principal_names?.length > 0) flags.push({ label: 'SPN', cls: 'bg-amber-500/20 text-amber-400' })
  if (user.password_never_expires) flags.push({ label: 'No Expiry', cls: 'bg-blue-500/20 text-blue-400' })
  if (user.is_service_account) flags.push({ label: 'Service', cls: 'bg-gray-600/50 text-gray-400' })

  return (
    <tr className="hover:bg-gray-800/50 transition-colors">
      <td className="px-4 py-2.5 font-mono text-xs text-white">{user.sam_account_name}</td>
      <td className="px-4 py-2.5 text-gray-300 text-xs">{user.display_name}</td>
      <td className="px-4 py-2.5 text-xs text-gray-400">{user.last_logon ? new Date(user.last_logon).toLocaleDateString() : '—'}</td>
      <td className="px-4 py-2.5 text-xs text-gray-400">{user.pwd_last_set ? new Date(user.pwd_last_set).toLocaleDateString() : '—'}</td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-1">
          {[user.is_privileged, user.dont_require_preauth, user.service_principal_names?.length > 0, user.password_never_expires].filter(Boolean).length > 0 && (
            <div className="flex gap-0.5">
              {[user.is_privileged, user.dont_require_preauth, user.service_principal_names?.length > 0, user.password_never_expires].map((v, i) => (
                <div key={i} className={clsx('w-1.5 h-3 rounded-sm', v ? 'bg-red-400' : 'bg-gray-700')} />
              ))}
            </div>
          )}
        </div>
      </td>
      <td className="px-4 py-2.5">
        <span className={clsx('text-xs px-2 py-0.5 rounded-full', user.enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-400')}>
          {user.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap gap-1">
          {flags.map((f, i) => <span key={i} className={clsx('text-xs px-1.5 py-0.5 rounded', f.cls)}>{f.label}</span>)}
        </div>
      </td>
    </tr>
  )
}
