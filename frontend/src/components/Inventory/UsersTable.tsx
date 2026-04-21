import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import { Search } from 'lucide-react'
import clsx from 'clsx'
import type { ADUser } from '../../types'

interface Props {
  snapshotId: string
}

export function UsersTable({ snapshotId }: Props) {
  const [search, setSearch] = useState('')
  const [filterPrivileged, setFilterPrivileged] = useState(false)
  const [filterEnabled, setFilterEnabled] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'users', snapshotId],
    queryFn: () => inventoryApi.getUsers(snapshotId).then(r => r.data),
    enabled: !!snapshotId,
  })

  const users = data?.items ?? []

  const filtered = users.filter(u => {
    if (search && !u.sam_account_name.toLowerCase().includes(search.toLowerCase()) &&
        !u.display_name.toLowerCase().includes(search.toLowerCase())) return false
    if (filterPrivileged && !u.is_privileged) return false
    if (filterEnabled && !u.enabled) return false
    return true
  })

  return (
    <div>
      {/* Toolbar */}
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
        <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer">
          <input type="checkbox" checked={filterPrivileged} onChange={e => setFilterPrivileged(e.target.checked)} />
          Privileged only
        </label>
        <span className="text-xs text-gray-500 ml-auto">{filtered.length} of {users.length}</span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
              <th className="px-4 py-3 font-medium">Username</th>
              <th className="px-4 py-3 font-medium">Display Name</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Flags</th>
              <th className="px-4 py-3 font-medium">Last Logon</th>
              <th className="px-4 py-3 font-medium">Pwd Last Set</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {isLoading && (
              <tr><td colSpan={6} className="text-center py-8 text-gray-500">Loading...</td></tr>
            )}
            {!isLoading && filtered.length === 0 && (
              <tr><td colSpan={6} className="text-center py-8 text-gray-500">No users found.</td></tr>
            )}
            {filtered.map((user, i) => (
              <UserRow key={i} user={user} />
            ))}
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
      <td className="px-4 py-2.5 text-gray-300">{user.display_name}</td>
      <td className="px-4 py-2.5">
        <span className={clsx('text-xs px-2 py-0.5 rounded-full', user.enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-400')}>
          {user.enabled ? 'Enabled' : 'Disabled'}
        </span>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap gap-1">
          {flags.map((f, i) => (
            <span key={i} className={clsx('text-xs px-1.5 py-0.5 rounded', f.cls)}>{f.label}</span>
          ))}
        </div>
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400">
        {user.last_logon ? new Date(user.last_logon).toLocaleDateString() : '—'}
      </td>
      <td className="px-4 py-2.5 text-xs text-gray-400">
        {user.pwd_last_set ? new Date(user.pwd_last_set).toLocaleDateString() : '—'}
      </td>
    </tr>
  )
}
