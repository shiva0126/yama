import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import clsx from 'clsx'
import type { ADComputer } from '../../types'

export function ComputersTable({ snapshotId }: { snapshotId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'computers', snapshotId],
    queryFn: () => inventoryApi.getComputers(snapshotId).then(r => r.data),
  })
  const computers = data?.items ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
            <th className="px-4 py-3 font-medium">Name</th>
            <th className="px-4 py-3 font-medium">OS</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Flags</th>
            <th className="px-4 py-3 font-medium">Last Logon</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {isLoading && <tr><td colSpan={5} className="text-center py-8 text-gray-500">Loading...</td></tr>}
          {(computers as ADComputer[]).map((c, i) => (
            <tr key={i} className="hover:bg-gray-800/50 transition-colors">
              <td className="px-4 py-2.5">
                <p className="font-medium text-white font-mono text-xs">{c.name}</p>
                <p className="text-gray-500 text-xs">{c.dns_host_name}</p>
              </td>
              <td className="px-4 py-2.5 text-xs text-gray-300">{c.operating_system}</td>
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
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
