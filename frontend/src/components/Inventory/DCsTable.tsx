import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import clsx from 'clsx'
import type { ADDomainController } from '../../types'

export function DCsTable({ snapshotId }: { snapshotId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'dcs', snapshotId],
    queryFn: () => inventoryApi.getDomainControllers(snapshotId).then(r => r.data),
  })
  const dcs = data?.items ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
            <th className="px-4 py-3 font-medium">DC Name</th>
            <th className="px-4 py-3 font-medium">IP</th>
            <th className="px-4 py-3 font-medium">OS</th>
            <th className="px-4 py-3 font-medium">FSMO Roles</th>
            <th className="px-4 py-3 font-medium">Security Flags</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {isLoading && <tr><td colSpan={5} className="text-center py-8 text-gray-500">Loading...</td></tr>}
          {(dcs as ADDomainController[]).map((dc, i) => (
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
              <td className="px-4 py-2.5 text-xs text-gray-400">{dc.fsmo_roles?.join(', ') || '—'}</td>
              <td className="px-4 py-2.5">
                <div className="flex flex-wrap gap-1">
                  {dc.spooler_running && <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">Spooler</span>}
                  {!dc.smb_signing_required && <span className="text-xs bg-orange-500/20 text-orange-400 px-1.5 py-0.5 rounded">No SMB Sign</span>}
                  {!dc.ldap_signing_required && <span className="text-xs bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">No LDAP Sign</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
