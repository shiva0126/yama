import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import clsx from 'clsx'
import type { ADGPO } from '../../types'

export function GPOsTable({ snapshotId }: { snapshotId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'gpos', snapshotId],
    queryFn: () => inventoryApi.getGPOs(snapshotId).then(r => r.data),
  })
  const gpos = data?.items ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
            <th className="px-4 py-3 font-medium">GPO Name</th>
            <th className="px-4 py-3 font-medium">Status</th>
            <th className="px-4 py-3 font-medium">Links</th>
            <th className="px-4 py-3 font-medium">Flags</th>
            <th className="px-4 py-3 font-medium">Modified</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {isLoading && <tr><td colSpan={5} className="text-center py-8 text-gray-500">Loading...</td></tr>}
          {(gpos as ADGPO[]).map((gpo, i) => (
            <tr key={i} className="hover:bg-gray-800/50 transition-colors">
              <td className="px-4 py-2.5 font-medium text-white">{gpo.name}</td>
              <td className="px-4 py-2.5 text-xs text-gray-400">{gpo.status}</td>
              <td className="px-4 py-2.5 text-xs text-gray-300">{gpo.linked_ous?.length ?? 0} OU{gpo.linked_ous?.length !== 1 ? 's' : ''}</td>
              <td className="px-4 py-2.5">
                <div className="flex gap-1">
                  {!gpo.is_linked && <span className="text-xs bg-gray-700 text-gray-400 px-1.5 py-0.5 rounded">Unlinked</span>}
                  {gpo.sysvol_writable_by_nonadmin && <span className="text-xs bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded">SYSVOL Write</span>}
                </div>
              </td>
              <td className="px-4 py-2.5 text-xs text-gray-400">
                {gpo.modified ? new Date(gpo.modified).toLocaleDateString() : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
