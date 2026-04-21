import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '../../api'
import clsx from 'clsx'
import type { ADGroup } from '../../types'

export function GroupsTable({ snapshotId }: { snapshotId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory', 'groups', snapshotId],
    queryFn: () => inventoryApi.getGroups(snapshotId).then(r => r.data),
  })
  const groups = (data?.items ?? []).sort((a: ADGroup, b: ADGroup) =>
    b.members.length - a.members.length
  )

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-left border-b border-gray-800 text-xs">
            <th className="px-4 py-3 font-medium">Group Name</th>
            <th className="px-4 py-3 font-medium">Scope</th>
            <th className="px-4 py-3 font-medium">Members</th>
            <th className="px-4 py-3 font-medium">Privilege</th>
            <th className="px-4 py-3 font-medium">Description</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {isLoading && <tr><td colSpan={5} className="text-center py-8 text-gray-500">Loading...</td></tr>}
          {groups.map((g: ADGroup, i: number) => (
            <tr key={i} className="hover:bg-gray-800/50 transition-colors">
              <td className="px-4 py-2.5 font-medium text-white">{g.name}</td>
              <td className="px-4 py-2.5 text-xs text-gray-400">{g.group_scope}</td>
              <td className="px-4 py-2.5 text-xs text-gray-300">{g.members?.length ?? 0}</td>
              <td className="px-4 py-2.5">
                {g.is_privileged && (
                  <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">Privileged</span>
                )}
              </td>
              <td className="px-4 py-2.5 text-xs text-gray-500 max-w-xs truncate">{g.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
