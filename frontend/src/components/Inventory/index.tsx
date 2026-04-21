import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi, scansApi } from '../../api'
import { Users, Layers, Monitor, FileCode, Server } from 'lucide-react'
import { UsersTable } from './UsersTable'
import { GroupsTable } from './GroupsTable'
import { ComputersTable } from './ComputersTable'
import { GPOsTable } from './GPOsTable'
import { DCsTable } from './DCsTable'
import clsx from 'clsx'

type Tab = 'users' | 'groups' | 'computers' | 'gpos' | 'dcs'

const TABS: { id: Tab; label: string; icon: typeof Users }[] = [
  { id: 'users',     label: 'Users',       icon: Users },
  { id: 'groups',    label: 'Groups',      icon: Layers },
  { id: 'computers', label: 'Computers',   icon: Monitor },
  { id: 'gpos',      label: 'GPOs',        icon: FileCode },
  { id: 'dcs',       label: 'Domain Controllers', icon: Server },
]

export function Inventory() {
  const [activeTab, setActiveTab] = useState<Tab>('users')
  const [selectedSnapshot, setSelectedSnapshot] = useState('')

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const completedScans = scansData?.scans?.filter(s => s.status === 'completed') ?? []
  const snapshotId = selectedSnapshot || completedScans[0]?.snapshot_id || ''

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-white">Inventory</h1>
          <p className="text-gray-400 text-sm mt-1">Browse all AD objects from latest scan</p>
        </div>

        {completedScans.length > 0 && (
          <select
            value={selectedSnapshot}
            onChange={e => setSelectedSnapshot(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:border-violet-500 focus:outline-none"
          >
            {completedScans.map(s => (
              <option key={s.snapshot_id} value={s.snapshot_id ?? ''}>
                {s.domain} — {new Date(s.completed_at!).toLocaleDateString()}
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 bg-gray-900 border border-gray-800 rounded-xl p-1 w-fit">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors',
              activeTab === id
                ? 'bg-violet-600 text-white'
                : 'text-gray-400 hover:text-white hover:bg-gray-800'
            )}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {!snapshotId ? (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center">
          <p className="text-gray-400">Run a scan to populate the inventory.</p>
        </div>
      ) : (
        <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
          {activeTab === 'users'     && <UsersTable     snapshotId={snapshotId} />}
          {activeTab === 'groups'    && <GroupsTable    snapshotId={snapshotId} />}
          {activeTab === 'computers' && <ComputersTable snapshotId={snapshotId} />}
          {activeTab === 'gpos'      && <GPOsTable      snapshotId={snapshotId} />}
          {activeTab === 'dcs'       && <DCsTable       snapshotId={snapshotId} />}
        </div>
      )}
    </div>
  )
}
