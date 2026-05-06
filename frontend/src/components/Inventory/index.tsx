import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Boxes, FileCode2, Monitor, Server, Shield, Users } from 'lucide-react'
import clsx from 'clsx'
import { scansApi } from '../../api'
import { ComputersTable } from './ComputersTable'
import { DCsTable } from './DCsTable'
import { GPOsTable } from './GPOsTable'
import { GroupsTable } from './GroupsTable'
import { UsersTable } from './UsersTable'

type Tab = 'users' | 'groups' | 'computers' | 'gpos' | 'dcs'

const tabs: { id: Tab; label: string; icon: typeof Users; note: string }[] = [
  { id: 'users', label: 'Identities', icon: Users, note: 'Users, privilege, service accounts' },
  { id: 'groups', label: 'Groups', icon: Shield, note: 'Privilege containers and nesting' },
  { id: 'computers', label: 'Assets', icon: Monitor, note: 'Workstations, servers, stale systems' },
  { id: 'gpos', label: 'Policies', icon: FileCode2, note: 'GPO posture and exposure' },
  { id: 'dcs', label: 'Controllers', icon: Server, note: 'Domain controller security state' },
]

export function Inventory() {
  const [activeTab, setActiveTab] = useState<Tab>('users')
  const [selectedSnapshot, setSelectedSnapshot] = useState('')

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then((r) => r.data),
  })

  const completedScans = scansData?.scans?.filter((scan) => scan.status === 'completed') ?? []
  const scansLoading = scansData === undefined
  useEffect(() => {
    if (!selectedSnapshot && completedScans[0]?.snapshot_id) {
      setSelectedSnapshot(completedScans[0].snapshot_id)
    }
  }, [completedScans, selectedSnapshot])
  const snapshotId = selectedSnapshot || completedScans[0]?.snapshot_id || ''
  const currentRun = completedScans.find((scan) => scan.snapshot_id === snapshotId) ?? completedScans[0]

  const summary = useMemo(
    () => [
      { label: 'Protection index', value: scansLoading ? 'Loading' : currentRun?.overall_score ?? '—' },
      { label: 'Critical findings', value: scansLoading ? 'Loading' : currentRun?.critical_count ?? 0 },
      { label: 'Total findings', value: scansLoading ? 'Loading' : currentRun?.total_findings ?? 0 },
      { label: 'Assessment date', value: scansLoading ? 'Loading' : currentRun?.completed_at ? new Date(currentRun.completed_at).toLocaleDateString() : '—' },
    ],
    [currentRun, scansLoading]
  )

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="label">Directory intelligence</p>
            <h2 className="mt-2 text-2xl font-semibold text-white">Directory state</h2>
          </div>

          {scansLoading ? (
            <div className="min-w-[280px]">
              <label className="label">Assessment snapshot</label>
              <div className="mt-2 rounded-2xl border border-white/8 bg-white/[0.03] px-4 py-3 text-sm text-slate-500">
                Loading assessments…
              </div>
            </div>
          ) : completedScans.length > 0 && (
            <div className="min-w-[280px]">
              <label className="label">Assessment snapshot</label>
              <select value={selectedSnapshot} onChange={(e) => setSelectedSnapshot(e.target.value)} className="select mt-2">
                {completedScans.map((scan) => (
                  <option key={scan.snapshot_id} value={scan.snapshot_id ?? ''}>
                    {scan.domain} · {scan.completed_at ? new Date(scan.completed_at).toLocaleDateString() : 'Pending'}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {summary.map((item) => (
            <div key={item.label} className="rounded-2xl border border-white/8 bg-white/[0.03] p-4">
              <p className="text-xs uppercase tracking-[0.16em] text-slate-500">{item.label}</p>
              <p className="mt-2 text-2xl font-semibold text-white">{item.value}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="panel p-3">
        <div className="grid gap-2 xl:grid-cols-5">
          {tabs.map(({ id, label, icon: Icon, note }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={clsx(
                'flex items-start gap-3 rounded-2xl border p-4 text-left transition',
                activeTab === id
                  ? 'border-sky-400/22 bg-sky-400/10'
                  : 'border-transparent bg-transparent hover:border-white/8 hover:bg-white/[0.03]'
              )}
            >
              <div
                className={clsx(
                  'flex h-10 w-10 items-center justify-center rounded-xl border',
                  activeTab === id
                    ? 'border-sky-400/18 bg-sky-400/10 text-sky-200'
                    : 'border-white/8 bg-white/[0.03] text-slate-500'
                )}
              >
                <Icon className="h-4 w-4" />
              </div>
              <div>
                <p className="text-sm font-semibold text-white">{label}</p>
                <p className="mt-1 text-xs text-slate-500">{note}</p>
              </div>
            </button>
          ))}
        </div>
      </section>

      {!snapshotId ? (
        <div className="panel p-12 text-center">
          <Boxes className="mx-auto h-10 w-10 text-slate-600" />
          <p className="mt-4 text-sm font-medium text-slate-300">
            {scansLoading ? 'Loading assessment data…' : 'No completed assessment data available yet.'}
          </p>
        </div>
      ) : (
        <section className="panel overflow-hidden">
          {activeTab === 'users' && <UsersTable snapshotId={snapshotId} />}
          {activeTab === 'groups' && <GroupsTable snapshotId={snapshotId} />}
          {activeTab === 'computers' && <ComputersTable snapshotId={snapshotId} />}
          {activeTab === 'gpos' && <GPOsTable snapshotId={snapshotId} />}
          {activeTab === 'dcs' && <DCsTable snapshotId={snapshotId} />}
        </section>
      )}
    </div>
  )
}
