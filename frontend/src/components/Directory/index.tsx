import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { inventoryApi, scansApi } from '../../api'
import type { ADUser, ADGroup, ADComputer, ADDomainController, ADGPO } from '../../types'

type Tab = 'users' | 'groups' | 'computers' | 'dcs' | 'gpos'

export function Directory() {
  const [tab, setTab] = useState<Tab>('users')
  const [search, setSearch] = useState('')

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const latestScan = scansData?.scans?.find(s => s.status === 'completed')
  const snapshotId = latestScan?.snapshot_id

  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ['users', snapshotId],
    queryFn: () => inventoryApi.getUsers(snapshotId!).then(r => r.data),
    enabled: !!snapshotId && tab === 'users',
  })
  const { data: groupsData, isLoading: groupsLoading } = useQuery({
    queryKey: ['groups', snapshotId],
    queryFn: () => inventoryApi.getGroups(snapshotId!).then(r => r.data),
    enabled: !!snapshotId && tab === 'groups',
  })
  const { data: computersData, isLoading: computersLoading } = useQuery({
    queryKey: ['computers', snapshotId],
    queryFn: () => inventoryApi.getComputers(snapshotId!).then(r => r.data),
    enabled: !!snapshotId && tab === 'computers',
  })
  const { data: dcsData, isLoading: dcsLoading } = useQuery({
    queryKey: ['dcs', snapshotId],
    queryFn: () => inventoryApi.getDomainControllers(snapshotId!).then(r => r.data),
    enabled: !!snapshotId && tab === 'dcs',
  })
  const { data: gposData, isLoading: gposLoading } = useQuery({
    queryKey: ['gpos', snapshotId],
    queryFn: () => inventoryApi.getGPOs(snapshotId!).then(r => r.data),
    enabled: !!snapshotId && tab === 'gpos',
  })

  const tabs: { id: Tab; label: string; count?: number }[] = [
    { id: 'users',     label: 'Users',               count: usersData?.total },
    { id: 'groups',    label: 'Groups',              count: groupsData?.total },
    { id: 'computers', label: 'Computers',           count: computersData?.total },
    { id: 'dcs',       label: 'Domain Controllers',  count: dcsData?.total },
    { id: 'gpos',      label: 'GPOs',                count: gposData?.total },
  ]

  const handleTabChange = (t: Tab) => { setTab(t); setSearch('') }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#f4f6f9' }}>
      {/* Tab + search bar */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        borderBottom: '1px solid #e4e8ef',
        padding: '0 24px', background: '#ffffff', flexShrink: 0,
      }}>
        <div style={{ display: 'flex' }}>
          {tabs.map(t => (
            <button
              key={t.id}
              onClick={() => handleTabChange(t.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '12px 16px', fontSize: 13, fontWeight: 500,
                background: 'none', border: 'none', cursor: 'pointer',
                borderBottom: tab === t.id ? '2px solid #2563eb' : '2px solid transparent',
                color: tab === t.id ? '#2563eb' : '#4b5c72',
                marginBottom: -1, transition: 'color 0.15s',
              }}
            >
              {t.label}
              {t.count != null && (
                <span style={{
                  fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10,
                  background: tab === t.id ? '#eff6ff' : '#f0f3f8',
                  color: tab === t.id ? '#2563eb' : '#8a9ab5',
                }}>
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative', width: 220 }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#8a9ab5', pointerEvents: 'none' }} />
          <input
            className="field"
            style={{ paddingLeft: 32 }}
            placeholder="Filter…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* No snapshot */}
      {!snapshotId ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8, color: '#8a9ab5' }}>
          <div style={{ fontSize: 14, fontWeight: 500, color: '#4b5c72' }}>No directory data available</div>
          <div style={{ fontSize: 12 }}>Run an assessment to populate the directory</div>
        </div>
      ) : (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {tab === 'users'     && <UsersTable     data={usersData?.items ?? []}     loading={usersLoading}     search={search} />}
          {tab === 'groups'    && <GroupsTable    data={groupsData?.items ?? []}    loading={groupsLoading}    search={search} />}
          {tab === 'computers' && <ComputersTable data={computersData?.items ?? []} loading={computersLoading} search={search} />}
          {tab === 'dcs'       && <DCsTable       data={dcsData?.items ?? []}       loading={dcsLoading}       search={search} />}
          {tab === 'gpos'      && <GPOsTable      data={gposData?.items ?? []}      loading={gposLoading}      search={search} />}
        </div>
      )}
    </div>
  )
}

function Skeleton() {
  return (
    <div style={{ padding: '16px 24px' }}>
      {[...Array(10)].map((_, i) => <div key={i} className="skeleton" style={{ height: 44, marginBottom: 3 }} />)}
    </div>
  )
}

function Bool({ val }: { val: boolean }) {
  return <span style={{ fontSize: 11, fontWeight: 600, color: val ? '#16a34a' : '#8a9ab5' }}>{val ? 'Yes' : 'No'}</span>
}

function EmptyRow({ cols, msg }: { cols: number; msg: string }) {
  return <tr><td colSpan={cols} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>{msg}</td></tr>
}

function UsersTable({ data, loading, search }: { data: ADUser[]; loading: boolean; search: string }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(u => u.sam_account_name?.toLowerCase().includes(q) || u.display_name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <Skeleton />
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Username</th><th>Display name</th><th>Enabled</th>
          <th>Privileged</th><th>Pwd never expires</th><th>Last logon</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(u => (
          <tr key={u.distinguished_name}>
            <td style={{ fontFamily: 'monospace', fontSize: 12, color: '#0f1923', fontWeight: 500 }}>{u.sam_account_name}</td>
            <td style={{ color: '#0f1923' }}>{u.display_name}</td>
            <td><Bool val={u.enabled} /></td>
            <td>
              {u.is_privileged
                ? <span style={{ color: '#dc2626', fontSize: 11, fontWeight: 600 }}>Yes</span>
                : <span style={{ color: '#8a9ab5', fontSize: 11 }}>No</span>}
            </td>
            <td><Bool val={u.password_never_expires} /></td>
            <td style={{ color: '#8a9ab5', fontSize: 12 }}>{u.last_logon ? new Date(u.last_logon).toLocaleDateString() : '—'}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow cols={6} msg="No users match the filter" />}
      </tbody>
    </table>
  )
}

function GroupsTable({ data, loading, search }: { data: ADGroup[]; loading: boolean; search: string }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(g => g.name?.toLowerCase().includes(q) || g.sam_account_name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <Skeleton />
  return (
    <table className="data-table">
      <thead><tr><th>Name</th><th>Scope</th><th>Privileged</th><th>Members</th></tr></thead>
      <tbody>
        {rows.map(g => (
          <tr key={g.distinguished_name}>
            <td style={{ fontWeight: 500, color: '#0f1923' }}>{g.name}</td>
            <td style={{ color: '#4b5c72', fontSize: 12 }}>{g.group_scope}</td>
            <td>
              {g.is_privileged
                ? <span style={{ color: '#dc2626', fontSize: 11, fontWeight: 600 }}>Yes</span>
                : <span style={{ color: '#8a9ab5', fontSize: 11 }}>No</span>}
            </td>
            <td style={{ color: '#4b5c72' }}>{g.members?.length ?? 0}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow cols={4} msg="No groups match the filter" />}
      </tbody>
    </table>
  )
}

function ComputersTable({ data, loading, search }: { data: ADComputer[]; loading: boolean; search: string }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(c => c.name?.toLowerCase().includes(q) || c.dns_host_name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <Skeleton />
  return (
    <table className="data-table">
      <thead><tr><th>Name</th><th>OS</th><th>Enabled</th><th>LAPS</th><th>Last logon</th></tr></thead>
      <tbody>
        {rows.map(c => (
          <tr key={c.distinguished_name}>
            <td style={{ fontWeight: 500, color: '#0f1923', fontFamily: 'monospace', fontSize: 12 }}>{c.name}</td>
            <td style={{ color: '#4b5c72', fontSize: 12 }}>{c.operating_system}</td>
            <td><Bool val={c.enabled} /></td>
            <td><Bool val={c.laps_enabled} /></td>
            <td style={{ color: '#8a9ab5', fontSize: 12 }}>{c.last_logon ? new Date(c.last_logon).toLocaleDateString() : '—'}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow cols={5} msg="No computers match the filter" />}
      </tbody>
    </table>
  )
}

function DCsTable({ data, loading, search }: { data: ADDomainController[]; loading: boolean; search: string }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(d => d.name?.toLowerCase().includes(q) || d.site?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <Skeleton />
  return (
    <table className="data-table">
      <thead><tr><th>Name</th><th>Site</th><th>Global Catalog</th><th>RODC</th><th>LDAP signing</th><th>FSMO roles</th></tr></thead>
      <tbody>
        {rows.map((d, i) => (
          <tr key={i}>
            <td style={{ fontWeight: 500, color: '#0f1923', fontFamily: 'monospace', fontSize: 12 }}>{d.name}</td>
            <td style={{ color: '#4b5c72' }}>{d.site}</td>
            <td>{d.is_global_catalog ? <span style={{ color: '#2563eb', fontSize: 11, fontWeight: 600 }}>GC</span> : <span style={{ color: '#8a9ab5' }}>—</span>}</td>
            <td><Bool val={d.is_read_only} /></td>
            <td><Bool val={d.ldap_signing_required} /></td>
            <td style={{ color: '#8a9ab5', fontSize: 11 }}>{d.fsmo_roles?.join(', ') || '—'}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow cols={6} msg="No domain controllers found" />}
      </tbody>
    </table>
  )
}

function GPOsTable({ data, loading, search }: { data: ADGPO[]; loading: boolean; search: string }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(g => g.name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <Skeleton />
  return (
    <table className="data-table">
      <thead><tr><th>Name</th><th>Status</th><th>Linked</th><th>SYSVOL writable</th><th>Modified</th></tr></thead>
      <tbody>
        {rows.map(g => (
          <tr key={g.id}>
            <td style={{ fontWeight: 500, color: '#0f1923' }}>{g.name}</td>
            <td style={{ color: '#4b5c72', fontSize: 12 }}>{g.status}</td>
            <td><Bool val={g.is_linked} /></td>
            <td>
              {g.sysvol_writable_by_nonadmin
                ? <span style={{ color: '#dc2626', fontSize: 11, fontWeight: 600 }}>Exposed</span>
                : <span style={{ color: '#8a9ab5', fontSize: 11 }}>No</span>}
            </td>
            <td style={{ color: '#8a9ab5', fontSize: 12 }}>{g.modified ? new Date(g.modified).toLocaleDateString() : '—'}</td>
          </tr>
        ))}
        {rows.length === 0 && <EmptyRow cols={5} msg="No GPOs match the filter" />}
      </tbody>
    </table>
  )
}
