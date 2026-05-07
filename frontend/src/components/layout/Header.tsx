import { useLocation } from 'react-router-dom'
import { Bell, RefreshCw } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { scansApi } from '../../api'
import { formatDistanceToNow } from 'date-fns'

const TITLES: Record<string, { title: string; sub: string }> = {
  '/':          { title: 'Overview',    sub: 'Command center' },
  '/assess':    { title: 'Assessment',  sub: 'Scan & findings' },
  '/directory': { title: 'Directory',   sub: 'AD object inventory' },
  '/defend':    { title: 'Defend',      sub: 'Threat detection & response' },
  '/reports':   { title: 'Reports',     sub: 'Security reporting' },
  '/agents':    { title: 'Agents',      sub: 'Collector management' },
  '/settings':  { title: 'Settings',    sub: 'Appearance & customisation' },
}

export function Header() {
  const { pathname } = useLocation()
  const meta = TITLES[pathname] ?? { title: 'Yama', sub: '' }

  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
    refetchInterval: 30_000,
    staleTime: 15_000,
  })
  const latestScan = scansData?.scans?.find(s => s.status === 'completed')

  return (
    <header style={{
      height: 52, flexShrink: 0,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 24px',
      background: '#ffffff',
      borderBottom: '1px solid #e4e8ef',
      zIndex: 10,
    }}>
      {/* Left — page identity */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
        <span style={{ fontSize: 15, fontWeight: 600, color: '#0f1923', letterSpacing: '-0.01em' }}>
          {meta.title}
        </span>
        <span style={{ fontSize: 12, color: '#8a9ab5', fontWeight: 400 }}>{meta.sub}</span>
      </div>

      {/* Right — status + actions */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        {latestScan && (
          <div style={{
            fontSize: 11, color: '#4b5c72', fontWeight: 500,
            background: '#f4f6f9', border: '1px solid #e4e8ef',
            borderRadius: 6, padding: '4px 10px',
            display: 'flex', alignItems: 'center', gap: 6,
          }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#16a34a', flexShrink: 0, display: 'inline-block' }} />
            Last scan {formatDistanceToNow(new Date(latestScan.completed_at!), { addSuffix: true })}
          </div>
        )}

        <button className="btn-icon" title="Refresh"><RefreshCw size={14} /></button>
        <button className="btn-icon" title="Notifications"><Bell size={14} /></button>

        <div style={{
          width: 30, height: 30, borderRadius: '50%',
          background: 'linear-gradient(135deg, #1d4ed8, #2563eb)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#fff', fontSize: 12, fontWeight: 700,
          cursor: 'default', flexShrink: 0,
          boxShadow: '0 1px 3px rgba(37,99,235,0.3)',
        }} title="admin">
          A
        </div>
      </div>
    </header>
  )
}
