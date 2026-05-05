import { Activity, ChevronsRight, PanelLeft, ShieldCheck, Wifi, WifiOff } from 'lucide-react'
import { useLocation } from 'react-router-dom'
import clsx from 'clsx'
import { useScanStore } from '../../stores/scanStore'

const pageMeta: Record<string, { title: string; section: string; description: string }> = {
  '/dashboard': {
    title: 'Security Dashboard',
    section: 'Overview',
    description: 'Posture, exposure, and latest results.',
  },
  '/scanner': {
    title: 'Assessment Operations',
    section: 'Assessment',
    description: 'Run and track collection jobs.',
  },
  '/findings': {
    title: 'Exposure Analysis',
    section: 'Exposure',
    description: 'Prioritized findings and remediation.',
  },
  '/inventory': {
    title: 'Directory Intelligence',
    section: 'Directory',
    description: 'Objects, policies, and controllers.',
  },
  '/topology': {
    title: 'Forest Topology',
    section: 'Topology',
    description: 'Sites, trusts, and controller layout.',
  },
  '/reports': {
    title: 'Reporting',
    section: 'Exports',
    description: 'Assessment output and downloads.',
  },
  '/agents': {
    title: 'Agent Fleet',
    section: 'Collectors',
    description: 'Collector status and deployment.',
  },
}

interface HeaderProps {
  collapsed: boolean
  onToggle: () => void
}

export function Header({ collapsed, onToggle }: HeaderProps) {
  const location = useLocation()
  const { wsConnected, activeScan } = useScanStore()
  const meta = pageMeta[location.pathname] ?? pageMeta['/dashboard']

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/86 backdrop-blur-xl">
      <div className="shell-inner flex items-center justify-between gap-4 py-4">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onToggle}
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-slate-200 bg-white text-slate-600 shadow-sm transition hover:border-slate-300 hover:text-slate-900"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <PanelLeft className="h-4 w-4" /> : <ChevronsRight className="h-4 w-4" />}
          </button>

          <div className="min-w-0">
            <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
              <span>{meta.section}</span>
              <span className="text-slate-300">/</span>
              <span>Yama</span>
            </div>
            <div className="mt-1 flex min-w-0 items-center gap-3">
              <h1 className="truncate text-2xl font-semibold tracking-[0.01em] text-slate-950">{meta.title}</h1>
              <span className="hidden rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-emerald-700 md:inline-flex">
                Online
              </span>
            </div>
            <p className="mt-1 truncate text-sm text-slate-500">{meta.description}</p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <div
            className={clsx(
              'chip border shadow-sm',
              wsConnected
                ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
                : 'border-slate-200 bg-slate-100 text-slate-500'
            )}
          >
            {wsConnected ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
            <span className="hidden sm:inline">{wsConnected ? 'Telemetry' : 'Offline'}</span>
          </div>

          {activeScan?.status === 'running' ? (
            <div className="hidden min-w-[220px] items-center gap-3 rounded-2xl border border-sky-200 bg-sky-50 px-4 py-3 shadow-sm lg:flex">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-sky-200 bg-white text-sky-700">
                <Activity className="h-4 w-4 animate-pulse" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-sky-700">
                  <span>Active assessment</span>
                  <span>{activeScan.progress}%</span>
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-sky-100">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-sky-600 to-cyan-500"
                    style={{ width: `${activeScan.progress}%` }}
                  />
                </div>
              </div>
            </div>
          ) : (
            <div className="hidden chip border-sky-200 bg-sky-50 text-sky-700 shadow-sm md:inline-flex">
              <ShieldCheck className="h-3.5 w-3.5" />
              Ready
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
