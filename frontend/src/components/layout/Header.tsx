import { Activity, AlertTriangle, ChevronsRight, PanelLeft, ShieldCheck, Wifi, WifiOff } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { useLocation } from 'react-router-dom'
import clsx from 'clsx'
import type { ReactNode } from 'react'
import { useScanStore } from '../../stores/scanStore'
import { defenseApi, overviewApi } from '../../api'

const pageMeta: Record<string, { title: string; section: string; description: string }> = {
  '/defense': {
    title: 'Defense Command',
    section: 'Defense',
    description: 'Live incidents, catalog coverage, evidence, and policy controls.',
  },
  '/defense/incidents': {
    title: 'Incident Queue',
    section: 'Defense',
    description: 'Correlated attack chains and containment priorities.',
  },
  '/defense/catalog': {
    title: 'Attack Catalog',
    section: 'Defense',
    description: 'Technique families, detector coverage, and signal mapping.',
  },
  '/defense/response': {
    title: 'Response Playbooks',
    section: 'Defense',
    description: 'Containment actions, approvals, and rollback posture.',
  },
  '/defense/evidence': {
    title: 'Evidence Ledger',
    section: 'Defense',
    description: 'Bundles, hashes, and preserved response artifacts.',
  },
  '/defense/policy': {
    title: 'Policy Controls',
    section: 'Defense',
    description: 'Protected scopes, exclusions, and enforcement thresholds.',
  },
  '/overview': {
    title: 'Command Center',
    section: 'Overview',
    description: 'Executive posture, analyst queue, and fleet health.',
  },
  '/scanner': {
    title: 'Assessment Operations',
    section: 'Assessment',
    description: 'Run and track collection jobs.',
  },
  '/findings': {
    title: 'Exposure Queue',
    section: 'Triage',
    description: 'Prioritized findings, evidence, and remediation.',
  },
  '/inventory': {
    title: 'Directory Intelligence',
    section: 'Directory',
    description: 'Objects, policies, and controllers.',
  },
  '/topology': {
    title: 'Attack Surface Map',
    section: 'Topology',
    description: 'Sites, trusts, and controller layout.',
  },
  '/reports': {
    title: 'Evidence Packages',
    section: 'Exports',
    description: 'Assessment output and downloads.',
  },
  '/agents': {
    title: 'Collector Fleet',
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
  const meta = pageMeta[location.pathname] ?? pageMeta['/overview']
  const isDefenseRoute = location.pathname.startsWith('/defense')
  const { data } = useQuery({
    queryKey: ['overview-summary'],
    queryFn: () => overviewApi.summary().then((r) => r.data),
    refetchInterval: 20_000,
  })
  const { data: defenseSummary } = useQuery({
    queryKey: ['defense-summary'],
    queryFn: () => defenseApi.summary().then((r) => r.data),
    refetchInterval: 20_000,
    enabled: isDefenseRoute,
  })
  const { data: defenseIncidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then((r) => r.data),
    refetchInterval: 20_000,
    enabled: isDefenseRoute,
  })

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/80 bg-white/90 backdrop-blur-xl">
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
              <span className="hidden rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-700 md:inline-flex">
                {data?.collectors.online ?? 0} online
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

          <div className="hidden gap-2 lg:flex">
            {isDefenseRoute ? (
              <>
                <HeaderStat label="Detectors" value={defenseSummary?.detector_count ?? 0} tone="info" />
                <HeaderStat label="Incidents" value={defenseIncidents?.length ?? 0} tone="danger" icon={<AlertTriangle className="h-3.5 w-3.5" />} />
                <HeaderStat label="Policy" value={defenseSummary?.demo_ready_count ?? 0} tone="success" icon={<ShieldCheck className="h-3.5 w-3.5" />} />
              </>
            ) : (
              <>
                <HeaderStat label="Critical" value={data?.findings.critical ?? 0} tone="danger" />
                <HeaderStat label="Reports" value={data?.reports.total ?? 0} tone="neutral" />
                {activeScan?.status === 'running' ? (
                  <HeaderStat label="Assessment" value={`${activeScan.progress}%`} tone="info" icon={<Activity className="h-3.5 w-3.5 animate-pulse" />} />
                ) : (
                  <HeaderStat label="State" value="Ready" tone="success" icon={<ShieldCheck className="h-3.5 w-3.5" />} />
                )}
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  )
}

function HeaderStat({
  label,
  value,
  tone,
  icon,
}: {
  label: string
  value: number | string
  tone: 'neutral' | 'danger' | 'info' | 'success'
  icon?: ReactNode
}) {
  const className =
    tone === 'danger'
      ? 'border-red-200 bg-red-50 text-red-700'
      : tone === 'info'
        ? 'border-sky-200 bg-sky-50 text-sky-700'
        : tone === 'success'
          ? 'border-emerald-200 bg-emerald-50 text-emerald-700'
          : 'border-slate-200 bg-slate-50 text-slate-700'

  return (
    <div className={clsx('hidden min-w-[104px] rounded-2xl border px-3 py-2 text-left lg:block', className)}>
      <p className="text-[10px] font-semibold uppercase tracking-[0.16em] opacity-80">{label}</p>
      <div className="mt-1 flex items-center gap-2 text-sm font-semibold">
        {icon}
        <span>{value}</span>
      </div>
    </div>
  )
}
