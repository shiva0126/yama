import { NavLink } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Boxes,
  ChevronsLeft,
  ChevronsRight,
  FileSpreadsheet,
  Fingerprint,
  Flame,
  LogOut,
  Network,
  Radar,
  Shield,
  ShieldCheck,
  ShieldQuestion,
  Waypoints,
} from 'lucide-react'
import clsx from 'clsx'

const navGroups = [
  {
    title: 'Defense Plane',
    items: [
      { to: '/defense', label: 'Defense Overview', icon: ShieldCheck },
      { to: '/defense/incidents', label: 'Incidents', icon: AlertTriangle },
      { to: '/defense/catalog', label: 'Attack Catalog', icon: Flame },
      { to: '/defense/response', label: 'Response', icon: Fingerprint },
      { to: '/defense/evidence', label: 'Evidence', icon: FileSpreadsheet },
      { to: '/defense/policy', label: 'Policy', icon: ShieldQuestion },
    ],
  },
  {
    title: 'Assessment Plane',
    items: [
      { to: '/overview', label: 'Overview', icon: Shield },
      { to: '/scanner', label: 'Assessments', icon: Radar },
      { to: '/findings', label: 'Exposure Queue', icon: Activity },
      { to: '/inventory', label: 'Directory', icon: Boxes },
      { to: '/topology', label: 'Attack Surface', icon: Waypoints },
      { to: '/reports', label: 'Reports', icon: FileSpreadsheet },
      { to: '/agents', label: 'Agents', icon: Network },
    ],
  },
]

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const handleLogout = () => {
    localStorage.removeItem('auth_token')
    window.location.href = '/login'
  }

  return (
    <aside
      className={clsx(
        'sticky top-0 flex h-screen shrink-0 flex-col border-r border-slate-950/10 bg-[linear-gradient(180deg,#0a1420_0%,#0d1827_55%,#0f1c2d_100%)] shadow-[18px_0_36px_rgba(15,23,42,0.12)] transition-[width] duration-200',
        collapsed ? 'w-[84px]' : 'w-[280px]'
      )}
    >
      <div className={clsx('flex items-center border-b border-white/10 px-4 py-5', collapsed ? 'justify-center' : 'justify-between')}>
        <div className={clsx('flex items-center gap-3', collapsed && 'justify-center')}>
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-sky-300/20 bg-sky-400/10 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)]">
            <img src="/yama.svg" className="h-7 w-7" alt="Yama" />
          </div>
          {!collapsed && (
              <div className="min-w-0">
                <p className="text-base font-semibold tracking-[0.04em] text-slate-50">Yama</p>
                <p className="text-[11px] font-medium uppercase tracking-[0.18em] text-slate-400/75">AD Security Console</p>
              </div>
            )}
          </div>

        {!collapsed && (
          <button
            type="button"
            onClick={onToggle}
            className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-slate-400 transition hover:bg-white/[0.08] hover:text-slate-200"
            aria-label="Collapse sidebar"
          >
            <ChevronsLeft className="h-4 w-4" />
          </button>
        )}
      </div>

      <div className={clsx('flex-1 overflow-y-auto py-5', collapsed ? 'px-3' : 'px-4')}>
        <nav className={clsx('space-y-5', collapsed ? 'mt-0' : 'mt-3')}>
          {navGroups.map((group) => (
            <div key={group.title} className="space-y-2">
              {!collapsed && <p className="px-3 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400/70">{group.title}</p>}
              <div className="space-y-1.5">
                {group.items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    title={collapsed ? label : undefined}
                    className={({ isActive }) =>
                      clsx(
                        'group flex items-center rounded-2xl border transition',
                        collapsed ? 'justify-center px-0 py-3' : 'gap-3 px-3 py-3.5',
                        isActive
                          ? 'border-sky-300/25 bg-sky-400/10 shadow-[inset_0_1px_0_rgba(255,255,255,0.05),0_10px_24px_rgba(2,132,199,0.08)]'
                          : 'border-transparent hover:border-white/8 hover:bg-white/[0.04]'
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <div
                          className={clsx(
                            'flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border transition',
                            isActive
                              ? 'border-sky-300/24 bg-white text-sky-700'
                              : 'border-white/8 bg-white/[0.03] text-slate-500 group-hover:text-slate-200'
                          )}
                        >
                          <Icon className="h-[18px] w-[18px]" />
                        </div>
                        {!collapsed && (
                          <div className="min-w-0">
                            <p className={clsx('text-sm font-semibold', isActive ? 'text-white' : 'text-slate-300')}>{label}</p>
                          </div>
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
      </div>

      <div className={clsx('border-t border-white/10 py-4', collapsed ? 'px-3' : 'px-4')}>
        {collapsed ? (
          <div className="space-y-2">
            <button
              type="button"
              onClick={onToggle}
              className="flex h-12 w-full items-center justify-center rounded-2xl border border-white/10 bg-white/[0.04] text-slate-400 transition hover:bg-white/[0.08] hover:text-slate-200"
              aria-label="Expand sidebar"
              title="Expand"
            >
              <ChevronsRight className="h-4 w-4" />
            </button>
            <button
              onClick={handleLogout}
              className="flex h-12 w-full items-center justify-center rounded-2xl border border-transparent text-slate-400 transition hover:border-red-500/20 hover:bg-red-500/8 hover:text-red-300"
              title="Sign out"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-2xl border border-transparent px-4 py-3 text-sm font-medium text-slate-400 transition hover:border-red-500/20 hover:bg-red-500/8 hover:text-red-300"
          >
            <LogOut className="h-4 w-4" />
            <span>Sign out</span>
          </button>
        )}
      </div>
    </aside>
  )
}
