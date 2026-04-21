import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard, Search, Server, ShieldAlert,
  Network, FileText, LogOut
} from 'lucide-react'
import clsx from 'clsx'

const nav = [
  { to: '/dashboard',  label: 'Dashboard',  icon: LayoutDashboard },
  { to: '/scanner',    label: 'Scanner',    icon: Search },
  { to: '/inventory',  label: 'Inventory',  icon: Server },
  { to: '/findings',   label: 'Findings',   icon: ShieldAlert },
  { to: '/topology',   label: 'Topology',   icon: Network },
  { to: '/reports',    label: 'Reports',    icon: FileText },
]

export function Sidebar() {
  const handleLogout = () => {
    localStorage.removeItem('auth_token')
    window.location.href = '/login'
  }

  return (
    <div className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <img src="/yama.svg" className="w-9 h-9" alt="Yama" />
        <div>
          <p className="text-white font-semibold text-sm">Yama</p>
          <p className="text-gray-500 text-xs">Active Directory Assessment</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {nav.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-violet-600/20 text-violet-400 border border-violet-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              )
            }
          >
            <Icon className="w-4 h-4 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Logout */}
      <div className="px-3 py-4 border-t border-gray-800">
        <button
          onClick={handleLogout}
          className="flex items-center gap-3 px-3 py-2.5 w-full rounded-lg text-sm font-medium text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors"
        >
          <LogOut className="w-4 h-4" />
          Logout
        </button>
      </div>
    </div>
  )
}
