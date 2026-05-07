import { NavLink, useNavigate } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'
import { Database, FileText, LogOut, Map, Radio, Server, Settings, Shield, User } from 'lucide-react'

interface NavItem { to: string; label: string; icon: LucideIcon; exact?: boolean }

const ASSESS: NavItem[] = [
  { to: '/',          label: 'Overview',   icon: Map,      exact: true },
  { to: '/assess',    label: 'Assessment', icon: Radio },
  { to: '/directory', label: 'Directory',  icon: Database },
]
const DEFEND: NavItem[] = [
  { to: '/defend', label: 'Defend', icon: Shield },
]
const MANAGE: NavItem[] = [
  { to: '/reports',  label: 'Reports',  icon: FileText },
  { to: '/agents',   label: 'Agents',   icon: Server },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Sidebar() {
  const navigate = useNavigate()
  const logout = () => { localStorage.removeItem('auth_token'); navigate('/login') }

  return (
    <aside style={{
      width: 220, flexShrink: 0,
      display: 'flex', flexDirection: 'column',
      background: 'var(--sb-bg)',
      height: '100vh',
      borderRight: '1px solid var(--sb-border)',
      transition: 'background 0.3s',
    }}>

      {/* Logo */}
      <div style={{
        height: 60, display: 'flex', alignItems: 'center',
        padding: '0 18px', gap: 11,
        borderBottom: '1px solid var(--sb-border)', flexShrink: 0,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 9, flexShrink: 0,
          background: 'rgba(var(--accent-rgb, 37 99 235) / 0.2)',
          border: '1px solid var(--accent-bd)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 12px rgba(37,99,235,0.12)',
        }}>
          <Shield size={16} color="var(--accent)" />
        </div>
        <div>
          <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--sb-act)', letterSpacing: '-0.02em', lineHeight: 1.2 }}>
            Yama
          </div>
          <div style={{ fontSize: 9, color: 'var(--sb-dim)', fontWeight: 700, letterSpacing: '0.18em', textTransform: 'uppercase' }}>
            AD Security
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: 'auto', overflowX: 'hidden', padding: '14px 10px 10px' }}>
        <NavGroup label="Assess" items={ASSESS} />
        <NavGroup label="Defend" items={DEFEND} accent />
        <NavGroup label="Manage" items={MANAGE} />
      </nav>

      {/* User section */}
      <div style={{ borderTop: '1px solid var(--sb-border)', padding: '12px 10px', flexShrink: 0 }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '9px 12px', borderRadius: 8,
          background: 'rgba(255,255,255,0.04)',
          border: '1px solid var(--sb-border)',
        }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
            background: 'var(--accent)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 12, fontWeight: 700, color: '#fff',
            boxShadow: '0 1px 4px rgba(0,0,0,0.2)',
          }}>
            A
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--sb-act)', lineHeight: 1.3 }}>admin</div>
            <div style={{ fontSize: 10, color: 'var(--sb-dim)' }}>Administrator</div>
          </div>
          <button
            onClick={logout}
            title="Sign out"
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--sb-dim)', padding: 4, borderRadius: 5, display: 'flex',
              transition: 'color 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
            onMouseLeave={e => (e.currentTarget.style.color = 'var(--sb-dim)')}
          >
            <LogOut size={13} />
          </button>
        </div>
      </div>
    </aside>
  )
}

function NavGroup({ label, items, accent }: { label: string; items: NavItem[]; accent?: boolean }) {
  return (
    <div style={{ marginBottom: 4 }}>
      <div style={{
        fontSize: 9, fontWeight: 700, letterSpacing: '0.18em', textTransform: 'uppercase',
        color: accent ? 'color-mix(in srgb, var(--accent) 55%, transparent)' : 'color-mix(in srgb, var(--sb-act) 25%, transparent)',
        padding: '8px 12px 5px',
      }}>
        {label}
      </div>
      {items.map(item => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.exact}
          style={({ isActive }) => ({
            display: 'flex', alignItems: 'center', gap: 9,
            padding: '8px 12px',
            borderRadius: 7, textDecoration: 'none',
            fontSize: 13, fontWeight: isActive ? 600 : 400,
            marginBottom: 2,
            color: isActive ? 'var(--sb-act)' : 'var(--sb-txt)',
            background: isActive
              ? (accent ? 'color-mix(in srgb, var(--accent) 18%, transparent)' : 'rgba(255,255,255,0.08)')
              : 'transparent',
            borderLeft: `2px solid ${isActive ? 'var(--accent)' : 'transparent'}`,
            transition: 'all 0.12s',
          })}
        >
          {({ isActive }) => (
            <>
              <item.icon
                size={15}
                color={isActive ? 'var(--accent)' : 'var(--sb-txt)'}
                style={{ flexShrink: 0, transition: 'color 0.12s' }}
              />
              {item.label}
            </>
          )}
        </NavLink>
      ))}
    </div>
  )
}
