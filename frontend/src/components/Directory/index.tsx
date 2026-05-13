import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AlertTriangle, CheckCircle, ChevronRight, Clock, Filter,
  Key, Monitor, Search, Server, Shield, ShieldAlert, Users, X, XCircle,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { inventoryApi, scansApi } from '../../api'
import type { ADUser, ADGroup, ADComputer, ADDomainController, ADGPO } from '../../types'

// ─── Tab definition ──────────────────────────────────────────────────────────
type Tab = 'overview' | 'users' | 'services' | 'groups' | 'computers' | 'dcs' | 'gpos'

// ─── Utility helpers ──────────────────────────────────────────────────────────

function staleDays(dateStr: string | null | undefined): number | null {
  if (!dateStr) return null
  const d = new Date(dateStr)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return null
  return Math.floor((Date.now() - d.getTime()) / 86400000)
}

function bestLogon(u: ADUser): string | null {
  // Prefer lastLogonTimestamp (replicated) but fall back to lastLogon
  const ts = u.last_logon_timestamp ?? u.last_logon
  if (!ts || ts.startsWith('0001')) return null
  return ts
}

function StaleChip({ dateStr }: { dateStr: string | null | undefined }) {
  const days = staleDays(dateStr)
  if (days === null)
    return <span style={{ fontSize: 11, color: '#8a9ab5', background: '#f0f3f8', padding: '2px 8px', borderRadius: 10 }}>Never</span>
  if (days < 30)
    return <span style={{ fontSize: 11, color: '#16a34a', background: '#f0fdf4', padding: '2px 8px', borderRadius: 10 }}>{days}d ago</span>
  if (days < 90)
    return <span style={{ fontSize: 11, color: '#d97706', background: '#fffbeb', padding: '2px 8px', borderRadius: 10 }}>{days}d ago</span>
  return <span style={{ fontSize: 11, color: '#dc2626', background: '#fef2f2', padding: '2px 8px', borderRadius: 10 }}>{days}d ago</span>
}

function ouContainer(dn: string): string {
  const parts = dn.split(',')
  if (parts.length < 2) return '—'
  const seg = parts[1] ?? ''
  const name = seg.replace(/^(OU|CN)=/, '')
  return name || '—'
}

function avatarColor(name: string): string {
  const colors = ['#2563eb','#7c3aed','#0891b2','#059669','#d97706','#dc2626','#db2777','#65a30d']
  let h = 0; for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) & 0x7fffffff
  return colors[h % colors.length]
}

function RiskBadge({ label, color, bg }: { label: string; color: string; bg: string }) {
  return (
    <span style={{ fontSize: 10, fontWeight: 700, color, background: bg, padding: '2px 6px', borderRadius: 4, letterSpacing: '0.05em', textTransform: 'uppercase' as const }}>
      {label}
    </span>
  )
}

function tierColor(level: string): { color: string; bg: string } {
  if (level === 'Tier0') return { color: '#dc2626', bg: '#fef2f2' }
  if (level === 'Tier1') return { color: '#d97706', bg: '#fffbeb' }
  return { color: '#2563eb', bg: '#eff6ff' }
}

function cn(dn: string): string {
  const m = dn.match(/^CN=([^,]+)/)
  return m ? m[1] : dn
}

// ─── Detail drawer ────────────────────────────────────────────────────────────

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  if (!value && value !== 0 && value !== false) return null
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 13, color: '#0f1923' }}>{value}</div>
    </div>
  )
}

function Drawer({ title, icon, onClose, children }: { title: string; icon: React.ReactNode; onClose: () => void; children: React.ReactNode }) {
  return (
    <div style={{
      position: 'fixed', top: 0, right: 0, bottom: 0, width: 420,
      background: '#fff', borderLeft: '1px solid #e4e8ef',
      boxShadow: '-8px 0 32px rgba(15,25,35,0.12)',
      zIndex: 100, display: 'flex', flexDirection: 'column',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '16px 20px', borderBottom: '1px solid #f0f3f8', flexShrink: 0 }}>
        <div style={{ color: '#2563eb' }}>{icon}</div>
        <div style={{ flex: 1, fontSize: 14, fontWeight: 600, color: '#0f1923', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{title}</div>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8a9ab5', padding: 4 }}><X size={16} /></button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>{children}</div>
    </div>
  )
}

// ─── Object-specific drawers ──────────────────────────────────────────────────

function UserDrawer({ user, onClose }: { user: ADUser; onClose: () => void }) {
  const logon = bestLogon(user)
  return (
    <Drawer title={user.sam_account_name} icon={<Users size={16} />} onClose={onClose}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        {!user.enabled && <RiskBadge label="Disabled" color="#8a9ab5" bg="#f0f3f8" />}
        {user.is_privileged && <RiskBadge label="Privileged" color="#dc2626" bg="#fef2f2" />}
        {user.service_principal_names?.length > 0 && <RiskBadge label="Kerberoastable" color="#7c3aed" bg="#f5f3ff" />}
        {user.password_never_expires && <RiskBadge label="Pwd never exp" color="#d97706" bg="#fffbeb" />}
        {user.locked && <RiskBadge label="Locked" color="#dc2626" bg="#fef2f2" />}
        {user.dont_require_preauth && <RiskBadge label="ASREPRoastable" color="#dc2626" bg="#fef2f2" />}
        {user.trusted_for_delegation && <RiskBadge label="Unconstrained delegation" color="#dc2626" bg="#fef2f2" />}
        {user.has_shadow_credentials && <RiskBadge label="Shadow creds" color="#dc2626" bg="#fef2f2" />}
        {user.is_gmsa && <RiskBadge label="gMSA" color="#2563eb" bg="#eff6ff" />}
        {user.reversible_encryption && <RiskBadge label="Reversible enc" color="#dc2626" bg="#fef2f2" />}
      </div>

      <div style={{ background: '#f8fafc', borderRadius: 8, padding: '14px', marginBottom: 20 }}>
        <Field label="Display name" value={user.display_name || '—'} />
        <Field label="UPN" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{user.user_principal_name || '—'}</span>} />
        <Field label="SAM Account" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{user.sam_account_name}</span>} />
        <Field label="Department" value={user.department} />
        <Field label="Title" value={user.title} />
        <Field label="Description" value={user.description} />
        <Field label="Domain" value={user.domain} />
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>Account Status</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {([
            ['Enabled', user.enabled],
            ['Locked', user.locked ?? false],
            ['Pwd expired', user.password_expired ?? false],
            ['Pwd never exp', user.password_never_expires],
            ['Smartcard req', user.smartcard_required ?? false],
            ['Preauth req', !user.dont_require_preauth],
          ] as [string, boolean][]).map(([l, v]) => (
            <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#4b5c72' }}>
              {v ? <CheckCircle size={13} color="#16a34a" /> : <XCircle size={13} color="#dc2626" />}
              {l}
            </div>
          ))}
        </div>
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Activity</div>
        <Field label="Last logon" value={logon ? new Date(logon).toLocaleString() : 'Never'} />
        <Field label="Password last set" value={user.pwd_last_set && !user.pwd_last_set.startsWith('0001') ? new Date(user.pwd_last_set).toLocaleString() : '—'} />
      </div>

      {user.service_principal_names?.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Service Principal Names</div>
          {user.service_principal_names.map(spn => (
            <div key={spn} style={{ fontFamily: 'monospace', fontSize: 11, color: '#0f1923', background: '#f0f3f8', padding: '4px 8px', borderRadius: 4, marginBottom: 4 }}>{spn}</div>
          ))}
        </div>
      )}

      {user.privileged_groups?.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Privileged Groups</div>
          {user.privileged_groups.map(g => (
            <div key={g} style={{ fontSize: 12, color: '#dc2626', background: '#fef2f2', padding: '3px 8px', borderRadius: 4, marginBottom: 3 }}>{g}</div>
          ))}
        </div>
      )}

      {user.member_of?.length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Member of ({user.member_of.length})</div>
          {user.member_of.map(dn => (
            <div key={dn} style={{ fontSize: 12, color: '#4b5c72', padding: '3px 8px', borderBottom: '1px solid #f0f3f8' }}>{cn(dn)}</div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Distinguished Name</div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#8a9ab5', wordBreak: 'break-all' }}>{user.distinguished_name}</div>
      </div>
    </Drawer>
  )
}

function GroupDrawer({ group, onClose }: { group: ADGroup; onClose: () => void }) {
  const tier = tierColor(group.privilege_level)
  return (
    <Drawer title={group.name} icon={<Shield size={16} />} onClose={onClose}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        {group.privilege_level && <RiskBadge label={group.privilege_level} color={tier.color} bg={tier.bg} />}
        {group.is_privileged && <RiskBadge label="Privileged" color="#dc2626" bg="#fef2f2" />}
        <RiskBadge label={group.group_scope} color="#2563eb" bg="#eff6ff" />
        <RiskBadge label={group.group_category} color="#4b5c72" bg="#f0f3f8" />
      </div>

      <div style={{ background: '#f8fafc', borderRadius: 8, padding: '14px', marginBottom: 20 }}>
        <Field label="SAM Account" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{group.sam_account_name}</span>} />
        <Field label="Description" value={group.description} />
        <Field label="Domain" value={group.domain} />
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>
          Members ({group.members?.length ?? 0})
        </div>
        {(group.members ?? []).slice(0, 30).map(dn => (
          <div key={dn} style={{ fontSize: 12, color: '#4b5c72', padding: '3px 8px', borderBottom: '1px solid #f0f3f8' }}>{cn(dn)}</div>
        ))}
        {(group.members?.length ?? 0) > 30 && (
          <div style={{ fontSize: 11, color: '#8a9ab5', padding: '4px 8px' }}>+{group.members.length - 30} more</div>
        )}
      </div>

      <div style={{ marginTop: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Distinguished Name</div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#8a9ab5', wordBreak: 'break-all' }}>{group.distinguished_name}</div>
      </div>
    </Drawer>
  )
}

function ComputerDrawer({ computer, onClose }: { computer: ADComputer; onClose: () => void }) {
  const logon = computer.last_logon_timestamp ?? computer.last_logon
  return (
    <Drawer title={computer.name} icon={<Monitor size={16} />} onClose={onClose}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        {!computer.enabled && <RiskBadge label="Disabled" color="#8a9ab5" bg="#f0f3f8" />}
        {computer.is_domain_controller && <RiskBadge label="DC" color="#2563eb" bg="#eff6ff" />}
        {!computer.laps_enabled && <RiskBadge label="No LAPS" color="#d97706" bg="#fffbeb" />}
        {computer.trusted_for_delegation && <RiskBadge label="Unconstrained delegation" color="#dc2626" bg="#fef2f2" />}
        {computer.trusted_to_auth_for_delegation && <RiskBadge label="Constrained delegation" color="#d97706" bg="#fffbeb" />}
      </div>

      <div style={{ background: '#f8fafc', borderRadius: 8, padding: '14px', marginBottom: 20 }}>
        <Field label="DNS Hostname" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{computer.dns_host_name}</span>} />
        <Field label="Operating System" value={computer.operating_system} />
        <Field label="OS Version" value={computer.operating_system_version} />
        <Field label="Domain" value={computer.domain} />
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Status</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {([
            ['Enabled', computer.enabled],
            ['LAPS', computer.laps_enabled],
            ['Is DC', computer.is_domain_controller],
            ['Read-only DC', computer.is_read_only_dc ?? false],
            ['Unconstrained deleg', computer.trusted_for_delegation],
          ] as [string, boolean][]).map(([l, v]) => (
            <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#4b5c72' }}>
              {v ? <CheckCircle size={13} color="#16a34a" /> : <XCircle size={13} color={['Enabled', 'LAPS'].includes(l) && !v ? '#dc2626' : '#8a9ab5'} />}
              {l}
            </div>
          ))}
        </div>
      </div>

      <Field label="Last logon" value={logon && !logon.startsWith('0001') ? new Date(logon).toLocaleString() : 'Never'} />
      <Field label="Password last set" value={computer.pwd_last_set && !computer.pwd_last_set.startsWith('0001') ? new Date(computer.pwd_last_set).toLocaleString() : '—'} />

      {computer.service_principal_names && computer.service_principal_names.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>SPNs ({computer.service_principal_names.length})</div>
          {computer.service_principal_names.slice(0, 10).map(spn => (
            <div key={spn} style={{ fontFamily: 'monospace', fontSize: 10, color: '#4b5c72', background: '#f0f3f8', padding: '3px 8px', borderRadius: 4, marginBottom: 3 }}>{spn}</div>
          ))}
          {computer.service_principal_names.length > 10 && (
            <div style={{ fontSize: 11, color: '#8a9ab5' }}>+{computer.service_principal_names.length - 10} more</div>
          )}
        </div>
      )}

      <div style={{ marginTop: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Distinguished Name</div>
        <div style={{ fontFamily: 'monospace', fontSize: 10, color: '#8a9ab5', wordBreak: 'break-all' }}>{computer.distinguished_name}</div>
      </div>
    </Drawer>
  )
}

function DCDrawer({ dc, onClose }: { dc: ADDomainController; onClose: () => void }) {
  return (
    <Drawer title={dc.name} icon={<Server size={16} />} onClose={onClose}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        {dc.is_global_catalog && <RiskBadge label="Global Catalog" color="#2563eb" bg="#eff6ff" />}
        {dc.is_read_only && <RiskBadge label="RODC" color="#4b5c72" bg="#f0f3f8" />}
        {!dc.ldap_signing_required && <RiskBadge label="LDAP signing off" color="#dc2626" bg="#fef2f2" />}
        {!dc.smb_signing_required && <RiskBadge label="SMB signing off" color="#dc2626" bg="#fef2f2" />}
        {dc.spooler_running && <RiskBadge label="Print spooler" color="#d97706" bg="#fffbeb" />}
      </div>

      <div style={{ background: '#f8fafc', borderRadius: 8, padding: '14px', marginBottom: 20 }}>
        <Field label="Hostname" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{dc.host_name}</span>} />
        <Field label="IP Address" value={<span style={{ fontFamily: 'monospace', fontSize: 12 }}>{dc.ip_address}</span>} />
        <Field label="Site" value={dc.site} />
        <Field label="Operating System" value={dc.operating_system} />
        <Field label="Domain" value={dc.domain} />
      </div>

      {dc.fsmo_roles?.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>FSMO Roles</div>
          {dc.fsmo_roles.map(role => (
            <div key={role} style={{ fontSize: 12, color: '#2563eb', background: '#eff6ff', padding: '3px 8px', borderRadius: 4, marginBottom: 3 }}>{role}</div>
          ))}
        </div>
      )}

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Security Controls</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {([
            ['LDAP Signing Required', dc.ldap_signing_required],
            ['SMB Signing Required', dc.smb_signing_required],
            ['Global Catalog', dc.is_global_catalog],
            ['Read-Only DC', dc.is_read_only],
            ['Print Spooler Running', dc.spooler_running],
          ] as [string, boolean][]).map(([l, v]) => (
            <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#4b5c72' }}>
              {v
                ? <CheckCircle size={14} color={l === 'Print Spooler Running' ? '#d97706' : '#16a34a'} />
                : <XCircle size={14} color={['LDAP Signing Required', 'SMB Signing Required'].includes(l) ? '#dc2626' : '#8a9ab5'} />}
              {l}
            </div>
          ))}
        </div>
      </div>
    </Drawer>
  )
}

function GPODrawer({ gpo, onClose }: { gpo: ADGPO; onClose: () => void }) {
  return (
    <Drawer title={gpo.name} icon={<Shield size={16} />} onClose={onClose}>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20 }}>
        <RiskBadge label={gpo.status} color="#4b5c72" bg="#f0f3f8" />
        {!gpo.is_linked && <RiskBadge label="Unlinked" color="#8a9ab5" bg="#f0f3f8" />}
        {gpo.sysvol_writable_by_nonadmin && <RiskBadge label="SYSVOL exposed" color="#dc2626" bg="#fef2f2" />}
      </div>

      <Field label="GPO ID" value={<span style={{ fontFamily: 'monospace', fontSize: 11 }}>{gpo.id}</span>} />
      <Field label="Display Name" value={gpo.display_name} />
      <Field label="Domain" value={gpo.domain} />
      <Field label="Modified" value={gpo.modified && !gpo.modified.startsWith('0001') ? new Date(gpo.modified).toLocaleString() : '—'} />
      <Field label="SYSVOL path" value={gpo.gpc_file_sys_path ? <span style={{ fontFamily: 'monospace', fontSize: 10, wordBreak: 'break-all' }}>{gpo.gpc_file_sys_path}</span> : undefined} />

      {gpo.linked_ous?.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: '#8a9ab5', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Linked OUs</div>
          {gpo.linked_ous.map((l, i) => (
            <div key={i} style={{ fontSize: 11, color: '#4b5c72', background: '#f8fafc', padding: '4px 8px', borderRadius: 4, marginBottom: 3 }}>
              {l.ou_dn}
              {l.enforced && <span style={{ marginLeft: 6, fontSize: 10, color: '#d97706' }}>Enforced</span>}
              {!l.enabled && <span style={{ marginLeft: 6, fontSize: 10, color: '#8a9ab5' }}>Disabled</span>}
            </div>
          ))}
        </div>
      )}
    </Drawer>
  )
}

// ─── Overview pane ────────────────────────────────────────────────────────────

function OverviewPane({
  users, groups, computers, dcs, gpos, usersLoading,
}: {
  users: ADUser[]; groups: ADGroup[]; computers: ADComputer[]
  dcs: ADDomainController[]; gpos: ADGPO[]; usersLoading: boolean
}) {
  const stats = useMemo(() => {
    const privileged = users.filter(u => u.is_privileged)
    const services = users.filter(u => u.service_principal_names?.length > 0)
    const kerberoastable = users.filter(u => u.enabled && u.service_principal_names?.length > 0 && u.sam_account_name !== 'krbtgt')
    const stale = users.filter(u => {
      const d = staleDays(bestLogon(u)); return d === null || d > 90
    })
    const pwdNeverExp = users.filter(u => u.password_never_expires)
    const asreproastable = users.filter(u => u.dont_require_preauth && u.enabled)
    const tier0 = groups.filter(g => g.privilege_level === 'Tier0')
    const noLaps = computers.filter(c => !c.is_domain_controller && !c.laps_enabled)
    const ldapUnsigned = dcs.filter(d => !d.ldap_signing_required)
    const smbUnsigned = dcs.filter(d => !d.smb_signing_required)
    const spooler = dcs.filter(d => d.spooler_running)
    return { privileged, services, kerberoastable, stale, pwdNeverExp, asreproastable, tier0, noLaps, ldapUnsigned, smbUnsigned, spooler }
  }, [users, groups, computers, dcs])

  const kpis = [
    { label: 'Users', value: users.length, icon: <Users size={18} />, color: '#2563eb', bg: '#eff6ff' },
    { label: 'Privileged', value: stats.privileged.length, icon: <ShieldAlert size={18} />, color: '#dc2626', bg: '#fef2f2' },
    { label: 'Service Accts', value: stats.services.length, icon: <Key size={18} />, color: '#7c3aed', bg: '#f5f3ff' },
    { label: 'Kerberoastable', value: stats.kerberoastable.length, icon: <AlertTriangle size={18} />, color: '#dc2626', bg: '#fef2f2' },
    { label: 'Stale (>90d)', value: stats.stale.length, icon: <Clock size={18} />, color: '#d97706', bg: '#fffbeb' },
    { label: 'Pwd Never Exp', value: stats.pwdNeverExp.length, icon: <XCircle size={18} />, color: '#d97706', bg: '#fffbeb' },
    { label: 'Groups', value: groups.length, icon: <Shield size={18} />, color: '#059669', bg: '#f0fdf4' },
    { label: 'Computers', value: computers.length, icon: <Monitor size={18} />, color: '#0891b2', bg: '#ecfeff' },
  ]

  if (usersLoading) {
    return (
      <div style={{ padding: 24 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
          {[...Array(8)].map((_, i) => <div key={i} className="skeleton" style={{ height: 76 }} />)}
        </div>
      </div>
    )
  }

  return (
    <div style={{ padding: 24 }}>
      {/* KPI strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, marginBottom: 24 }}>
        {kpis.map(k => (
          <div key={k.label} className="card" style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: k.bg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: k.color, flexShrink: 0 }}>
              {k.icon}
            </div>
            <div>
              <div style={{ fontSize: 24, fontWeight: 700, color: k.color, lineHeight: 1 }}>{k.value}</div>
              <div style={{ fontSize: 11, color: '#8a9ab5', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginTop: 2 }}>{k.label}</div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Risk hotspots */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #f0f3f8', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={14} color="#dc2626" />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>Account Risk Hotspots</span>
          </div>
          <div style={{ padding: '0 0 4px' }}>
            {stats.kerberoastable.map(u => (
              <div key={u.sam_account_name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 18px', borderBottom: '1px solid #f8fafc' }}>
                <span style={{ fontSize: 13, color: '#0f1923', fontWeight: 500, fontFamily: 'monospace' }}>{u.sam_account_name}</span>
                <RiskBadge label="Kerberoastable" color="#7c3aed" bg="#f5f3ff" />
              </div>
            ))}
            {stats.asreproastable.map(u => (
              <div key={u.sam_account_name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 18px', borderBottom: '1px solid #f8fafc' }}>
                <span style={{ fontSize: 13, color: '#0f1923', fontWeight: 500, fontFamily: 'monospace' }}>{u.sam_account_name}</span>
                <RiskBadge label="ASREPRoastable" color="#dc2626" bg="#fef2f2" />
              </div>
            ))}
            {stats.privileged.filter(u => u.password_never_expires).map(u => (
              <div key={u.sam_account_name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 18px', borderBottom: '1px solid #f8fafc' }}>
                <span style={{ fontSize: 13, color: '#0f1923', fontWeight: 500, fontFamily: 'monospace' }}>{u.sam_account_name}</span>
                <RiskBadge label="Priv + Pwd∞" color="#d97706" bg="#fffbeb" />
              </div>
            ))}
            {stats.kerberoastable.length === 0 && stats.asreproastable.length === 0 && stats.privileged.filter(u => u.password_never_expires).length === 0 && (
              <div style={{ padding: '24px 18px', textAlign: 'center', color: '#8a9ab5', fontSize: 13 }}>No critical account risks</div>
            )}
          </div>
        </div>

        {/* Domain health */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #f0f3f8', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={14} color="#2563eb" />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>Domain Health</span>
          </div>
          <div style={{ padding: '4px 0' }}>
            {([
              { label: `LDAP signing required on all DCs`, ok: stats.ldapUnsigned.length === 0, detail: stats.ldapUnsigned.length > 0 ? `${stats.ldapUnsigned.length} DC(s) not enforcing` : '' },
              { label: `SMB signing required on all DCs`, ok: stats.smbUnsigned.length === 0, detail: stats.smbUnsigned.length > 0 ? `${stats.smbUnsigned.length} DC(s) not enforcing` : '' },
              { label: `Print spooler stopped on DCs`, ok: stats.spooler.length === 0, detail: stats.spooler.length > 0 ? `Running on ${stats.spooler.length} DC(s)` : '' },
              { label: `LAPS deployed on workstations`, ok: stats.noLaps.length === 0, detail: stats.noLaps.length > 0 ? `${stats.noLaps.length} device(s) without LAPS` : '' },
              { label: `No Tier-0 groups with non-privileged members`, ok: stats.tier0.every(g => g.members.length < 6), detail: stats.tier0.some(g => g.members.length >= 6) ? `${stats.tier0.filter(g => g.members.length >= 6).length} over-privileged group(s)` : '' },
            ] as { label: string; ok: boolean; detail: string }[]).map(item => (
              <div key={item.label} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '10px 18px', borderBottom: '1px solid #f8fafc' }}>
                {item.ok
                  ? <CheckCircle size={15} color="#16a34a" style={{ flexShrink: 0, marginTop: 1 }} />
                  : <AlertTriangle size={15} color="#dc2626" style={{ flexShrink: 0, marginTop: 1 }} />}
                <div>
                  <div style={{ fontSize: 13, color: '#0f1923' }}>{item.label}</div>
                  {item.detail && <div style={{ fontSize: 11, color: '#dc2626', marginTop: 1 }}>{item.detail}</div>}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Tier-0 groups */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #f0f3f8', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Shield size={14} color="#dc2626" />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>Tier-0 Privileged Groups</span>
          </div>
          <div>
            {groups.filter(g => g.privilege_level === 'Tier0').map(g => (
              <div key={g.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 18px', borderBottom: '1px solid #f8fafc' }}>
                <span style={{ fontSize: 13, color: '#0f1923', fontWeight: 500 }}>{g.name}</span>
                <span style={{ fontSize: 12, color: '#dc2626', fontWeight: 600 }}>{g.members?.length ?? 0} members</span>
              </div>
            ))}
            {groups.filter(g => g.privilege_level === 'Tier0').length === 0 && (
              <div style={{ padding: '24px 18px', textAlign: 'center', color: '#8a9ab5', fontSize: 13 }}>No Tier-0 groups found</div>
            )}
          </div>
        </div>

        {/* Recent findings by object */}
        <div className="card" style={{ overflow: 'hidden' }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #f0f3f8', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} color="#d97706" />
            <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>Stale Privileged Accounts</span>
          </div>
          <div>
            {stats.privileged.map(u => {
              const logon = bestLogon(u)
              const days = staleDays(logon)
              return (
                <div key={u.sam_account_name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 18px', borderBottom: '1px solid #f8fafc' }}>
                  <div>
                    <div style={{ fontSize: 13, color: '#0f1923', fontWeight: 500, fontFamily: 'monospace' }}>{u.sam_account_name}</div>
                    <div style={{ fontSize: 11, color: '#8a9ab5' }}>{(u.privileged_groups ?? []).join(', ')}</div>
                  </div>
                  <StaleChip dateStr={logon} />
                </div>
              )
            })}
            {stats.privileged.length === 0 && (
              <div style={{ padding: '24px 18px', textAlign: 'center', color: '#8a9ab5', fontSize: 13 }}>No privileged accounts found</div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Users pane ───────────────────────────────────────────────────────────────

function UsersPane({ data, loading, search, onSelect }: { data: ADUser[]; loading: boolean; search: string; onSelect: (u: ADUser) => void }) {
  const [filter, setFilter] = useState<'all' | 'privileged' | 'stale' | 'risk'>('all')

  const rows = useMemo(() => {
    let list = data
    if (filter === 'privileged') list = list.filter(u => u.is_privileged)
    if (filter === 'stale') list = list.filter(u => { const d = staleDays(bestLogon(u)); return d === null || d > 90 })
    if (filter === 'risk') list = list.filter(u => u.is_privileged || u.password_never_expires || u.dont_require_preauth || u.locked || u.service_principal_names?.length > 0)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(u => u.sam_account_name?.toLowerCase().includes(q) || u.display_name?.toLowerCase().includes(q) || u.department?.toLowerCase().includes(q))
    }
    return list
  }, [data, search, filter])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(10)].map((_, i) => <div key={i} className="skeleton" style={{ height: 60, marginBottom: 3 }} />)}</div>

  const filters: { id: typeof filter; label: string }[] = [
    { id: 'all', label: 'All' }, { id: 'privileged', label: 'Privileged' },
    { id: 'stale', label: 'Stale >90d' }, { id: 'risk', label: 'At Risk' },
  ]

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px', borderBottom: '1px solid #f0f3f8', background: '#fafbfc' }}>
        <Filter size={12} color="#8a9ab5" />
        {filters.map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            fontSize: 12, padding: '3px 10px', borderRadius: 6, border: '1px solid',
            borderColor: filter === f.id ? '#2563eb' : '#e4e8ef',
            background: filter === f.id ? '#eff6ff' : '#fff',
            color: filter === f.id ? '#2563eb' : '#4b5c72', cursor: 'pointer', fontWeight: filter === f.id ? 600 : 400,
          }}>{f.label}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: '#8a9ab5' }}>{rows.length} of {data.length}</span>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th style={{ width: 280 }}>Account</th>
            <th>Container</th>
            <th>Risk Flags</th>
            <th>Last Logon</th>
            <th>Pwd Last Set</th>
            <th style={{ width: 32 }}></th>
          </tr>
        </thead>
        <tbody>
          {rows.map(u => {
            const logon = bestLogon(u)
            const col = avatarColor(u.sam_account_name)
            return (
              <tr key={u.distinguished_name} onClick={() => onSelect(u)} style={{ cursor: 'pointer' }}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 8, background: col,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      color: '#fff', fontSize: 13, fontWeight: 700, flexShrink: 0,
                    }}>
                      {(u.sam_account_name?.[0] ?? '?').toUpperCase()}
                    </div>
                    <div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#0f1923', fontWeight: 600 }}>{u.sam_account_name}</div>
                      <div style={{ fontSize: 11, color: '#8a9ab5', marginTop: 1 }}>{u.display_name || u.user_principal_name || '—'}</div>
                    </div>
                  </div>
                </td>
                <td style={{ fontSize: 12, color: '#4b5c72' }}>{ouContainer(u.distinguished_name)}</td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {u.is_privileged && <RiskBadge label="PRIV" color="#dc2626" bg="#fef2f2" />}
                    {u.service_principal_names?.length > 0 && <RiskBadge label="SPN" color="#7c3aed" bg="#f5f3ff" />}
                    {u.password_never_expires && <RiskBadge label="PWD∞" color="#d97706" bg="#fffbeb" />}
                    {u.locked && <RiskBadge label="LOCKED" color="#dc2626" bg="#fef2f2" />}
                    {u.dont_require_preauth && <RiskBadge label="ASREP" color="#dc2626" bg="#fef2f2" />}
                    {!u.enabled && <RiskBadge label="DISABLED" color="#8a9ab5" bg="#f0f3f8" />}
                    {u.trusted_for_delegation && <RiskBadge label="DELEG" color="#dc2626" bg="#fef2f2" />}
                  </div>
                </td>
                <td><StaleChip dateStr={logon} /></td>
                <td style={{ fontSize: 11, color: '#8a9ab5' }}>
                  {u.pwd_last_set && !u.pwd_last_set.startsWith('0001')
                    ? formatDistanceToNow(new Date(u.pwd_last_set), { addSuffix: true })
                    : '—'}
                </td>
                <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
              </tr>
            )
          })}
          {rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No users match</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

// ─── Service Accounts pane ────────────────────────────────────────────────────

function ServiceAccountsPane({ data, loading, search, onSelect }: { data: ADUser[]; loading: boolean; search: string; onSelect: (u: ADUser) => void }) {
  const rows = useMemo(() => {
    const svc = data.filter(u => u.service_principal_names?.length > 0 || u.is_service_account || u.is_gmsa || u.is_msa)
    if (!search) return svc
    const q = search.toLowerCase()
    return svc.filter(u => u.sam_account_name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 60, marginBottom: 3 }} />)}</div>

  return (
    <div>
      <div style={{ padding: '10px 24px', background: '#fffbeb', borderBottom: '1px solid #fde68a', display: 'flex', alignItems: 'center', gap: 8 }}>
        <AlertTriangle size={13} color="#d97706" />
        <span style={{ fontSize: 12, color: '#92400e' }}>
          Accounts with Service Principal Names are Kerberoastable — any domain user can request their TGS ticket and attempt offline password cracking.
        </span>
      </div>
      <table className="data-table">
        <thead>
          <tr>
            <th>Account</th><th>Risk</th><th>Service Principal Names</th><th>Last Logon</th><th>Pwd Last Set</th><th style={{ width: 32 }}></th>
          </tr>
        </thead>
        <tbody>
          {rows.map(u => {
            const isKerberoastable = u.enabled && u.service_principal_names?.length > 0 && u.sam_account_name !== 'krbtgt'
            return (
              <tr key={u.distinguished_name} onClick={() => onSelect(u)} style={{ cursor: 'pointer' }}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 32, height: 32, borderRadius: 8, background: '#7c3aed',
                      display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                    }}>
                      <Key size={14} color="#fff" />
                    </div>
                    <div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#0f1923', fontWeight: 600 }}>{u.sam_account_name}</div>
                      <div style={{ fontSize: 11, color: '#8a9ab5' }}>{u.display_name || ouContainer(u.distinguished_name)}</div>
                    </div>
                  </div>
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {isKerberoastable && <RiskBadge label="Kerberoastable" color="#7c3aed" bg="#f5f3ff" />}
                    {u.is_privileged && <RiskBadge label="PRIV" color="#dc2626" bg="#fef2f2" />}
                    {u.password_never_expires && <RiskBadge label="PWD∞" color="#d97706" bg="#fffbeb" />}
                    {u.is_gmsa && <RiskBadge label="gMSA" color="#059669" bg="#f0fdf4" />}
                    {!u.enabled && <RiskBadge label="Disabled" color="#8a9ab5" bg="#f0f3f8" />}
                  </div>
                </td>
                <td>
                  {(u.service_principal_names ?? []).slice(0, 2).map(spn => (
                    <div key={spn} style={{ fontFamily: 'monospace', fontSize: 10, color: '#4b5c72', background: '#f0f3f8', padding: '2px 6px', borderRadius: 4, marginBottom: 2, display: 'inline-block', marginRight: 4 }}>
                      {spn.length > 50 ? spn.slice(0, 47) + '…' : spn}
                    </div>
                  ))}
                  {(u.service_principal_names?.length ?? 0) > 2 && (
                    <span style={{ fontSize: 11, color: '#8a9ab5' }}>+{u.service_principal_names.length - 2} more</span>
                  )}
                </td>
                <td><StaleChip dateStr={bestLogon(u)} /></td>
                <td style={{ fontSize: 11, color: '#8a9ab5' }}>
                  {u.pwd_last_set && !u.pwd_last_set.startsWith('0001') ? formatDistanceToNow(new Date(u.pwd_last_set), { addSuffix: true }) : '—'}
                </td>
                <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
              </tr>
            )
          })}
          {rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No service accounts detected</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

// ─── Groups pane ──────────────────────────────────────────────────────────────

function GroupsPane({ data, loading, search, onSelect }: { data: ADGroup[]; loading: boolean; search: string; onSelect: (g: ADGroup) => void }) {
  const [filter, setFilter] = useState<'all' | 'privileged' | 'tier0'>('all')

  const rows = useMemo(() => {
    let list = data
    if (filter === 'privileged') list = list.filter(g => g.is_privileged)
    if (filter === 'tier0') list = list.filter(g => g.privilege_level === 'Tier0')
    if (search) { const q = search.toLowerCase(); list = list.filter(g => g.name?.toLowerCase().includes(q)) }
    return list
  }, [data, search, filter])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(8)].map((_, i) => <div key={i} className="skeleton" style={{ height: 50, marginBottom: 3 }} />)}</div>

  const filters: { id: typeof filter; label: string }[] = [
    { id: 'all', label: 'All' }, { id: 'privileged', label: 'Privileged' }, { id: 'tier0', label: 'Tier-0 Only' },
  ]

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px', borderBottom: '1px solid #f0f3f8', background: '#fafbfc' }}>
        <Filter size={12} color="#8a9ab5" />
        {filters.map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            fontSize: 12, padding: '3px 10px', borderRadius: 6, border: '1px solid',
            borderColor: filter === f.id ? '#2563eb' : '#e4e8ef',
            background: filter === f.id ? '#eff6ff' : '#fff',
            color: filter === f.id ? '#2563eb' : '#4b5c72', cursor: 'pointer', fontWeight: filter === f.id ? 600 : 400,
          }}>{f.label}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: '#8a9ab5' }}>{rows.length} of {data.length}</span>
      </div>
      <table className="data-table">
        <thead>
          <tr><th>Group</th><th>Tier</th><th>Scope</th><th>Members</th><th>Description</th><th style={{ width: 32 }}></th></tr>
        </thead>
        <tbody>
          {rows.map(g => {
            const tier = tierColor(g.privilege_level)
            return (
              <tr key={g.distinguished_name} onClick={() => onSelect(g)} style={{ cursor: 'pointer' }}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ width: 30, height: 30, borderRadius: 7, background: g.is_privileged ? '#fef2f2' : '#f0f3f8', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                      <Shield size={14} color={g.is_privileged ? '#dc2626' : '#8a9ab5'} />
                    </div>
                    <div style={{ fontSize: 13, fontWeight: 500, color: '#0f1923' }}>{g.name}</div>
                  </div>
                </td>
                <td>
                  {g.privilege_level ? (
                    <span style={{ fontSize: 11, fontWeight: 700, color: tier.color, background: tier.bg, padding: '2px 8px', borderRadius: 4 }}>{g.privilege_level}</span>
                  ) : <span style={{ color: '#8a9ab5', fontSize: 12 }}>—</span>}
                </td>
                <td style={{ fontSize: 12, color: '#4b5c72' }}>{g.group_scope}</td>
                <td>
                  <span style={{ fontSize: 13, fontWeight: 600, color: (g.members?.length ?? 0) > 10 ? '#d97706' : '#0f1923' }}>
                    {g.members?.length ?? 0}
                  </span>
                </td>
                <td style={{ fontSize: 12, color: '#8a9ab5', maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{g.description || '—'}</td>
                <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
              </tr>
            )
          })}
          {rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No groups match</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

// ─── Computers pane ───────────────────────────────────────────────────────────

function ComputersPane({ data, loading, search, onSelect }: { data: ADComputer[]; loading: boolean; search: string; onSelect: (c: ADComputer) => void }) {
  const [filter, setFilter] = useState<'all' | 'risk' | 'nolaps'>('all')

  const rows = useMemo(() => {
    let list = data
    if (filter === 'risk') list = list.filter(c => !c.laps_enabled || c.trusted_for_delegation)
    if (filter === 'nolaps') list = list.filter(c => !c.laps_enabled)
    if (search) { const q = search.toLowerCase(); list = list.filter(c => c.name?.toLowerCase().includes(q) || c.operating_system?.toLowerCase().includes(q)) }
    return list
  }, [data, search, filter])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(8)].map((_, i) => <div key={i} className="skeleton" style={{ height: 50, marginBottom: 3 }} />)}</div>

  function osBadge(os: string): { color: string; bg: string } {
    if (!os) return { color: '#8a9ab5', bg: '#f0f3f8' }
    if (os.includes('2016') || os.includes('2019') || os.includes('2022')) return { color: '#059669', bg: '#f0fdf4' }
    if (os.includes('2012') || os.includes('2008')) return { color: '#d97706', bg: '#fffbeb' }
    if (os.includes('Windows 10') || os.includes('Windows 11')) return { color: '#2563eb', bg: '#eff6ff' }
    return { color: '#8a9ab5', bg: '#f0f3f8' }
  }

  const filters: { id: typeof filter; label: string }[] = [
    { id: 'all', label: 'All' }, { id: 'risk', label: 'At Risk' }, { id: 'nolaps', label: 'No LAPS' },
  ]

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 24px', borderBottom: '1px solid #f0f3f8', background: '#fafbfc' }}>
        <Filter size={12} color="#8a9ab5" />
        {filters.map(f => (
          <button key={f.id} onClick={() => setFilter(f.id)} style={{
            fontSize: 12, padding: '3px 10px', borderRadius: 6, border: '1px solid',
            borderColor: filter === f.id ? '#2563eb' : '#e4e8ef',
            background: filter === f.id ? '#eff6ff' : '#fff',
            color: filter === f.id ? '#2563eb' : '#4b5c72', cursor: 'pointer', fontWeight: filter === f.id ? 600 : 400,
          }}>{f.label}</button>
        ))}
        <span style={{ marginLeft: 'auto', fontSize: 12, color: '#8a9ab5' }}>{rows.length} of {data.length}</span>
      </div>
      <table className="data-table">
        <thead>
          <tr><th>Computer</th><th>Operating System</th><th>Container</th><th>LAPS</th><th>Delegation</th><th>Last Logon</th><th style={{ width: 32 }}></th></tr>
        </thead>
        <tbody>
          {rows.map(c => {
            const logon = c.last_logon_timestamp ?? c.last_logon
            const { color, bg } = osBadge(c.operating_system)
            return (
              <tr key={c.distinguished_name} onClick={() => onSelect(c)} style={{ cursor: 'pointer' }}>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Monitor size={14} color={c.is_domain_controller ? '#2563eb' : '#8a9ab5'} />
                    <div>
                      <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#0f1923', fontWeight: 600 }}>{c.name}</div>
                      {c.is_domain_controller && <div style={{ fontSize: 10, color: '#2563eb' }}>Domain Controller</div>}
                    </div>
                  </div>
                </td>
                <td>
                  <span style={{ fontSize: 11, color, background: bg, padding: '2px 8px', borderRadius: 10 }}>
                    {c.operating_system || '—'}
                  </span>
                </td>
                <td style={{ fontSize: 12, color: '#4b5c72' }}>{ouContainer(c.distinguished_name)}</td>
                <td>
                  {c.laps_enabled
                    ? <CheckCircle size={14} color="#16a34a" />
                    : <XCircle size={14} color={c.is_domain_controller ? '#8a9ab5' : '#dc2626'} />}
                </td>
                <td>
                  {c.trusted_for_delegation
                    ? <RiskBadge label="Unconstrained" color="#dc2626" bg="#fef2f2" />
                    : c.trusted_to_auth_for_delegation
                    ? <RiskBadge label="Constrained" color="#d97706" bg="#fffbeb" />
                    : <span style={{ color: '#16a34a', fontSize: 12 }}>None</span>}
                </td>
                <td><StaleChip dateStr={logon} /></td>
                <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
              </tr>
            )
          })}
          {rows.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No computers match</td></tr>}
        </tbody>
      </table>
    </div>
  )
}

// ─── DCs pane ─────────────────────────────────────────────────────────────────

function DCsPane({ data, loading, search, onSelect }: { data: ADDomainController[]; loading: boolean; search: string; onSelect: (d: ADDomainController) => void }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(d => d.name?.toLowerCase().includes(q) || d.site?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 70, marginBottom: 3 }} />)}</div>

  return (
    <table className="data-table">
      <thead>
        <tr><th>Name</th><th>OS</th><th>Roles</th><th>LDAP Signing</th><th>SMB Signing</th><th>Print Spooler</th><th>Last Logon</th><th style={{ width: 32 }}></th></tr>
      </thead>
      <tbody>
        {rows.map((d, i) => (
          <tr key={i} onClick={() => onSelect(d)} style={{ cursor: 'pointer' }}>
            <td>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Server size={14} color="#2563eb" />
                <div>
                  <div style={{ fontFamily: 'monospace', fontSize: 12, color: '#0f1923', fontWeight: 600 }}>{d.name}</div>
                  <div style={{ fontSize: 11, color: '#8a9ab5' }}>
                    {d.is_global_catalog && <span style={{ color: '#2563eb' }}>GC </span>}
                    {d.is_read_only && <span>RODC </span>}
                    {d.site && <span>{d.site}</span>}
                  </div>
                </div>
              </div>
            </td>
            <td style={{ fontSize: 12, color: '#4b5c72' }}>{d.operating_system || '—'}</td>
            <td>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {d.fsmo_roles?.map(r => (
                  <span key={r} style={{ fontSize: 10, color: '#2563eb', background: '#eff6ff', padding: '1px 6px', borderRadius: 4, whiteSpace: 'nowrap' }}>{r.split(' ')[0]}</span>
                ))}
              </div>
            </td>
            <td>{d.ldap_signing_required == null ? <span style={{ color: '#8a9ab5' }}>—</span> : d.ldap_signing_required ? <CheckCircle size={14} color="#16a34a" /> : <XCircle size={14} color="#dc2626" />}</td>
            <td>{d.smb_signing_required == null ? <span style={{ color: '#8a9ab5' }}>—</span> : d.smb_signing_required ? <CheckCircle size={14} color="#16a34a" /> : <XCircle size={14} color="#dc2626" />}</td>
            <td>{d.spooler_running == null ? <span style={{ color: '#8a9ab5' }}>—</span> : d.spooler_running ? <AlertTriangle size={14} color="#d97706" /> : <CheckCircle size={14} color="#16a34a" />}</td>
            <td><StaleChip dateStr={(d as any).last_logon} /></td>
            <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
          </tr>
        ))}
        {rows.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No domain controllers found</td></tr>}
      </tbody>
    </table>
  )
}

// ─── GPOs pane ────────────────────────────────────────────────────────────────

function GPOsPane({ data, loading, search, onSelect }: { data: ADGPO[]; loading: boolean; search: string; onSelect: (g: ADGPO) => void }) {
  const rows = useMemo(() => {
    if (!search) return data
    const q = search.toLowerCase()
    return data.filter(g => g.name?.toLowerCase().includes(q))
  }, [data, search])

  if (loading) return <div style={{ padding: '16px 24px' }}>{[...Array(4)].map((_, i) => <div key={i} className="skeleton" style={{ height: 50, marginBottom: 3 }} />)}</div>

  return (
    <table className="data-table">
      <thead>
        <tr><th>Name</th><th>Status</th><th>Linked</th><th>SYSVOL Risk</th><th>Modified</th><th style={{ width: 32 }}></th></tr>
      </thead>
      <tbody>
        {rows.map(g => (
          <tr key={g.id} onClick={() => onSelect(g)} style={{ cursor: 'pointer' }}>
            <td style={{ fontWeight: 500, color: '#0f1923' }}>{g.name}</td>
            <td>
              <span style={{ fontSize: 11, color: g.status === 'AllSettingsEnabled' ? '#16a34a' : '#d97706', background: g.status === 'AllSettingsEnabled' ? '#f0fdf4' : '#fffbeb', padding: '2px 8px', borderRadius: 10 }}>
                {g.status || '—'}
              </span>
            </td>
            <td>
              {g.is_linked
                ? <CheckCircle size={14} color="#16a34a" />
                : <span style={{ fontSize: 12, color: '#8a9ab5' }}>Unlinked</span>}
            </td>
            <td>
              {g.sysvol_writable_by_nonadmin
                ? <RiskBadge label="EXPOSED" color="#dc2626" bg="#fef2f2" />
                : <CheckCircle size={14} color="#16a34a" />}
            </td>
            <td style={{ color: '#8a9ab5', fontSize: 12 }}>
              {g.modified && !g.modified.startsWith('0001') ? formatDistanceToNow(new Date(g.modified), { addSuffix: true }) : '—'}
            </td>
            <td style={{ color: '#8a9ab5' }}><ChevronRight size={14} /></td>
          </tr>
        ))}
        {rows.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: '#8a9ab5', padding: '40px 0', fontSize: 13 }}>No GPOs match</td></tr>}
      </tbody>
    </table>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

type DrawerState =
  | { type: 'user'; obj: ADUser }
  | { type: 'group'; obj: ADGroup }
  | { type: 'computer'; obj: ADComputer }
  | { type: 'dc'; obj: ADDomainController }
  | { type: 'gpo'; obj: ADGPO }
  | null

export function Directory() {
  const [tab, setTab] = useState<Tab>('overview')
  const [search, setSearch] = useState('')
  const [drawer, setDrawer] = useState<DrawerState>(null)

  const { data: scansData } = useQuery({ queryKey: ['scans'], queryFn: () => scansApi.list().then(r => r.data) })
  const latestScan = scansData?.scans?.find(s => s.status === 'completed')
  const snapshotId = latestScan?.snapshot_id

  const { data: usersData,     isLoading: usersLoading }    = useQuery({ queryKey: ['users', snapshotId],     queryFn: () => inventoryApi.getUsers(snapshotId!).then(r => r.data),             enabled: !!snapshotId })
  const { data: groupsData,    isLoading: groupsLoading }   = useQuery({ queryKey: ['groups', snapshotId],    queryFn: () => inventoryApi.getGroups(snapshotId!).then(r => r.data),            enabled: !!snapshotId && (tab === 'groups' || tab === 'overview') })
  const { data: computersData, isLoading: computersLoading }= useQuery({ queryKey: ['computers', snapshotId],queryFn: () => inventoryApi.getComputers(snapshotId!).then(r => r.data),          enabled: !!snapshotId && (tab === 'computers' || tab === 'overview') })
  const { data: dcsData,       isLoading: dcsLoading }      = useQuery({ queryKey: ['dcs', snapshotId],       queryFn: () => inventoryApi.getDomainControllers(snapshotId!).then(r => r.data), enabled: !!snapshotId })
  const { data: gposData,      isLoading: gposLoading }     = useQuery({ queryKey: ['gpos', snapshotId],      queryFn: () => inventoryApi.getGPOs(snapshotId!).then(r => r.data),              enabled: !!snapshotId && (tab === 'gpos' || tab === 'overview') })

  const users     = usersData?.items     ?? []
  const groups    = groupsData?.items    ?? []
  const computers = computersData?.items ?? []
  const dcs       = dcsData?.items       ?? []
  const gpos      = gposData?.items      ?? []

  const serviceAccounts = users.filter(u => u.service_principal_names?.length > 0 || u.is_service_account || u.is_gmsa || u.is_msa)

  const tabs: { id: Tab; label: string; count?: number; icon: React.ReactNode }[] = [
    { id: 'overview',   label: 'Overview',            icon: <Shield size={13} /> },
    { id: 'users',      label: 'Users',               count: usersData?.total,     icon: <Users size={13} /> },
    { id: 'services',   label: 'Service Accounts',    count: serviceAccounts.length, icon: <Key size={13} /> },
    { id: 'groups',     label: 'Groups',              count: groupsData?.total,    icon: <Shield size={13} /> },
    { id: 'computers',  label: 'Computers',           count: computersData?.total, icon: <Monitor size={13} /> },
    { id: 'dcs',        label: 'Domain Controllers',  count: dcsData?.total,       icon: <Server size={13} /> },
    { id: 'gpos',       label: 'GPOs',                count: gposData?.total,      icon: <Shield size={13} /> },
  ]

  const handleTabChange = (t: Tab) => { setTab(t); setSearch(''); setDrawer(null) }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: '#f4f6f9' }}>
      {/* Header bar */}
      <div style={{ background: '#fff', borderBottom: '1px solid #e4e8ef', flexShrink: 0 }}>
        {/* Domain info strip */}
        {latestScan && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 24px 0', borderBottom: '1px solid #f0f3f8' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Server size={13} color="#2563eb" />
              <span style={{ fontSize: 13, fontWeight: 600, color: '#0f1923' }}>{latestScan.domain}</span>
              <ChevronRight size={13} color="#8a9ab5" />
              <span style={{ fontSize: 12, color: '#8a9ab5' }}>Active Directory Inventory</span>
            </div>
            <div style={{ fontSize: 11, color: '#8a9ab5', paddingBottom: 10 }}>
              Snapshot · {latestScan.completed_at ? formatDistanceToNow(new Date(latestScan.completed_at), { addSuffix: true }) : '—'}
            </div>
          </div>
        )}

        {/* Tab + search */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 24px' }}>
          <div style={{ display: 'flex', overflowX: 'auto' }}>
            {tabs.map(t => (
              <button key={t.id} onClick={() => handleTabChange(t.id)} style={{
                display: 'flex', alignItems: 'center', gap: 6, padding: '12px 14px', fontSize: 13, fontWeight: 500,
                background: 'none', border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
                borderBottom: tab === t.id ? '2px solid #2563eb' : '2px solid transparent',
                color: tab === t.id ? '#2563eb' : '#4b5c72', marginBottom: -1, transition: 'color 0.15s',
              }}>
                <span style={{ color: tab === t.id ? '#2563eb' : '#8a9ab5' }}>{t.icon}</span>
                {t.label}
                {t.count != null && (
                  <span style={{ fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 10, background: tab === t.id ? '#eff6ff' : '#f0f3f8', color: tab === t.id ? '#2563eb' : '#8a9ab5' }}>
                    {t.count}
                  </span>
                )}
              </button>
            ))}
          </div>

          {tab !== 'overview' && (
            <div style={{ position: 'relative', width: 220, flexShrink: 0 }}>
              <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#8a9ab5', pointerEvents: 'none' }} />
              <input className="field" style={{ paddingLeft: 32 }} placeholder="Search…" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
          )}
        </div>
      </div>

      {/* No snapshot */}
      {!snapshotId ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8, color: '#8a9ab5' }}>
          <Shield size={40} style={{ opacity: 0.2, color: '#2563eb' }} />
          <div style={{ fontSize: 14, fontWeight: 500, color: '#4b5c72' }}>No directory data</div>
          <div style={{ fontSize: 12 }}>Run an assessment first to populate the directory</div>
        </div>
      ) : (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {tab === 'overview'   && <OverviewPane users={users} groups={groups} computers={computers} dcs={dcs} gpos={gpos} usersLoading={usersLoading} />}
          {tab === 'users'      && <UsersPane     data={users}     loading={usersLoading}     search={search} onSelect={u => setDrawer({ type: 'user',     obj: u })} />}
          {tab === 'services'   && <ServiceAccountsPane data={users} loading={usersLoading}   search={search} onSelect={u => setDrawer({ type: 'user',     obj: u })} />}
          {tab === 'groups'     && <GroupsPane    data={groups}    loading={groupsLoading}    search={search} onSelect={g => setDrawer({ type: 'group',    obj: g })} />}
          {tab === 'computers'  && <ComputersPane data={computers} loading={computersLoading} search={search} onSelect={c => setDrawer({ type: 'computer', obj: c })} />}
          {tab === 'dcs'        && <DCsPane       data={dcs}       loading={dcsLoading}       search={search} onSelect={d => setDrawer({ type: 'dc',       obj: d })} />}
          {tab === 'gpos'       && <GPOsPane      data={gpos}      loading={gposLoading}      search={search} onSelect={g => setDrawer({ type: 'gpo',      obj: g })} />}
        </div>
      )}

      {/* Detail drawer */}
      {drawer?.type === 'user'     && <UserDrawer     user={drawer.obj}     onClose={() => setDrawer(null)} />}
      {drawer?.type === 'group'    && <GroupDrawer    group={drawer.obj}    onClose={() => setDrawer(null)} />}
      {drawer?.type === 'computer' && <ComputerDrawer computer={drawer.obj} onClose={() => setDrawer(null)} />}
      {drawer?.type === 'dc'       && <DCDrawer       dc={drawer.obj}       onClose={() => setDrawer(null)} />}
      {drawer?.type === 'gpo'      && <GPODrawer      gpo={drawer.obj}      onClose={() => setDrawer(null)} />}
    </div>
  )
}
