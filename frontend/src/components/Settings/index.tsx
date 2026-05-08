import { Check, RotateCcw } from 'lucide-react'
import {
  useTheme,
  ACCENT_PALETTES, SIDEBAR_PALETTES,
  type AccentColor, type ContentMode, type MapStyle, type SidebarStyle,
} from '../../contexts/ThemeContext'

export function Settings() {
  const { theme, setTheme, reset } = useTheme()

  return (
    <div className="page-content" style={{ maxWidth: 720 }}>
      <div style={{ marginBottom: 4 }}>
        <div className="page-title">Settings</div>
        <div style={{ fontSize: 12, color: 'var(--txt-dim)', marginTop: 4 }}>
          Customise the look and feel of Yama. Changes are saved automatically.
        </div>
      </div>

      {/* ── Content theme ─────────────────────────────── */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <SectionHead title="Content theme" sub="Controls the main content area background and card colours" />
        <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
          {(['light', 'dark'] as ContentMode[]).map(mode => (
            <ThemeOption
              key={mode}
              active={theme.contentMode === mode}
              onClick={() => setTheme({ contentMode: mode })}
            >
              <div style={{
                height: 64, borderRadius: 7, overflow: 'hidden', marginBottom: 10,
                border: '1px solid var(--border)',
                background: mode === 'light' ? '#f4f6f9' : '#111827',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              }}>
                <div style={{ width: 28, height: 40, borderRadius: 4, background: mode === 'light' ? '#ffffff' : '#1f2937', border: '1px solid', borderColor: mode === 'light' ? '#e4e8ef' : '#374151' }} />
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 4, paddingRight: 8 }}>
                  {[1,2,3].map(i => <div key={i} style={{ height: 5, borderRadius: 3, background: mode === 'light' ? '#e4e8ef' : '#374151' }} />)}
                </div>
              </div>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--txt-pri)', textTransform: 'capitalize' }}>{mode}</span>
            </ThemeOption>
          ))}
        </div>
      </div>

      {/* ── Sidebar style ─────────────────────────────── */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <SectionHead title="Sidebar style" sub="Choose the navigation sidebar colour scheme" />
        <div style={{ display: 'flex', gap: 10, marginTop: 16, flexWrap: 'wrap' }}>
          {(Object.keys(SIDEBAR_PALETTES) as SidebarStyle[]).map(style => {
            const p = SIDEBAR_PALETTES[style]
            return (
              <ThemeOption
                key={style}
                active={theme.sidebarStyle === style}
                onClick={() => setTheme({ sidebarStyle: style })}
                compact
              >
                <div style={{
                  width: 52, height: 52, borderRadius: 8, marginBottom: 6,
                  background: p.bg, border: `1px solid ${p.border === 'rgba(255,255,255,0.05)' ? 'rgba(255,255,255,0.08)' : p.border}`,
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4,
                }}>
                  {[1,2,3].map(i => <div key={i} style={{ width: 28, height: 4, borderRadius: 2, background: p.txt, opacity: 0.5 }} />)}
                </div>
                <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--txt-sec)', textTransform: 'capitalize' }}>{style}</span>
              </ThemeOption>
            )
          })}
        </div>
      </div>

      {/* ── Accent colour ─────────────────────────────── */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <SectionHead title="Accent colour" sub="Used for buttons, active states, and highlights throughout the app" />
        <div style={{ display: 'flex', gap: 10, marginTop: 16, flexWrap: 'wrap' }}>
          {(Object.keys(ACCENT_PALETTES) as AccentColor[]).map(color => {
            const p = ACCENT_PALETTES[color]
            const active = theme.accentColor === color
            return (
              <button
                key={color}
                onClick={() => setTheme({ accentColor: color })}
                style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '8px 14px', borderRadius: 8, cursor: 'pointer',
                  border: `1px solid ${active ? p.accent : 'var(--border)'}`,
                  background: active ? p.light : 'var(--bg-card)',
                  transition: 'all 0.15s',
                }}
              >
                <div style={{ width: 16, height: 16, borderRadius: '50%', background: p.accent, flexShrink: 0 }} />
                <span style={{ fontSize: 12, fontWeight: 600, color: active ? p.accent : 'var(--txt-sec)', textTransform: 'capitalize' }}>
                  {color}
                </span>
                {active && <Check size={13} color={p.accent} />}
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Map style ─────────────────────────────────── */}
      <div className="card" style={{ padding: '20px 24px' }}>
        <SectionHead title="Topology map background" sub="Controls the AD network topology map on Overview and Topology pages" />
        <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
          {(['dark', 'light'] as MapStyle[]).map(style => (
            <ThemeOption
              key={style}
              active={theme.mapStyle === style}
              onClick={() => setTheme({ mapStyle: style })}
            >
              <div style={{
                height: 64, borderRadius: 7, marginBottom: 10,
                border: '1px solid var(--border)',
                background: style === 'dark' ? '#07101a' : '#f8fafc',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              }}>
                {[
                  { bg: style === 'dark' ? 'rgba(37,99,235,0.3)' : '#dbeafe', size: 28 },
                  { bg: style === 'dark' ? 'rgba(255,255,255,0.1)'  : '#e2e8f0', size: 20 },
                  { bg: style === 'dark' ? 'rgba(22,163,74,0.25)'  : '#dcfce7', size: 16 },
                ].map((n, i) => (
                  <div key={i} style={{
                    width: n.size, height: n.size, borderRadius: 5,
                    background: n.bg,
                    border: `1px solid ${style === 'dark' ? 'rgba(255,255,255,0.1)' : '#cbd5e1'}`,
                  }} />
                ))}
              </div>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--txt-pri)', textTransform: 'capitalize' }}>
                {style}
              </span>
            </ThemeOption>
          ))}
        </div>
      </div>

      {/* ── Reset ─────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button className="btn btn-ghost" onClick={reset} style={{ gap: 7 }}>
          <RotateCcw size={13} />
          Reset to defaults
        </button>
      </div>
    </div>
  )
}

function SectionHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--txt-pri)', marginBottom: 3 }}>{title}</div>
      <div style={{ fontSize: 12, color: 'var(--txt-dim)' }}>{sub}</div>
    </div>
  )
}

function ThemeOption({ children, active, onClick, compact }: {
  children: React.ReactNode; active: boolean; onClick: () => void; compact?: boolean
}) {
  return (
    <button
      onClick={onClick}
      style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        padding: compact ? '10px 12px' : '12px 16px',
        borderRadius: 10, cursor: 'pointer',
        border: `2px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
        background: active ? 'var(--accent-lt)' : 'var(--bg-card)',
        transition: 'all 0.15s',
        position: 'relative', minWidth: compact ? 80 : 140,
      }}
    >
      {active && (
        <div style={{
          position: 'absolute', top: -8, right: -8,
          width: 20, height: 20, borderRadius: '50%',
          background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}>
          <Check size={11} color="#fff" />
        </div>
      )}
      {children}
    </button>
  )
}
