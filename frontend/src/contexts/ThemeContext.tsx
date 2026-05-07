import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'

export type ContentMode  = 'light' | 'dark'
export type SidebarStyle = 'dark' | 'light' | 'ocean' | 'forest' | 'slate'
export type AccentColor  = 'blue' | 'violet' | 'emerald' | 'rose' | 'amber'
export type MapStyle     = 'dark' | 'light'

export interface ThemeConfig {
  contentMode:  ContentMode
  sidebarStyle: SidebarStyle
  accentColor:  AccentColor
  mapStyle:     MapStyle
}

const DEFAULTS: ThemeConfig = {
  contentMode:  'light',
  sidebarStyle: 'dark',
  accentColor:  'blue',
  mapStyle:     'dark',
}

/* ── Accent palettes ───────────────────────────────────── */
export const ACCENT_PALETTES: Record<AccentColor, { accent: string; dark: string; light: string; border: string }> = {
  blue:    { accent: '#2563eb', dark: '#1d4ed8', light: '#eff6ff', border: '#bfdbfe' },
  violet:  { accent: '#7c3aed', dark: '#6d28d9', light: '#f5f3ff', border: '#ddd6fe' },
  emerald: { accent: '#059669', dark: '#047857', light: '#ecfdf5', border: '#a7f3d0' },
  rose:    { accent: '#e11d48', dark: '#be123c', light: '#fff1f2', border: '#fecdd3' },
  amber:   { accent: '#d97706', dark: '#b45309', light: '#fffbeb', border: '#fde68a' },
}

/* ── Sidebar palettes ──────────────────────────────────── */
export const SIDEBAR_PALETTES: Record<SidebarStyle, {
  bg: string; border: string; txt: string; act: string; dim: string; logo: string
}> = {
  dark:   { bg: '#0d1826', border: 'rgba(255,255,255,0.05)', txt: '#5a7a96', act: '#e2ecf6', dim: '#2a4a66', logo: '#2a4a66' },
  light:  { bg: '#ffffff', border: '#e4e8ef',                txt: '#4b5c72', act: '#0f1923', dim: '#8a9ab5', logo: '#8a9ab5' },
  ocean:  { bg: '#0b3d5e', border: 'rgba(255,255,255,0.07)', txt: '#5ba8c9', act: '#e0f7ff', dim: '#1e5c7a', logo: '#1e5c7a' },
  forest: { bg: '#0f2d1f', border: 'rgba(255,255,255,0.07)', txt: '#5a9070', act: '#d4f0e0', dim: '#1c4a32', logo: '#1c4a32' },
  slate:  { bg: '#1e293b', border: 'rgba(255,255,255,0.06)', txt: '#64748b', act: '#e2e8f0', dim: '#334155', logo: '#334155' },
}

/* ── Apply theme to DOM ────────────────────────────────── */
function applyTheme(cfg: ThemeConfig) {
  const root = document.documentElement
  const sb   = SIDEBAR_PALETTES[cfg.sidebarStyle]
  const ac   = ACCENT_PALETTES[cfg.accentColor]

  // Sidebar vars
  root.style.setProperty('--sb-bg',     sb.bg)
  root.style.setProperty('--sb-border', sb.border)
  root.style.setProperty('--sb-txt',    sb.txt)
  root.style.setProperty('--sb-act',    sb.act)
  root.style.setProperty('--sb-dim',    sb.dim)

  // Accent vars
  root.style.setProperty('--accent',    ac.accent)
  root.style.setProperty('--accent-dk', ac.dark)
  root.style.setProperty('--accent-lt', ac.light)
  root.style.setProperty('--accent-bd', ac.border)

  // Content mode
  if (cfg.contentMode === 'dark') {
    root.style.setProperty('--bg',      '#111827')
    root.style.setProperty('--bg-card', '#1f2937')
    root.style.setProperty('--bg-raised','#374151')
    root.style.setProperty('--bg-hover','#2d3748')
    root.style.setProperty('--border',  '#374151')
    root.style.setProperty('--border-md','#4b5563')
    root.style.setProperty('--txt-pri', '#f9fafb')
    root.style.setProperty('--txt-sec', '#d1d5db')
    root.style.setProperty('--txt-dim', '#9ca3af')
    root.setAttribute('data-theme', 'dark')
  } else {
    root.style.setProperty('--bg',       '#f4f6f9')
    root.style.setProperty('--bg-card',  '#ffffff')
    root.style.setProperty('--bg-raised','#f9fafb')
    root.style.setProperty('--bg-hover', '#f0f3f8')
    root.style.setProperty('--border',   '#e4e8ef')
    root.style.setProperty('--border-md','#d1d9e6')
    root.style.setProperty('--txt-pri',  '#0f1923')
    root.style.setProperty('--txt-sec',  '#4b5c72')
    root.style.setProperty('--txt-dim',  '#8a9ab5')
    root.setAttribute('data-theme', 'light')
  }

  root.setAttribute('data-map', cfg.mapStyle)
}

/* ── Context ───────────────────────────────────────────── */
interface ThemeCtx {
  theme:    ThemeConfig
  setTheme: (patch: Partial<ThemeConfig>) => void
  reset:    () => void
}

const Ctx = createContext<ThemeCtx>({
  theme:    DEFAULTS,
  setTheme: () => {},
  reset:    () => {},
})

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeConfig>(() => {
    try {
      const saved = localStorage.getItem('yama_theme')
      return saved ? { ...DEFAULTS, ...JSON.parse(saved) } : DEFAULTS
    } catch { return DEFAULTS }
  })

  useEffect(() => { applyTheme(theme) }, [theme])

  const setTheme = (patch: Partial<ThemeConfig>) => {
    setThemeState(prev => {
      const next = { ...prev, ...patch }
      localStorage.setItem('yama_theme', JSON.stringify(next))
      return next
    })
  }

  const reset = () => {
    localStorage.removeItem('yama_theme')
    setThemeState(DEFAULTS)
  }

  return <Ctx.Provider value={{ theme, setTheme, reset }}>{children}</Ctx.Provider>
}

export const useTheme = () => useContext(Ctx)
