import { create } from 'zustand'
import type { ScanJob, WSMessage, ScanProgressPayload } from '../types'

const WS_URL = import.meta.env.VITE_WS_URL || `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`

interface ScanStore {
  activeScan: ScanJob | null
  scanProgress: Record<string, number>  // scanId -> progress %
  scanMessages: Record<string, string>  // scanId -> status message
  wsConnected: boolean

  setActiveScan: (scan: ScanJob | null) => void
  updateProgress: (scanId: string, progress: number, message?: string) => void
  connectWebSocket: () => void
  disconnectWebSocket: () => void
}

let ws: WebSocket | null = null

export const useScanStore = create<ScanStore>((set, get) => ({
  activeScan: null,
  scanProgress: {},
  scanMessages: {},
  wsConnected: false,

  setActiveScan: (scan) => set({ activeScan: scan }),

  updateProgress: (scanId, progress, message) =>
    set((state) => ({
      scanProgress: { ...state.scanProgress, [scanId]: progress },
      scanMessages: message ? { ...state.scanMessages, [scanId]: message } : state.scanMessages,
    })),

  connectWebSocket: () => {
    if (ws && ws.readyState === WebSocket.OPEN) return

    const token = localStorage.getItem('auth_token')
    ws = new WebSocket(`${WS_URL}/ws?token=${token}`)

    ws.onopen = () => {
      set({ wsConnected: true })
      console.log('[WS] Connected')
    }

    ws.onclose = () => {
      set({ wsConnected: false })
      console.log('[WS] Disconnected')
      // Reconnect after 3s
      setTimeout(() => get().connectWebSocket(), 3000)
    }

    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        switch (msg.type) {
          case 'scan_progress': {
            const payload = msg.payload as ScanProgressPayload
            get().updateProgress(payload.scan_id, payload.progress, payload.message)

            // Update active scan if it matches
            const active = get().activeScan
            if (active && active.id === payload.scan_id) {
              set({ activeScan: { ...active, progress: payload.progress } })
            }
            break
          }
          case 'scan_complete': {
            const payload = msg.payload as ScanJob
            const active = get().activeScan
            if (active && active.id === payload.id) {
              set({ activeScan: payload })
            }
            break
          }
        }
      } catch (err) {
        console.error('[WS] Failed to parse message', err)
      }
    }

    ws.onerror = (err) => {
      console.error('[WS] Error', err)
    }
  },

  disconnectWebSocket: () => {
    if (ws) {
      ws.close()
      ws = null
    }
  },
}))
