import { Wifi, WifiOff } from 'lucide-react'
import { useScanStore } from '../../stores/scanStore'
import clsx from 'clsx'

export function Header() {
  const { wsConnected, activeScan } = useScanStore()

  return (
    <header className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        {activeScan && activeScan.status === 'running' && (
          <div className="flex items-center gap-2 bg-violet-600/20 border border-violet-500/30 rounded-lg px-3 py-1.5">
            <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
            <span className="text-violet-400 text-sm font-medium">
              Scan running — {activeScan.progress}%
            </span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-3">
        {/* WebSocket status */}
        <div className={clsx('flex items-center gap-1.5 text-xs', wsConnected ? 'text-emerald-400' : 'text-gray-500')}>
          {wsConnected ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
          <span>{wsConnected ? 'Live' : 'Disconnected'}</span>
        </div>
      </div>
    </header>
  )
}
