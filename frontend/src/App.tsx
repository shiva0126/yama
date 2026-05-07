import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from './contexts/ThemeContext'
import { Layout } from './components/layout/Layout'
import { Login } from './components/Login'
import { Overview } from './components/Overview'
import { Assess } from './components/Assess'
import { Directory } from './components/Directory'
import { Defend } from './components/Defend'
import { Reports } from './components/Reports'
import { Agents } from './components/Agents'
import { Settings } from './components/Settings'
import { Chatbot } from './components/Chatbot'
import { useScanStore } from './stores/scanStore'

const qc = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, retry: 1, refetchOnWindowFocus: false } },
})

function AppRoutes() {
  const { connectWebSocket } = useScanStore()
  const isAuth = !!localStorage.getItem('auth_token')

  useEffect(() => {
    if (isAuth) connectWebSocket()
  }, [isAuth, connectWebSocket])

  if (!isAuth) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="assess"    element={<Assess />} />
          <Route path="directory" element={<Directory />} />
          <Route path="defend"    element={<Defend />} />
          <Route path="reports"   element={<Reports />} />
          <Route path="agents"    element={<Agents />} />
          <Route path="settings"  element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
        <Route path="/login" element={<Navigate to="/" replace />} />
      </Routes>
      <Chatbot />
    </>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <ThemeProvider>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  )
}
