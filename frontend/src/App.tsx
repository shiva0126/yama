import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Layout } from './components/layout/Layout'
import { Dashboard } from './components/Dashboard'
import { Scanner } from './components/Scanner'
import { Inventory } from './components/Inventory'
import { Findings } from './components/Findings'
import { Topology } from './components/Topology'
import { Reports } from './components/Reports'
import { Login } from './components/Login'
import { useScanStore } from './stores/scanStore'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 2,
    },
  },
})

function AppRoutes() {
  const { connectWebSocket } = useScanStore()

  useEffect(() => {
    const token = localStorage.getItem('auth_token')
    if (token) {
      connectWebSocket()
    }
  }, [connectWebSocket])

  const isAuthenticated = !!localStorage.getItem('auth_token')

  if (!isAuthenticated) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="scanner" element={<Scanner />} />
        <Route path="inventory" element={<Inventory />} />
        <Route path="findings" element={<Findings />} />
        <Route path="topology" element={<Topology />} />
        <Route path="reports" element={<Reports />} />
      </Route>
      <Route path="/login" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  )
}
