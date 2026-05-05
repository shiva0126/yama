import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Loader2 } from 'lucide-react'
import { authApi } from '../api'

export function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async (event: React.FormEvent) => {
    event.preventDefault()
    setLoading(true)
    setError('')
    try {
      const response = await authApi.login(username, password)
      localStorage.setItem('auth_token', response.data.token)
      navigate('/dashboard')
    } catch {
      setError('Invalid credentials')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-transparent px-4 py-10">
      <div className="mx-auto grid min-h-[calc(100vh-5rem)] max-w-6xl items-center gap-8 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="hidden xl:block">
          <div className="panel-strong p-10">
            <h1 className="text-5xl font-semibold tracking-tight text-white">Yama</h1>
            <p className="mt-4 max-w-xl text-base leading-8 text-slate-400">Active Directory security operations.</p>
          </div>
        </div>

        <div className="mx-auto w-full max-w-md">
          <div className="mb-8 text-center">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-3xl border border-sky-400/20 bg-sky-400/10">
              <img src="/yama.svg" className="h-10 w-10" alt="Yama" />
            </div>
            <h2 className="mt-5 text-3xl font-semibold text-white">Sign in to Yama</h2>
            <p className="mt-2 text-sm text-slate-400">Security Console</p>
          </div>

          <form onSubmit={handleLogin} className="panel p-6">
            <div className="space-y-4">
              <label className="block">
                <span className="label">Username</span>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin"
                  className="input mt-2"
                />
              </label>

              <label className="block">
                <span className="label">Password</span>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  className="input mt-2"
                />
              </label>
            </div>

            {error && <p className="mt-4 text-sm text-red-300">{error}</p>}

            <button type="submit" disabled={loading} className="btn-primary mt-6 w-full">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {loading ? 'Signing in' : 'Enter console'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
