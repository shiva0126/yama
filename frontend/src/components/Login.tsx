import { useState } from 'react'
import { Shield } from 'lucide-react'
import { authApi } from '../api'

export function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState('')
  const [loading, setLoading]   = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true); setError('')
    try {
      const res = await authApi.login(username, password)
      localStorage.setItem('auth_token', res.data.token)
      window.location.href = '/'
    } catch { setError('Invalid username or password') }
    finally   { setLoading(false) }
  }

  return (
    <div style={{ minHeight:'100vh', background:'#f4f6f9', display:'flex', alignItems:'center', justifyContent:'center' }}>
      <div style={{ width:360 }}>
        {/* Brand */}
        <div style={{ textAlign:'center', marginBottom:28 }}>
          <div style={{
            width:48, height:48, borderRadius:12, margin:'0 auto 14px',
            background:'#eff6ff', border:'1px solid #bfdbfe',
            display:'flex', alignItems:'center', justifyContent:'center',
          }}>
            <Shield size={22} color="#2563eb" />
          </div>
          <div style={{ fontSize:22, fontWeight:700, color:'#0f1923', letterSpacing:'-0.02em' }}>Yama</div>
          <div style={{ fontSize:12, color:'#8a9ab5', marginTop:3, fontWeight:500 }}>
            Active Directory Security Platform
          </div>
        </div>

        {/* Card */}
        <div className="card" style={{ padding:24 }}>
          <div style={{ fontSize:15, fontWeight:600, color:'#0f1923', marginBottom:20 }}>Sign in to your account</div>
          <form onSubmit={submit} style={{ display:'flex', flexDirection:'column', gap:14 }}>
            <div>
              <label style={{ display:'block', fontSize:12, fontWeight:600, color:'#4b5c72', marginBottom:6 }}>Username</label>
              <input className="field" value={username} onChange={e => setUsername(e.target.value)} placeholder="admin" autoFocus autoComplete="username" />
            </div>
            <div>
              <label style={{ display:'block', fontSize:12, fontWeight:600, color:'#4b5c72', marginBottom:6 }}>Password</label>
              <input className="field" type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" />
            </div>
            {error && (
              <div style={{ fontSize:12, color:'#b91c1c', background:'#fef2f2', border:'1px solid #fecaca', borderRadius:6, padding:'8px 12px' }}>
                {error}
              </div>
            )}
            <button type="submit" className="btn btn-primary" disabled={loading || !username || !password}
              style={{ width:'100%', justifyContent:'center', padding:'9px 0', fontSize:14, marginTop:4 }}>
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>

        <div style={{ textAlign:'center', marginTop:18, fontSize:11, color:'#c4cdd8' }}>
          Yama AD Security Platform · Confidential
        </div>
      </div>
    </div>
  )
}
