import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { Download, FileText, Loader2, Plus, X } from 'lucide-react'
import { reportsApi, scansApi } from '../../api'

export function Reports() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [scanId, setScanId] = useState('')
  const [format, setFormat] = useState<'html' | 'pdf' | 'json'>('html')

  const { data: reportsData, isLoading } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.list().then(r => r.data),
    refetchInterval: 15_000,
  })
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list().then(r => r.data),
  })

  const generate = useMutation({
    mutationFn: () => reportsApi.generate(scanId, format),
    onSuccess: () => {
      setShowModal(false)
      setScanId('')
      qc.invalidateQueries({ queryKey: ['reports'] })
    },
  })

  const completedScans = scansData?.scans?.filter(s => s.status === 'completed') ?? []
  const reports = reportsData?.reports ?? []

  return (
    <div className="page-content">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div className="page-title">Reports</div>
          <div style={{ fontSize: 12, color: '#8a9ab5', marginTop: 3 }}>
            {reports.length} report{reports.length !== 1 ? 's' : ''} generated
          </div>
        </div>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>
          <Plus size={14} /> Generate report
        </button>
      </div>

      <div className="card" style={{ overflow: 'hidden', padding: 0 }}>
        {isLoading ? (
          <div style={{ padding: 20 }}>
            {[...Array(5)].map((_, i) => <div key={i} className="skeleton" style={{ height: 44, marginBottom: 4 }} />)}
          </div>
        ) : reports.length === 0 ? (
          <div style={{ padding: '60px 0', textAlign: 'center' }}>
            <FileText size={36} style={{ opacity: 0.2, margin: '0 auto 12px', display: 'block', color: '#2563eb' }} />
            <div style={{ fontSize: 14, fontWeight: 500, color: '#4b5c72', marginBottom: 4 }}>No reports yet</div>
            <div style={{ fontSize: 12, color: '#8a9ab5' }}>Generate a report from a completed assessment</div>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Domain</th><th>Format</th><th>Score</th><th>Generated</th>
                <th style={{ width: 60 }}></th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r: any) => (
                <tr key={r.id}>
                  <td style={{ fontWeight: 500, color: '#0f1923' }}>{r.domain}</td>
                  <td>
                    <span style={{
                      fontFamily: 'monospace', fontSize: 11, fontWeight: 600,
                      textTransform: 'uppercase', color: '#4b5c72',
                      background: '#f0f3f8', padding: '2px 7px', borderRadius: 4,
                    }}>
                      {r.format}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontWeight: 700,
                      color: r.score >= 70 ? '#16a34a' : r.score >= 40 ? '#d97706' : '#dc2626',
                    }}>
                      {r.score ?? '—'}
                    </span>
                  </td>
                  <td style={{ fontSize: 12, color: '#8a9ab5' }}>
                    {r.generated_at ? formatDistanceToNow(new Date(r.generated_at), { addSuffix: true }) : '—'}
                  </td>
                  <td>
                    <a href={`/api/v1/reports/${r.id}/download`} target="_blank" rel="noreferrer">
                      <button className="btn btn-ghost" style={{ padding: '5px 8px' }}>
                        <Download size={13} />
                      </button>
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Generate modal */}
      {showModal && (
        <div style={{
          position: 'fixed', inset: 0,
          background: 'rgba(15,25,35,0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50,
          backdropFilter: 'blur(2px)',
        }} onClick={() => setShowModal(false)}>
          <div style={{
            background: '#ffffff',
            border: '1px solid #e4e8ef',
            borderRadius: 14,
            padding: 28,
            width: 420,
            boxShadow: '0 20px 60px rgba(15,25,35,0.18)',
          }} onClick={e => e.stopPropagation()}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 22 }}>
              <div style={{ fontSize: 16, fontWeight: 600, color: '#0f1923' }}>Generate report</div>
              <button onClick={() => setShowModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#8a9ab5', padding: 4 }}>
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', display: 'block', marginBottom: 7, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Assessment
                </label>
                <select className="field" value={scanId} onChange={e => setScanId(e.target.value)}>
                  <option value="">Select a completed scan…</option>
                  {completedScans.map(s => (
                    <option key={s.id} value={s.id}>{s.domain} — score {s.overall_score ?? 'N/A'}</option>
                  ))}
                </select>
              </div>
              <div>
                <label style={{ fontSize: 11, fontWeight: 600, color: '#4b5c72', display: 'block', marginBottom: 7, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  Format
                </label>
                <div style={{ display: 'flex', gap: 6 }}>
                  {(['html', 'pdf', 'json'] as const).map(f => (
                    <button key={f} onClick={() => setFormat(f)} style={{
                      flex: 1, padding: '10px', borderRadius: 8,
                      border: `1px solid ${format === f ? '#2563eb' : '#e4e8ef'}`,
                      background: format === f ? '#eff6ff' : '#f9fafb',
                      color: format === f ? '#2563eb' : '#4b5c72',
                      fontSize: 12, fontWeight: 700, cursor: 'pointer',
                      textTransform: 'uppercase', letterSpacing: '0.06em',
                      transition: 'all 0.15s',
                    }}>
                      {f}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10, marginTop: 24, justifyContent: 'flex-end' }}>
              <button className="btn btn-ghost" onClick={() => setShowModal(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                disabled={!scanId || generate.isPending}
                onClick={() => generate.mutate()}
              >
                {generate.isPending && <Loader2 size={13} style={{ animation: 'spin 1s linear infinite' }} />}
                Generate
              </button>
            </div>

            {generate.isError && (
              <div style={{ marginTop: 14, fontSize: 12, color: '#dc2626', background: '#fef2f2', padding: '8px 12px', borderRadius: 7, border: '1px solid #fecaca' }}>
                Generation failed — verify the scan has a snapshot available
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
