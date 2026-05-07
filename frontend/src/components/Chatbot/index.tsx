import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Bot, ChevronDown, Loader2, Send, X } from 'lucide-react'
import { agentsApi, defenseApi, findingsApi, inventoryApi, scansApi } from '../../api'
import { formatDistanceToNow } from 'date-fns'

interface ChatMessage {
  id: string
  role: 'user' | 'bot'
  text: string
  rows?: { cols: string[]; data: string[][] }
  time: Date
}

const uid = () => Math.random().toString(36).slice(2, 9)

/* ── Intent handlers ─────────────────────────────────────── */
type BotResponse = { text: string; rows?: { cols: string[]; data: string[][] } }

async function handleQuery(q: string): Promise<BotResponse> {
  const lq = q.toLowerCase()

  /* Help */
  if (/^(hi|hello|hey|help|what can you|capabilities|commands)/.test(lq)) {
    return {
      text: `Hi! I'm the Yama assistant. I can answer questions about your environment. Try asking:\n\n• **"What's my security score?"**\n• **"Show critical findings"**\n• **"How many agents are online?"**\n• **"Any active incidents?"**\n• **"Last assessment?"**\n• **"List domain controllers"**\n• **"How many users?"**\n• **"Show high findings"**\n• **"Detector count"**\n• **"Agent status"**`,
    }
  }

  /* Security score */
  if (/score|posture|health|how (secure|safe)/.test(lq)) {
    const { data } = await scansApi.list()
    const latest = data.scans?.find(s => s.status === 'completed')
    if (!latest) return { text: 'No completed assessments found. Run a scan first.' }
    const s = latest.overall_score ?? 0
    const level = s >= 70 ? '✅ Healthy' : s >= 40 ? '⚠️ At risk' : '🔴 Critical'
    return {
      text: `**Security score: ${s}/100** — ${level}\n\nDomain: ${latest.domain}\nAssessed: ${formatDistanceToNow(new Date(latest.completed_at!), { addSuffix: true })}\n\nFindings: ${(latest as any).critical_count ?? 0} critical, ${(latest as any).high_count ?? 0} high, ${(latest as any).medium_count ?? 0} medium`,
    }
  }

  /* Agents */
  if (/agent|collector|sensor/.test(lq)) {
    const { data } = await agentsApi.list()
    const agents = data.agents ?? []
    const online = agents.filter(a => a.status === 'online')
    const offline = agents.filter(a => a.status !== 'online')
    if (agents.length === 0) return { text: 'No agents registered. Deploy an agent from the Agents page.' }
    return {
      text: `**${online.length}/${agents.length} agents online**`,
      rows: {
        cols: ['Name', 'Domain', 'IP', 'Status'],
        data: agents.map(a => [
          a.name ?? a.hostname ?? '—',
          a.domain ?? '—',
          a.ip_address ?? '—',
          a.status === 'online' ? '🟢 online' : '🔴 ' + a.status,
        ]),
      },
    }
  }

  /* Incidents */
  if (/incident|threat|attack|breach|compromise/.test(lq)) {
    const { data } = await defenseApi.incidents()
    const incidents = data ?? []
    const open = incidents.filter((i: any) => i.status === 'open')
    if (incidents.length === 0) return { text: '✅ No incidents recorded.' }
    return {
      text: `**${open.length} open incident${open.length !== 1 ? 's' : ''}** out of ${incidents.length} total`,
      rows: {
        cols: ['Title', 'Severity', 'Actor → Target', 'Status'],
        data: incidents.slice(0, 8).map((i: any) => [
          i.title ?? '—',
          i.severity ?? '—',
          `${i.primary_actor ?? '?'} → ${i.primary_target ?? '?'}`,
          i.status,
        ]),
      },
    }
  }

  /* Critical / High / Medium / Low findings */
  const sevMatch = lq.match(/\b(critical|high|medium|low|info)\b/)
  if (sevMatch || /finding|exposure|vuln|risk|issue/.test(lq)) {
    const { data } = await findingsApi.list()
    const all = data.findings ?? []
    const sev = sevMatch?.[1] as string | undefined
    const filtered = sev ? all.filter((f: any) => f.severity === sev) : all
    if (filtered.length === 0) return { text: sev ? `No ${sev} findings. ✅` : 'No findings yet. Run an assessment.' }
    const counts: Record<string, number> = {}
    all.forEach((f: any) => { counts[f.severity] = (counts[f.severity] ?? 0) + 1 })
    const summary = Object.entries(counts).map(([s, c]) => `${c} ${s}`).join(', ')
    return {
      text: sev
        ? `**${filtered.length} ${sev} finding${filtered.length !== 1 ? 's' : ''}**`
        : `**${all.length} total findings:** ${summary}`,
      rows: {
        cols: ['Name', 'Severity', 'Category'],
        data: filtered.slice(0, 10).map((f: any) => [
          f.name ?? '—',
          f.severity ?? '—',
          f.category ?? '—',
        ]),
      },
    }
  }

  /* Detectors / defense catalog */
  if (/detector|catalog|defense|detection|rule/.test(lq)) {
    const { data } = await defenseApi.summary()
    return {
      text: `**Defense catalog:** ${data.detector_count ?? 0} detectors across ${data.family_count ?? 0} attack families\n${data.critical_count ?? 0} critical-severity detectors · ${data.demo_ready_count ?? 0} demo-ready`,
    }
  }

  /* Domain controllers */
  if (/domain controller|dc\b|\.dc\./.test(lq)) {
    const { data: scansData } = await scansApi.list()
    const snap = scansData.scans?.find(s => s.status === 'completed')?.snapshot_id
    if (!snap) return { text: 'No assessment data available. Run a scan first.' }
    const { data } = await inventoryApi.getDomainControllers(snap)
    const dcs = data.items ?? []
    if (dcs.length === 0) return { text: 'No domain controllers found in the latest snapshot.' }
    return {
      text: `**${dcs.length} domain controller${dcs.length !== 1 ? 's' : ''} found**`,
      rows: {
        cols: ['Name', 'Site', 'Global Catalog', 'FSMO roles'],
        data: dcs.slice(0, 10).map((d: any) => [
          d.name ?? '—',
          d.site ?? '—',
          d.is_global_catalog ? '✅ Yes' : 'No',
          d.fsmo_roles?.join(', ') || '—',
        ]),
      },
    }
  }

  /* Users */
  if (/\buser|identity|account|principal/.test(lq)) {
    const { data: scansData } = await scansApi.list()
    const snap = scansData.scans?.find(s => s.status === 'completed')?.snapshot_id
    if (!snap) return { text: 'No assessment data available. Run a scan first.' }
    const { data } = await inventoryApi.getUsers(snap)
    const users = data.items ?? []
    const priv = users.filter((u: any) => u.is_privileged).length
    const noPwd = users.filter((u: any) => u.password_never_expires).length
    return {
      text: `**${data.total ?? users.length} users** in directory\n\n${priv} privileged · ${noPwd} with password never expires`,
      rows: users.length > 0 ? {
        cols: ['Username', 'Display name', 'Enabled', 'Privileged'],
        data: users.slice(0, 8).map((u: any) => [
          u.sam_account_name ?? '—',
          u.display_name ?? '—',
          u.enabled ? '✅' : '❌',
          u.is_privileged ? '⚠️ Yes' : 'No',
        ]),
      } : undefined,
    }
  }

  /* Computers */
  if (/computer|machine|workstation|server|endpoint/.test(lq)) {
    const { data: scansData } = await scansApi.list()
    const snap = scansData.scans?.find(s => s.status === 'completed')?.snapshot_id
    if (!snap) return { text: 'No assessment data. Run a scan first.' }
    const { data } = await inventoryApi.getComputers(snap)
    const comps = data.items ?? []
    return {
      text: `**${data.total ?? comps.length} computers** in directory`,
      rows: comps.length > 0 ? {
        cols: ['Name', 'OS', 'Enabled', 'LAPS'],
        data: comps.slice(0, 8).map((c: any) => [
          c.name ?? '—',
          c.operating_system ?? '—',
          c.enabled ? '✅' : '❌',
          c.laps_enabled ? '✅' : '❌',
        ]),
      } : undefined,
    }
  }

  /* Last scan / assessment */
  if (/last|recent|latest|assessment|scan/.test(lq)) {
    const { data } = await scansApi.list()
    const scans = data.scans ?? []
    if (scans.length === 0) return { text: 'No scans found. Go to Assessment to run your first scan.' }
    return {
      text: `**${scans.length} scan${scans.length !== 1 ? 's' : ''} in history**`,
      rows: {
        cols: ['Domain', 'Status', 'Score', 'Date'],
        data: scans.slice(0, 6).map(s => [
          s.domain ?? '—',
          s.status,
          s.overall_score != null ? `${s.overall_score}/100` : '—',
          s.completed_at ? formatDistanceToNow(new Date(s.completed_at), { addSuffix: true }) : '—',
        ]),
      },
    }
  }

  /* What is Yama */
  if (/what is yama|about yama|yama|application|app/.test(lq)) {
    return {
      text: `**Yama** is an Active Directory Security Assessment & Defense platform.\n\n**Phase 1 — Assessment:** Scan your AD environment, collect topology and object data, and identify security exposures across Kerberos, ACLs, ADCS, GPOs, and more.\n\n**Phase 2 — Defend:** Real-time threat detection with ${38} detectors across attack families including credential theft, lateral movement, privilege escalation, and persistence.\n\nUse the sidebar to navigate between pages.`,
    }
  }

  return {
    text: `I'm not sure about that. Try asking:\n\n• Security score · Findings · Agents · Incidents\n• Domain controllers · Users · Computers\n• Last scan · Detector count`,
  }
}

/* ── Format bot text (bold + newlines) ───────────────────── */
function BotText({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*)/)
  return (
    <span>
      {parts.map((p, i) =>
        p.startsWith('**') && p.endsWith('**')
          ? <strong key={i}>{p.slice(2, -2)}</strong>
          : p.split('\n').map((line, j) => (
              <span key={j}>{line}{j < p.split('\n').length - 1 ? <br /> : null}</span>
            ))
      )}
    </span>
  )
}

/* ── Main chatbot component ──────────────────────────────── */
export function Chatbot() {
  const [open, setOpen]       = useState(false)
  const [input, setInput]     = useState('')
  const [loading, setLoading] = useState(false)
  const [msgs, setMsgs]       = useState<ChatMessage[]>([{
    id: uid(), role: 'bot', time: new Date(),
    text: `Hi! I'm your Yama assistant. Ask me anything about your AD environment — agents, findings, incidents, users, scores, and more.`,
  }])
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [msgs])

  const send = async (e?: FormEvent) => {
    e?.preventDefault()
    const q = input.trim()
    if (!q || loading) return
    setInput('')

    const userMsg: ChatMessage = { id: uid(), role: 'user', text: q, time: new Date() }
    setMsgs(p => [...p, userMsg])
    setLoading(true)

    try {
      const res = await handleQuery(q)
      setMsgs(p => [...p, { id: uid(), role: 'bot', text: res.text, rows: res.rows, time: new Date() }])
    } catch (err: any) {
      setMsgs(p => [...p, {
        id: uid(), role: 'bot', time: new Date(),
        text: `Error fetching data: ${err?.message ?? 'unknown error'}. Make sure you're authenticated and services are running.`,
      }])
    } finally {
      setLoading(false)
    }
  }

  const SUGGESTIONS = ['Security score?', 'Show critical findings', 'Agent status', 'Active incidents']

  return (
    <>
      {/* ── Floating button ─────────────────────────── */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          position: 'fixed', bottom: 24, right: 24, zIndex: 200,
          width: 52, height: 52, borderRadius: '50%',
          background: 'var(--accent)',
          border: 'none', cursor: 'pointer',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 4px 20px rgba(0,0,0,0.2)',
          transition: 'transform 0.2s, box-shadow 0.2s',
        }}
        onMouseEnter={e => { e.currentTarget.style.transform = 'scale(1.08)'; e.currentTarget.style.boxShadow = '0 6px 24px rgba(0,0,0,0.28)' }}
        onMouseLeave={e => { e.currentTarget.style.transform = 'scale(1)';    e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,0,0,0.2)' }}
        title="Yama assistant"
      >
        {open ? <ChevronDown size={22} color="#fff" /> : <Bot size={22} color="#fff" />}
      </button>

      {/* ── Chat panel ──────────────────────────────── */}
      {open && (
        <div style={{
          position: 'fixed', bottom: 88, right: 24, zIndex: 200,
          width: 400, height: 560,
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 16, boxShadow: '0 24px 60px rgba(0,0,0,0.18)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          {/* Header */}
          <div style={{
            padding: '14px 18px', background: 'var(--accent)',
            display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'rgba(255,255,255,0.2)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Bot size={18} color="#fff" />
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>Yama Assistant</div>
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.7)' }}>Ask anything about your environment</div>
            </div>
            <button onClick={() => setOpen(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'rgba(255,255,255,0.8)', padding: 4, display: 'flex' }}>
              <X size={16} />
            </button>
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '16px 14px', display: 'flex', flexDirection: 'column', gap: 12 }}>
            {msgs.map(msg => (
              <div key={msg.id} style={{
                display: 'flex',
                flexDirection: msg.role === 'user' ? 'row-reverse' : 'row',
                gap: 8, alignItems: 'flex-start',
              }}>
                {msg.role === 'bot' && (
                  <div style={{
                    width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                    background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    <Bot size={14} color="#fff" />
                  </div>
                )}
                <div style={{ maxWidth: '85%', display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{
                    padding: '10px 13px', borderRadius: msg.role === 'user' ? '14px 14px 4px 14px' : '14px 14px 14px 4px',
                    background: msg.role === 'user' ? 'var(--accent)' : 'var(--bg-raised)',
                    border: msg.role === 'user' ? 'none' : '1px solid var(--border)',
                    fontSize: 12.5, lineHeight: 1.55,
                    color: msg.role === 'user' ? '#fff' : 'var(--txt-pri)',
                  }}>
                    <BotText text={msg.text} />
                  </div>
                  {/* Data table */}
                  {msg.rows && (
                    <div style={{
                      borderRadius: 8, overflow: 'hidden',
                      border: '1px solid var(--border)',
                      fontSize: 11,
                    }}>
                      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${msg.rows.cols.length}, 1fr)`, background: 'var(--bg-raised)', borderBottom: '1px solid var(--border)' }}>
                        {msg.rows.cols.map((c, i) => (
                          <div key={i} style={{ padding: '5px 8px', fontWeight: 700, color: 'var(--txt-dim)', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{c}</div>
                        ))}
                      </div>
                      {msg.rows.data.map((row, ri) => (
                        <div key={ri} style={{ display: 'grid', gridTemplateColumns: `repeat(${msg.rows!.cols.length}, 1fr)`, borderBottom: ri < msg.rows!.data.length - 1 ? '1px solid var(--border)' : 'none' }}>
                          {row.map((cell, ci) => (
                            <div key={ci} style={{ padding: '5px 8px', color: 'var(--txt-sec)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</div>
                          ))}
                        </div>
                      ))}
                    </div>
                  )}
                  <div style={{ fontSize: 10, color: 'var(--txt-dim)', alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
                    {msg.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </div>
                </div>
              </div>
            ))}
            {loading && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <div style={{ width: 26, height: 26, borderRadius: '50%', background: 'var(--accent)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <Bot size={14} color="#fff" />
                </div>
                <div style={{ padding: '10px 13px', background: 'var(--bg-raised)', border: '1px solid var(--border)', borderRadius: '14px 14px 14px 4px', display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Loader2 size={13} color="var(--txt-dim)" style={{ animation: 'spin 1s linear infinite' }} />
                  <span style={{ fontSize: 12, color: 'var(--txt-dim)' }}>Fetching data…</span>
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Suggestions */}
          {msgs.length <= 2 && (
            <div style={{ padding: '8px 14px', display: 'flex', gap: 6, flexWrap: 'wrap', borderTop: '1px solid var(--border)', flexShrink: 0 }}>
              {SUGGESTIONS.map(s => (
                <button key={s} onClick={() => { setInput(s); setTimeout(() => send(), 0) }} style={{
                  fontSize: 11, padding: '4px 10px', borderRadius: 20, cursor: 'pointer',
                  border: '1px solid var(--border)', background: 'var(--bg-raised)',
                  color: 'var(--txt-sec)', transition: 'all 0.12s',
                }}>
                  {s}
                </button>
              ))}
            </div>
          )}

          {/* Input */}
          <form onSubmit={send} style={{
            padding: '10px 14px', display: 'flex', gap: 8, alignItems: 'center',
            borderTop: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-card)',
          }}>
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Ask about agents, findings, incidents…"
              className="field"
              style={{ flex: 1, fontSize: 12 }}
              autoFocus
            />
            <button type="submit" disabled={!input.trim() || loading} style={{
              width: 34, height: 34, borderRadius: 8, border: 'none',
              background: input.trim() ? 'var(--accent)' : 'var(--border)',
              color: '#fff', cursor: input.trim() ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              transition: 'background 0.15s', flexShrink: 0,
            }}>
              <Send size={14} />
            </button>
          </form>
        </div>
      )}
    </>
  )
}
