import { useMemo, useState, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import {
  ArrowRight,
  CircleAlert,
  Flame,
  Package,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import clsx from 'clsx'
import { defenseApi } from '../../api'
import type { DefenseIncident, DefenseDetection } from '../../types'

const tone: Record<string, string> = {
  critical: 'border-red-200 bg-red-50 text-red-700',
  high: 'border-orange-200 bg-orange-50 text-orange-700',
  medium: 'border-amber-200 bg-amber-50 text-amber-700',
  low: 'border-sky-200 bg-sky-50 text-sky-700',
  info: 'border-slate-200 bg-slate-50 text-slate-700',
}

export function DefenseOverview() {
  const { data: summary } = useQuery({
    queryKey: ['defense-summary'],
    queryFn: () => defenseApi.summary().then((r) => r.data),
    refetchInterval: 20_000,
  })
  const { data: incidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then((r) => r.data),
    refetchInterval: 20_000,
  })
  const { data: detections } = useQuery({
    queryKey: ['defense-detections'],
    queryFn: () => defenseApi.detections().then((r) => r.data),
    refetchInterval: 20_000,
  })

  const criticalIncident = incidents?.[0]
  const topDetector = detections?.[0]

  return (
    <div className="space-y-6">
      <section className="panel-strong overflow-hidden">
        <div className="grid gap-6 border-b border-slate-200/80 px-6 py-6 xl:grid-cols-[1.2fr_0.8fr]">
          <div>
            <p className="label">Defense plane</p>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight text-slate-950">Active Directory attack defense console</h2>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-600">
              Technique-driven detections, incident correlation, response planning, and evidence preservation in one operator surface.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <Kpi label="Detectors" value={summary?.detector_count ?? 0} icon={<Flame className="h-4 w-4" />} />
            <Kpi label="Demo ready" value={summary?.demo_ready_count ?? 0} icon={<ShieldCheck className="h-4 w-4" />} />
            <Kpi label="Critical" value={summary?.critical_count ?? 0} icon={<ShieldAlert className="h-4 w-4" />} />
            <Kpi label="Incidents" value={incidents?.length ?? 0} icon={<CircleAlert className="h-4 w-4" />} />
          </div>
        </div>

        <div className="grid gap-4 px-6 py-6 md:grid-cols-3">
          <StatCard label="Active campaign" value={criticalIncident?.title ?? 'No active incident'} detail={criticalIncident?.metadata.story ?? 'Awaiting defense telemetry'} />
          <StatCard label="Latest detector" value={topDetector?.title ?? '—'} detail={topDetector ? `${topDetector.actor} -> ${topDetector.target}` : 'No detections yet'} />
          <StatCard label="Coverage family" value={Object.entries(summary?.by_family ?? {})[0]?.[0] ?? '—'} detail="Most populated detector family in the seed catalog" />
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="panel overflow-hidden">
          <div className="border-b border-slate-200/80 px-6 py-4">
            <p className="label">Incident queue</p>
            <h3 className="mt-1 text-lg font-semibold text-slate-950">Correlated attack chains</h3>
          </div>
          <div className="divide-y divide-slate-200/80">
            {(incidents ?? []).map((incident) => (
              <div key={incident.id} className="px-6 py-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-950">{incident.title}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      {incident.primary_actor} · {incident.primary_target} · {formatDistanceToNow(new Date(incident.opened_at), { addSuffix: true })}
                    </p>
                  </div>
                  <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', tone[incident.severity])}>
                    {incident.severity}
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {incident.response_actions.map((action) => (
                    <span key={action} className="chip">
                      {action}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid gap-6">
          <div className="panel p-6">
            <p className="label">Coverage posture</p>
            <div className="mt-4 grid gap-3">
              <Bar label="Critical detectors" value={summary?.critical_count ?? 0} total={summary?.detector_count ?? 0} />
              <Bar label="High detectors" value={summary?.high_count ?? 0} total={summary?.detector_count ?? 0} />
              <Bar label="Demo ready" value={summary?.demo_ready_count ?? 0} total={summary?.detector_count ?? 0} />
            </div>
          </div>

          <div className="panel p-6">
            <p className="label">Primary response posture</p>
            <h3 className="mt-2 text-lg font-semibold text-slate-950">Approval-gated containment</h3>
            <p className="mt-2 text-sm leading-7 text-slate-600">
              The first defense release stays operator-safe: review first, approve second, auto-contain only after high-confidence chains.
            </p>
          </div>
        </div>
      </section>
    </div>
  )
}

export function DefenseCatalog() {
  const { data: summary } = useQuery({
    queryKey: ['defense-summary'],
    queryFn: () => defenseApi.summary().then((r) => r.data),
  })
  const { data: catalog } = useQuery({
    queryKey: ['defense-catalog'],
    queryFn: () => defenseApi.catalog().then((r) => r.data),
  })

  const families = Object.entries(summary?.by_family ?? {}).sort((a, b) => b[1] - a[1])
  const responseProfiles = Object.entries(summary?.response_profiles ?? {}).sort((a, b) => b[1] - a[1])
  const detectors = (catalog?.detectors ?? []).slice(0, 8)

  return (
    <div className="space-y-6">
      <section className="panel-strong p-6">
        <p className="label">Attack catalog</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">Technique coverage map</h2>
        <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-600">
          The backend now exposes a normalized detector catalog. This view turns that into an operator-friendly coverage summary.
        </p>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="panel p-6">
          <p className="label">Family spread</p>
          <div className="mt-4 space-y-3">
            {families.map(([family, count]) => (
              <div key={family}>
                <div className="flex items-center justify-between text-sm">
                  <span className="font-medium text-slate-950">{family}</span>
                  <span className="text-slate-500">{count}</span>
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
                  <div className="h-full rounded-full bg-gradient-to-r from-sky-500 to-cyan-400" style={{ width: `${Math.max(12, (count / (summary?.detector_count || 1)) * 100)}%` }} />
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6">
            <p className="label">Response profiles</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {responseProfiles.map(([profile, count]) => (
                <span key={profile} className="chip">
                  {profile} · {count}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="panel overflow-hidden">
          <div className="border-b border-slate-200/80 px-6 py-4">
            <p className="label">Seed detectors</p>
            <h3 className="mt-1 text-lg font-semibold text-slate-950">First production-priority coverage</h3>
          </div>
          <div className="divide-y divide-slate-200/80">
            {detectors.map((detector: any) => (
              <div key={detector.id} className="px-6 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-950">{detector.name}</p>
                    <p className="mt-1 text-xs text-slate-500">{detector.family_id} · {detector.type}</p>
                  </div>
                  <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', tone[detector.detector_priority || 'info'])}>
                    {detector.detector_priority}
                  </span>
                </div>
                <p className="mt-2 text-sm leading-6 text-slate-600">{detector.description}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {(detector.mitre_ids ?? []).map((id: string) => (
                    <span key={id} className="chip">{id}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}

export function DefenseIncidents() {
  const qc = useQueryClient()
  const { data: incidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then((r) => r.data),
    refetchInterval: 15_000,
  })
  const { data: detections } = useQuery({
    queryKey: ['defense-detections'],
    queryFn: () => defenseApi.detections().then((r) => r.data),
  })

  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = incidents?.find((item) => item.id === selectedId) ?? incidents?.[0] ?? null
  const selectedDetections = useMemo(
    () => (detections ?? []).filter((d) => selected?.detection_ids.includes(d.id)),
    [detections, selected]
  )

  const plan = useMutation({
    mutationFn: (incident: DefenseIncident) => defenseApi.plan(incident),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['defense-incidents'] }),
  })

  return (
    <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
      <section className="panel overflow-hidden">
        <div className="border-b border-slate-200/80 px-6 py-4">
          <p className="label">Incidents</p>
          <h2 className="mt-1 text-lg font-semibold text-slate-950">Defense queue</h2>
        </div>
        <div className="divide-y divide-slate-200/80">
          {(incidents ?? []).map((incident) => (
            <button
              key={incident.id}
              onClick={() => setSelectedId(incident.id)}
              className={clsx('w-full px-6 py-4 text-left transition hover:bg-slate-50', selected?.id === incident.id && 'bg-slate-50')}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-950">{incident.title}</p>
                  <p className="mt-1 text-xs text-slate-500">{incident.primary_actor} · {incident.primary_target}</p>
                </div>
                <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', tone[incident.severity])}>
                  {incident.status}
                </span>
              </div>
            </button>
          ))}
        </div>
      </section>

      <aside className="grid gap-6">
        {selected && (
          <section className="panel p-6">
            <p className="label">Selected incident</p>
            <h3 className="mt-2 text-xl font-semibold text-slate-950">{selected.title}</h3>
            <p className="mt-2 text-sm text-slate-600">
              {selected.primary_actor} on {selected.primary_target} · {selected.confidence}
            </p>

            <div className="mt-5 grid gap-3 sm:grid-cols-2">
              <MiniStat label="Opened" value={formatDistanceToNow(new Date(selected.opened_at), { addSuffix: true })} />
              <MiniStat label="Detections" value={selected.detection_ids.length} />
              <MiniStat label="Actions" value={selected.response_actions.length} />
              <MiniStat label="State" value={selected.status} />
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {selected.response_actions.map((action) => (
                <span key={action} className="chip">{action}</span>
              ))}
            </div>

            <button onClick={() => plan.mutate(selected)} className="btn-primary mt-6">
              Plan response
              <ArrowRight className="h-4 w-4" />
            </button>
          </section>
        )}

        <section className="panel p-6">
          <p className="label">Supporting detections</p>
          <div className="mt-4 space-y-3">
            {selectedDetections.map((detection) => (
              <div key={detection.id} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-semibold text-slate-950">{detection.title}</p>
                  <span className={clsx('rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.14em]', tone[detection.severity])}>
                    {detection.severity}
                  </span>
                </div>
                <p className="mt-2 text-xs text-slate-500">
                  {detection.actor} · {detection.source_host} · {detection.detector_id}
                </p>
              </div>
            ))}
          </div>
        </section>
      </aside>
    </div>
  )
}

export function DefenseResponse() {
  const { data: incidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then((r) => r.data),
  })

  const playbooks = [
    { title: 'Contain account', detail: 'Disable or quarantine a suspicious actor account after review.' },
    { title: 'Revert attribute', detail: 'Undo changes to shadow credentials, delegation, or SPN writes.' },
    { title: 'Disable template', detail: 'Cut off vulnerable AD CS issuance paths immediately.' },
    { title: 'Approve rollback', detail: 'Restore before/after state from preserved evidence bundles.' },
  ]

  return (
    <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
      <section className="panel p-6">
        <p className="label">Response policy</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">Containment first, disruption second</h2>
        <p className="mt-3 text-sm leading-7 text-slate-600">
          Response is approval-gated. The first release stays focused on planning, evidence, and safe rollback.
        </p>

        <div className="mt-6 space-y-3">
          {playbooks.map((item) => (
            <div key={item.title} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <p className="text-sm font-semibold text-slate-950">{item.title}</p>
              <p className="mt-1 text-sm text-slate-600">{item.detail}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-slate-200/80 px-6 py-4">
          <p className="label">Planned actions</p>
          <h3 className="mt-1 text-lg font-semibold text-slate-950">Incident-based response suggestions</h3>
        </div>
        <div className="divide-y divide-slate-200/80">
          {(incidents ?? []).map((incident) => (
            <div key={incident.id} className="px-6 py-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold text-slate-950">{incident.title}</p>
                  <p className="mt-1 text-xs text-slate-500">{incident.primary_actor} · {incident.primary_target}</p>
                </div>
                <span className="chip uppercase">{incident.confidence}</span>
              </div>
              <div className="mt-3 flex flex-wrap gap-2">
                {incident.response_actions.map((action) => (
                  <span key={action} className="chip">{action}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}

export function DefenseEvidence() {
  const qc = useQueryClient()
  const { data: incidents } = useQuery({
    queryKey: ['defense-incidents'],
    queryFn: () => defenseApi.incidents().then((r) => r.data),
  })
  const { data: summary } = useQuery({
    queryKey: ['defense-summary'],
    queryFn: () => defenseApi.summary().then((r) => r.data),
  })
  const [selectedIncidentId, setSelectedIncidentId] = useState(incidents?.[0]?.id ?? '')

  const createBundle = useMutation({
    mutationFn: () =>
      defenseApi
        .evidence({
          incident_id: selectedIncidentId || incidents?.[0]?.id || 'inc-demo-001',
          metadata: {
            detector: 'CRED-001',
            artifact: 'security-event-4662',
            family_count: String(summary?.family_count ?? 0),
          },
        })
        .then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['defense-incidents'] }),
  })

  return (
    <div className="grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
      <section className="panel p-6">
        <p className="label">Evidence</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">Forensic bundle builder</h2>
        <p className="mt-3 text-sm leading-7 text-slate-600">
          The evidence ledger stores bundle metadata now, and the backend can later attach MinIO objects and hashes to the same incident.
        </p>

        <div className="mt-5 space-y-3">
          <label className="label">Target incident</label>
          <select value={selectedIncidentId} onChange={(e) => setSelectedIncidentId(e.target.value)} className="select">
            {(incidents ?? []).map((incident) => (
              <option key={incident.id} value={incident.id}>
                {incident.title}
              </option>
            ))}
          </select>
        </div>

        <button onClick={() => createBundle.mutate()} className="btn-primary mt-5">
          <Package className="h-4 w-4" />
          Create evidence bundle
        </button>
      </section>

      <section className="panel overflow-hidden">
        <div className="border-b border-slate-200/80 px-6 py-4">
          <p className="label">Bundle story</p>
          <h3 className="mt-1 text-lg font-semibold text-slate-950">What gets preserved</h3>
        </div>
        <div className="grid gap-4 p-6 md:grid-cols-2">
          <InfoBox title="Immutable refs" detail="Event references, detector IDs, and response decisions." />
          <InfoBox title="Artifact hashes" detail="SHA tracking for bundle integrity and chain-of-custody." />
          <InfoBox title="Rollback state" detail="Before/after evidence for reversible containment." />
          <InfoBox title="Storage target" detail="MinIO-backed bundles once phase 2 lands." />
        </div>
      </section>
    </div>
  )
}

export function DefensePolicy() {
  const { data } = useQuery({
    queryKey: ['defense-policy'],
    queryFn: () => defenseApi.policy().then((r) => r.data),
    refetchInterval: 20_000,
  })

  return (
    <div className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
      <section className="panel p-6">
        <p className="label">Policy</p>
        <h2 className="mt-2 text-2xl font-semibold text-slate-950">Protected scopes and enforcement</h2>
        <p className="mt-3 text-sm leading-7 text-slate-600">
          The policy plane keeps the response engine conservative. Break-glass and production-critical objects stay protected.
        </p>

        <div className="mt-5 space-y-3">
          <InfoBox title="Mode" detail={data?.mode ?? 'production-safe'} />
          <InfoBox title="Protected scopes" detail={(data?.protected_scopes ?? []).join(', ')} />
          <InfoBox title="Exclusions" detail={(data?.exclusions ?? []).join(', ')} />
        </div>
      </section>

      <section className="panel p-6">
        <p className="label">Thresholds</p>
        <div className="mt-4 grid gap-3">
          {Object.entries(data?.approval_thresholds ?? {}).map(([action, threshold]) => (
            <div key={action} className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <div className="flex items-center justify-between gap-3">
                <p className="text-sm font-semibold text-slate-950">{action}</p>
                <span className="chip uppercase">{threshold}</span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}

function Kpi({ label, value, icon }: { label: string; value: number | string; icon: ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white/90 px-4 py-4 shadow-sm">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-slate-700">
          {icon}
        </div>
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
          <p className="mt-1 text-lg font-semibold text-slate-950">{value}</p>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-2 text-sm font-semibold text-slate-950">{value}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{detail}</p>
    </div>
  )
}

function Bar({ label, value, total }: { label: string; value: number; total: number }) {
  const width = total ? Math.max(8, (value / total) * 100) : 0
  return (
    <div>
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-slate-950">{label}</span>
        <span className="text-slate-500">
          {value}/{total}
        </span>
      </div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
        <div className="h-full rounded-full bg-gradient-to-r from-sky-500 to-cyan-400" style={{ width: `${width}%` }} />
      </div>
    </div>
  )
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{label}</p>
      <p className="mt-1 text-sm font-semibold text-slate-950">{value}</p>
    </div>
  )
}

function InfoBox({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
      <p className="text-sm font-semibold text-slate-950">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-600">{detail || '—'}</p>
    </div>
  )
}
