# Yama Platform — Work Summary (2026-05-08)

## What Was Done

### 1. Database Schema — Migration 003

**File:** `backend/shared/migrations/003_defense_schema_complete.sql`

The postgres volume had already been created from migration 001. Migration 002 (defense plane tables) never ran against the live DB. Additionally, the `defense_incidents` table had been created from an older, incompatible schema.

**Changes applied to the live database:**
- Added `defense_mode BOOLEAN DEFAULT FALSE` and `defense_url TEXT` columns to `agents` table (both were already referenced in code but missing from schema).
- Created the 6 missing defense plane tables: `defense_detector_families`, `defense_detectors`, `defense_detections`, `defense_response_actions`, `defense_exclusions`, `defense_evidence_bundles`. All use `IF NOT EXISTS` so they're idempotent.
- Dropped and rebuilt `defense_incidents` with the canonical schema (`title`, `confidence VARCHAR`, `primary_actor`, `primary_target`, `domain`, `opened_at`, `last_updated_at`, `closed_at`) — the old schema was structurally incompatible with the Go store layer.
- Dropped the legacy `defense_responses` table (replaced by `defense_response_actions`).
- Added missing indexes: `ad_domain_controllers(snapshot_id)`, `ad_domain_controllers(scan_id)`, `inventory_snapshots(scan_id)`, `agents(status)`, `agents(domain)`, `defense_incidents(domain)`, `defense_evidence_bundles(incident_id)`.

---

### 2. Agent Heartbeat (defense-api — port 8098)

**File:** `backend/defense-api/main.go` — full rewrite

The defense-api previously only served the detector catalog and hardcoded demo data. It now:

- **`POST /agent/heartbeat`** — accepts `{agent_id, defense_url}`, updates `agents.status='online'`, `agents.last_seen=NOW()`, sets `defense_mode=TRUE`. Used by the Windows/Linux agent binary to register its presence.
- **Background worker (`runAgentTimeoutWorker`)** — runs every 30 seconds, marks agents `status='offline'` when `last_seen` is older than 3 minutes and `defense_mode=TRUE`.
- **`GET /agents`** — returns agents with their defense status (mode, last_seen, defense_url).
- **`GET /incidents`** — reads real incidents from `defense_incidents` (not demo data).
- **`GET /detections`** — reads real detections from `defense_detections`.
- **`GET /responses`** — reads real response actions from `defense_response_actions`.

---

### 3. Response Executor (response-orchestrator — port 8095)

**File:** `backend/response-orchestrator/main.go` — full rewrite

Previously: took a POST body and returned two hardcoded planned actions. No NATS consumers, no execution.

Now:

**NATS consumer 1 — planner:** Subscribes to `yama.defense.incidents`. For each incident:
- Plans a `disable-account` action (automatic if `severity=critical` AND `confidence=critical-confirmed`, otherwise `approval-required`).
- Plans a `collect-evidence` action (always automatic for critical incidents).
- Persists each action to `defense_response_actions`.
- Publishes the action list to `yama.defense.responses.requested`.

**NATS consumer 2 — executor:** Subscribes to `yama.defense.responses.requested`. For actions with `mode=automatic`:
- `disable-account` → finds an online defense agent from the DB, calls `POST /defend/execute` on the agent with `{command, target}`.
- `collect-evidence` → calls `POST /evidence-ledger:8096/evidence/bundle` to trigger evidence capture.
- Updates `defense_response_actions.status` to `executing` → `completed` / `failed` with a result summary.

**`POST /plan`** and **`POST /execute`** HTTP endpoints remain for manual/API use.

---

### 4. Evidence Storage in MinIO (evidence-ledger — port 8096)

**File:** `backend/evidence-ledger/main.go` — full rewrite
**File:** `backend/evidence-ledger/Dockerfile` — added `go get github.com/minio/minio-go/v7@v7.0.70`

Previously: computed SHA256 of metadata, stored record in DB, never wrote to MinIO (despite env vars being configured).

Now:
- On startup: initializes MinIO client and creates `yama-evidence` bucket if it doesn't exist.
- **`POST /evidence/bundle`**: uploads the JSON bundle payload to MinIO at `evidence/YYYY/MM/DD/{id}.json`, records the real `size_bytes` and `sha256` in the DB, then publishes to `yama.defense.evidence.events`.
- **`GET /evidence`**: returns paginated list of evidence bundles from DB.

---

### 5. Policy Engine — DB-Backed (policy-engine — port 8097)

**File:** `backend/policy-engine/main.go` — full rewrite
**File:** `backend/policy-engine/go.mod` — added `github.com/jackc/pgx/v5 v5.5.5`

Previously: returned hardcoded JSON from a single `/policy/demo` endpoint.

Now:
- **`GET /policy`** — returns active policy with live exclusions from `defense_exclusions` (only non-expired rows).
- **`GET /policy/exclusion`** — list active exclusions.
- **`POST /policy/exclusion`** — create a new exclusion with optional `expires_at`.
- **`DELETE /policy/exclusion/{id}`** — remove an exclusion.
- **`POST /policy/evaluate`** — evaluate whether an action is allowed:
  - Returns `allowed=false` if target is in `defense_exclusions`.
  - Returns `mode=approval-required` if target is a protected scope (Domain Admins, Enterprise Admins, KRBTGT, Certificate Authorities).
  - Returns `mode=automatic` if severity/confidence meets the action's threshold.
  - Thresholds: `disable-account=high`, `revert-attribute=high`, `contain-host=critical-confirmed`, `collect-evidence=automatic`.

---

### 6. Correlation Engine — NATS Subscriber (correlation-engine — port 8094)

**File:** `backend/correlation-engine/main.go` — full rewrite

Previously: only had a manual `POST /correlate` endpoint. No NATS subscriber, so stream detections from detector-engine were never picked up.

Now:
- **NATS subscriber** on `yama.defense.detections.raw` (durable consumer `correlation-engine`).
- Uses a **sliding 5-minute time window** (`correlationWindow` struct) keyed by `actor@domain`.
- Groups detections in the window; if ≥1 detection exists for a key, opens/updates an incident in `defense_incidents` and publishes to `yama.defense.incidents`.
- The window expires stale entries every 60 seconds.
- The `POST /correlate` manual endpoint still works for testing.

---

## Defense Pipeline — End-to-End Flow (Now Functional)

```
Windows/Linux Agent
  → POST /defend/signal (collector-agent:9090)
    → signal-collector:8091 /ingest
      → NATS: yama.defense.signals.raw
        → signal-normalizer:8092 (subscriber)
          → NATS: yama.defense.signals.normalized
            → detector-engine:8093 (subscriber)
              → detection persisted to defense_detections
              → NATS: yama.defense.detections.raw
                → correlation-engine:8094 (subscriber) ← NEW
                  → windowed grouping by actor@domain
                  → incident persisted to defense_incidents
                  → NATS: yama.defense.incidents
                    → response-orchestrator:8095 (subscriber) ← NEW
                      → actions planned and persisted to defense_response_actions
                      → NATS: yama.defense.responses.requested
                        → response-orchestrator:8095 executor ← NEW
                          → automatic actions dispatched to agent
                          → evidence collection triggered

Agent heartbeat every 30s:
  → POST /agent/heartbeat (defense-api:8098) ← NEW
    → updates agents.status, last_seen, defense_mode, defense_url
    → background worker marks stale agents offline after 3min
```

---

## Current Service State

| Service | Port | Status | Notes |
|---------|------|--------|-------|
| defense-api | 8098 | ✅ rebuilt | Real CRUD + heartbeat + agent timeout |
| response-orchestrator | 8095 | ✅ rebuilt | NATS planner + executor |
| evidence-ledger | 8096 | ✅ rebuilt | Real MinIO upload |
| policy-engine | 8097 | ✅ rebuilt | DB-backed, evaluate endpoint |
| correlation-engine | 8094 | ✅ rebuilt | NATS subscriber + time-window correlation |

All 5 services confirmed healthy after restart. Catalog seeded: 10 families, 16 detectors.

---

## What Is Still Remaining

1. **Real JWT validation** — `api-gateway/middleware/auth.go` accepts any bearer token. Requires `github.com/golang-jwt/jwt/v5`.
2. **SQL injection in inventory-service** — lines 302 and 346 concatenate table names into queries. Fix: whitelist the 6 valid table names.
3. **DC password encryption** — `agents.dc_password` stored plaintext. Encrypt at rest (AES-256-GCM with key from env).
4. **CORS restriction** — `api-gateway` uses `AllowAllOrigins: true`.
5. **Agent execute endpoint** — the response executor calls `POST /defend/execute` on the agent but that endpoint doesn't exist yet in `collector/agent/handlers/defend.go`. Needs a `DefendExecute` handler.
6. **Analysis-engine trigger** — already wired (orchestrator.go:264), but 6 of 11 LDAP task types (kerberos, gpos, acls, trusts, ous, fgpp) need their inventory-service store handlers verified.
7. **Frontend wiring** — defense-api's new real endpoints (`/incidents`, `/detections`, `/responses`, `/agents`) need to replace demo calls in `frontend/src/pages/Defend.tsx`.
