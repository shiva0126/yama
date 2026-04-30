# Yama — Active Directory Assessment Platform

Yama is an enterprise-grade Active Directory security assessment platform. It automates discovery of AD vulnerabilities, collects a full inventory of domain objects, scores your environment against **46+ security indicators**, and generates actionable remediation reports — all through a real-time web dashboard.

> **No Windows agent. No port changes. No domain admin required.**
> Yama uses direct LDAP (port 389) with any read-only domain user account.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Development Setup](#development-setup)
- [Running a Scan](#running-a-scan)
- [Security Indicators](#security-indicators)
- [Dashboard & UI](#dashboard--ui)
- [Reports](#reports)
- [Configuration Reference](#configuration-reference)
- [Makefile Reference](#makefile-reference)
- [Project Structure](#project-structure)

---

## Architecture Overview

```
Browser
  └── Frontend (React + TypeScript)  :80
        └── API Gateway              :9080  (JWT auth, WebSocket hub)
              ├── Scan Orchestrator  :8081  (LDAP collection engine, workflow)
              ├── Inventory Service  :8082  (AD object snapshots, PostgreSQL)
              ├── Analysis Engine    :8083  (46+ security indicator checks)
              └── Report Service     :8084  (HTML / PDF / JSON generation)

Target domain (read-only user sufficient)
  └── LDAP  :389   ← only connection needed
```

**Stack:**
- Go 1.22 microservices (Gin), PostgreSQL 16, Redis 7
- React 18, Vite, TailwindCSS, Recharts, ReactFlow
- Docker Compose — single `make up` deploys everything

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker & Docker Compose | 24+ |
| Go (dev only) | 1.22+ |
| Node.js (dev only) | 20+ |
| Target AD | Any read-only domain user, LDAP port 389 reachable |

---

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/shiva0126/yama.git
cd yama

# 2. Start the full stack
make up

# 3. Open the dashboard
#    http://localhost
#    Default login: admin / admin
```

The first run builds all images and runs database migrations automatically.

```bash
make down     # stop everything
make logs     # tail logs for all services
```

---

## Development Setup

### 1. Start infrastructure

```bash
make dev-infra        # starts PostgreSQL and Redis in Docker
make migrate          # run DB migrations
```

### 2. Start backend services (each in its own terminal)

```bash
cd backend/api-gateway       && go run .
cd backend/scan-orchestrator && go run .
cd backend/inventory-service && go run .
cd backend/analysis-engine   && go run .
cd backend/report-service    && go run .
```

### 3. Start frontend

```bash
cd frontend && npm install && npm run dev
# http://localhost:3000
```

### Environment variables

All defaults are set in `docker-compose.yml`. Key variables:

| Variable | Default | Description |
|---|---|---|
| `PORT` | per-service | HTTP listen port |
| `DB_DSN` | postgres://... | PostgreSQL connection string |
| `REDIS_URL` | redis://localhost:6379 | Redis address |
| `JWT_SECRET` | change-me | JWT signing key — **change in production** |
| `ORCHESTRATOR_URL` | http://localhost:8081 | Internal service routing |
| `INVENTORY_URL` | http://localhost:8082 | Internal service routing |
| `ANALYSIS_URL` | http://localhost:8083 | Internal service routing |
| `REPORT_URL` | http://localhost:8084 | Internal service routing |

---

## Running a Scan

1. Open `http://localhost` and log in.
2. Go to **Agents** → register a collector agent (provide LDAP target, domain, credentials).
3. Navigate to **Scanner** → select the agent and target domain.
4. Choose collection modules or select **All modules**.
5. Click **Start Scan**.

Scan progress streams in real time via WebSocket. Results appear in **Findings**, **Inventory**, and **Topology** tabs immediately upon completion.

### Collection Modules

| Module | What it collects |
|---|---|
| **Forest Topology** | Domain structure, trusts |
| **Users** | Accounts, password flags, SPNs, shadow credentials |
| **Groups** | Security groups, membership, privilege level |
| **Computers** | Computer accounts, OS, LAPS, delegation flags |
| **Group Policy** | GPO links, SYSVOL permissions |
| **Domain Controllers** | DC health, FSMO roles, SMB/LDAP signing |
| **Kerberos Config** | krbtgt age, encryption types, delegation |
| **ACL Analysis** | Dangerous permissions on sensitive objects |
| **Trust Relationships** | Forest/domain trusts, SID filtering |
| **ADCS / PKI** | Certificate templates, ESC vulnerability chains |
| **Sites & Services** | AD sites, subnets, site links, MachineAccountQuota |
| **Fine-Grained Passwords** | Password Settings Objects |

---

## Security Indicators

The Analysis Engine evaluates **46+ built-in checks** across 11 categories using a self-registering indicator registry pattern. Each check implements a standard `Indicator` interface making new checks trivial to add.

### Scoring

```
Score = 100 − (crit_penalty + high_penalty + med_penalty + low_penalty)

crit_penalty = min(40, critical_count × 20)
high_penalty = min(30, high_count    × 8)
med_penalty  = min(20, medium_count  × 4)
low_penalty  = min(10, low_count     × 1)
```

Penalties are tier-capped to prevent a single category of findings from collapsing the overall score.

### Indicator Categories

| Category | Key Checks |
|---|---|
| **Kerberos** | AS-REP roasting, Kerberoastable SPNs, unconstrained delegation, krbtgt age |
| **Account Security** | Password never expires, stale accounts, default Administrator, blank passwords |
| **Privileged Access** | Excessive Domain Admins, nested admin groups, shadow admins, adminCount orphans |
| **Group Policy** | Unlinked GPOs, SYSVOL writable by non-admin, WMI filter issues |
| **Domain Controllers** | Print Spooler running, SMB signing disabled, LDAP signing not required |
| **AD Structure** | Empty OUs, schema anomalies |
| **Delegation** | Unconstrained delegation on non-DCs, constrained delegation misconfiguration |
| **Trusts** | External trusts with SID filtering disabled |
| **PKI / Certificate Services** | ESC1 (enrollee supplies SAN), ESC2 (Any Purpose), ESC3 (Cert Request Agent), ESC4 (weak template ACL), ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2), ESC7 (ManageCA low-priv) |
| **NTLM & Authentication** | NTLMv1 permitted (LmCompatibilityLevel < 3), RC4 Kerberos encryption allowed, shadow credentials on privileged accounts |
| **Persistence Mechanisms** | Machine Account Quota > 0, AD Recycle Bin disabled, inactive computer accounts |

Each finding includes:
- Severity: **Critical / High / Medium / Low / Info**
- Affected AD objects (DN, type, detail)
- MITRE ATT&CK technique tags (with direct links)
- Step-by-step remediation guidance
- Risk score contribution

### Adding a Custom Indicator

1. Create a file in `backend/analysis-engine/indicators/`
2. Implement the `Indicator` interface:

```go
type Indicator interface {
    Metadata() types.SecurityIndicator
    Check(snapshot *types.InventorySnapshot, scanID string) []types.Finding
}
```

3. Call `registry.Register(&MyIndicator{})` in the `init()` function — it is automatically included in every scan run.

---

## Dashboard & UI

### Dashboard
- **Security score gauge** with color-coded thresholds (≥80 green, ≥60 amber, <60 red)
- **Score trend chart** — line graph across last 10 scans with delta vs previous
- **Category health grid** — per-category scores, click to filter findings
- **Top priority findings** — critical + high findings sorted by risk score
- **Running scan indicator** with live progress

### Findings
- Full-text search across name, description, indicator ID, affected object names
- **Severity filter chips** (Critical / High / Medium / Low / Info)
- Sort by severity, risk score, name, or detection date
- **Grouped by category** or flat list toggle
- Expandable finding detail: affected objects, remediation steps, MITRE tags, references

### Inventory
All 5 AD object tables (Users, Groups, Computers, GPOs, Domain Controllers) feature:
- **Sortable columns** (click header to sort asc/desc)
- **Search** with real-time filtering
- **Risk-based default sort** (highest risk objects surface first)
- Relevant security flags as inline badges

### Topology
- **ReactFlow graph** — domain node → site nodes → DC nodes
- Color coding: Global Catalog DCs (green), regular DCs (purple)
- Site link edges with cost labels
- Risk flags: MachineAccountQuota, AD Recycle Bin status, ADCS ESC count
- Sites & Services table with DC-to-site mapping and subnet ranges

### Reports
- Generate HTML / PDF / JSON reports for any completed scan
- **Report history table** with per-row re-download
- Scan summary preview (score, findings, critical count) before generating

---

## Reports

From the **Reports** page:

| Format | Use case |
|---|---|
| **HTML** | Browser-readable, shareable with stakeholders |
| **PDF** | Executive summary / audit distribution |
| **JSON** | SIEM / ticketing system integration |

Reports include the overall score, severity breakdown, full findings list with remediation, and an inventory summary.

---

## Configuration Reference

Service ports (host → container):

| Service | Host Port | Container Port |
|---|---|---|
| Frontend | 80 | 3000 |
| API Gateway | 9080 | 8080 |
| Scan Orchestrator | 9081 | 8081 |
| Inventory Service | 9082 | 8082 |
| Analysis Engine | 9083 | 8083 |
| Report Service | 9084 | 8084 |
| PostgreSQL | 5433 | 5432 |
| Redis | 6380 | 6379 |

---

## Makefile Reference

```bash
make up               # Build and start all Docker services
make down             # Stop and remove containers
make build            # Rebuild all Docker images
make migrate          # Run database migrations
make dev-infra        # Start only PostgreSQL and Redis
make dev-frontend     # Start React dev server (hot reload)
make logs             # Tail logs for all services
```

---

## Project Structure

```
yama/
├── backend/
│   ├── api-gateway/           # JWT auth, WebSocket hub, reverse proxy
│   │   ├── handlers/          # Route handlers (proxy.go)
│   │   ├── middleware/        # JWT middleware
│   │   └── websocket/         # Real-time hub (Redis pub/sub → browser)
│   ├── scan-orchestrator/     # LDAP collection engine, scan workflow
│   │   └── ldapcollector/     # LDAP collectors (users, groups, adcs, sites, ...)
│   ├── inventory-service/     # AD snapshot storage, topology endpoint
│   ├── analysis-engine/       # Security checks
│   │   └── indicators/        # Self-registering indicator registry
│   ├── report-service/        # HTML / PDF / JSON generation
│   └── shared/
│       ├── types/             # Shared Go types (AD objects, findings, scan)
│       ├── config/            # Env config loader
│       └── migrations/        # PostgreSQL schema migrations
├── frontend/
│   └── src/
│       ├── components/        # Dashboard, Findings, Inventory, Scanner, ...
│       ├── api/               # Axios API client
│       ├── stores/            # Zustand state (active scan)
│       └── types/             # TypeScript type definitions
├── docker-compose.yml
└── Makefile
```

---

## Security Notice

Yama is designed for **authorized security assessments only**. Always obtain written authorization before running assessments against any Active Directory environment. The tool uses read-only LDAP queries and makes no changes to the target domain.
