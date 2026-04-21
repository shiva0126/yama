# Yama — Active Directory Assessment Platform

Yama is an enterprise-grade Active Directory security assessment platform. It automates the discovery of AD vulnerabilities, collects a full inventory of domain objects, scores your environment against 40+ security indicators, and generates actionable remediation reports — all through a real-time web dashboard.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Quick Start (Docker)](#quick-start-docker)
- [Development Setup](#development-setup)
- [Collector Agent (Windows)](#collector-agent-windows)
- [Running a Scan](#running-a-scan)
- [Security Indicators](#security-indicators)
- [Reports](#reports)
- [Configuration Reference](#configuration-reference)
- [Makefile Reference](#makefile-reference)
- [Project Structure](#project-structure)

---

## Architecture Overview

```
Browser
  └── Frontend (React + TypeScript)  :80 / :3000
        └── API Gateway              :8080  (JWT auth, WebSocket)
              ├── Scan Orchestrator  :8081  (workflow, agent coordination)
              ├── Inventory Service  :8082  (AD object snapshots)
              ├── Analysis Engine    :8083  (40+ security checks)
              └── Report Service     :8084  (HTML / PDF / JSON reports)

Windows domain-joined machine
  └── Collector Agent  :9090  (PowerShell + C# execution)
```

- **Backend**: Go 1.22 microservices with Gin
- **Database**: PostgreSQL 16
- **Cache / Pub-Sub**: Redis 7
- **Frontend**: React 18, Vite, TailwindCSS
- **Data collection**: PowerShell modules + extensible C# tooling

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker & Docker Compose | 24+ |
| Go (dev only) | 1.22+ |
| Node.js (dev only) | 20+ |
| Windows collector machine | PowerShell 5.0+, domain-joined |

---

## Quick Start (Docker)

```bash
# 1. Clone the repo
git clone https://github.com/shiva0126/yama.git
cd yama

# 2. Start the full stack (DB, Redis, all services, frontend)
make up

# 3. Open the dashboard
#    http://localhost
```

The first run builds all images and runs database migrations automatically.

To stop everything:

```bash
make down
```

To view logs:

```bash
make logs                  # all services
docker compose logs -f api-gateway   # specific service
```

---

## Development Setup

### 1. Start infrastructure only

```bash
make dev-infra             # starts PostgreSQL and Redis in Docker
```

### 2. Run database migrations

```bash
make migrate
```

### 3. Start backend services (each in its own terminal)

```bash
cd backend/api-gateway      && go run .
cd backend/scan-orchestrator && go run .
cd backend/inventory-service && go run .
cd backend/analysis-engine   && go run .
cd backend/report-service    && go run .
```

### 4. Start the frontend dev server

```bash
make dev-frontend
# or
cd frontend && npm install && npm run dev
```

Frontend is available at `http://localhost:3000`, API gateway at `http://localhost:8080`.

### Environment variables

Each service reads its config from environment variables. Defaults are set in `docker-compose.yml`. For local development, copy and edit the relevant values:

| Variable | Default | Description |
|---|---|---|
| `PORT` | per-service | HTTP listen port |
| `DB_DSN` | postgres://... | PostgreSQL connection string |
| `REDIS_URL` | redis://localhost:6379 | Redis address |
| `JWT_SECRET` | change-me | JWT signing key |
| `ORCHESTRATOR_URL` | http://localhost:8081 | Internal service URL |
| `INVENTORY_URL` | http://localhost:8082 | Internal service URL |
| `ANALYSIS_URL` | http://localhost:8083 | Internal service URL |
| `REPORT_URL` | http://localhost:8084 | Internal service URL |

---

## Collector Agent (Windows)

The collector agent runs on a **Windows machine that is joined to the target domain**. It exposes a local HTTP API that the Scan Orchestrator calls to execute PowerShell collection modules.

### Build the agent

```bash
make build-agent
# produces: collector/agent/yama-agent.exe (cross-compiled for Windows amd64)
```

### Deploy and register

1. Copy `yama-agent.exe` and the `collector/powershell/modules/` folder to the target Windows machine.
2. Start the agent (runs on port 9090 by default):

```powershell
.\yama-agent.exe
```

3. In the Yama dashboard go to **Settings → Agents → Register Agent** and provide:
   - Agent hostname / IP
   - Port (default 9090)
   - Capabilities (topology, users, groups, computers, gpos, kerberos, acls, dc-info)

The agent will appear as **online** in the dashboard once registered.

### PowerShell modules included

| Module | Collects |
|---|---|
| `Get-ADTopology` | Forest / domain structure |
| `Get-ADUsers` | User accounts, password policies, flags |
| `Get-ADGroups` | Groups and memberships |
| `Get-ADComputers` | Computer accounts, OS versions |
| `Get-ADGPOs` | Group Policy Objects |
| `Get-KerberosConfig` | Kerberos delegation, SPNs |
| `Get-ACLAnalysis` | Sensitive ACL permissions |
| `Get-DCInfo` | Domain controller details |

---

## Running a Scan

1. Open the dashboard at `http://localhost`.
2. Navigate to **Scanner**.
3. Select a registered online agent.
4. Choose the collection modules to run (or select all).
5. Click **Start Scan**.

Scan progress streams in real time via WebSocket. When complete, findings appear in the **Findings** tab and a report can be generated from the **Reports** tab.

---

## Security Indicators

The Analysis Engine evaluates 40+ built-in checks across these categories:

| Category | Example Checks |
|---|---|
| Kerberos | Kerberoastable accounts, unconstrained delegation, AS-REP roasting |
| Account Security | Password never expires, stale accounts, default Administrator enabled |
| Privileged Access | Nested admin groups, excessive Domain Admins, shadow admins |
| Group Policy | GPO enforcement gaps, WMI filter issues |
| Domain Controllers | SYSVOL replication, DC OS patch levels |
| Trusts | External trusts with SID filtering disabled |
| ACLs | GenericAll / WriteDACL on sensitive objects |
| AD Structure | Empty OUs, schema anomalies |

Each finding includes:
- Severity: **Critical / High / Medium / Low / Info**
- Affected objects
- MITRE ATT&CK technique mapping
- Step-by-step remediation guidance
- Risk score contribution

---

## Reports

From the **Reports** page, select a completed scan and choose a format:

| Format | Use case |
|---|---|
| **HTML** | Browser-readable, shareable |
| **PDF** | Executive / audit distribution |
| **JSON** | Integration with SIEM / ticketing tools |

Reports include the overall security score, severity breakdown, all findings with remediation steps, and an inventory summary.

---

## Configuration Reference

Primary configuration is in `docker-compose.yml`. Key service ports:

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
make build            # Build all Docker images
make migrate          # Run database migrations
make dev-infra        # Start only PostgreSQL and Redis
make dev-frontend     # Start React dev server
make build-agent      # Cross-compile Windows collector agent
make logs             # Tail logs for all services
```

---

## Project Structure

```
yama/
├── backend/
│   ├── api-gateway/          # Auth, routing, WebSocket hub
│   ├── scan-orchestrator/    # Scan workflow and agent coordination
│   ├── inventory-service/    # AD object storage and retrieval
│   ├── analysis-engine/      # Security indicator execution
│   ├── report-service/       # Report generation
│   └── shared/               # Types, config, DB migrations
├── collector/
│   ├── agent/                # Windows collector agent (Go)
│   ├── powershell/modules/   # PowerShell collection scripts
│   └── csharp/ADCollector/   # C# tools (extensible)
├── frontend/                 # React + TypeScript SPA
├── docker-compose.yml
└── Makefile
```

---

## License

This project is intended for authorized security assessments only. Always obtain proper written authorization before running assessments against any Active Directory environment.
