# Yama 2.0 — Changelog 2026-05-13

## Summary

Session completing Phase 2–5 production hardening, ADCS ESC9-15 coverage, host sensor layer,
response safety, and UI bug fixes. First live assessment run against `migratesuccess.local`.

---

## Backend Changes

### api-gateway
- **JWT** — HS256 stdlib implementation in `handlers/proxy.go` + `middleware/auth.go`. Token includes `sub`, `username`, `iat`, `exp`.
- **CORS** — Explicit allowlist (localhost:3000, :5173, :80) + `CORS_ALLOWED_ORIGIN` env override in `main.go`.
- **overview.go** — Fixed `types.Severity` → `string` cast when calling `severityRank()` (was a compile error).

### analysis-engine — ADCS ESC indicators (`indicators/adcs.go`)
| Indicator | What it checks |
|-----------|---------------|
| ESC9 | `CT_FLAG_NO_SECURITY_EXTENSION` set → SAN bypass possible |
| ESC10 | Weak certificate mapping — `!LDAPSigningRequired` or WDigest enabled on DC |
| ESC13 | Issuance policy OID group link (`1.3.6.1.4.1.311.21.8` prefix in RA/App policies) |
| ESC15 | Schema V1 template — application policies override EKU |

**Bug fixes:**
- `checkESC10`: `dc.LDAPSigning` → `!dc.LDAPSigningRequired`, `dc.DistinguishedName` → `dc.HostName`

### scan-orchestrator — LDAP collector (`ldapcollector/adcs.go`)
Extended LDAP search to collect `msPKI-Certificate-Application-Policy`, `msPKI-RA-Application-Policies`,
`msPKI-Private-Key-Flag`, and `msPKI-Enrollment-Servers`. Template map now sets:
`vulnerable_esc9`, `vulnerable_esc10`, `vulnerable_esc13`, `vulnerable_esc15`, `schema_version`,
`no_security_extension`, `has_smartcard_logon`, `has_pkinit_kdc`.

CA map keys corrected to `request_encryption_disabled` and `shell_access_enabled` (matching `ADCertificateAuthority` JSON tags).

### shared/types — `ad_objects.go`
`ADCertificateTemplate` extended with `VulnerableESC9`, `VulnerableESC10`, `VulnerableESC13`,
`VulnerableESC15`, `OIDGroupLink`, `HasSmartcardLogon`, `HasPKINITKDC`, `NoSecurityExtension`.

### shared/crypto — `aead.go` (new file)
AES-256-GCM field encryption for `dc_password` in the agents table.
- Key: `YAMA_FIELD_ENC_KEY` env var (64 hex chars = 32 bytes)
- Ciphertext prefix `"enc:"` for backward compatibility with plaintext values
- Used in `scan-orchestrator/orchestrator/orchestrator.go`

### detector-engine — `main.go`
Added `TOOL-001` detector: fires when `event_type=proc.create` and `offensive_tool=true` attribute is present.
Includes `process_name` in detection metadata.

Existing detector families: `CRED-001/005`, `KRB-001/004/014`, `NTLM-001`, `DC-001`,
`ADCS-001/008`, `ACL-004/011/017`, `PERS-002`, `LAT-005`, `GPO-001`, `EVADE-001`, `TOOL-001`.

### correlation-engine — `main.go`
9 named attack chain templates:
1. DCSync Attack (`CRED-001` required)
2. Shadow Credentials Attack (`ACL-004` required)
3. RBCD Privilege Escalation (`KRB-014` required)
4. NTLM Relay Chain (`NTLM-001` required)
5. GPO Abuse for Persistence (`GPO-001` required)
6. Kerberoasting Campaign (`KRB-001` required)
7. Evasion + Attack Combo (`EVADE-001` required, `TOOL-001` optional)
8. Credential Extraction via LSASS (`CRED-005` required, `TOOL-001` optional)
9. **Offensive Tooling Detected** (`TOOL-001` required) — new, `critical-confirmed`

Tier-0 assets escalate to `critical-confirmed` when targeted.

### response-orchestrator — `main.go`
Chain-aware response planning:
- `collect-evidence`: automatic for critical/high incidents (non-destructive)
- `disable-account`: automatic for `critical-confirmed` non-protected actors
- `revoke-tickets`: approval-required for DCSync, Shadow Creds, RBCD, **Offensive Tooling** chains
- `reset-password`: approval-required for all critical incidents
- `block-network`: approval-required for LSASS dump / NTLM Relay
- `revoke-certificate`: approval-required for NTLM Relay / ADCS title
- `quarantine-computer`: approval-required for GPO Abuse chain

Protected accounts (krbtgt, administrator, svc-backup, svc-monitoring) can never auto-disable.

### signal-normalizer — `main.go`
30+ EventID mappings including ETW events (4688 proc create, 4624/4625 logon, 4769 Kerberos,
4663/4670 object access, 4724 password reset, 4728/4732/4756 group changes, 7045 service install, etc.).

### inventory-service — `main.go`
`allowedInventoryTables` map guards all dynamic table queries against SQL injection.

---

## Collector Agent (`collector/agent/`)

### sensor/ (new package)
| File | Contents |
|------|----------|
| `sensor.go` | Platform-agnostic coordinator; starts ETW + proc + svc watchers via build tag |
| `sensor_windows.go` | ETW PowerShell subscriber, 4688 proc watcher, 7045 service watcher, Sysmon reader, LSASS PPL monitor |
| `sensor_notwindows.go` | No-op stubs for Linux builds |

Offensive tool signatures detected: mimikatz, rubeus, impacket, bloodhound, cobalt strike, sharphound.

### executor/powershell.go
6 defense actions via PowerShell:
- `disable-account` — `Disable-ADAccount`
- `reset-password` — `Set-ADAccountPassword`
- `revoke-tickets` — `Invoke-Command` + `klist purge`
- `block-network` — Windows Firewall `New-NetFirewallRule`
- `revoke-certificate` — `Revoke-CACertificate`
- `quarantine-computer` — `Move-ADObject` to quarantine OU

### main.go
- `AGENT_API_KEY` env var (not `YAMA_API_KEY`) for authentication
- `/sensor/health` HTTP endpoint
- `AGENT_DOMAIN` and `AGENT_ID` env vars supported

---

## Frontend

### `Assess/index.tsx` — FindingsTab
- **Auto-selects latest completed scan** on first load (no manual selection needed)
- **Finding detail drawer** now fetches full finding by ID (`GET /api/v1/findings/:id`) when clicked — description, remediation, affected objects, MITRE ATT&CK tags now populate correctly
- Selected row highlighted in table

### `Agents/index.tsx`
- **Live install job progress banner** — appears after clicking Deploy; shows progress bar, status, and message; polls every 2 seconds until completed/failed
- **Recent installs table** — shows last 5 install jobs with status badges; click to re-open progress banner
- Added `CheckCircle`, `XCircle` icons for success/failure states

### `Defend/index.tsx`
- `IncidentCard` with Approve / Rollback / Close buttons
- Rollback reason form (modal)
- Tier-0 badge on critical incidents

### `Defense/index.tsx`
- `SuppressionsTab` — CRUD for false-positive policy exclusions via policy-engine

### `Topology/index.tsx`
- DC nodes rendered in red when implicated in an open incident (attack map overlay)

---

## Deployment Notes

### Windows Agent on DC01 (172.16.242.57)
- DC has **no SSH** (port 22 blocked). WinRM port 5985 is open.
- Binary deployed via: HTTP server on host (port 7777) → `System.Net.WebClient.DownloadFile` via WinRM
- Scheduled task `YamaSecurityAgent` created under SYSTEM account with `-api-key` flag embedded in binary path
- **Important env vars for agent**: `AGENT_API_KEY` (not `YAMA_API_KEY`), `AGENT_DOMAIN`, `AGENT_ID`
- API key in use: `f3a29c1e8b4d7059a16e32cf5b78d041`

### Live Assessment Results
- Domain: `migratesuccess.local` | Target DC: `172.16.242.57`
- Score: **28/100** (Poor)
- Findings: 1 critical · 6 high · 6 medium · 2 low
- Snapshot ID: `03416c22-cabe-4db9-b30b-1fb0ce931dcc`

---

## Git

Commit `f03ac8c` pushed to:
- `origin` → `https://github.com/shiva0126/yama.git`
- `yama2` → `https://github.com/shiva0126/yama-2.0.git`
