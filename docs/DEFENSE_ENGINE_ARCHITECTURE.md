# Yama Defense Engine Architecture Blueprint

## Purpose

This document defines the backend-first architecture for evolving Yama from an Active Directory assessment platform into a production-grade Active Directory defense platform.

The target outcome is not a noisy SIEM clone.

The target outcome is:

- attack-technique driven detection
- minimal but high-signal telemetry
- cross-signal correlation
- confidence-based containment
- forensic-grade evidence retention
- safe and controlled production response

This is the blueprint for building the defense stack before expanding the UI.

## Product Model

Yama should have two coordinated but separate planes.

### 1. Assessment Plane

Purpose:

- scheduled and on-demand assessment
- AD inventory
- posture scoring
- attack-path visibility
- exposure mapping
- findings and reports
- historical baseline and drift analysis

Current Yama already covers a significant part of this.

### 2. Defense Plane

Purpose:

- near-real-time attack detection
- detector execution by attack technique
- correlation of events, object changes, and protocol behaviors
- incident generation
- confidence scoring
- containment / disruption / rollback
- evidence packaging
- operator workflows

The defense plane is the focus of this document.

## Design Principles

### 1. Attack-Technique Driven, Not Log-Driven

The primary object is a detector specification, not a raw log feed.

Bad design:

- collect everything
- search everything
- generate many weak alerts

Good design:

- define the attack
- define only the signals required to prove or strongly infer the attack
- correlate those signals with identity, host, privilege, and time context
- respond only when confidence is sufficient

### 2. Signals Over Logs

Logs are one source of evidence, not the product itself.

The engine should consume:

- event IDs where they are meaningful
- directory attribute changes
- protocol behaviors
- object creation / deletion
- ticket issuance patterns
- privilege transitions
- replication activity
- certificate issuance patterns
- trust and GPO state changes

### 3. Assessment and Defense Share Context

Assessment should feed defense with:

- crown-jewel assets
- high-risk identities
- exposed delegation paths
- certificate risk
- trust risk
- critical GPOs
- baseline behaviors

Defense should feed assessment with:

- incidents
- exploited weaknesses
- validated attack paths
- control failures

### 4. Production Safety Is Mandatory

This is a production defense system. It must include:

- exclusions
- approval modes
- rollback
- dry-run
- protected account/host tiers
- rate limits on automated action
- evidence-first response flow

## Backend-First Defense Architecture

The backend should be built as a dedicated subsystem, not scattered across assessment services.

## Target Services

### 1. `signal-collector`

Purpose:

- ingest telemetry from Windows and AD-integrated systems

Sources:

- Windows Security Event Logs
- PowerShell logs
- Sysmon
- Directory Service logs
- Kerberos / KDC logs
- NTLM auth signals
- AD CS logs
- DNS logs
- GPO change signals
- trust and replication signals
- optional EDR / Sysmon / Zeek / network context later

Notes:

- can be agent-based on Windows hosts and DCs
- can support pull and push ingestion
- must support secure authenticated delivery

### 2. `signal-normalizer`

Purpose:

- convert raw telemetry into a common AD security event model

Outputs:

- normalized security events
- normalized object change records
- normalized auth flow records
- normalized replication records
- normalized certificate records

This service should remove source-specific parsing from the detectors.

### 3. `detector-engine`

Purpose:

- run technique detectors against normalized signals

Responsibilities:

- load detector definitions
- evaluate per-signal rules
- maintain short-lived technique state
- emit detections with evidence fragments

### 4. `correlation-engine`

Purpose:

- merge multiple detections and signals into incidents

Responsibilities:

- actor correlation
- host correlation
- object correlation
- time-window correlation
- chain scoring
- blast radius estimation
- ATT&CK tactic progression tracking

This is where "attack pattern" becomes "incident."

### 5. `response-orchestrator`

Purpose:

- execute containment safely

Capabilities:

- disable accounts
- expire/reset passwords
- revoke tickets or force logoff
- remove group memberships
- revert ACL/delegation changes
- disable malicious GPO links
- revert dangerous certificate mappings
- quarantine via integrations later

Modes:

- observe
- alert
- approval-required
- semi-automatic
- automatic high-confidence containment

### 6. `evidence-ledger`

Purpose:

- preserve a tamper-evident record of detections, incidents, signals, and responses

Stores:

- source event references
- hashes of evidence bundles
- response decisions
- before/after state
- rollback metadata
- analyst notes

This service is the correct place for immutable or blockchain-backed audit logic if retained.

### 7. `identity-graph`

Purpose:

- maintain a graph of principals, groups, computers, OUs, GPOs, templates, trusts, CAs, and rights

Use:

- evaluate whether an attack affects Tier 0
- prioritize incidents
- calculate reachable blast radius
- enrich detectors with context from assessment

### 8. `policy-engine`

Purpose:

- enforce safety controls and response policy

Controls:

- protected identities
- protected systems
- confidence thresholds
- business-hour restrictions
- maintenance windows
- auto-response eligibility
- approval chains

### 9. `defense-api`

Purpose:

- backend API for operator console

Endpoints:

- alerts
- incidents
- evidence
- detector health
- response actions
- response approvals
- exclusions and policy
- coverage metrics

## Data Stores

Use the right store for the right data.

### PostgreSQL

Use for:

- detectors
- incidents
- alerts
- response actions
- policy
- exclusions
- case management
- evidence metadata
- object baselines

### Redis / Message Bus

Use for:

- streaming signal transport
- short-lived correlation state
- realtime operator updates
- workflow fan-out

### Object Storage

Use for:

- large evidence bundles
- raw event exports
- snapshots
- response rollback state

### Optional Graph Store Later

Optional if PostgreSQL graph-like modeling becomes insufficient.

Use for:

- attack path correlation
- high-speed graph traversal
- tier-zero blast radius computation

## Core Event Model

All detectors should operate on normalized event classes rather than raw source schema.

Minimum normalized classes:

- `AuthenticationEvent`
- `TicketEvent`
- `NTLMEvent`
- `DirectoryObjectChangeEvent`
- `ReplicationEvent`
- `PrivilegeChangeEvent`
- `ProcessExecutionEvent`
- `ServiceControlEvent`
- `GPOChangeEvent`
- `CertificateEvent`
- `TrustEvent`
- `DNSChangeEvent`
- `HostSecurityEvent`
- `CoercionEvent`

Core dimensions on every event:

- tenant / forest / domain
- host
- source host
- target host
- actor account
- actor SID
- target object
- target DN
- object class
- privilege context
- timestamp
- correlation ID / session ID if known
- source channel
- raw event reference

## Detector Standard

Every detector must be represented in a structured form.

Required fields:

- detector ID
- attack name
- attack family
- technique type
  - primitive
  - exploit
  - persistence
  - lateral movement
  - coercion
  - chain
- MITRE mapping
- required signals
- optional corroborating signals
- prerequisite conditions
- suppression conditions
- correlation window
- severity
- confidence model
- response candidates
- rollback requirements
- required evidence bundle
- production safety notes

## Confidence Model

Confidence should not equal severity.

Example inputs:

- signal quality
- number of independent corroborating signals
- rarity in that environment
- whether actor is expected admin
- whether source host is normal for the actor
- whether target is Tier 0
- whether assessment plane already flagged target path as exposed
- whether the action sequence matches a known chain

Suggested output:

- `low`
- `medium`
- `high`
- `critical-confirmed`

## Response Model

Responses should be policy-driven and reversible where possible.

Response levels:

- `observe`
- `alert`
- `queue_for_approval`
- `contain_partial`
- `contain_full`
- `remediate`

Possible response actions:

- disable account
- force password reset
- clear privileged group memberships
- terminate active sessions
- revoke Kerberos tickets through practical enforcement actions
- revert ACL changes
- revert delegation attributes
- disable affected certificate template
- disable explicit certificate mapping
- remove rogue machine account
- unlink malicious GPO
- revert rogue GPO scripts or scheduled tasks
- mark host for isolation through endpoint integration

## Safety Controls

The policy engine must support:

- Tier 0 protected accounts
- break-glass accounts
- critical service accounts
- domain controller protections
- allowlists for maintenance operations
- time-based exceptions
- environment mode
  - lab
  - staging
  - production
- confidence thresholds per action
- approval routing
- automatic rollback where available

## Coverage Blueprint

The defense engine should be organized by detector families.

## Family 1. Credential Dumping and Secret Extraction

Coverage:

- DCSync
- NTDS.dit direct extraction
- VSS NTDS copy
- IFM / ntdsutil extraction
- LSASS dump
- comsvcs.dll LSASS dump
- ProcDump / MiniDump LSASS
- SAM dumping
- SECURITY / SYSTEM / LSA secrets extraction
- cached domain credentials dumping
- DPAPI secret theft
- WDigest plaintext harvest
- token theft / impersonation

Required signals:

- process creation on DCs and privileged hosts
- sensitive file access
- VSS operations
- replication request patterns
- SeDebugPrivilege usage indicators
- LSASS access patterns
- suspicious credential API access
- directory replication rights usage

## Family 2. Kerberos Abuse

Coverage:

- Kerberoasting
- targeted Kerberoasting
- AS-REP roasting
- Golden Ticket
- Silver Ticket
- Diamond Ticket
- Sapphire Ticket
- Pass-the-Ticket
- Overpass-the-Hash
- Pass-the-Key
- Bronze Bit
- Skeleton Key
- MS14-068 PAC forgery
- unconstrained delegation abuse
- constrained delegation abuse
- RBCD
- KrbRelayUp
- trust ticket forgery
- ExtraSIDs
- PKINIT-based certificate auth takeover
- UnPAC-the-Hash

Required signals:

- TGT/TGS issuance patterns
- unusual SPN requests
- account attribute changes
- delegation-related attribute changes
- service ticket anomalies
- logon type and source mismatches
- KDC events
- machine account creation plus delegation sequence

## Family 3. NTLM and Authentication Abuse

Coverage:

- Pass-the-Hash
- NTLM relay
- SMB relay
- LDAP relay
- HTTP relay
- RPC relay
- LLMNR / NBT-NS poisoning
- mDNS poisoning
- DHCPv6 / mitm6 abuse
- WPAD abuse
- NTLM downgrade / NTLMv1 capture
- Drop-the-MIC
- password spraying
- brute force
- dictionary attack
- credential stuffing

Required signals:

- authentication failures and successes
- protocol negotiation details
- relay-indicative sequences
- name resolution anomalies
- unusual machine-to-machine auth
- cert enrollment following relayed auth

## Family 4. Replication and Domain Controller Abuse

Coverage:

- DCSync
- DCShadow
- DRSUAPI direct abuse
- rogue DC registration
- ZeroLogon
- DSRM abuse
- USN rollback
- snapshot / restore abuse
- krbtgt reset timing abuse

Required signals:

- replication permission changes
- replication request behavior
- domain controller object registration
- Netlogon anomalies
- privileged DC-local operations
- system restore / snapshot operations
- high-risk directory changes on DC objects

## Family 5. AD CS / PKI Abuse

Coverage:

- ESC1
- ESC2
- ESC3
- ESC4
- ESC5
- ESC6
- ESC7
- ESC8
- ESC9
- ESC10
- ESC11
- ESC12
- ESC13
- ESC14
- ESC15
- ESC16
- Certifried
- PetitPotam + ADCS relay
- explicit certificate mapping takeover
- altSecurityIdentities abuse

Required signals:

- certificate template changes
- CA ACL changes
- enrollment events
- unusual SANs
- request-agent usage
- certificate mapping changes
- machine account UPN changes
- relayed auth followed by enrollment

## Family 6. ACL, Delegation, and Object Control Abuse

Coverage:

- GenericAll abuse
- GenericWrite abuse
- WriteDACL abuse
- WriteOwner abuse
- ForceChangePassword
- AddMember / self-membership abuse
- DCSync rights via ACL
- shadow credentials
- pre-created computer object takeover
- CreateChild abuse
- AllExtendedRights abuse
- delegation attribute tampering
- LAPS secret read abuse
- gMSA secret read abuse
- foreign security principal abuse

Required signals:

- directory ACL changes
- group membership changes
- password reset operations
- attribute write events for:
  - `servicePrincipalName`
  - `userAccountControl`
  - `msDS-KeyCredentialLink`
  - `msDS-AllowedToActOnBehalfOfOtherIdentity`
  - `altSecurityIdentities`
  - managed password attributes

## Family 7. Persistence

Coverage:

- Golden Ticket persistence
- SIDHistory injection
- AdminSDHolder abuse
- shadow credentials
- skeleton key
- malicious SSP
- DSRM backdoor
- machine account persistence
- WMI event subscription
- scheduled tasks via GPO
- DCShadow persistence
- AdminCount abuse

Required signals:

- persistence-related object changes
- service / DLL registration events
- recurring scheduled task rollout
- WMI subscription creation
- privileged attribute drift

## Family 8. Lateral Movement

Coverage:

- Pass-the-Hash movement
- Pass-the-Ticket movement
- PsExec
- SMB admin share abuse
- WinRM
- WMI
- RDP
- DCOM
- linked SQL server abuse
- SCCM / MECM abuse
- WSUS abuse

Required signals:

- remote service creation
- remote process execution
- remote task creation
- remote PowerShell sessions
- administrative share access
- management platform action logs

## Family 9. Trust and Cross-Domain / Forest Abuse

Coverage:

- inter-forest trust abuse
- child-to-parent escalation
- cross-forest Kerberoasting
- trust key / inter-realm TGT forging
- SID filtering bypass
- AD sites abuse
- MachineAccountQuota abuse

Required signals:

- trust object changes
- SIDHistory or ExtraSIDs behavior
- cross-domain ticket requests
- child domain to root privilege pivots
- site object changes
- machine account creation spikes

## Family 10. GPO and Domain Policy Abuse

Coverage:

- malicious GPO modification
- malicious GPO link
- startup/shutdown script injection
- scheduled task deployment through GPO
- domain policy modification
- SYSVOL abuse
- GPP credential abuse

Required signals:

- GPO object changes
- SYSVOL file writes
- script deployment paths
- policy setting deltas
- cpassword / preference file access

## Family 11. Authentication Coercion

Coverage:

- PrinterBug / SpoolSample
- PetitPotam
- DFSCoerce
- ShadowCoerce
- MSEven
- SRVSvc coercion
- PrivExchange
- PrintNightmare-related auth coercion chains

Required signals:

- RPC service access patterns
- coerced authentication sequences
- inbound auth from unexpected server-to-server paths
- immediate relay or enrollment behavior after coercion

## Family 12. Discovery and Pre-Attack Path Staging

Coverage:

- BloodHound / SharpHound enumeration
- LDAP enumeration
- SPN scanning
- domain trust enumeration
- GPP credential discovery
- DNS admin discovery
- SCCM surface discovery
- WSUS discovery

Required signals:

- high-volume LDAP queries
- unusual graph-collection query patterns
- broad SPN enumeration
- trust and ACL enumeration bursts
- SYSVOL pattern access

This family is important for confidence scoring and early warning.

## Family 13. Defense Evasion and Destructive Abuse

Coverage:

- log clearing
- security logging disablement
- audit policy weakening
- tampering with event forwarding
- timestomping related artifacts
- deletion or sabotage of domain objects
- mass group membership modification
- malicious password reset campaigns

Required signals:

- audit policy changes
- logging service changes
- bulk object mutation
- suspicious rollback or deletion sequences

## Normalized Master Catalog

The attack inventory must be normalized.

Every row in the master catalog should contain:

- `catalog_id`
- `name`
- `family`
- `type`
- `mitre_id`
- `canonical_name`
- `aliases`
- `description`
- `required_signals`
- `state_changes`
- `preconditions`
- `detector_priority`
- `response_priority`
- `production_risk`

### Technique Types

Use these values:

- `primitive`
- `technique`
- `chain`
- `exploit`
- `coercion`
- `persistence`
- `enumeration`
- `evasion`
- `destructive`

## Production Build Sequence

This should be built in phases.

### Phase 1. Core Platform

Build first:

- normalized event model
- signal ingestion
- detector framework
- correlation engine
- evidence model
- response policy engine

### Phase 2. Highest-Impact Detector Families

Build next:

- credential dumping and extraction
- Kerberos abuse
- NTLM relay / coercion
- replication and DC abuse
- ACL / delegation abuse
- AD CS abuse

### Phase 3. Safe Response Orchestration

Build next:

- approval flows
- exclusions
- rollback
- partial containment
- full containment playbooks
- evidence-linked action execution

### Phase 4. Advanced Coverage

Build next:

- trust / forest abuse
- GPO abuse
- SCCM / WSUS / Exchange-adjacent abuse
- anomaly tuning
- baseline deviation models

### Phase 5. Continuous Hardening

Build ongoing:

- false positive tuning
- environment-specific baselines
- detector simulation and replay testing
- coverage drift analysis
- response safety validation

## Backend Service Contracts

Recommended internal APIs:

### signal-collector

- `POST /signals/batch`
- `POST /signals/heartbeat`
- `GET /collectors`
- `POST /collectors/register`

### signal-normalizer

- internal message-based pipeline preferred

Outputs:

- `normalized.events`
- `normalized.object_changes`
- `normalized.auth_flows`

### detector-engine

Inputs:

- normalized streams

Outputs:

- `detections.raw`

### correlation-engine

Inputs:

- `detections.raw`
- graph context
- baseline context

Outputs:

- `incidents`
- `incidents.updates`

### response-orchestrator

- `POST /responses/execute`
- `POST /responses/approve`
- `POST /responses/rollback`
- `GET /responses/:id`

### evidence-ledger

- `POST /evidence/bundle`
- `GET /evidence/:incident_id`
- `POST /evidence/hash`

## Operator Data Model

The UI should eventually show:

- signals
- detections
- incidents
- response actions
- evidence bundles
- detector coverage
- false positive review queue
- policy and exclusions
- asset / identity risk context

But the backend must come first.

## Immediate Backend Outcome

The first production backend milestone should deliver:

- signal ingestion
- normalized event pipeline
- attack-technique detector framework
- correlation service
- incident store
- safe response orchestrator in alert-only and approval mode
- evidence bundle retention

That is the minimum viable defense stack.

## Final Direction

Yama should become:

- an AD assessment platform
- plus a full Active Directory defense stack
- with broad known-technique coverage
- clean backend architecture
- low-noise detection
- production-safe response
- and forensic integrity by design

This document is the backend architecture blueprint for that build.
