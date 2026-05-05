# Yama Defense Engine Building Notes

## Current Product Understanding

Yama should not remain only an Active Directory assessment platform with a small defense layer attached.

The intended product shape is:

- Assessment plane
  - inventory
  - posture analysis
  - attack-path visibility
  - findings
  - topology
  - reporting
  - historical baselines
- Defense plane
  - continuous signal collection
  - attack-technique detection
  - correlation across hosts, identities, privileges, and time windows
  - confidence scoring
  - containment and response workflows
  - forensic evidence preservation
  - rollback and operator safety controls

The defense model should not be old-school "watch all logs like hell."

It should be:

- attack-technique driven
- signal curated
- correlation based
- low-noise
- high-confidence
- response aware

Logs are evidence inputs, not the product itself.

## Defense Architecture Direction

The defense engine should use this shape:

1. Signal ingestion
   - Windows Security Event Logs
   - PowerShell logs
   - Sysmon
   - directory object change signals
   - Kerberos and NTLM authentication signals
   - replication signals
   - AD CS signals
   - GPO change signals
   - trust and ACL change signals

2. Normalization
   - convert raw data into a common AD security event model
   - core entities: user, computer, domain controller, ticket, session, group, OU, GPO, CA, template, trust, credential operation

3. Technique detectors
   - detectors are defined per attack pattern
   - each detector maps:
     - technique
     - preconditions
     - minimal high-signal events
     - protocol behavior
     - state changes
     - correlation logic
     - confidence rules
     - response playbook
     - evidence package

4. Correlation and confidence
   - combine event IDs, source host, target object, privileges, sequence, rarity, and context
   - score confidence instead of firing raw events directly as incidents

5. Response engine
   - alert-only
   - approval-required
   - semi-automatic
   - fully automatic for high-confidence paths

6. Evidence layer
   - preserve detections, actions, source artifacts, hashes, and operator decisions
   - this is where tamper-evident or immutable audit design fits

7. Safety layer
   - protected accounts
   - exclusion lists
   - confidence thresholds
   - rollback
   - dry-run mode
   - maintenance windows
   - business-impact safeguards

## Important Design Principle

The detection engine should be attack-technique driven, not log-source driven.

The primary object in the system should be a detector specification such as:

- technique name
- ATT&CK mapping
- attack category
- required signals
- optional corroborating signals
- time window
- false-positive suppressors
- severity
- confidence
- automated response options
- evidence bundle requirements

Assessment and defense should remain separate subsystems that share:

- identity graph
- asset graph
- findings taxonomy
- risk model
- ATT&CK mapping
- UI shell

Assessment answers:

- what can be abused

Defense answers:

- what is being abused right now

## Active Directory Attack Catalog

This is a working catalog of major known AD attack classes and techniques that the Yama defense engine should eventually model. It is not guaranteed to be mathematically complete forever; it should be treated as a living coverage baseline.

### 1. Credential Access and Credential Theft

- NTDS.dit theft
  - direct file copy
  - Volume Shadow Copy abuse
  - `ntdsutil` IFM abuse
  - raw disk reads
  - backup abuse
- DCSync
- LSASS dump on domain controllers or privileged systems
- SAM / SECURITY / SYSTEM hive extraction
- DPAPI secret extraction
- KRBTGT hash extraction
- cached domain credential dumping
- LSA secret dumping
- AD database replication secret extraction
- plaintext credential theft from memory
- password filter abuse to capture credentials
- password spray against AD-authenticated services
- brute force against domain accounts
- credential stuffing against federated or AD-backed apps
- SSP injection for credential capture
- skeleton key style credential manipulation

### 2. Kerberos Abuse

- Kerberoasting
- AS-REP roasting
- Golden Ticket
- Silver Ticket
- Diamond Ticket
- Sapphire / forged PAC style ticket abuse
- Pass-the-Ticket
- Overpass-the-Hash / Pass-the-Key
- unconstrained delegation abuse
- constrained delegation abuse
- resource-based constrained delegation abuse
- S4U2Self abuse
- S4U2Proxy abuse
- SPN manipulation for Kerberos abuse
- KRBTGT stale password exploitation
- RC4 downgrade / weak encryption abuse
- ticket renewal abuse
- forged inter-realm trust ticket abuse

### 3. NTLM and Legacy Authentication Abuse

- Pass-the-Hash
- NTLM relay
- SMB relay
- LDAP relay
- HTTP relay to AD CS or other AD-integrated services
- MIC removal / downgrade relay variants
- NTLMv1 exploitation
- coerced NTLM authentication followed by relay
- challenge-response capture and crack
- session hijack of NTLM-authenticated contexts

### 4. Replication and Domain Controller Abuse

- DCSync
- DCShadow
- rogue domain controller registration
- replication rights abuse
- abuse of `Get-Changes`, `Get-Changes-All`, `Get-Changes-In-Filtered-Set`
- malicious metadata injection through replication paths
- SYSVOL tampering from privileged context
- domain controller backup abuse
- IFM media abuse
- AD snapshot abuse
- directory service restore mode misuse
- unauthorized schema/admin replication path changes

### 5. Privilege Escalation in AD

- adminCount abuse
- AdminSDHolder abuse
- SDProp persistence
- WriteDACL abuse on high-value objects
- WriteOwner abuse
- GenericAll abuse
- GenericWrite abuse
- force-change-password abuse
- AddMember / self-membership abuse on privileged groups
- SIDHistory injection
- Shadow Admin / delegated-rights abuse
- ACL abuse on OUs, groups, GPOs, users, computers, and domains
- Exchange privilege escalation paths into domain compromise
- certificate-based privilege escalation
- machine account creation for privilege pivoting

### 6. Persistence in Active Directory

- DCShadow for stealth persistence
- SIDHistory persistence
- shadow credentials / `msDS-KeyCredentialLink`
- AdminSDHolder backdoor ACLs
- GPO scheduled task / startup script persistence
- malicious logon script persistence
- service principal or service account persistence
- rogue certificate template persistence
- CA ACL persistence
- trust-based persistence
- OU / delegation-based persistence
- KRBTGT compromise persistence
- managed service account abuse for persistence
- computer account persistence via stale or planted objects
- alternate authentication material persistence

### 7. Lateral Movement and Execution Through AD

- Pass-the-Hash lateral movement
- Pass-the-Ticket lateral movement
- remote service creation using domain credentials
- PsExec style authenticated movement
- WinRM movement using stolen or relayed creds
- WMI authenticated remote execution
- RDP with stolen domain credentials
- remote scheduled task deployment
- GPO-based code deployment
- logon script deployment
- SCCM / management-plane abuse when backed by AD privileges

### 8. Group Policy Abuse

- malicious GPO creation
- privileged GPO edit
- startup script / shutdown script injection
- scheduled task deployment through GPO
- software deployment abuse
- security settings weakening via GPO
- SYSVOL writable path abuse
- WMI filter abuse
- GPO link hijacking
- GPO inheritance / block inheritance abuse
- preference password / cpassword abuse

### 9. AD CS and PKI Abuse

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
- weak template ACL abuse
- Any Purpose / SubCA abuse
- SAN supply abuse
- enrollment agent abuse
- CA ACL abuse
- CA configuration tampering
- certificate mapping abuse
- PKINIT abuse with forged or stolen certificates
- relay to AD CS enrollment endpoints
- malicious certificate issuance for privileged identities

### 10. Trust and Forest Abuse

- external trust abuse
- forest trust abuse
- shortcut trust abuse
- SID filtering disabled abuse
- trust key theft / trust ticket abuse
- cross-forest Kerberos abuse
- selective authentication misconfiguration abuse
- name suffix routing abuse
- inter-forest privilege pivoting

### 11. ACL, Delegation, and Object Control Abuse

- domain root ACL abuse
- OU ACL abuse
- group ACL abuse
- user object ACL abuse
- computer object ACL abuse
- GPO object ACL abuse
- certificate template ACL abuse
- CA ACL abuse
- `AllowedToActOnBehalfOfOtherIdentity` abuse
- `AllowedToDelegateTo` abuse
- `trustedForDelegation` abuse
- DNS object ACL abuse
- delegation of join rights / reset password / write SPN abuse

### 12. User and Identity Object Abuse

- SPN planting
- shadow credentials
- password never expires abuse
- reversible encryption exposure
- stale privileged account abuse
- disabled account reactivation
- service account abuse
- gMSA misuse
- preauth disabled account abuse
- privileged account password reuse
- alternate UPN / altSecurityIdentities abuse
- smartcard requirement bypass via misconfiguration

### 13. Computer and Machine Account Abuse

- machine account quota abuse
- rogue computer account creation
- computer account takeover
- computer account password reset abuse
- unconstrained delegation on computers
- RBCD on computer objects
- stale computer object abuse
- LAPS misconfiguration exploitation
- domain controller impersonation through object tampering
- workstation trust abuse

### 14. DNS and AD-Integrated Infrastructure Abuse

- AD-integrated DNS record poisoning
- WPAD / name resolution abuse in domain context
- dynamic DNS abuse
- DC locator manipulation
- service discovery manipulation
- DNS ACL abuse

### 15. Domain Controller and Core AD Service Misconfiguration Abuse

- Print Spooler enabled on DCs
- SMB signing disabled
- LDAP signing not required
- LDAP channel binding disabled
- weak functional-level-related security posture
- time-service abuse impacting Kerberos
- backup privilege abuse on DCs
- DC local admin drift
- weak replication security configuration

### 16. Discovery and Enumeration With Defensive Value

These are not always attacks by themselves, but they often form early-stage attack chains and can contribute to confidence scoring.

- privileged group enumeration
- domain trust enumeration
- SPN enumeration
- AS-REP roast candidate enumeration
- ACL path enumeration
- BloodHound-style graph collection
- GPO enumeration
- AD CS enumeration
- domain controller discovery
- user and computer inventory scraping from unusual hosts

### 17. Defense Evasion Relevant to AD Operations

- log clearing on DCs
- PowerShell logging disablement
- Sysmon disablement
- audit policy weakening
- tampering with event forwarding
- tampering with security tooling through GPO
- account manipulation to look like admin activity
- replication-based stealth changes
- timestomping related artifacts on DCs

### 18. Data Manipulation and Destructive Operations

- group membership sabotage
- GPO sabotage
- trust deletion or poisoning
- OU move / delete sabotage
- object tombstoning for impact
- mass ACL weakening
- account disablement campaigns
- malicious password reset campaigns
- domain-wide policy weakening

## Recommended Coverage Model

Coverage should be implemented by detector families, not by ad hoc rules.

Suggested first-class detector families:

- credential theft
- Kerberos abuse
- NTLM abuse
- replication abuse
- privilege escalation
- persistence
- GPO abuse
- AD CS abuse
- trust abuse
- ACL and delegation abuse
- machine and computer abuse
- DC security abuse
- discovery chains
- defense evasion

## Build Direction

When the defense engine is built later, each detector should have:

- detector ID
- attack name
- ATT&CK mapping
- coverage family
- data dependencies
- event ID mapping
- state-change dependencies
- correlation logic
- confidence formula
- severity
- automated response candidates
- rollback / safety conditions
- evidence artifacts to preserve

This document is the baseline for that future build.

## Related Architecture

The full backend-first defense stack architecture is defined in:

- [DEFENSE_ENGINE_ARCHITECTURE.md](./DEFENSE_ENGINE_ARCHITECTURE.md)

That document should be treated as the implementation blueprint.
