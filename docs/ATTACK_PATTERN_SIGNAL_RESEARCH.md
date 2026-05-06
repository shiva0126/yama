# Yama Attack Pattern Signal Research

## Goal

This document grounds the defense-engine detector design in a small set of high-signal Active Directory behaviors instead of a generic "collect every log" approach.

It is not a complete threat-intel encyclopedia. It is a detector-design reference for the backend.

## Design Position

The defense plane should model attacks through:

- protocol behavior
- directory object and attribute changes
- constrained event IDs
- host-side process and memory abuse
- certificate issuance and certificate-auth behavior
- correlation windows tying these together

This is the core distinction:

- old design: "watch logs"
- Yama design: "prove attack patterns with minimum strong signals"

## Canonical Signal Families

### 1. Directory Object and Attribute Change Signals

These are the backbone for:

- Shadow Credentials
- RBCD
- SPN-jacking
- ForceChangePassword
- SIDHistory injection
- AdminSDHolder abuse
- GPO abuse
- certificate template abuse

High-value examples:

- `5136`: directory service object modified
- `5137`: object created
- `5141`: object deleted
- attribute writes such as:
  - `msDS-KeyCredentialLink`
  - `msDS-AllowedToActOnBehalfOfOtherIdentity`
  - `servicePrincipalName`
  - `sIDHistory`
  - `altSecurityIdentities`
  - `msPKI-Certificate-Name-Flag`

Why it matters:

- AD attacks often succeed by changing one attribute or one ACL, not by generating a large noisy stream.

### 2. Replication and Privileged Object Access Signals

These are the backbone for:

- DCSync
- DCShadow
- replication-rights abuse
- secret sync abuse

High-value examples:

- `4662` on DCs for object operations
- DRSUAPI / `IDL_DRSGetNCChanges`
- replication-right grants on domain or config objects

Why it matters:

- DCSync is fundamentally replication abuse. The strongest signal is not "hashes were dumped" after the fact. It is that a non-DC actor performed replication-style operations.

### 3. Kerberos Signals

These are the backbone for:

- Kerberoasting
- AS-REP roasting
- Golden/Silver/Diamond ticket patterns
- PKINIT-backed takeover paths
- delegation abuse

High-value examples:

- `4768`: TGT request
- `4769`: TGS request
- anomalous service tickets
- no-preauth AS-REQ usage
- S4U2Self / S4U2Proxy activity
- PKINIT-backed logon after directory write

Why it matters:

- many AD attack chains end with a valid Kerberos flow. The detector needs the auth event, but also the object-change or privilege path that made it possible.

### 4. NTLM and Coercion Signals

These are the backbone for:

- NTLM relay
- SMB/LDAP/HTTP relay
- PetitPotam-style chains
- coercion-fed AD CS takeover

High-value examples:

- NTLM authentication accepted on a target service
- source mismatch between original requester and target access
- coercion RPC activity immediately before outbound machine authentication
- certificate enrollment after relayed auth

Why it matters:

- relay detection is a chain problem. A single NTLM event is weak. NTLM plus coercion plus downstream object change or cert issuance is strong.

### 5. Host Process Abuse Signals

These are the backbone for:

- LSASS dumping
- DSRM abuse support activity
- Skeleton Key-style host compromise
- ntdsutil / VSS theft

High-value examples:

- process access to `lsass.exe`
- dump-file creation
- `vssadmin`, `diskshadow`, or `ntdsutil` execution on DCs
- unexpected privileged service creation or remote execution

Why it matters:

- several AD attacks start on endpoints or DCs, then pivot into domain compromise.

### 6. AD CS and Certificate Authentication Signals

These are the backbone for:

- ESC1-ESC16 families
- explicit certificate mapping abuse
- Shadow Credentials
- Certifried
- relay to enrollment endpoints

High-value examples:

- template flag and ACL changes
- issuance policy changes
- SAN-supply-capable enrollment
- CA-wide security-extension weakening
- PKINIT after certificate issuance or key-credential write

Why it matters:

- the certificate path is both a configuration plane and an authentication plane. Detectors need both sides.

## Detector Logic Templates

### DCSync

Pattern:

- a principal with replication rights
- uses DRS replication operations
- from a non-DC or unexpected host
- against domain naming context or KRBTGT-relevant material

Minimum strong signals:

- `4662`-style privileged object operation on DC
- replication-style API usage
- actor or host not aligned with legitimate DC behavior

Response posture:

- critical
- approval-required disable account
- approval-required revert replication rights if recently granted

### Shadow Credentials

Pattern:

- write to `msDS-KeyCredentialLink`
- followed by certificate-backed or PKINIT-based auth
- especially strong if target is Tier 0 or a computer object controlling privileged paths

Minimum strong signals:

- `5136`-style object modification
- attribute = `msDS-KeyCredentialLink`
- PKINIT or key-trust auth after the write

Response posture:

- critical
- approval-required revert attribute
- approval-required disable actor if confidence is high

### RBCD

Pattern:

- write to `msDS-AllowedToActOnBehalfOfOtherIdentity`
- optional machine-account creation shortly before
- S4U activity to impersonate another identity to target service

Minimum strong signals:

- directory attribute write
- S4U2Proxy behavior
- target computer or service in privileged path

Response posture:

- critical
- approval-required revert delegation
- approval-required remove rogue machine account if chain includes MAQ abuse

### Kerberoasting

Pattern:

- enumeration or identification of SPN-bearing accounts
- TGS requests against roastable services
- burst or unusual concentration by actor, source host, or target set

Minimum strong signals:

- `4769`
- unusual request shape or volume
- optional preceding SPN enumeration or write

Response posture:

- high
- often alert-first unless combined with SPN-jacking or privileged service accounts

### ESC1

Pattern:

- vulnerable template permits enrollee-supplied subject / SAN
- low-privileged principal enrolls
- resulting cert authenticates as higher-privilege identity

Minimum strong signals:

- template configuration allowing supplied subject
- enrollment event
- SAN or mapped identity mismatch
- PKINIT or certificate-auth follow-up

Response posture:

- critical
- approval-required disable template or remove issuance

### ESC8

Pattern:

- NTLM relay into AD CS web enrollment
- machine or privileged identity coerced or relayed
- issued certificate used for authentication takeover

Minimum strong signals:

- NTLM relay pattern
- HTTP enrollment
- optional coercion signal beforehand

Response posture:

- critical
- contain relay source
- approval-required disable vulnerable enrollment path

## Implementation Consequences

The backend should normalize raw input into a compact event model with:

- event ID
- protocol family
- actor
- source host
- target object / service
- changed attributes
- request context
- evidence references

Detectors should then consume normalized events rather than raw XML logs.

## Research References

These are the main sources used to anchor the detector model:

- Microsoft Learn, `drsuapi RPC Interface (MS-DRSR)`: documents `IDL_DRSGetNCChanges`, the core replication operation abused by DCSync.
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/58f33216-d9f1-43bf-a183-87e3c899c410

- Microsoft Learn, `Audit Directory Service Changes`: explains that DC-side auditing for object creation, deletion, movement, and modification is emitted through the directory-service changes audit category.
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes

- Microsoft Learn, `5136(S): A directory service object was modified`: authoritative reference for object/attribute modification auditing.
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

- Microsoft Learn, `4769(S, F): A Kerberos service ticket was requested`: authoritative reference for TGS requests, central to Kerberoasting and many Kerberos-abuse detections.
  - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769

- Microsoft Learn, `msDS-AllowedToDelegateTo` attribute: constrains delegation signal design for KCD-style paths.
  - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto

- Microsoft Learn, script/article for `msDS-KeyCredentialLink`: useful for grounding Shadow Credentials around the actual attribute and key-credential material.
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/script-to-view-msds-keycredentiallink-attribute-value

- Microsoft Learn, `ms-PKI-Certificate-Name-Flag` attribute: grounds ESC1-style template analysis around the certificate-template subject-name flags.
  - https://learn.microsoft.com/en-us/windows/win32/adschema/a-mspki-certificate-name-flag

- Microsoft Support, `KB5014754`: certificate-based authentication hardening changes, relevant to certificate mapping and SID extension behavior.
  - https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16

## Practical Scope

This research set is enough to design the first backend detector families correctly.

It does not mean:

- every detector is finished
- every event source is already collected
- every attack can be auto-remediated safely yet

It does mean:

- the detector model is being built on protocol and directory semantics
- the catalog is aligned to production AD attack patterns
- the backend can evolve without collapsing into a log-noise SIEM design
