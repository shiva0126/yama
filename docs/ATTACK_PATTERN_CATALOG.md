# Yama Active Directory Attack Pattern Catalog

## Purpose

This document normalizes the AD attack inventory into a backend detector catalog input.

It is designed for:

- defense-engine backend implementation
- detector authoring
- signal mapping
- correlation design
- response playbook selection

This is not a pure threat-intel list. It is an implementation-oriented catalog.

## Modeling Rules

### 1. Canonical Attack vs CVE vs Primitive

The defense engine should not build one detector per named blog post or one detector per CVE unless the exploitation pattern is materially different.

Use:

- canonical attack
- aliases
- exploit/CVE references
- signal model

Example:

- canonical attack: `NTLM Relay to AD CS`
- aliases: `ESC8`, `PetitPotam + relay`, `HTTP enrollment relay`
- CVEs can be attached if relevant

### 2. Detector Granularity

Each row in this catalog maps to either:

- a standalone detector
- a sub-detector under a detector family
- a correlation rule

### 3. Signal Shorthand

The `Signals` column uses normalized shorthand.

Examples:

- `auth.ntlm`
- `auth.kerberos.tgs`
- `dir.attr_write:servicePrincipalName`
- `dir.attr_write:msDS-KeyCredentialLink`
- `dir.acl_change`
- `dir.group_membership_change`
- `dc.replication_request`
- `cert.enroll`
- `cert.template_change`
- `proc.lsass_access`
- `proc.shadow_copy`
- `host.remote_service_create`
- `gpo.link_change`
- `files.sysvol_write`

### 4. Response Shorthand

- `alert`
- `approve-disable-account`
- `approve-reset-password`
- `approve-revert-acl`
- `approve-revert-delegation`
- `approve-remove-group-member`
- `approve-disable-template`
- `approve-remove-machine`
- `approve-unlink-gpo`
- `contain-host`
- `manual-only`

## Catalog Fields

- `ID`
- `Canonical Attack`
- `Family`
- `Type`
- `Aliases / CVEs`
- `Key Signals`
- `Core Preconditions`
- `Primary Response`

## Family A. Credential Dumping and Secret Extraction

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| CRED-001 | DCSync | Credential Extraction | technique | T1003.006 | `dc.replication_request`, `dir.rights_replication`, `auth.privileged` | replication rights | `approve-disable-account` |
| CRED-002 | NTDS.dit Direct Extraction | Credential Extraction | technique | T1003.003 | `files.ntds_access`, `proc.disk_raw_read`, `host.backup_ops` | DC or backup access | `contain-host` |
| CRED-003 | VSS NTDS Theft | Credential Extraction | technique | shadow copy theft | `proc.shadow_copy`, `files.ntds_access` | local admin / backup rights | `contain-host` |
| CRED-004 | IFM / ntdsutil Extraction | Credential Extraction | technique | IFM | `proc.ntdsutil`, `proc.ifm_export`, `files.ntds_access` | DC or backup access | `contain-host` |
| CRED-005 | LSASS Memory Dump | Credential Extraction | technique | T1003.001 | `proc.lsass_access`, `proc.dump_write`, `proc.sedebug` | admin/system on host | `contain-host` |
| CRED-006 | comsvcs.dll LSASS Dump | Credential Extraction | technique | LOLBIN dump | `proc.rundll32_comsvcs`, `proc.lsass_access` | admin/system on host | `contain-host` |
| CRED-007 | ProcDump / MiniDump LSASS | Credential Extraction | technique | ProcDump, MiniDump | `proc.procdump`, `proc.taskmgr_dump`, `proc.lsass_access` | admin/system on host | `contain-host` |
| CRED-008 | LSA Secrets Dumping | Credential Extraction | technique | T1003.004 | `registry.lsa_secret_read`, `proc.secretsdump_pattern` | local admin/system | `contain-host` |
| CRED-009 | SAM Database Dumping | Credential Extraction | technique | T1003.002 | `registry.sam_read`, `registry.system_read`, `proc.hash_dump_pattern` | local admin/system | `contain-host` |
| CRED-010 | Cached Credential Dumping | Credential Extraction | technique | DCC2, T1003.005 | `registry.cached_creds_read` | local admin/system | `contain-host` |
| CRED-011 | DPAPI Secret Theft | Credential Extraction | technique | T1555.004 | `proc.dpapi_blob_access`, `files.browser_secret_access`, `lsa.dpapi_key_access` | local access to victim context | `contain-host` |
| CRED-012 | WDigest Credential Harvesting | Credential Extraction | technique | plaintext WDigest | `registry.wdigest_change`, `proc.lsass_access` | local admin/system | `contain-host` |
| CRED-013 | Token Theft / Impersonation | Credential Extraction | primitive | T1134 | `proc.token_duplicate`, `proc.token_impersonation` | elevated local execution | `contain-host` |
| CRED-014 | KRBTGT Hash Theft | Credential Extraction | chain | via DCSync or NTDS | `dc.replication_request`, `files.ntds_access`, `target.krbtgt` | domain compromise path | `approve-disable-account` |
| CRED-015 | DirSync Confidential Attribute Abuse | Credential Extraction | primitive | LAPS sync abuse | `dc.dirsync_request`, `dir.secret_attribute_read` | DirSync rights | `approve-disable-account` |

## Family B. Lateral Movement

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| LAT-001 | Pass-the-Hash Lateral Movement | Lateral Movement | technique | PtH | `auth.ntlm`, `auth.source_mismatch`, `host.remote_admin` | NTLM hash | `approve-reset-password` |
| LAT-002 | Pass-the-Ticket Lateral Movement | Lateral Movement | technique | PtT | `auth.kerberos.tgs`, `auth.ticket_reuse`, `host.remote_admin` | stolen ticket | `approve-disable-account` |
| LAT-003 | Overpass-the-Hash | Lateral Movement | technique | pass-the-key ticket request | `auth.ntlm_to_kerberos_bridge`, `auth.kerberos.tgt` | NTLM hash | `approve-reset-password` |
| LAT-004 | Pass-the-Key | Lateral Movement | technique | AES key auth | `auth.kerberos.key_auth`, `auth.source_mismatch` | AES key | `approve-reset-password` |
| LAT-005 | PsExec / SMB Remote Execution | Lateral Movement | technique | T1021.002 | `host.remote_service_create`, `auth.admin_share`, `proc.psexec_pattern` | admin creds | `contain-host` |
| LAT-006 | WMI Remote Execution | Lateral Movement | technique | T1021.006 | `host.wmi_remote_exec`, `auth.remote_admin` | remote admin rights | `contain-host` |
| LAT-007 | WinRM / PowerShell Remoting | Lateral Movement | technique | T1021.006 | `host.winrm_session`, `powershell.remote_invocation` | remote admin rights | `contain-host` |
| LAT-008 | RDP Lateral Movement | Lateral Movement | technique | T1021.001 | `auth.rdp_logon`, `auth.source_mismatch` | valid creds | `alert` |
| LAT-009 | DCOM Remote Execution | Lateral Movement | technique | T1021.003 | `host.dcom_remote_exec` | remote execution rights | `contain-host` |
| LAT-010 | SMB Admin Share Abuse | Lateral Movement | primitive | ADMIN$, C$, IPC$ | `files.admin_share_write`, `auth.remote_admin` | admin creds | `contain-host` |
| LAT-011 | MSSQL Linked Server Abuse | Lateral Movement | AD-Adjacent | technique | linked SQL chain | `sql.link_exec`, `auth.domain_context` | SQL foothold | `manual-only` |
| LAT-012 | SCCM / MECM Abuse | Lateral Movement | AD-Adjacent | technique | management plane abuse | `mgmt.sccm_deploy`, `mgmt.sccm_secret_access` | SCCM access | `manual-only` |
| LAT-013 | WSUS Abuse | Lateral Movement | AD-Adjacent | technique | malicious update path | `mgmt.wsus_change`, `host.update_exec` | WSUS control | `manual-only` |

## Family C. Kerberos Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| KRB-001 | Kerberoasting | Kerberos | technique | T1558.003 | `auth.kerberos.tgs`, `dir.spn_enum`, `auth.request_burst` | SPN account | `alert` |
| KRB-002 | Targeted Kerberoasting | Kerberos | chain | SPN-jacking | `dir.attr_write:servicePrincipalName`, `auth.kerberos.tgs` | write SPN on target | `approve-revert-acl` |
| KRB-003 | AS-REP Roasting | Kerberos | technique | T1558.004 | `auth.asreq_no_preauth`, `dir.attr_read_uac` | preauth disabled account | `alert` |
| KRB-004 | AS-REP Inducement by Attribute Write | Kerberos | chain | UAC roast setup | `dir.attr_write:userAccountControl`, `auth.asreq_no_preauth` | write UAC on target | `approve-revert-acl` |
| KRB-005 | Golden Ticket | Kerberos | technique | T1558.001 | `auth.kerberos.tgt_anomaly`, `auth.krbtgt_usage_mismatch` | krbtgt secret | `approve-disable-account` |
| KRB-006 | Silver Ticket | Kerberos | technique | T1558.002 | `auth.service_ticket_anomaly`, `auth.no_kdc_validation_pattern` | service account key | `approve-reset-password` |
| KRB-007 | Diamond Ticket | Kerberos | technique | PAC patching | `auth.ticket_pac_mismatch` | krbtgt or ticket material | `approve-disable-account` |
| KRB-008 | Sapphire Ticket | Kerberos | technique | PAC copy | `auth.ticket_pac_anomaly` | krbtgt or PAC theft | `approve-disable-account` |
| KRB-009 | Skeleton Key | Kerberos | persistence | patched LSASS | `proc.lsass_patch`, `auth.universal_password_pattern` | DC code exec | `contain-host` |
| KRB-010 | MS14-068 PAC Forgery | Kerberos | exploit | legacy PAC forgery | `auth.ticket_pac_mismatch`, `auth.legacy_dc` | vulnerable legacy DC | `contain-host` |
| KRB-011 | Bronze Bit | Kerberos | exploit | CVE-2020-17049 | `auth.s4u_proxy_forwardable_anomaly` | service account and S4U path | `approve-reset-password` |
| KRB-012 | Unconstrained Delegation Abuse | Kerberos | technique | TGT harvest | `auth.tgt_forward_to_service`, `dir.delegation_flag` | unconstrained delegation | `alert` |
| KRB-013 | Constrained Delegation Abuse | Kerberos | technique | S4U2Self / S4U2Proxy | `auth.s4u2self`, `auth.s4u2proxy`, `dir.allowedtodelegateto` | KCD config | `approve-revert-delegation` |
| KRB-014 | Resource-Based Constrained Delegation | Kerberos | technique | RBCD | `dir.attr_write:msDS-AllowedToActOnBehalfOfOtherIdentity`, `auth.s4u2proxy` | write on computer object | `approve-revert-delegation` |
| KRB-015 | KrbRelayUp | Kerberos | chain | NTLM relay + RBCD | `auth.ntlm_relay`, `dir.attr_write:msDS-AllowedToActOnBehalfOfOtherIdentity`, `auth.s4u2proxy` | local privilege + relay path | `contain-host` |
| KRB-016 | ExtraSIDs Abuse | Kerberos | chain | trust ticket augmentation | `auth.ticket_sid_anomaly`, `trust.cross_domain` | forged/inter-realm ticket | `approve-disable-account` |
| KRB-017 | Trust Ticket Forging | Kerberos | technique | inter-realm TGT forgery | `auth.interrealm_ticket_anomaly` | trust key theft | `approve-disable-account` |
| KRB-018 | PKINIT Certificate Authentication Takeover | Kerberos | technique | cert auth takeover | `cert.auth_pkinit`, `auth.identity_mismatch` | usable cert | `approve-disable-account` |
| KRB-019 | UnPAC-the-Hash | Kerberos | chain | PKINIT to hash extraction | `cert.auth_pkinit`, `dc.ticket_to_secret_pattern` | certificate auth foothold | `approve-disable-account` |

## Family D. NTLM and Authentication Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| NTLM-001 | NTLM Relay | NTLM/Auth Abuse | technique | T1557.001 | `auth.ntlm`, `relay.target_service`, `auth.source_mismatch` | relayable auth + signing gaps | `contain-host` |
| NTLM-002 | SMB Relay | NTLM/Auth Abuse | technique | relay to SMB | `auth.ntlm`, `relay.smb_target` | signing not enforced | `contain-host` |
| NTLM-003 | LDAP Relay | NTLM/Auth Abuse | technique | relay to LDAP | `auth.ntlm`, `relay.ldap_target`, `dir.object_change_after_auth` | signing/channel binding gaps | `contain-host` |
| NTLM-004 | HTTP Relay | NTLM/Auth Abuse | technique | web relay | `auth.ntlm`, `relay.http_target` | HTTP endpoint accepts NTLM | `contain-host` |
| NTLM-005 | RPC Relay | NTLM/Auth Abuse | technique | RPC relay | `auth.ntlm`, `relay.rpc_target` | vulnerable RPC path | `contain-host` |
| NTLM-006 | LLMNR / NBT-NS Poisoning | NTLM/Auth Abuse | coercion | Responder | `net.llmnr_response`, `net.nbtns_poison`, `auth.ntlm_capture` | local subnet presence | `contain-host` |
| NTLM-007 | mDNS Poisoning | NTLM/Auth Abuse | coercion | multicast DNS spoofing | `net.mdns_poison`, `auth.ntlm_capture` | local subnet presence | `contain-host` |
| NTLM-008 | DHCPv6 / mitm6 Abuse | NTLM/Auth Abuse | coercion | mitm6 | `net.dhcpv6_spoof`, `dns.override`, `auth.ntlm_capture` | local segment foothold | `contain-host` |
| NTLM-009 | WPAD Abuse | NTLM/Auth Abuse | coercion | proxy autodiscovery spoof | `net.wpad_response`, `auth.ntlm_capture` | local segment foothold | `contain-host` |
| NTLM-010 | NTLM Downgrade / NTLMv1 Capture | NTLM/Auth Abuse | technique | weak NTLM | `auth.ntlm_v1`, `auth.negotiation_downgrade` | weak policy | `alert` |
| NTLM-011 | Drop-the-MIC Relay | NTLM/Auth Abuse | exploit | CVE-2019-1040 | `auth.ntlm_mic_anomaly`, `relay.success` | vulnerable target | `contain-host` |
| NTLM-012 | Password Spraying | NTLM/Auth Abuse | technique | T1110.003 | `auth.fail_burst_multiuser`, `auth.password_common_pattern` | reachable auth surface | `alert` |
| NTLM-013 | Brute Force | NTLM/Auth Abuse | technique | T1110.001 | `auth.fail_burst_singleuser` | reachable auth surface | `alert` |
| NTLM-014 | Credential Stuffing | NTLM/Auth Abuse | technique | T1110.004 | `auth.success_after_external_combo_pattern` | reused leaked creds | `approve-reset-password` |

## Family E. Domain Controller and Replication Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| DC-001 | DCShadow | DC/Replication Abuse | technique | T1207 | `dc.replication_stage`, `dir.dc_object_add`, `dir.hidden_change_pattern` | domain-level rights | `approve-disable-account` |
| DC-002 | Rogue DC Registration | DC/Replication Abuse | technique | fake DC object | `dir.dc_object_add`, `auth.machine_join_anomaly` | machine / domain rights | `approve-remove-machine` |
| DC-003 | DRSUAPI Direct Abuse | DC/Replication Abuse | primitive | replication API abuse | `dc.replication_request`, `rpc.drsuapi_usage` | replication rights | `approve-disable-account` |
| DC-004 | ZeroLogon | DC/Replication Abuse | exploit | CVE-2020-1472 | `netlogon.auth_zero_pattern`, `dc.machine_password_reset` | vulnerable Netlogon | `contain-host` |
| DC-005 | DSRM Password Abuse | DC/Replication Abuse | technique | restore mode admin | `auth.dsrm_logon`, `host.boot_repair_context` | DC local/restore access | `contain-host` |
| DC-006 | USN Rollback | DC/Replication Abuse | destructive | snapshot rollback | `dc.replication_usn_regress`, `vm.snapshot_restore` | DC virtualization or restore | `manual-only` |
| DC-007 | krbtgt Reset Timing Abuse | DC/Replication Abuse | chain | reset window exploitation | `auth.krbtgt_reset_window`, `auth.ticket_persistence_after_reset` | stolen tickets during reset window | `approve-disable-account` |

## Family F. AD CS and PKI Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| ADCS-001 | ESC1 | AD CS | technique | SAN supply | `cert.template_flags`, `cert.enroll`, `cert.san_unusual` | vulnerable template | `approve-disable-template` |
| ADCS-002 | ESC2 | AD CS | technique | Any Purpose / SubCA | `cert.template_eku_broad`, `cert.enroll` | vulnerable template | `approve-disable-template` |
| ADCS-003 | ESC3 | AD CS | technique | Enrollment Agent | `cert.enrollment_agent_use`, `cert.on_behalf_request` | vulnerable agent template | `approve-disable-template` |
| ADCS-004 | ESC4 | AD CS | technique | template ACL abuse | `cert.template_change`, `dir.acl_change` | write on template | `approve-disable-template` |
| ADCS-005 | ESC5 | AD CS | technique | PKI object ACL abuse | `cert.pki_object_acl_change` | write on PKI objects | `manual-only` |
| ADCS-006 | ESC6 | AD CS | technique | EDITF_ATTRIBUTESUBJECTALTNAME2 | `cert.ca_flag_change`, `cert.san_unusual` | CA config weakness | `manual-only` |
| ADCS-007 | ESC7 | AD CS | technique | ManageCA / ManageCertificates | `cert.ca_acl_change`, `cert.ca_admin_action` | weak CA rights | `manual-only` |
| ADCS-008 | ESC8 | AD CS | technique | NTLM relay to HTTP enrollment | `auth.ntlm_relay`, `cert.enroll_http` | HTTP enrollment endpoint | `contain-host` |
| ADCS-009 | ESC9 | AD CS | technique | no security extension template | `cert.template_no_security_extension`, `cert.enroll` | weak mapping posture | `approve-disable-template` |
| ADCS-010 | ESC10 | AD CS | technique | weak Schannel mapping | `cert.mapping_weak`, `cert.auth_pkinit` | weak certificate mapping | `manual-only` |
| ADCS-011 | ESC11 | AD CS | technique | NTLM relay to RPC enrollment | `auth.ntlm_relay`, `cert.enroll_rpc` | RPC enrollment weakness | `contain-host` |
| ADCS-012 | ESC12 | AD CS | technique | HSM / YubiHSM misuse | `cert.hsm_admin_action`, `cert.private_key_export` | HSM access | `manual-only` |
| ADCS-013 | ESC13 | AD CS | technique | AMA abuse | `cert.issuance_policy_mapping`, `auth.group_gain_via_cert` | vulnerable issuance policy | `manual-only` |
| ADCS-014 | ESC14 | AD CS | technique | explicit mapping | `dir.attr_write:altSecurityIdentities`, `cert.auth_pkinit` | explicit mapping path | `approve-revert-acl` |
| ADCS-015 | ESC15 | AD CS | technique | EKUwu / app policy injection | `cert.request_policy_injection`, `cert.v1_template_use` | vulnerable V1 template | `approve-disable-template` |
| ADCS-016 | ESC16 | AD CS | technique | CA security extension disabled | `cert.ca_security_extension_disabled`, `cert.auth_pkinit` | CA weak config | `manual-only` |
| ADCS-017 | Certifried | AD CS | exploit | CVE-2022-26923 | `dir.attr_write:UPN`, `cert.machine_enroll`, `cert.auth_pkinit` | machine account write path | `approve-remove-machine` |
| ADCS-018 | PetitPotam + ADCS Relay | AD CS | chain | coercion + relay | `rpc.coercion`, `auth.ntlm_relay`, `cert.enroll_http` | coercion path + ADCS | `contain-host` |
| ADCS-019 | Explicit Certificate Mapping Takeover | AD CS | technique | altSecurityIdentities takeover | `dir.attr_write:altSecurityIdentities`, `cert.auth_pkinit` | mapping write access | `approve-revert-acl` |

## Family G. Authentication Coercion

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| COERCE-001 | PrinterBug / SpoolSample | Coercion | coercion | MS-RPRN | `rpc.print_spooler_call`, `auth.outbound_machine_auth` | spooler exposed | `alert` |
| COERCE-002 | PetitPotam | Coercion | coercion | MS-EFSR | `rpc.efsr_call`, `auth.outbound_machine_auth` | EFS RPC exposed | `alert` |
| COERCE-003 | DFSCoerce | Coercion | coercion | MS-DFSNM | `rpc.dfsnm_call`, `auth.outbound_machine_auth` | DFSN exposed | `alert` |
| COERCE-004 | ShadowCoerce | Coercion | coercion | MS-FSRVP | `rpc.fsrvp_call`, `auth.outbound_machine_auth` | VSS RPC exposed | `alert` |
| COERCE-005 | MSEven Coerce | Coercion | coercion | Event Log coercion | `rpc.eventlog_call`, `auth.outbound_machine_auth` | event RPC exposed | `alert` |
| COERCE-006 | SRVSvc Coerce | Coercion | coercion | CVE-2022-30216 | `rpc.srvsvc_call`, `auth.outbound_machine_auth` | SRVSvc exposure | `alert` |
| COERCE-007 | PrivExchange | Coercion | AD-Adjacent | Exchange coercion | `ews.coercion_pattern`, `auth.outbound_machine_auth` | Exchange present | `manual-only` |
| COERCE-008 | PrintNightmare | Coercion | exploit | CVE-2021-1675, CVE-2021-34527 | `rpc.print_driver_install`, `proc.spooler_exec` | vulnerable spooler | `contain-host` |

## Family H. ACL, Delegation, and Object Permission Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| ACL-001 | GenericAll / GenericWrite Abuse | ACL/Object Control | primitive | T1222 | `dir.acl_change`, `dir.object_write` | write/full control | `approve-revert-acl` |
| ACL-002 | AdminSDHolder Abuse | ACL/Object Control | persistence | protected object ACL path | `dir.adminsdholder_change` | high rights | `approve-revert-acl` |
| ACL-003 | DCSync Rights via ACL | ACL/Object Control | chain | replication rights grant | `dir.acl_change`, `dir.rights_replication` | write on domain object | `approve-revert-acl` |
| ACL-004 | Shadow Credentials | ACL/Object Control | technique | msDS-KeyCredentialLink | `dir.attr_write:msDS-KeyCredentialLink`, `cert.auth_pkinit` | write on target object | `approve-revert-acl` |
| ACL-005 | GPO Abuse | ACL/Object Control | technique | T1484.001 | `gpo.change`, `files.sysvol_write` | GPO edit rights | `approve-unlink-gpo` |
| ACL-006 | Domain Policy Modification | ACL/Object Control | technique | T1484.002 | `gpo.domain_policy_change` | domain policy write rights | `manual-only` |
| ACL-007 | LAPS Password Abuse | ACL/Object Control | technique | T1552 | `dir.secret_attribute_read`, `attr.ms-Mcs-AdmPwd_read` | LAPS read rights | `alert` |
| ACL-008 | gMSA Password Theft | ACL/Object Control | technique | T1552 | `dir.secret_attribute_read`, `attr.msDS-ManagedPassword_read` | gMSA read rights | `alert` |
| ACL-009 | WriteOwner / WriteDACL Abuse | ACL/Object Control | primitive | T1222 | `dir.acl_owner_change`, `dir.acl_change` | ownership/DACL rights | `approve-revert-acl` |
| ACL-010 | Foreign Security Principal Abuse | ACL/Object Control | technique | FSP abuse | `dir.fsp_change`, `trust.cross_domain` | cross-domain object path | `manual-only` |
| ACL-011 | ForceChangePassword Abuse | ACL/Object Control | primitive | BloodHound edge | `dir.password_reset`, `auth.actor_target_mismatch` | reset rights | `approve-reset-password` |
| ACL-012 | AddMember / Self-Membership Abuse | ACL/Object Control | primitive | group injection | `dir.group_membership_change` | member-add rights | `approve-remove-group-member` |
| ACL-013 | CreateChild Abuse | ACL/Object Control | primitive | OU/container creation | `dir.object_create`, `dir.createchild_path` | create child rights | `approve-remove-machine` |
| ACL-014 | Pre-Created Computer Object Takeover | ACL/Object Control | chain | pre-staged computer abuse | `dir.computer_object_write`, `auth.machine_join_anomaly` | write on pre-created object | `approve-remove-machine` |
| ACL-015 | AllExtendedRights Abuse | ACL/Object Control | primitive | all extended rights | `dir.extended_right_use` | extended rights on target | `manual-only` |
| ACL-016 | AllowedToDelegateTo Tampering | ACL/Object Control | primitive | KCD attr write | `dir.attr_write:AllowedToDelegateTo` | write on service/computer | `approve-revert-delegation` |
| ACL-017 | SPN-Jacking / WriteSPN | ACL/Object Control | primitive | roast setup | `dir.attr_write:servicePrincipalName`, `auth.kerberos.tgs` | SPN write rights | `approve-revert-acl` |

## Family I. Persistence

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| PERS-001 | Golden Ticket Persistence | Persistence | persistence | long-lived forged TGT | `auth.kerberos.tgt_anomaly`, `auth.long_lived_ticket` | krbtgt material | `approve-disable-account` |
| PERS-002 | SIDHistory Injection | Persistence | persistence | T1134.005 | `dir.attr_write:sIDHistory`, `auth.token_sid_anomaly` | write to target object | `approve-revert-acl` |
| PERS-003 | Malicious SSP Installation | Persistence | persistence | T1547.005 | `proc.ssp_install`, `registry.ssp_change` | local admin/system | `contain-host` |
| PERS-004 | DSRM Backdoor | Persistence | persistence | DSRM reuse | `auth.dsrm_logon`, `policy.dsrm_change` | DC access | `contain-host` |
| PERS-005 | Skeleton Key Malware | Persistence | persistence | LSASS patching | `proc.lsass_patch` | DC code exec | `contain-host` |
| PERS-006 | Machine Account Persistence | Persistence | persistence | rogue machine | `dir.machine_create`, `dir.privileged_machine_acl` | machine creation path | `approve-remove-machine` |
| PERS-007 | WMI Event Subscription | Persistence | persistence | T1546.003 | `wmi.subscription_create` | local admin | `contain-host` |
| PERS-008 | Scheduled Task via GPO | Persistence | persistence | T1053.005 | `gpo.task_deploy`, `files.sysvol_write` | GPO rights | `approve-unlink-gpo` |
| PERS-009 | DCShadow Persistence | Persistence | persistence | hidden AD backdoor | `dc.replication_stage`, `dir.hidden_change_pattern` | domain rights | `approve-disable-account` |
| PERS-010 | AdminCount Persistence | Persistence | persistence | adminCount=1 abuse | `dir.attr_write:adminCount`, `policy.sdprop_change` | protected object path | `approve-revert-acl` |

## Family J. CVE-Led Critical Exploits

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| CVE-001 | ZeroLogon | Critical Exploit | exploit | CVE-2020-1472 | `netlogon.auth_zero_pattern`, `dc.machine_password_reset` | unpatched DC | `contain-host` |
| CVE-002 | PrintNightmare | Critical Exploit | exploit | CVE-2021-1675, CVE-2021-34527 | `rpc.print_driver_install`, `proc.spooler_exec` | vulnerable spooler | `contain-host` |
| CVE-003 | NoPac / sAMAccountName Spoofing | Critical Exploit | exploit | CVE-2021-42278, CVE-2021-42287 | `dir.attr_write:sAMAccountName`, `auth.dc_ticket_issued_to_machine` | unpatched AD | `approve-remove-machine` |
| CVE-004 | Certifried | Critical Exploit | exploit | CVE-2022-26923 | `dir.attr_write:UPN`, `cert.machine_enroll`, `cert.auth_pkinit` | vulnerable ADCS | `approve-remove-machine` |
| CVE-005 | PetitPotam (Unauth) | Critical Exploit | exploit | CVE-2021-36942 | `rpc.efsr_call`, `auth.outbound_machine_auth` | vulnerable target | `alert` |
| CVE-006 | Drop-the-MIC | Critical Exploit | exploit | CVE-2019-1040 | `auth.ntlm_mic_anomaly`, `relay.success` | vulnerable relay target | `contain-host` |
| CVE-007 | Bronze Bit | Critical Exploit | exploit | CVE-2020-17049 | `auth.s4u_proxy_forwardable_anomaly` | vulnerable KCD path | `approve-reset-password` |
| CVE-008 | EKUwu / ESC15 | Critical Exploit | exploit | CVE-2024-49019 | `cert.request_policy_injection`, `cert.v1_template_use` | vulnerable ADCS template | `approve-disable-template` |
| CVE-009 | BadSuccessor | Critical Exploit | exploit | CVE-2025-29810 | `dir.object_create`, `dir.attr_write:msDS-SupersededManagedAccountLink`, `auth.takeover_pattern` | WS2025 dMSA path | `approve-disable-account` |

## Family K. Trust and Cross-Domain / Forest Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| TRUST-001 | Inter-Forest Trust Abuse | Trust Abuse | technique | T1482 | `trust.cross_forest_auth`, `auth.sid_anomaly` | forest trust | `manual-only` |
| TRUST-002 | Child-to-Parent Escalation | Trust Abuse | chain | SIDHistory / ticket abuse | `trust.child_to_root_auth`, `auth.sid_anomaly` | child compromise | `manual-only` |
| TRUST-003 | Cross-Forest Kerberoasting | Trust Abuse | technique | T1558.003 | `auth.kerberos.tgs_cross_forest`, `dir.spn_enum` | forest trust | `alert` |
| TRUST-004 | Trust Key / Inter-Realm TGT Forging | Trust Abuse | technique | trust ticket forgery | `auth.interrealm_ticket_anomaly` | trust key theft | `approve-disable-account` |
| TRUST-005 | SID Filtering Bypass | Trust Abuse | chain | SIDHistory across trust | `auth.sid_anomaly`, `trust.sid_filter_disabled` | weak trust config | `manual-only` |
| TRUST-006 | AD Sites Abuse | Trust Abuse | primitive | site delegation abuse | `dir.site_object_change` | delegated site rights | `manual-only` |
| TRUST-007 | MachineAccountQuota Abuse | Trust Abuse | technique | MAQ abuse | `dir.machine_create_burst`, `policy.maq_nonzero` | MAQ > 0 | `approve-remove-machine` |

## Family L. Reconnaissance and Enumeration

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| RECON-001 | BloodHound / SharpHound Enumeration | Recon | enumeration | T1482 | `ldap.graph_query_pattern`, `ldap.enum_burst` | authenticated user | `alert` |
| RECON-002 | LDAP Enumeration | Recon | enumeration | T1087.002 | `ldap.enum_burst`, `ldap.scope_wide_query` | LDAP reachability | `alert` |
| RECON-003 | SPN Scanning | Recon | enumeration | SPN discovery | `ldap.spn_query_burst` | LDAP reachability | `alert` |
| RECON-004 | GPP Credential Discovery | Recon | enumeration | MS14-025 prep | `files.sysvol_gpp_read`, `files.cpassword_pattern` | SYSVOL access | `alert` |
| RECON-005 | Domain Trust Enumeration | Recon | enumeration | T1482 | `ldap.trust_query_burst` | LDAP reachability | `alert` |
| RECON-006 | DNS Admin Discovery | Recon | enumeration | DnsAdmins discovery | `ldap.group_query:DNSAdmins` | LDAP reachability | `alert` |
| RECON-007 | SCCM Surface Discovery | Recon | enumeration | management discovery | `mgmt.sccm_enum` | network reachability | `manual-only` |
| RECON-008 | WSUS Surface Discovery | Recon | enumeration | update infra discovery | `mgmt.wsus_enum` | network reachability | `manual-only` |

## Family M. AD-Adjacent Control Plane Abuse

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| ADJ-001 | DNSAdmins Privilege Abuse | AD-Adjacent | technique | service DLL load | `dir.group_membership_change:DNSAdmins`, `service.dns_plugin_load` | DNSAdmins rights | `manual-only` |
| ADJ-002 | Exchange Privilege Escalation | AD-Adjacent | technique | Exchange to DA paths | `exchange.privileged_write`, `dir.object_change` | Exchange rights | `manual-only` |
| ADJ-003 | PrivExchange | AD-Adjacent | coercion | EWS auth coercion | `ews.coercion_pattern`, `auth.outbound_machine_auth` | Exchange exposure | `manual-only` |
| ADJ-004 | SCCM Abuse | AD-Adjacent | technique | managed deployment abuse | `mgmt.sccm_deploy`, `mgmt.secret_read` | SCCM access | `manual-only` |
| ADJ-005 | WSUS Abuse | AD-Adjacent | technique | malicious update chain | `mgmt.wsus_change`, `host.update_exec` | WSUS control | `manual-only` |
| ADJ-006 | SQL Server Link Abuse | AD-Adjacent | technique | linked SQL movement | `sql.link_exec`, `sql.xp_cmdshell_chain` | SQL foothold | `manual-only` |

## Family N. Defense Evasion and Destructive Actions

| ID | Canonical Attack | Family | Type | Aliases / CVEs | Key Signals | Core Preconditions | Primary Response |
|---|---|---|---|---|---|---|---|
| EVADE-001 | Log Clearing on DCs | Evasion | evasion | event log clear | `host.log_clear`, `dc.role_host` | DC or admin access | `contain-host` |
| EVADE-002 | Audit Policy Weakening | Evasion | evasion | policy tamper | `policy.audit_change` | admin rights | `manual-only` |
| EVADE-003 | PowerShell Logging Disablement | Evasion | evasion | logging off | `policy.ps_logging_change`, `registry.ps_logging_change` | admin rights | `manual-only` |
| EVADE-004 | Sysmon Disablement | Evasion | evasion | EDR visibility reduction | `service.sysmon_stop`, `policy.sysmon_change` | admin rights | `manual-only` |
| EVADE-005 | Event Forwarding Tampering | Evasion | evasion | WEF tamper | `wef.subscription_change`, `wef.forwarder_disable` | admin rights | `manual-only` |
| DEST-001 | Mass Group Membership Sabotage | Destructive | destructive | privilege wipe | `dir.group_membership_burst` | admin/group rights | `manual-only` |
| DEST-002 | Malicious Password Reset Campaign | Destructive | destructive | reset flood | `dir.password_reset_burst` | reset rights | `manual-only` |
| DEST-003 | Malicious GPO Sabotage | Destructive | destructive | policy breakage | `gpo.change_burst`, `files.sysvol_write` | GPO rights | `manual-only` |
| DEST-004 | Trust Deletion or Poisoning | Destructive | destructive | trust sabotage | `trust.object_change`, `trust.delete` | trust write rights | `manual-only` |
| DEST-005 | OU / Object Tombstoning Sabotage | Destructive | destructive | deletion campaign | `dir.object_delete_burst` | delete rights | `manual-only` |

## Explicit Additions Beyond the Initial 125-Item Baseline

These attacks or primitives must remain in scope even when not always listed in popular "top AD attacks" lists:

- ForceChangePassword
- AddMember / self-membership abuse
- SPN-jacking / WriteSPN
- AS-REP inducement by attribute write
- DirSync confidential attribute abuse
- ExtraSIDs
- explicit `msDS-AllowedToActOnBehalfOfOtherIdentity` write
- explicit `altSecurityIdentities` certificate mapping takeover
- PKINIT takeover as an operational attack
- UnPAC-the-Hash
- CreateChild abuse
- pre-created computer object takeover
- AllExtendedRights abuse
- delegation attribute tampering

## Recommended Build Priority

Build first:

1. DCSync
2. DCShadow
3. Kerberoasting
4. AS-REP roasting
5. Pass-the-Hash
6. NTLM relay
7. Shadow credentials
8. RBCD
9. AdminSDHolder abuse
10. GPO abuse
11. AD CS ESC1 / ESC4 / ESC8 / ESC14
12. NoPac
13. Certifried
14. MachineAccountQuota abuse
15. LAPS and gMSA secret abuse

Then expand coverage family by family.

## Implementation Note

This catalog is a detector design input, not a promise that each row should become a totally isolated microservice or rule file.

Multiple rows may map to:

- one detector family
- one attribute-watch module
- one correlation rule
- one response playbook

The correct implementation unit is the detector family plus correlation logic, not a flat list of 100+ one-off scripts.
