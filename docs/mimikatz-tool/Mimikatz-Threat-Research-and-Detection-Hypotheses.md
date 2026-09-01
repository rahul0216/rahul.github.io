---
title: Mimikatz Threat Research and Detection Hypotheses
description: Evidence-based research on Mimikatz capabilities, ATT&CK flows, actor and campaign use, evasion methods, and detection hypotheses for Defender XDR and Microsoft Sentinel
author: Defender Content Team
ms.date: 2026-09-01
ms.topic: reference
keywords:
  - mimikatz
  - mitre attack
  - credential access
  - threat hunting
  - microsoft defender xdr
  - microsoft sentinel
estimated_reading_time: 25
---

## Executive Summary

Mimikatz is an open-source Windows security testing and credential-access toolkit
created by Benjamin Delpy. It can extract or manipulate NTLM hashes, Kerberos
tickets, cached credentials, LSA secrets, DPAPI keys, certificates, and other
authentication material. It can also reuse or forge authentication material through
pass-the-hash, pass-the-ticket, golden-ticket, and silver-ticket operations.

Mimikatz is not only an executable named `mimikatz.exe`. Public source code,
recompilation, reflective loading, renamed binaries, embedded implementations,
`Invoke-Mimikatz`, MimikatzLite, Wrapikatz, and `pypykatz` make name-only and
hash-only detections fragile. Durable coverage correlates access to credential
stores with authentication anomalies and subsequent remote activity.

The highest-priority detection themes are:

1. Unusual access to LSASS followed by dump creation or authentication activity.
2. DCSync from an unapproved system or identity.
3. NTLM credential replay followed by remote execution.
4. Credential-protection tampering followed by LSASS or registry-hive access.
5. Suspected credential access followed by privileged multi-host fan-out.

## Capability Overview

The primary Mimikatz capability families include:

* `sekurlsa`: parses LSASS authentication packages, logon sessions, Kerberos
  tickets, and credential material; supports minidump parsing and pass-the-hash
  process creation
* `lsadump`: accesses SAM data, cached domain credentials, LSA secrets, directory
  replication secrets, hash manipulation, and DCShadow-related functions
* `kerberos`: enumerates, exports, injects, purges, and forges Kerberos tickets
* `crypto`: interacts with Windows CAPI and CNG to extract or export certificates and
  private keys
* `vault` and DPAPI operations: accesses Credential Manager, vault files, DPAPI
  blobs, backup keys, and master keys
* `token`: enumerates and impersonates access tokens
* SSP and `misc` functions: supports credential interception, SID-history changes,
  and Skeleton Key-like domain-controller authentication modification

### Capability and ATT&CK Matrix

| Capability | Direct behavior | ATT&CK mapping | Prerequisite or qualification |
|---|---|---|---|
| Live LSASS parsing | Reads logon-session and authentication-package memory | T1003.001 | Usually requires administrator, SYSTEM, or equivalent access; exposed material varies by Windows configuration |
| LSASS dump parsing | Parses a captured minidump offline | T1003.001 | The parser might never access live LSASS on the acquisition endpoint |
| SAM extraction | Retrieves local account hashes from memory or hive material | T1003.002 | Requires suitable local privilege or offline hive access |
| LSA secret extraction | Retrieves secrets maintained by LSA | T1003.004 | Requires elevated access or offline SYSTEM and SECURITY material |
| Cached domain credentials | Retrieves cached domain logon material | T1003.005 when evidenced | Cached material is not necessarily reusable plaintext |
| DCSync | Requests directory-replication secrets | T1003.006 | Requires replication permissions but does not require execution on a domain controller |
| Credential Manager and vault access | Reads stored credentials and vault artifacts | T1555, T1555.004 | Availability and decryptability depend on context |
| Browser-protected material | Uses DPAPI or key material to recover browser secrets | T1555.003 when evidenced | DPAPI access alone does not prove browser credential theft |
| Pass-the-hash | Creates or supplies a logon context using NTLM material | T1550.002 | Remote execution is a downstream action |
| Pass-the-ticket | Injects or reuses Kerberos tickets | T1550.003 | Authentication can occur without a new password event |
| Golden ticket | Forges a TGT using a `krbtgt` secret | T1558.001 | Requires current usable `krbtgt` key material |
| Silver ticket | Forges a service ticket using a service or computer key | T1558.002 | Service-specific and may bypass a normal KDC service-ticket request |
| SSP interception | Loads or registers an SSP that captures credentials | T1547.005, T1556 | Requires privileged modification; registry and module-load evidence may remain |
| Skeleton Key-like operation | Patches domain-controller authentication in memory | T1556.001 | Requires domain-controller compromise; original Skeleton Key malware is separate |
| SID-history manipulation | Appends a privileged SID to SID history | T1134.005 | Requires significant directory privileges |
| Account hash manipulation | Changes an account password hash | T1098 when evidenced | Tool presence alone does not establish account persistence |
| DCShadow | Emulates replication behavior to introduce directory changes | T1207 | Requires substantial domain privilege and replication conditions |
| Private-key extraction | Exports certificate and private-key material | T1552.004, T1649 | Depends on key storage, permissions, and export restrictions |

## ATT&CK Use Across Intrusion Stages

Mimikatz most directly serves Credential Access. Some modules also support Defense
Evasion, Persistence, and Privilege Escalation. Other tactics commonly associated
with Mimikatz are usually consequences of credential reuse rather than direct tool
functions.

| Intrusion stage | Direct Mimikatz role | Enabled or correlated behavior | Analytic distinction |
|---|---|---|---|
| Initial Access | None established as a core function | Exploit, phishing, stolen session, or valid account provides the foothold | Do not map initial access from Mimikatz presence |
| Execution | Native binary, script-hosted payload, reflective loader, or embedded implementation runs | PowerShell, DLL loader, Cobalt Strike, or another host process may execute it | Detect the host and memory behavior, not only the filename |
| Persistence | SSP registration, Skeleton Key-like change, account/hash/SID manipulation, forged long-lived tickets | Stolen credentials may enable scheduled tasks, services, cloud persistence, or account changes | Map only the exact persistence mechanism observed |
| Privilege Escalation | Token impersonation, SID-history injection, privileged-ticket forging | Recovered administrator credentials enable elevation on other systems | Distinguish local token operations from credential reuse |
| Defense Evasion | Pass-the-hash, pass-the-ticket, process injection, DCShadow, modified builds | Security-tool tampering or log clearing may precede or follow use | Many evasion behaviors belong to the loader or operator, not the core tool |
| Credential Access | LSASS, SAM, LSA secrets, cached credentials, DCSync, vaults, DPAPI, private keys, ticket theft and forgery | Recovered secrets expand access | This is the primary direct role |
| Discovery | Can enumerate logon sessions, tickets, tokens, and credential context | Stolen identities enable domain, host, service, and cloud discovery | Separate local credential-context enumeration from broad discovery tools |
| Lateral Movement | PtH and PtT provide alternate authentication material | SMB, PsExec, WMI, WinRM, RDP, remote services, and management tools move laterally | Remote channel use is downstream unless incident evidence links it |
| Collection | Credential, certificate, key, and ticket material is collected | Credentials may enable mailbox, file-share, database, or cloud collection | Do not attribute downstream data collection to Mimikatz alone |
| Command and Control | No core C2 role | Mimikatz may run through a C2 framework or remote shell | Attribute C2 to the delivery framework |
| Exfiltration | No core exfiltration role | Dumps, hives, or credentials may be staged and transferred | Detect dump acquisition and transfer as separate stages |
| Impact | No core destructive role | Recovered privileges may enable ransomware, destructive changes, or service disruption | Treat impact as downstream activity |

## Representative ATT&CK Flows

### Flow 1: Endpoint Credential Theft to Lateral Movement

| Step | Behavior | Direct or downstream | ATT&CK mapping |
|---|---|---|---|
| 1 | Obtain local administrator or SYSTEM-equivalent access | Prerequisite | Depends on intrusion |
| 2 | Access live LSASS or create an LSASS dump | Direct or acquisition stage | T1003.001 |
| 3 | Parse LSASS data and recover NTLM material or Kerberos tickets | Direct | T1003.001 |
| 4 | Create or inject a PtH or PtT authentication context | Direct | T1550.002 or T1550.003 |
| 5 | Authenticate to a remote host | Downstream | T1021 family, depending on protocol |
| 6 | Execute through SMB service control, PsExec, WMI, WinRM, or RDP | Downstream | T1569.002, T1047, T1021.006, T1021.001, or applicable technique |
| 7 | Reuse the identity across additional systems | Downstream | T1078 and applicable remote-service technique |

**Detection opportunity:** correlate an unusual LSASS reader or dump file with a
new NTLM or Kerberos logon and remote process, service, or WMI activity by the same
account or source device.

### Flow 2: DCSync to Golden-Ticket Persistence

| Step | Behavior | Direct or downstream | ATT&CK mapping |
|---|---|---|---|
| 1 | Compromise an identity with directory-replication rights | Prerequisite | T1078 or applicable privilege path |
| 2 | Request replication secrets for `krbtgt` | Direct | T1003.006 |
| 3 | Forge a TGT with recovered `krbtgt` material | Direct | T1558.001 |
| 4 | Inject or use the forged ticket | Direct | T1550.003 |
| 5 | Request service tickets or access domain resources | Downstream | T1550.003 and resource-specific technique |
| 6 | Retain access until keys and relevant tickets are invalidated | Consequence | T1558.001 |

**Detection opportunity:** identify replication requests from sources outside the
approved domain-controller, identity-management, synchronization, backup, and
migration inventory. Correlate with unusual high-value Kerberos activity.

### Flow 3: Service-Key Theft to Silver-Ticket Access

| Step | Behavior | Direct or downstream | ATT&CK mapping |
|---|---|---|---|
| 1 | Obtain a service-account or computer-account key | Prerequisite or direct extraction | T1003 or another credential-access technique |
| 2 | Forge a service-specific ticket | Direct | T1558.002 |
| 3 | Present the forged ticket directly to the target service | Direct reuse | T1550.003 |
| 4 | Access the service without a normal KDC request chain | Downstream consequence | Service-specific technique |

**Detection opportunity:** correlate service-side Kerberos authentication with the
absence of an expected event 4769 across all relevant domain controllers. This is a
research hypothesis, not a standalone signature. Logging loss, cross-domain paths,
retention mismatch, cache behavior, and connector delay can create false gaps.

### Flow 4: Domain-Controller Authentication Backdoor

| Step | Behavior | Direct or downstream | ATT&CK mapping |
|---|---|---|---|
| 1 | Obtain domain administrator or equivalent control | Prerequisite | Depends on intrusion |
| 2 | Place or load a DLL or Mimikatz capability on a domain controller | Execution | T1218.011 or applicable loader technique |
| 3 | Modify LSASS authentication logic in memory | Direct | T1556.001 |
| 4 | Authenticate to multiple accounts with an alternate password | Direct consequence | T1556.001 |
| 5 | Redeploy after reboot if the in-memory patch is removed | Downstream persistence action | Depends on redeployment method |

The original 2015 Skeleton Key investigation observed PsExec, `rundll32`, temporary
DLL placement, LSASS access, `VirtualProtectEx`, and `WriteProcessMemory`. Mimikatz
contains similar functionality, but detection evidence must not automatically label
an incident as the original Skeleton Key malware.

### Flow 5: Credential-Assisted Ransomware Propagation

| Step | Behavior | Direct or downstream | ATT&CK mapping |
|---|---|---|---|
| 1 | Execute credential-recovery code on a compromised host | Direct or derived implementation | T1003.001 |
| 2 | Recover credentials for reachable systems | Direct | T1003 |
| 3 | Propagate with PsExec, WMI, SMB, or another channel | Downstream | T1569.002, T1047, T1021.002 |
| 4 | Deploy encryptor or destructive payload | Downstream | T1486 or applicable impact technique |

NotPetya reporting requires careful wording. ATT&CK describes a modified Mimikatz
credential component. Cisco Talos reported code that appeared based on Mimikatz but
was not specifically canonical Mimikatz. The supported conclusion is
"Mimikatz-derived or Mimikatz-like credential recovery."

## Threat Actors Documented by MITRE ATT&CK

The following groups appear in the ATT&CK S0002 "Groups That Use This Software"
section as of the research cutoff. Inclusion means ATT&CK links one or more sources
to Mimikatz use. It does not establish that every operation by the group used the
tool.

| ATT&CK ID | Group | Qualification available on S0002 |
|---|---|---|
| G0082 | APT38 | Source-linked use |
| G0119 | Indrik Spider | Source-linked use |
| G1043 | BlackByte | Credential dumping during operations |
| G0093 | GALLIUM | Source-linked use |
| G0094 | Kimsuky | Source-linked use |
| G1017 | Volt Typhoon | Source-linked use |
| G0096 | APT41 | Source-linked use, including campaign-specific evidence |
| G0035 | Dragonfly | Source-linked use |
| G0045 | menuPass | Source-linked use |
| G0050 | APT32 | Source-linked use |
| G0069 | MuddyWater | Source-linked use |
| G0037 | FIN6 | Source-linked use |
| G0077 | Leafminer | Source-linked use |
| G0046 | FIN7 | Source-linked use |
| G0034 | Sandworm Team | Source-linked use |
| G0129 | Mustang Panda | Source-linked use |
| G1015 | Scattered Spider | Credential gathering with Mimikatz |
| G0087 | APT39 | Source-linked use |
| G1024 | Akira | Source-linked use |
| G0049 | OilRig | Source-linked use |
| G0008 | Carbanak | Source-linked use |
| G0004 | Ke3chang | Source-linked use; related reporting includes MimikatzLite |
| G0006 | APT1 | Source-linked use |
| G0079 | DarkHydrus | Source-linked use |
| G0108 | Blue Mockingbird | Source-linked use |
| G0010 | Turla | Source-linked use |
| G0092 | TA505 | Source-linked use |
| G0016 | APT29 | Source-linked use, including SolarWinds-related reporting |
| G0114 | Chimera | Source-linked use |
| G0003 | Cleaver | Source-linked use |
| G1051 | Medusa Group | LSASS dumping for credential harvesting |
| G0060 | BRONZE BUTLER | Source-linked use |
| G0088 | TEMP.Veles | Source-linked use, including TRITON-related reporting |
| G0135 | BackdoorDiplomacy | Source-linked use |
| G0107 | Whitefly | Source-linked use |
| G1030 | Agrius | LSASS credential dumping |
| G0007 | APT28 | Source-linked use |
| G1023 | APT5 | Source-linked use |
| G0131 | Tonto Team | Source-linked use |
| G1006 | Earth Lusca | Source-linked use |
| G0076 | Thrip | Source-linked use |
| G1004 | LAPSUS$ | Source-linked use |
| G0080 | Cobalt Group | Source-linked use |
| G0102 | Wizard Spider | Source-linked use |
| G1040 | Play | Source-linked use |
| G1001 | HEXANE | Source-linked use |
| G0059 | Magic Hound | Source-linked use |
| G0027 | Threat Group-3390 | Modified Mimikatz variant named Wrapikatz |
| G0064 | APT33 | Source-linked use |
| G1016 | FIN13 | Source-linked use |
| G0011 | PittyTiger | Source-linked use |
| G1055 | VOID MANTICORE | Listed by ATT&CK; no procedure text was displayed on S0002 at collection time |

## Campaigns Documented by MITRE ATT&CK

| ATT&CK ID | Campaign | Supported observation |
|---|---|---|
| C0017 | C0017 | APT41 ran `lsadump::sam` against dumped registry hives to obtain local credentials and NTLM hashes |
| C0018 | C0018 | ATT&CK source-linked Mimikatz use; review the campaign page and original sources before operationalizing |
| C0032 | C0032 | ATT&CK source-linked use associated with TEMP.Veles reporting |
| C0038 | HomeLand Justice | Source-linked Mimikatz use in the campaign against Albania |
| C0061 | Operation Digital Eye | Threat actors used custom Mimikatz implementations |
| C0014 | Operation Wocao | Operators used `privilege::debug` and `lsadump::dcsync /all` to dump account credentials |
| C0058 | SharePoint ToolShell Exploitation | Microsoft reported Mimikatz after exploitation in Storm-2603 activity |
| C0024 | SolarWinds Compromise | ATT&CK links Mimikatz use to post-compromise activity |
| C0030 | Triton Safety Instrumented System Attack | ATT&CK links Mimikatz to the campaign through TRITON actor reporting |

## Additional Representative Operations and Incidents

| Date or period | Actor or operation | Reported use | Confidence and caveat |
|---|---|---|---|
| 2014 observations, reported 2015 | Skeleton Key intrusion activity | Domain-admin credentials, PsExec, `rundll32`, and in-memory LSASS authentication patching | High for original Skeleton Key behavior; separate malware with a capability later available in Mimikatz |
| 2016 | Sandworm-associated Ukraine power intrusion activity | ATT&CK reporting associates Mimikatz with credential access | Moderate to high at procedure level; validate the original incident sequence before campaign-specific detection |
| 2017-06-27 | NotPetya or Nyetya | Credential-recovery component supported PsExec and WMI propagation | High for credential-assisted propagation; characterize as modified or Mimikatz-like |
| 2019 | Operation Wocao | Mimikatz used for credential dumping and DCSync | High at report level |
| 2019 | Ke3chang-linked Okrum activity | MimikatzLite used for LSASS credential dumping | High for the documented variant |
| 2020 | PoetRAT campaigns against Azerbaijan | `voStro.exe`, described as compiled `pypykatz`, stole credentials | High for overlapping LSASS behavior; not canonical Mimikatz |
| 2020 | SolarWinds or Solorigate post-compromise activity | Microsoft described identity abuse and Mimikatz-related detections | Preserve incident-specific evidence boundaries |
| 2021-05 to 2022-02 | APT41 targeting US state governments | Mandiant reported Mimikatz among post-exploitation tools | High at campaign level |
| Reported 2023-07-06 | BlackByte intrusion | Microsoft assessed that the actor likely used Mimikatz | Moderate; retain the word "likely" |
| 2025-07 | Storm-2603 SharePoint ToolShell exploitation | Microsoft reported Mimikatz use before Warlock ransomware deployment | High for Microsoft-observed activity; ransomware impact was downstream |

## Obfuscation and Detection-Avoidance Methods

| Method | Evidence-based interpretation | Detection implication |
|---|---|---|
| Renamed executable | Operators can rename public tooling | Treat names as enrichment, not identity |
| Recompiled or modified source | Public source permits changes to strings, metadata, imports, signatures, and hashes | Static hashes and exact strings cover only specific builds |
| Custom implementation | Campaigns have used custom implementations and capability-equivalent code | Focus on credential-source access and resulting identity behavior |
| `Invoke-Mimikatz` | PowerSploit packaged Mimikatz in PowerShell | Correlate PowerShell or AMSI evidence with LSASS access and authentication |
| Reflective PE loading | PowerSploit can map a PE into PowerShell memory without normal disk execution | Hunt for suspicious script hosts, memory allocation, injection, and LSASS targeting |
| Process injection | Loaders can allocate and write memory and create remote threads | API or EDR injection signals are useful but not Mimikatz-specific |
| PE header modification | Reflective loading code can erase initial `MZ` bytes in memory | Memory scanning should not require an intact DOS header |
| Loader or beacon embedding | Credential code can be embedded in a loader, C2 beacon, resource section, or another process | Correlate parentage, memory behavior, LSASS access, and authentication outcomes |
| Reduced command visibility | Embedded or API-driven use can omit canonical module commands | Do not require command-line strings in high-priority analytics |
| Offline parsing | LSASS dumps or registry hives can be acquired on one host and parsed elsewhere | Detect acquisition, staging, archive, and transfer stages |
| Forks and alternatives | MimikatzLite, Wrapikatz, `pypykatz`, and compiled `pypykatz` overlap with Mimikatz capabilities | Build behavior-led rather than product-led detections |
| Living-off-the-land dumping | Legitimate dump utilities or APIs can collect LSASS memory | Add target process, signer, path, parent, output file, and follow-on activity context |
| Security-control tampering | An actor may weaken Defender, ASR, LSA protection, Credential Guard, logging, or audit policy first | Correlate control changes with later LSASS or hive access |
| Kernel-assisted access | A vulnerable or malicious driver may bypass normal user-mode protection and telemetry | Include driver-load and vulnerable-driver controls; document visibility gaps |

## Durable Hunting Pivots

These artifacts are pivots and enrichment, not a blocking list.

| Type | Value or pattern | Context | Limitation |
|---|---|---|---|
| Filename | `mimikatz.exe`, `mimikatz.log` | Canonical binary or output | Easily renamed or disabled |
| Script or function | `Invoke-Mimikatz` | PowerSploit packaging | Can be renamed, encoded, or loaded indirectly |
| Command family | `sekurlsa::`, `lsadump::`, `kerberos::`, `crypto::`, `vault::` | High-context command vocabulary | Might be absent in embedded or modified builds |
| Target process | `lsass.exe` | Common live credential source | Security, backup, and diagnostic software can access LSASS |
| Sensitive hive | `SAM`, `SYSTEM`, `SECURITY` | Offline hash and secret acquisition | Backup and recovery products access the same hives |
| Registry area | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | SSP and LSA-protection settings | Legitimate security administration changes this area |
| Service artifact | `PSEXESVC` | PsExec remote execution | PsExec can be authorized and is not specific to Mimikatz |
| Skeleton Key sample name | `ole64.dll`, `ole.dll`, `msuta64.dll` | Original Skeleton Key investigation | Sample-specific, not canonical Mimikatz |
| Alternate implementation | `pypykatz`, MimikatzLite, Wrapikatz, `voStro.exe` | Overlapping or modified implementations | Name-only matching remains weak |

## Hunting and Detection Hypotheses

Every hypothesis requires local schema inspection. In Defender XDR, enumerate observed
`ActionType` values in the target tenant instead of assuming them.

### H1: Unusual Process Access to LSASS

* Priority: P0
* Hypothesis: A rare, unsigned, user-writable-path, script-hosted, recently
  downloaded, or remote-session process that accesses LSASS is more likely to
  represent credential theft than an approved security process.
* Defender XDR data: `DeviceEvents`, `DeviceProcessEvents`, alert evidence, and
  `DeviceFileEvents` for follow-on dump files
* Microsoft Sentinel data: Sysmon event 10 in `WindowsEvent`; Security events 4656
  and 4663 only when process-object auditing and suitable SACLs provide useful data
* Correlation: LSASS access followed by dump creation, archive creation, outbound
  transfer, suspicious logon, or remote execution
* Expected false positives: EDR, antivirus, backup, password synchronization,
  identity agents, diagnostics, crash collection, and forensics
* Validation: build signer, path, initiating-process, access-right, and device-role
  baselines; test negative controls before alerting
* ATT&CK: T1003.001

### H2: LSASS Dump Creation and Staging

* Priority: P0
* Hypothesis: A process that opens LSASS and creates a dump in a temporary,
  user-writable, administrative-share, or staging path before compression or transfer
  indicates offline credential acquisition.
* Defender XDR data: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`, and
  `DeviceNetworkEvents`
* Microsoft Sentinel data: Sysmon events 1, 10, and 11; Security event 4688 when
  command-line auditing is enabled
* Correlation: dump utility or suspicious process, LSASS target, dump file, archive,
  and network transfer within a bounded window
* Expected false positives: Windows Error Reporting, support tools, authorized crash
  diagnostics, incident response, and memory forensics
* Validation: confirm target PID, destination, parentage, signer, support ticket, and
  whether the dump contains LSASS memory
* ATT&CK: T1003.001, T1074.001 when staged

### H3: DCSync From an Unexpected Source

* Priority: P0
* Hypothesis: Directory-replication requests from an identity or device outside the
  approved replication ecosystem indicate attempted domain credential extraction.
* Defender XDR data: `IdentityQueryEvents`, Defender for Identity alerts, and
  `DeviceNetworkEvents` where useful
* Microsoft Sentinel data: domain-controller Security and directory-service logs;
  exact connector and audit coverage must be verified
* Correlation: replication operation, unusual source, privileged target such as
  `krbtgt`, and subsequent high-value authentication
* Expected false positives: domain controllers, Entra Connect, IAM, migration,
  backup, disaster recovery, and approved security tooling
* Validation: maintain explicit approved source and service-account inventories;
  test each expected replication platform
* ATT&CK: T1003.006

### H4: Pass-the-Hash or Replayed NTLM Followed by Remote Execution

* Priority: P0
* Hypothesis: An unusual NTLM network logon followed by service creation, WMI, SMB
  administration, or a remote process on one or more systems is consistent with
  replayed NTLM material.
* Defender XDR data: `DeviceLogonEvents`, `IdentityLogonEvents`,
  `DeviceProcessEvents`, and `DeviceEvents`
* Microsoft Sentinel data: Security events 4624, 4648, 4672, 4688, and system event
  7045 where available
* Correlation: rare account-source-target tuple, NTLM use, privileged logon, remote
  service or WMI execution, and multi-host fan-out
* Expected false positives: help desk, deployment systems, scanners, jump hosts,
  backup products, and legacy applications
* Validation: baseline management subnets, service accounts, and normal
  account-to-device relationships
* ATT&CK: T1550.002 and the observed remote-service technique

### H5: Protection Tampering Before Credential Access

* Priority: P0
* Hypothesis: Disabling or weakening Defender, the LSASS ASR rule, LSA protection,
  Credential Guard, audit policy, PowerShell logging, or Sysmon shortly before LSASS
  or hive access increases the likelihood of intentional credential theft.
* Defender XDR data: `DeviceRegistryEvents`, `DeviceProcessEvents`, and `DeviceEvents`
* Microsoft Sentinel data: Sysmon events 12 through 14, Security policy events,
  registry telemetry, Code Integrity logs, and Defender operational logs
* Correlation: unapproved privileged configuration change followed by LSASS access,
  dump creation, or sensitive-hive acquisition
* Expected false positives: policy deployment, troubleshooting, OS upgrade,
  application compatibility work, and security-product maintenance
* Validation: compare change-management windows and expected policy source; require
  downstream credential-access behavior for higher severity
* ATT&CK: T1562.001 plus the observed credential-access technique

### H6: PowerShell or Script-Hosted In-Memory Credential Access

* Priority: P1
* Hypothesis: Suspicious PowerShell or another script host exhibiting reflective
  loading, dynamic interop, memory allocation, injection, or credential-tool content
  followed by LSASS access indicates in-memory credential dumping.
* Defender XDR data: `DeviceProcessEvents`, `DeviceEvents`, alert evidence, and
  script content where licensed and available
* Microsoft Sentinel data: PowerShell events 4103 and 4104, AMSI or Defender
  telemetry, and Sysmon events 1, 8, and 10
* Correlation: encoded or downloaded script, reflective-loader behavior, LSASS
  target, and subsequent logon or dump artifact
* Expected false positives: red teams, administration frameworks, software
  deployment, and endpoint security products
* Validation: do not alert on generic API strings alone; require target and sequence
  context
* ATT&CK: T1059.001, T1620 or T1055 when evidenced, and T1003.001

### H7: Sensitive Registry-Hive Acquisition

* Priority: P1
* Hypothesis: Collection of multiple sensitive hives through `reg`, shadow copies,
  backup APIs, raw-volume access, or an unusual process followed by archive or
  transfer indicates offline hash and LSA-secret acquisition.
* Defender XDR data: `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceEvents`
* Microsoft Sentinel data: Sysmon events 1, 9, and 11; Security events 4656 and 4663
  with validated SACL coverage
* Correlation: two or more of SAM, SYSTEM, and SECURITY; unusual destination;
  archive; and outbound transfer
* Expected false positives: backup, recovery, forensics, migration, and endpoint
  management
* Validation: tune by process signer, user, path, host role, and maintenance window
* ATT&CK: T1003.002, T1003.004, and T1003.005 where applicable

### H8: Golden-Ticket Indicators

* Priority: P1
* Hypothesis: High-value Kerberos use from an implausible device, unusual ticket
  lifetime or encryption, missing expected authentication history, or a disabled or
  nonexistent principal can indicate a forged TGT.
* Defender XDR data: `IdentityLogonEvents`, `DeviceLogonEvents`, and Defender for
  Identity alerts
* Microsoft Sentinel data: Security events 4768, 4769, and 4624; account inventory;
  domain-controller collection
* Correlation: high-value identity, novel source, anomalous ticket properties,
  resource access, and any prior DCSync or `krbtgt` exposure
* Expected false positives: trusts, non-Windows clients, legacy encryption, stale
  inventory, logging gaps, and specialized applications
* Validation: confirm domain policy, patched event version, field population,
  account lifecycle, trusts, and clock alignment
* ATT&CK: T1558.001 and T1550.003

### H9: Silver-Ticket or Direct Service-Ticket Use

* Priority: P1 research analytic
* Hypothesis: Kerberos authentication recorded by a sensitive service without a
  corresponding expected event 4769 on any relevant domain controller can indicate
  a forged service ticket.
* Defender XDR data: `IdentityLogonEvents`, `DeviceLogonEvents`, and service-specific
  telemetry
* Microsoft Sentinel data: event 4769 from all relevant domain controllers,
  destination event 4624, service logs, synchronized clocks, and overlapping
  retention
* Correlation: negative KDC-chain result plus privileged user, sensitive SPN, novel
  device, or other suspicious context
* Expected false positives: collection loss, connector delay, retention mismatch,
  cross-domain activity, service behavior, and cache effects
* Validation: measure expected join success and use negative controls before any
  alerting deployment
* ATT&CK: T1558.002 and T1550.003

### H10: SSP or Authentication-Package Modification

* Priority: P1
* Hypothesis: An unexpected change to LSA security or authentication packages,
  followed by a new DLL or unusual LSASS image load, indicates credential
  interception or authentication tampering.
* Defender XDR data: `DeviceRegistryEvents`, `DeviceFileEvents`, and
  `DeviceImageLoadEvents`
* Microsoft Sentinel data: Sysmon events 7 and 11 through 14; Security events 4610
  and 4622 where collected; Code Integrity logs
* Correlation: registry modification, DLL creation, LSASS module load, and later
  credential or logon anomalies
* Expected false positives: authentication products, smart-card middleware,
  password filters, security software, and OS servicing
* Validation: maintain an approved plug-in inventory by domain-controller and server
  role
* ATT&CK: T1547.005 and T1556

### H11: Skeleton Key-Like Domain-Controller Activity

* Priority: P1
* Hypothesis: PsExec or service installation, `rundll32`, temporary DLL activity,
  LSASS memory modification, and unusual authentication success on a domain
  controller form a high-risk authentication-backdoor sequence.
* Defender XDR data: `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceEvents`, and
  `DeviceLogonEvents`
* Microsoft Sentinel data: system events 7036 and 7045; Sysmon events 1, 7, 8, 10,
  and 11; domain-controller logons
* Correlation: require several stages on a domain controller in a short period
* Expected false positives: authorized emergency administration, security testing,
  and support operations
* Validation: scope tightly to domain controllers and inspect memory-protection or
  process-tampering evidence
* ATT&CK: T1556.001 with observed execution and lateral-movement techniques

### H12: Credential Access Followed by Rapid Fan-Out

* Priority: P0
* Hypothesis: An account that authenticates to many systems or sensitive tiers soon
  after suspected credential access is more likely to represent stolen-credential
  expansion than ordinary user activity.
* Defender XDR data: `DeviceEvents`, `DeviceLogonEvents`, `IdentityLogonEvents`, and
  `DeviceProcessEvents`
* Microsoft Sentinel data: events 4624, 4768, and 4769 plus endpoint and network
  telemetry
* Correlation: credential-access event or alert followed by same-account fan-out,
  remote execution, or sensitive-tier access
* Expected false positives: software deployment, scanners, service accounts,
  orchestration, and jump-host operations
* Validation: use role-aware thresholds and compare account-source-target baselines
* ATT&CK: T1003 followed by T1078, T1550, or the observed remote-service technique

### H13: Private-Key, Certificate, or DPAPI Extraction

* Priority: P2
* Hypothesis: An unusual process accessing certificate stores, DPAPI material, or
  private-key locations and then exporting files or authenticating with a new
  certificate indicates theft of non-password authentication material.
* Defender XDR data: `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceEvents`
* Microsoft Sentinel data: CAPI operational logs, certificate-service logs, and
  validated Sysmon or Security file events
* Correlation: sensitive store access, export or copy, archive or transfer, and
  subsequent authentication
* Expected false positives: certificate enrollment, backup, browser activity,
  enterprise credential software, and key-management agents
* Validation: tune by key location, caller, signer, host role, and expected enrollment
  workflow
* ATT&CK: T1552.004 and T1649

### H14: Known Mimikatz Names, Commands, and Variants

* Priority: P2 enrichment
* Hypothesis: Canonical filenames, output files, command families, script names, or
  documented variants provide high-context leads when combined with behavioral
  evidence.
* Defender XDR data: `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceEvents`
* Microsoft Sentinel data: PowerShell logs, Sysmon events 1 and 11, and Security
  event 4688
* Correlation: name or string plus LSASS, hives, DCSync, suspicious logon, or remote
  execution
* Expected false positives: security testing, training labs, malware analysis, and
  documentation copied into scripts
* Validation: use as triage and enrichment rather than a primary detection boundary
* ATT&CK: map to the behavior actually observed

## Prioritized Detection Backlog

### P0: Implement First

1. LSASS access correlated with dump creation or downstream authentication.
2. DCSync from unapproved devices and identities.
3. Suspected PtH or NTLM replay followed by remote execution.
4. Credential-protection or audit-policy tampering followed by LSASS or hive access.
5. Credential-access evidence followed by privileged multi-host fan-out.

### P1: Implement After Prerequisite Validation

1. PowerShell, AMSI, or reflective-loading activity leading to LSASS access.
2. Sensitive registry-hive acquisition and offline-dump staging.
3. Golden-ticket and high-value Kerberos anomaly correlation.
4. Silver-ticket service use without an expected KDC chain as a research analytic.
5. SSP or authentication-package registry and LSASS module changes.
6. Skeleton Key-like behavior on domain controllers.
7. Pass-the-ticket or ticket-injection-linked resource access.

### P2: Add Supporting Coverage

1. Known names, commands, strings, output files, and public variants.
2. Kerberos replay, integrity, and encryption anomaly baselines.
3. DPAPI, certificate, and private-key extraction chains.
4. Rare credential-tool files and metadata for enrichment.

## Validation Plan

1. Confirm each table exists and required columns are populated.
2. Enumerate observed Defender XDR `ActionType` values before writing production
   filters.
3. Verify process creation and command-line collection.
4. Verify PowerShell module and script-block logging where appropriate.
5. Verify domain-controller Kerberos and directory-service auditing.
6. Verify Sysmon rules for LSASS access, process injection, registry changes, file
   creation, and process creation.
7. Verify required SACLs before depending on Security events 4656 or 4663.
8. Baseline EDR, antivirus, backup, IAM synchronization, password management,
   support, forensic, and red-team tooling.
9. Test only in an authorized isolated lab with nonproduction credentials.
10. Confirm event arrival time, clock alignment, retention overlap, join reliability,
    and field normalization.
11. Include approved LSASS readers, backups, replication services, PsExec use, and
    ordinary Kerberos traffic as negative controls.
12. Measure false-positive volume separately for workstations, servers, domain
    controllers, jump hosts, and identity-management systems.
13. Document the detection boundary, required telemetry, known bypasses, and response
    procedure before promotion to an analytic rule.

## Defensive Control Context

* Credential Guard isolates NTLM hashes, Kerberos TGTs, and application domain
  credentials with virtualization-based security. It does not protect the Active
  Directory database or local SAM, and Microsoft does not recommend it on domain
  controllers.
* Added LSA protection restricts untrusted reads and code injection into LSASS.
  Test LSA plug-ins, drivers, smart-card components, and password filters before
  broad enforcement.
* The Defender ASR rule for blocking credential stealing from LSASS can reduce
  exposure where Credential Guard or LSA protection cannot be enabled. Audit mode can
  be noisy, and one block event does not independently prove malicious activity.
* Restrict directory-replication rights and monitor every non-domain-controller
  principal that holds them.
* Tier administrative identities and prevent privileged credentials from reaching
  lower-trust systems.
* Reduce or disable NTLM where operationally possible, and monitor residual NTLM use.
* Rotate exposed service and computer keys. A golden-ticket response normally
  requires a carefully managed double rotation of `krbtgt` plus investigation of the
  original privilege path.

## Assessment Gaps and Uncertainty

* Public reporting sometimes uses "Mimikatz" for modified, embedded, derived, or
  functionally similar credential-recovery code.
* NotPetya characterization differs between ATT&CK and Cisco Talos. Detection content
  should use the qualified phrase "Mimikatz-derived or Mimikatz-like."
* Microsoft's BlackByte assessment says "likely" and should not be upgraded to
  confirmed use.
* Offline parsing can separate acquisition from parsing and move the identifiable
  tool outside endpoint visibility.
* Kernel-assisted dumping or protection bypass can evade ordinary user-mode process
  access telemetry.
* Credential Guard does not protect every credential source.
* Kerberos forgery detection is correlational. Missing event chains can indicate
  collection failure instead of forgery.
* Event versions, audit policy, SACLs, connectors, licensing, retention, and Defender
  schemas vary by tenant.
* ATT&CK group and campaign associations summarize cited reporting. They are not
  proof that the tool appears in every intrusion attributed to that actor.

## Sources

| # | Title | Publisher | Date | URL | Accessed |
|---|---|---|---|---|---|
| 1 | Mimikatz, Software S0002 | MITRE ATT&CK | Living reference, version 1.11 modified 2026-05-12 | <https://attack.mitre.org/software/S0002/> | 2026-09-01 |
| 2 | Mimikatz project repository and README | Benjamin Delpy, gentilkiwi | Current repository; release 2.2.0 dated 2022-09-19 | <https://github.com/gentilkiwi/mimikatz> | 2026-09-01 |
| 3 | Invoke-ReflectivePEInjection.ps1 | PowerSploit, PowerShellMafia | Repository archived 2021-01-21 | <https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1> | 2026-09-01 |
| 4 | Invoke-Mimikatz.ps1 | PowerSploit, PowerShellMafia | Updated for Mimikatz 2.1 on 2016-10-29 | <https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1> | 2026-09-01 |
| 5 | pypykatz | skelsec | Active repository | <https://github.com/skelsec/pypykatz> | 2026-09-01 |
| 6 | Credential Guard overview | Microsoft | 2026-04-27 | <https://learn.microsoft.com/windows/security/identity-protection/credential-guard/> | 2026-09-01 |
| 7 | Configure added LSA protection | Microsoft | Updated 2026-02-16 | <https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection> | 2026-09-01 |
| 8 | Attack surface reduction rules reference | Microsoft | Updated 2026-08-14 | <https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference> | 2026-09-01 |
| 9 | PoetRAT, Software S0428 | MITRE ATT&CK | Modified 2024-08-05 | <https://attack.mitre.org/software/S0428/> | 2026-09-01 |
| 10 | Okrum, Software S0439 | MITRE ATT&CK | Modified 2025-04-25 | <https://attack.mitre.org/software/S0439/> | 2026-09-01 |
| 11 | Sysmon | Microsoft Sysinternals | 2026-06-17 | <https://learn.microsoft.com/sysinternals/downloads/sysmon> | 2026-09-01 |
| 12 | Event 4656, a handle to an object was requested | Microsoft | Reference updated 2026-04-27 | <https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4656> | 2026-09-01 |
| 13 | Event 4663, an attempt was made to access an object | Microsoft | Reference updated 2026-04-27 | <https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4663> | 2026-09-01 |
| 14 | Event 4768, a Kerberos authentication ticket was requested | Microsoft | Reference updated 2026-04-27 | <https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768> | 2026-09-01 |
| 15 | Event 4769, a Kerberos service ticket was requested | Microsoft | Reference updated 2026-04-27 | <https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769> | 2026-09-01 |
| 16 | Skeleton Key Malware Analysis | Dell SecureWorks CTU, hosted by Sophos | 2015-01-12 | <https://www.sophos.com/en-us/research/skeleton-key-malware-analysis> | 2026-09-01 |
| 17 | Skeleton Key, Software S0007 | MITRE ATT&CK | Modified 2024-02-06 | <https://attack.mitre.org/software/S0007/> | 2026-09-01 |
| 18 | NotPetya, Software S0368 | MITRE ATT&CK | Modified 2025-04-16 | <https://attack.mitre.org/software/S0368/> | 2026-09-01 |
| 19 | New Ransomware Variant Nyetya Compromises Systems Worldwide | Cisco Talos | 2017-06-27, updated 2017-07-06 | <https://blog.talosintelligence.com/worldwide-ransomware-variant/> | 2026-09-01 |
| 20 | Joint report on publicly available hacking tools | UK NCSC and partner agencies | 2018-10-11 | <https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools> | 2026-09-01 |
| 21 | Operation Wocao | Fox-IT | 2019 | <https://www.fox-it.com/media/kadlze5c/201912_report_operation_wocao.pdf> | 2026-09-01 |
| 22 | Using Microsoft 365 Defender to coordinate protection against Solorigate | Microsoft | 2020-12-28 | <https://www.microsoft.com/security/blog/2020/12/28/using-microsoft-365-defender-to-coordinate-protection-against-solorigate/> | 2026-09-01 |
| 23 | APT41 targeting US state governments | Mandiant, Google Cloud Threat Intelligence | 2022 | <https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments> | 2026-09-01 |
| 24 | The five-day job, a BlackByte ransomware intrusion case study | Microsoft | 2023-07-06 | <https://www.microsoft.com/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/> | 2026-09-01 |
| 25 | Disrupting active exploitation of on-premises SharePoint vulnerabilities | Microsoft | 2025-07-22 | <https://www.microsoft.com/security/blog/2025/07/22/disrupting-active-exploitation-of-on-premises-sharepoint-vulnerabilities/> | 2026-09-01 |
| 26 | DeviceProcessEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table> | 2026-09-01 |
| 27 | DeviceFileEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-devicefileevents-table> | 2026-09-01 |
| 28 | DeviceEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceevents-table> | 2026-09-01 |
| 29 | DeviceLogonEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-devicelogonevents-table> | 2026-09-01 |
| 30 | DeviceImageLoadEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceimageloadevents-table> | 2026-09-01 |
| 31 | IdentityLogonEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-identitylogonevents-table> | 2026-09-01 |
| 32 | IdentityQueryEvents table | Microsoft | Living schema reference | <https://learn.microsoft.com/defender-xdr/advanced-hunting-identityqueryevents-table> | 2026-09-01 |
| 33 | SecurityEvent table | Microsoft Azure Monitor | Updated 2026-08-28 | <https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityevent> | 2026-09-01 |
| 34 | WindowsEvent table | Microsoft Azure Monitor | Updated 2026-07-28 | <https://learn.microsoft.com/azure/azure-monitor/reference/tables/windowsevent> | 2026-09-01 |
