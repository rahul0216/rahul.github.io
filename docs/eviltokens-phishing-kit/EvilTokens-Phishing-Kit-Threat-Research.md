---
title: "EvilTokens Phishing Kit Threat Research and Hunting Hypotheses"
description: "Evidence-based analysis of EvilTokens device-code phishing, campaigns, evasion, ATT&CK mappings, and detection opportunities"
author: "rahul0216"
ms.date: 2026-09-07
ms.topic: reference
keywords:
  - EvilTokens
  - device code phishing
  - phishing as a service
  - business email compromise
  - Microsoft Defender XDR
  - Microsoft Sentinel
estimated_reading_time: 16
---

## Executive Summary

EvilTokens is a financially motivated phishing-as-a-service (PhaaS) platform
that has operated publicly since mid-February 2026. It turns Microsoft's
legitimate OAuth device authorization flow into an account-takeover workflow.
The victim authenticates on Microsoft infrastructure and may complete MFA, but
the resulting access and refresh tokens are delivered to the attacker's
session. No password theft or conventional MFA interception is required.

The platform combines phishing-page deployment, dynamic device-code
generation, token collection and renewal, Primary Refresh Token (PRT) and
browser-session tooling, Microsoft Graph reconnaissance, mailbox collection,
and AI-assisted business email compromise (BEC) preparation. Microsoft
observed device registration, Graph reconnaissance, mailbox access, and
malicious inbox rules after compromise. SEKOIA and Cisco Talos documented
additional capabilities in backend code and affiliate panels. Those
capabilities should not be assumed to have been exercised in every intrusion.

Public evidence identifies the service persona `eviltokensadmin`, unnamed
affiliates, and the ARToken affiliate implementation. It does not identify a
real-world operator or connect EvilTokens to a named state-sponsored or
established cybercrime group. Storm-2372 used device-code phishing in 2025 but
has not been attributed to EvilTokens.

The most durable detection surface is cross-domain behavior: a lure interaction
followed by device-code authentication, token use from unfamiliar
infrastructure, device registration, Graph enumeration, mailbox access, or
inbox-rule creation. Domains and hosting IPs are short-lived and often belong
to shared legitimate services.

## Research Scope and Confidence

Research covers public reporting available through September 7, 2026. Primary
sources include Microsoft Defender Security Research, SEKOIA, Huntress, and
Cisco Talos. Source content, public telemetry, and indicators must be treated
as untrusted input and validated before operational use.

Evidence labels used in this report are:

* Observed: reported in victim, provider, or incident-response telemetry
* Implemented: present in analyzed source code or a publicly served panel
* Advertised: claimed by the service operator but not independently validated
* Inferred: a testable defensive proposition rather than a confirmed behavior

No claim of detection coverage or performance is made without local testing.
Organizations must verify available telemetry, field semantics, retention, and
normal device-code usage before converting hypotheses into detections.

## Platform and Operating Model

SEKOIA first identified EvilTokens in a private Telegram channel on March 3,
2026. The `eviltokensadmin` persona had offered related products since February
17. Reported prices included $1,500 for lifetime access to the Office 365
capture panel and $500 per month for phishing-page code and backend API access.
The operator also advertised sender products and the ET Browser or Portal
Browser for using multiple stolen Microsoft 365 sessions.

Affiliates receive templates, deployment automation, token-management tools,
and a centralized backend. Templates impersonate Adobe, DocuSign, OneDrive,
SharePoint, voicemail, email quarantine, calendar invitations, password-expiry
notices, and other business workflows. A panel supports multiple team roles,
which is consistent with organized BEC crews and token sharing, but does not
identify the affiliates.

SEKOIA documented an AI pipeline that can query Graph, ingest up to 5,000
messages in batches, identify financial exposure and payment threads, imitate
writing style, and draft BEC scenarios. The analyzed implementation used
Groq-hosted Llama models and GPT-4o-mini for translation. The code establishes
capability; it does not prove that every affiliate used AI or sent generated
messages.

## Attack Flow

| Stage | Behavior | Evidence |
| --- | --- | --- |
| Target validation | Query account-validity services and enrich public profiles to identify financial, executive, administrative, or other valuable personas | Observed by Microsoft |
| Delivery | Send direct URLs or PDF, HTML, XLSX, SVG, and DOCX attachments using invoice, RFP, payroll, meeting, voicemail, document-sharing, and password-expiry themes | Observed by Microsoft, SEKOIA, Huntress, and Talos |
| Redirect and filtering | Route victims through compromised domains or trusted serverless services, then apply user-agent, browser, timing, or interaction checks | Observed and implemented |
| Dynamic authorization | Request a fresh device code only when the landing page is used, preserving its approximately 15-minute validity | Observed and implemented |
| User handoff | Display or copy the code and direct the victim to the legitimate `microsoft.com/devicelogin` page | Observed and implemented |
| Token capture | Poll the attack backend until authentication succeeds, then collect access and refresh tokens | Observed and implemented |
| Persistence | Renew tokens, register an attacker-controlled device, convert material to a PRT, or create browser and OWA sessions | Device registration observed; other paths implemented |
| Discovery | Query Graph for users, groups, roles, applications, domains, contacts, calendars, reporting lines, and organization details | Observed and implemented |
| Collection | Read and search mail, download attachments, and potentially access SharePoint, OneDrive, or Teams data | Mail observed; other services implemented |
| BEC preparation | Identify payment threads and high-value contacts, analyze writing style, and generate fraud scenarios | Implemented; AI-personalized lures observed |
| Follow-on action | Create forwarding or hiding rules, send as the victim, or place malicious shared files | Inbox rules observed; other actions implemented in ARToken |

### Device-code mechanism

The attacker initiates a legitimate device authorization request using a client
application and desired resource scopes. EvilTokens relays the returned user
code to the victim. The victim enters it at Microsoft's legitimate device login
page and completes normal authentication. The attacker's backend polls the
token endpoint and receives tokens after the victim approves the request.

Dynamic generation removes the operational weakness of older attacks that sent
an already-aging code. EvilTokens starts the validity window when the victim
reaches the final page. Some implementations copy the code to the clipboard and
poll for completion every three to five seconds.

## Actors and Campaigns

| Entity or activity | Period | Targets and use | Attribution assessment |
| --- | --- | --- | --- |
| `eviltokensadmin` | Since February 17, 2026 | Telegram sales, licensing, deployment bots, support, and product development | Confirmed service persona; real identity and location unknown |
| EvilTokens affiliates | From early March 2026 | Globally distributed phishing and BEC activity against finance, HR, logistics, sales, legal, executive, and other roles | Confirmed customer population; no basis to treat affiliates as one actor |
| Unnamed Railway affiliate | March 2026 | DocuSign and Outlook pages deployed from public repositories to Railway | SEKOIA assessed the repositories as affiliate-owned with high confidence; operator unnamed |
| Huntress Railway campaign | February 19 to March 19, 2026 | A surge affected 344 organizations in the United States, Canada, Australia, New Zealand, and Germany | Huntress explicitly associated the cluster with EvilTokens; one or multiple affiliates unresolved |
| Microsoft widespread campaign | Reported April 6, 2026 | AI-personalized lures, serverless redirect infrastructure, device registration, Graph discovery, email collection, and inbox rules | Microsoft stated that the activity aligned with EvilTokens; individual operators unnamed |
| ARToken | Lures observed April 20; reported July 1, 2026 | Targeted vendor-impersonation invoice phishing against US accounts-payable personnel; token, mailbox, SharePoint, and BEC tooling | Talos linked it to EvilTokens with high technical confidence; best treated as an affiliate implementation |
| NOIRLEGACY GROUP | March 2026 reporting context | Telegram venue where an early advertisement appeared | Distribution venue only; not attributed as operator, developer, or affiliate |

### Attribution exclusions

* Storm-2372 is a separate actor associated with a February 2025 device-code
  phishing campaign. Microsoft cited it as historical comparison, not as an
  EvilTokens affiliate.
* EvilProxy and other adversary-in-the-middle kits share customers and BEC
  objectives, but public evidence does not establish common ownership or code
  lineage.
* Railway, Cloudflare Workers, Vercel, AWS Lambda, DigitalOcean, and compromised
  legitimate sites are infrastructure, not actor identities.
* Device-code authentication, Graph access, token replay, and PRT abuse predate
  EvilTokens and cannot establish platform attribution by themselves.

## Targeting and Campaign Themes

SEKOIA collected 66 lure attachments by March 19 and tracked more than 1,000
associated pages. Campaigns reached the Americas, Europe, the Middle East, Asia,
and Oceania. The most affected countries in SEKOIA's collection were the United
States, Australia, Canada, France, India, Switzerland, and the United Arab
Emirates. These are telemetry-dependent observations, not a complete victim
distribution.

Lures targeted workflows likely to produce account access or BEC value:

* Financial reviews, invoices, investment proposals, and purchase orders
* Accounts-payable questions that abuse real vendor relationships
* Payroll adjustments and human-resources documents
* Logistics, shipping, manufacturing, and construction proposals
* DocuSign, Adobe, OneDrive, SharePoint, and generic shared documents
* Meeting invitations, voicemail, email quarantine, fax, and password expiry

Talos documented an ARToken email that spoofed a real vendor, changed the
`Reply-To` destination, failed SPF, DKIM, and DMARC, and used visible SharePoint
text that differed subtly from the actual attacker-controlled SharePoint link.
Random strings and inline image variation provided light per-message mutation.

## Obfuscation and Detection Avoidance

| Method | Defensive effect | Scope and confidence |
| --- | --- | --- |
| Legitimate Microsoft device login | The credential and MFA interaction occurs on a trusted domain | Core behavior, observed |
| Dynamic device-code generation | Codes are fresh when used and are absent from the original email | Core behavior, observed |
| Trusted and compromised redirectors | Shared reputation weakens domain-only and URL-only controls | Observed |
| Serverless and PaaS hosting | Cloudflare Workers, Railway, Vercel, and AWS blend with legitimate traffic and enable rapid rotation | Observed |
| Domain shadowing and randomized subdomains | Each lure can use a distinct hostname, reducing reputation value | Observed by Microsoft |
| AES-GCM runtime decryption | A small loader decrypts Base64 content with Web Crypto and injects the page at runtime | EvilTokens core pages, implemented |
| XOR runtime decryption | ARToken decrypts a JavaScript payload with a 16-byte XOR key | ARToken-specific, implemented |
| User-agent and automation filtering | Blocks crawlers, command-line clients, Selenium, Puppeteer, and Playwright | Core and ARToken variants, implemented |
| Browser and headless checks | Tests `navigator.webdriver`, browser features, vendor, dimensions, and input APIs | ARToken-specific, implemented |
| Human-interaction gates | Requires mouse or touch activity, minimum dwell time, and non-linear movement | ARToken-specific, implemented |
| Time-bound anti-bot header | `X-Antibot-Token` derives from a secret, timestamp, and `antibot`, with a five-minute acceptance window | Core fingerprint, implemented |
| Clipboard population | Reduces user friction and time between lure and authorization | Observed by Microsoft |
| Legitimate SharePoint hosting | Attacker-controlled Microsoft 365 tenants inherit trusted service reputation | ARToken campaign, observed |
| Per-message mutation | Random strings and image variation frustrate exact content matching | ARToken campaign, observed |
| Delayed post-compromise action | Some actors wait hours before inbox-rule creation or collection | Observed by Microsoft |

## MITRE ATT&CK Mapping

| ID | Technique | Rationale | Confidence |
| --- | --- | --- | --- |
| T1566.002 | Phishing: Spearphishing Link | Links and linked attachments lead victims into the authorization flow | High |
| T1204.001 | User Execution: Malicious Link | The victim opens the lure and follows its device-login instructions | High |
| T1528 | Steal Application Access Token | The platform captures access and refresh tokens issued after authorization | High |
| T1550.001 | Use Alternate Authentication Material: Application Access Token | Stolen tokens access Microsoft 365 without normal reauthentication | High |
| T1098.005 | Account Manipulation: Device Registration | Microsoft observed registration shortly after compromise to support persistence | High |
| T1087.004 | Account Discovery: Cloud Account | Graph enumeration collects tenant users and account context | High |
| T1069.003 | Permission Groups Discovery: Cloud Groups | Backend functions enumerate groups and directory roles | High |
| T1526 | Cloud Service Discovery | Implemented functions enumerate Azure subscriptions, resource groups, and resources | Medium |
| T1114.002 | Email Collection: Remote Email Collection | Microsoft observed email collection; platform code automates mailbox access | High |
| T1114.003 | Email Collection: Email Forwarding Rule | Microsoft observed malicious inbox rules and panels support forwarding | High |
| T1564.008 | Hide Artifacts: Email Hiding Rules | Rules can conceal replies or delete evidence from the mailbox | High |
| T1213.002 | Data from Information Repositories: SharePoint | ARToken implements SharePoint browsing and file operations | Medium |
| T1530 | Data from Cloud Storage | SharePoint and OneDrive collection is implemented but not proven in every campaign | Medium |
| T1027 | Obfuscated Files or Information | Core pages use AES-GCM and ARToken uses XOR runtime decryption | High |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | ARToken performs automation, browser, dimension, timing, and interaction checks | High for ARToken |
| T1583.006 | Acquire Infrastructure: Web Services | Affiliates use serverless and PaaS services for redirect, phishing, and polling nodes | High |

`T1531 Account Access Removal` is excluded because the sources do not establish
intentional victim lockout. `T1098.001 Additional Cloud Credentials` is less
precise than the directly supported device-registration sub-technique.

## Hunting and Detection Hypotheses

The following hypotheses are analytic starting points. Exact Microsoft Defender
XDR or Sentinel tables and fields must be selected from the locally available
schema before query development.

| Priority | Type | Hypothesis and correlation | Telemetry and window | False positives, tuning, and validation |
| --- | --- | --- | --- | --- |
| P0 | Technique-level | A click on a URL or linked attachment from an external or rare sender is followed by device-code authentication for the same user | Email, URL-click, and Entra sign-in concepts; 2 to 15 minutes | Exclude approved onboarding and known senders; test with an authorized device-flow application |
| P0 | Technique-level | A device authorization pending or interruption result, including code `50199` where applicable, is followed by success for the same user and session or correlation identifier | Entra authentication result and session concepts; 5 to 15 minutes | Baseline normal device enrollment and CLI use; verify error semantics in the tenant |
| P0 | Technique-level | Device-code authentication originates from a hosting provider or ASN not previously used by the user or tenant, then accesses Microsoft 365 resources | Sign-in protocol, IP, ASN, client, resource, and token-use concepts; 0 to 60 minutes | Hosting providers are shared; require behavioral corroboration and maintain tenant baselines |
| P0 | Technique-level | A new device registration follows suspicious device-code authentication for the same identity | Sign-in and directory or device audit concepts; 0 to 30 minutes | Exclude managed enrollment, help-desk windows, and known provisioning services; reproduce safely in a test tenant |
| P0 | Technique-level | Non-interactive token use appears from a new IP, geography, ASN, user agent, or client without a matching normal interactive session | Interactive and non-interactive sign-in concepts; 0 to 24 hours | Account for mobile networks, VPNs, brokers, and roaming; compare user and peer-group history |
| P1 | Kit-specific | A browser contacts `/api/device/start` and repeatedly polls `/api/device/status/` or `/state`, especially with `X-Antibot-Token` or `clientMode: "broker"` | Secure web gateway, proxy, HTTP inspection, browser, or network telemetry; same session within 15 minutes | Paths can be copied by unrelated kits; validate destination ownership and subsequent device login |
| P1 | Kit-specific | A Worker hostname matching EvilTokens service and target patterns leads to a device-login redirect and device-code sign-in | Email URL chain, DNS, proxy, and sign-in concepts; 30 minutes | Do not block all `workers.dev`; combine naming patterns, API paths, headers, and identity activity |
| P1 | Technique-level | A suspicious token event is followed by a burst of Graph calls for users, groups, roles, applications, domains, contacts, events, managers, or sent items | Cloud application and API audit concepts; 0 to 30 minutes | Baseline HR, identity-governance, backup, and administrative automation; score endpoint diversity and user rarity |
| P1 | Technique-level | Mail item access, attachment download, or mailbox search volume rises sharply after suspicious authorization or token use | Exchange and cloud application audit concepts; 0 to 6 hours | Compare historical volume, application, IP, ISP, and user role; validate against approved eDiscovery and backup jobs |
| P1 | Technique-level | A forwarding, deletion, hiding, transport, or symbol-only inbox rule is created after suspicious device-code or token activity | Exchange audit, inbox-rule, and sign-in concepts; 0 to 24 hours | Allowlist approved mail automation; retain rule names, actions, destinations, application, and source IP for review |
| P2 | Capability-led | SharePoint or OneDrive enumeration, bulk download, upload, sharing, or permission changes follow suspicious token acquisition | File collaboration and cloud audit concepts; 0 to 24 hours | Baseline sync clients, migrations, and collaboration tools; prioritize new apps, external sharing, and uncommon IPs |
| P2 | BEC-focused | A mailbox read or search burst is followed by sending as the victim, a changed reply path, a new external recipient, or activity in an existing payment thread | Mail read, send, rule, and message metadata concepts; 0 to 72 hours | Prioritize finance and executive personas; tune for delegates, shared mailboxes, CRM, and approved bulk senders |
| P2 | Capability-led | Access persists after password reset or refresh-token revocation through a newly registered device or changed browser session | Remediation timeline, token, session, sign-in, and device concepts; up to 24 hours | Do not infer PRT use from persistence alone; validate revocation timing and access-token lifetime in a test tenant |
| P3 | Kit-specific | Web content contains a small loader that combines Base64 decoding, `crypto.subtle`, AES-GCM, `TextDecoder`, and runtime document injection | Web-content capture, sandbox, or file telemetry | Legitimate encrypted web applications may match; use the published multi-string YARA logic and page-size constraints |

### Detection composition

High-confidence detections should combine independent signals rather than rely
on one indicator. Useful sequences include:

1. Rare sender or lure click, device-code pending state, and successful sign-in.
2. Device-code success, new hosting ASN, and device registration within 30
   minutes.
3. Suspicious token use, rapid Graph enumeration, and mailbox collection.
4. Suspicious authorization, mailbox reads, and an external forwarding or
   concealment rule.
5. EvilTokens HTTP fingerprint, Microsoft device-login navigation, and a
   matching identity event.

Microsoft has published Defender XDR hunting examples for the `50199`-to-success
sequence, URL-click correlation, device registration, inbox-rule creation, and
uncommon-ISP mailbox access. These queries should be reviewed against the
current product schema before reuse.

## Validation and Tuning Plan

1. Inventory legitimate device-code authentication by user, application,
   client, source network, role, and frequency for at least 30 days.
2. Confirm that email, URL-click, interactive and non-interactive sign-in,
   device audit, Graph, Exchange, and file collaboration telemetry is retained
   with joinable identity and session concepts.
3. Reproduce an authorized device-code flow in a test tenant and verify the
   expected authentication results, timing, client identity, and audit trail.
4. Test each hypothesis first as a hunt, record false-positive classes, then
   add scoring or multi-stage correlation before enabling alerts.
5. Validate historical EvilTokens indicators as investigation pivots. Do not
   block shared cloud ranges without current evidence and business review.
6. Measure detection delay from authorization to Graph or mailbox activity.
   EvilTokens automation can reduce the response window to minutes.

## Indicators and Tracking Pivots

| Type | Value or pattern | Use and limitation |
| --- | --- | --- |
| HTTP header | `X-Antibot-Token` | Strong core-kit fingerprint in inspected traffic; five-minute validity logic |
| HTTP header | `X-Tenant-Secret` | Affiliate-to-backend authentication observed by SEKOIA |
| HTTP paths | `/api/device/start`, `/api/device/status/`, `/state` | Behavioral pivots; require destination and identity context |
| Request property | `clientMode: "broker"` | EvilTokens and ARToken PRT-oriented implementation marker |
| ARToken domains | `pamconj.com`, `dashboard-bl.pamconj.com`, `spx.pamconj.com` | Historical Talos pivots; validate current resolution and ownership |
| EvilTokens domains | `bumpgames.net`, `update.youcreadio.cfd`, `docusend.networksolutionmail.com`, `framebound.cloud` | Historical SEKOIA examples, not a complete or current blocklist |
| Hosting ranges | `162.220.232.0/22`, `162.220.234.0/22` | Railway-associated activity; shared infrastructure creates blocking risk |
| Additional IP prefixes | `89.150.45.*`, `185.81.113.*`, `8.228.105.*` | Microsoft-observed sign-in infrastructure; validate notation and currency before use |

SEKOIA's public community repository and the Talos IOC bundle contain larger
collections. Most domains are disposable, and shared Cloudflare or Railway IPs
are unsuitable as standalone malicious verdicts.

## Defensive Priorities

* Block device-code flow with Conditional Access where it is not required.
* Restrict permitted device-code use to approved users, applications, devices,
  and contexts where business requirements permit.
* Enable Safe Links, anti-phishing controls, risky sign-in protections, and
  phishing-resistant authentication.
* Monitor new device registration, non-interactive token use, Graph discovery,
  mailbox access, and inbox-rule changes as one identity-centered sequence.
* On confirmed compromise, temporarily disable the account when immediate
  containment is necessary, revoke sessions and refresh tokens, remove
  unauthorized devices and rules, and inspect financial correspondence.
  Existing access tokens may remain usable for approximately one hour.

## Intelligence Gaps

* The real identity, location, and organization behind `eviltokensadmin` remain
  unknown.
* Public reporting does not enumerate individual affiliates or establish how
  many campaigns each operated.
* ARToken may be a licensed customization or a related code branch; Talos
  supports an affiliate relationship but not operator identity equivalence.
* The success rate, financial losses, and full victim count are not public.
* PRT, OWA, Azure, SharePoint, Teams, AI analysis, and token-sharing features
  are not independently observed in every intrusion.
* It remains unclear how often AI-generated BEC messages were sent rather than
  prepared for an operator.
* Infrastructure and indicators may have changed substantially since the
  published collections.

## Sources

* [Microsoft: Inside an AI-enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/), April 6, 2026
* [SEKOIA: New widespread EvilTokens kit, Part 1](https://www.sekoia.com/blog/new-widespread-eviltokens-kit-device-code-phishing-as-a-service-part-1), updated March 30, 2026
* [SEKOIA: EvilTokens AI-augmented BEC fraud, Part 2](https://www.sekoia.com/blog/eviltokens-an-ai-augmented-phishing-as-a-service-for-automating-bec-fraud-part-2), updated April 7, 2026
* [Huntress: Riding the Rails](https://www.huntress.com/blog/railway-paas-m365-token-replay-campaign), March 20, 2026, updated March 23, 2026
* [Huntress: How EvilTokens Turbocharges Old School Phishing with AI](https://www.huntress.com/blog/device-code-phishing-ai-mfa-bypass), May 11, 2026
* [Cisco Talos: ARToken, Inside an EvilTokens affiliate panel](https://blog.talosintelligence.com/artoken-inside-an-eviltokens-affiliate-panel-targeting-microsoft-365/), July 1, 2026
* [Cisco Talos ARToken IOC bundle](https://github.com/Cisco-Talos/IOCs/tree/main/2026/07)
* [SEKOIA EvilTokens community indicators](https://github.com/SEKOIA-IO/Community/tree/main/IOCs/eviltokens)
* [Microsoft OAuth 2.0 device authorization grant](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code)
* [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/)