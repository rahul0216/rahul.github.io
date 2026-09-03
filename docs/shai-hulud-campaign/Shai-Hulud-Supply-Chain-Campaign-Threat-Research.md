---
title: "Shai-Hulud Software Supply-Chain Campaign Threat Research"
description: "Analysis of the Shai-Hulud npm supply-chain campaign and threat-hunting hypotheses"
author: "rahul0216"
ms.date: 2026-09-04
ms.topic: reference
keywords:
  - Shai-Hulud
  - npm
  - software supply chain
  - threat hunting
  - Microsoft Defender XDR
  - Microsoft Sentinel
estimated_reading_time: 18
---

## Executive Summary

Shai-Hulud describes a succession of credential-stealing, self-propagating
software supply-chain attacks against developer workstations, CI/CD runners,
npm packages, GitHub repositories, and cloud environments. The activity began
as a mass npm worm in September 2025 and evolved through several operationally
distinct waves. Later variants added CI-only execution, OIDC abuse, encrypted
exfiltration, developer-tool persistence, provenance forgery, runner-memory
scraping, and fallback command-and-control mechanisms.

The common attack model is to compromise a package maintainer or release
workflow, publish a trusted package containing a lifecycle hook, harvest
credentials from the host and connected services, exfiltrate the material, and
use stolen package or source-control authority to propagate. Public release or
reuse of Mini Shai-Hulud source code weakens attribution across later waves.
Shared branding, filenames, and code lineage do not prove common operational
control.


## Research Scope and Confidence

Research covers public reporting available through September 4, 2026. Sources
include Microsoft, GitHub, government advisories, and original research from
security vendors. Package and version counts differ because sources measured
different dates, ecosystems, and units. A count of malicious package versions,
packages, repositories, or public exfiltration repositories must not be treated
as a victim count.

| Period | Activity | Assessment |
| --- | --- | --- |
| September 2025 | Original Shai-Hulud npm worm | Confirmed mass campaign |
| November 2025 | `Sha1-Hulud: The Second Coming` | Confirmed mass campaign and major technical evolution |
| December 2025 | `Goldox-T3chs: Only Happy Girl` | Confirmed sample in one package; likely limited or test deployment |
| April-May 2026 | Mini Shai-Hulud, SAP and broader waves, then `@antv` | Confirmed multi-wave campaign; moderate-confidence TeamPCP attribution for May activity |
| August 2026 | CHAINDROP/Keyv `Here We Go Again` | Confirmed mass campaign based on Mini Shai-Hulud source lineage |
| August 28-29, 2026 | Trinitite variant | Confirmed limited compromise; operator attribution unresolved |

## Campaign Evolution

### September 2025 original campaign

Compromised npm packages used a `postinstall` hook to execute a roughly 3.6 MB
`bundle.js` payload. The malware profiled Linux and macOS hosts, collected
environment variables, ran TruffleHog, queried AWS and Google Cloud secret
stores, created public GitHub repositories named or described with
`Shai-Hulud`, and inserted `.github/workflows/shai-hulud-workflow.yml`.

The worm used stolen npm credentials to identify packages the victim could
publish and released malicious versions to continue propagation. GitHub
reported removing more than 500 compromised packages. Reporting assessed
phishing or maintainer credential theft as a likely seed, but the original
campaign's initial compromise has not been publicly proven.

### November 2025 Second Coming

The Second Coming moved execution from `postinstall` to `preinstall`. A
`setup_bun.js` stage installed Bun and launched a heavily obfuscated
`bun_environment.js` payload. This wave added Azure Key Vault collection,
detached execution on developer systems, and a self-hosted GitHub Actions runner
named `SHA1HULUD`. It also created a discussion-triggered workflow and contained
a Linux home-directory shredding path for a destructive fallback condition.

Initial access varied by victim. PostHog documented exploitation of a vulnerable
`pull_request_target` workflow. Postman traced malicious dependencies entering
an unlocked build through AsyncAPI. These are confirmed organization-specific
paths and do not establish a universal seed for the campaign.

### December 2025 Golden Path

`@vietmoney/react-big-calendar@0.26.2` contained `bun_installer.js` and
`environment_source.js`. The sample used the repository description
`Goldox-T3chs: Only Happy Girl` and wrote staged collection files such as
`3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, and `pigS3cr3ts.json`.

Aikido and OX found no evidence of broad propagation or victim exfiltration.
Payload testing or a limited deployment is therefore a stronger assessment than
a widespread campaign.

### April and May 2026 Mini Shai-Hulud

Mini Shai-Hulud first appeared in SAP-related packages and then spread across
more than 170 npm packages and two PyPI packages over 404 malicious versions,
according to Microsoft. GitGuardian separately counted more than 300 packages
during the May 11-12 phase. The difference reflects collection time and counting
methodology rather than a direct contradiction.

The malware abused OIDC-enabled CI/CD publication, optional dependencies, npm
cache execution, Session messaging, attacker-accessible GitHub repositories,
Claude Code `SessionStart` hooks, VS Code tasks, and encrypted payloads.
Microsoft documented execution through an obfuscated `FilePII_*.js` payload
followed by an intentionally failed optional dependency installation.

### May 2026 antv wave

The May 19 `@antv` wave gated execution to Linux GitHub Actions environments.
Microsoft reported runner-memory scraping and theft targeting AWS, Kubernetes,
Vault, npm, and 1Password material. The malware attempted passwordless `sudo`,
forged SLSA provenance, used GitHub as fallback exfiltration, and installed a
Python backdoor at `~/.local/share/kitty/cat.py`.

GitHub removed 640 malicious versions and invalidated 61,274 writable npm
tokens. Wiz attributed the May activity to TeamPCP with moderate confidence,
based on infrastructure, malware functionality, and operational overlap. This
attribution should not be generalized to every later use of public Mini
Shai-Hulud code.

### August 2026 CHAINDROP and Keyv wave

Attackers compromised the Keyv maintainer's GitHub account, modified `main`, and
published provenance-signed releases beginning August 4. `setup.mjs` downloaded
Bun 1.3.13 and ran `Math_Symbol.js`; worm-created packages commonly used
`math_init.js`.

Aikido counted at least 444 packages across 1,381 versions as of August 5.
GitGuardian reported more than 800 packages across thousands of versions, and
the Cyber Security Agency of Singapore later reported more than 1,300
compromised versions. These figures are snapshots with different collection
criteria and are not interchangeable.

CHAINDROP expanded filesystem collection from 189 to 469 hardcoded locations.
It targeted AWS, Kubernetes, Vault, npm, GitHub, SSH, Terraform, Docker, IDE,
AI-agent, wallet, Slack, and Stripe material. It persisted through
`.claude/settings.json` and `.vscode/tasks.json`, used commits attributed to
`claude <claude@users.noreply.github.com>`, encrypted stolen data, created
repositories described as `Shai-Hulud: Here We Go Again`, and queried an
Ethereum contract for fallback command-and-control infrastructure.

### August 2026 Trinitite variant

Eight confirmed versions of `@7nohe/openapi-react-query-codegen` were
compromised on August 28 and 29. OX observed nine exfiltration repositories. The
variant reused Mini Shai-Hulud code while changing keys, branding, obfuscation,
state paths, and the Bun version. OX explicitly assessed attribution as
difficult.

## Infection and Attack Flow

### Stage 1: Maintainer or build-path compromise

Observed entry paths include stolen npm or GitHub credentials, compromise of a
maintainer GitHub account, vulnerable GitHub Actions configurations such as
`pull_request_target`, malicious transitive dependencies entering unlocked
builds, and abuse of OIDC-enabled trusted publishing. No single initial-access
method explains every wave.

### Stage 2: Trusted package publication

The operator publishes a malicious version under a legitimate package name.
Later waves abused trusted publishing or forged provenance, allowing the release
to retain signals that users may associate with a normal package build.

### Stage 3: Lifecycle-triggered execution

Package installation invokes `preinstall` or `postinstall`. Node.js executes a
bootstrap file that may install Bun and launch a larger, obfuscated JavaScript
payload. Mini variants also used optional dependencies and npm cache paths to
stage execution or conceal the causal package.

### Stage 4: Environment gating and host discovery

Payloads inspect operating system, architecture, hostname, username, environment
variables, and CI markers. Some versions prefer or require Linux GitHub Actions
runners. Others detach on developer endpoints. Gating reduces sandbox exposure
and selects hosts likely to contain publication or cloud credentials.

### Stage 5: Credential and secret discovery

Collection targets include environment variables, `.npmrc`, GitHub and npm
tokens, SSH keys, cloud CLI profiles, AWS instance metadata, Azure Key Vault,
Google Cloud secret stores, Kubernetes configuration, HashiCorp Vault,
Terraform, Docker, password stores, IDE settings, AI-agent configuration,
wallets, and third-party service credentials. Tools and code include TruffleHog,
direct filesystem reads, process-memory scraping, API calls, and cloud metadata
queries.

### Stage 6: Credential validation and privilege expansion

Stolen tokens are tested against GitHub, npm, cloud, and service APIs. The
malware enumerates packages and repositories the identity can modify, may test
passwordless `sudo`, and uses available publication or workflow authority to
expand access.

### Stage 7: Exfiltration and command and control

Observed channels include public or attacker-accessible GitHub repositories,
`webhook.site`, Session, direct HTTPS infrastructure, and GitHub fallback paths.
CHAINDROP encrypted data before upload and could retrieve fallback infrastructure
through an Ethereum smart contract queried through public RPC services.

### Stage 8: Propagation

The worm modifies packages accessible to stolen npm credentials or source-control
authority, adds lifecycle hooks and payload files, increments versions, and
publishes new releases. This turns each exposed maintainer or CI runner into a
potential propagation point.

### Stage 9: Persistence and destructive fallback

Observed persistence mechanisms include a self-hosted GitHub Actions runner,
discussion-triggered workflows, Claude Code `SessionStart` hooks, VS Code tasks,
macOS LaunchAgents, Linux user services, and the Kitty-path Python backdoor. The
November payload also contained a Linux home-directory shredding path. Public
reporting does not establish that every coded persistence or destructive path
executed successfully at scale.

## Affected Packages and Artifacts

The entries below are representative confirmed artifacts, not a complete block
list. Defenders should consume the cited vendor machine-readable inventories and
compare exact package versions against lockfiles, package caches, SBOMs, build
records, container layers, and endpoint telemetry.

| Activity | Representative confirmed packages and artifacts |
| --- | --- |
| September 2025 | `@ctrl/tinycolor`; GitHub reported more than 500 packages removed |
| November 2025 | Packages associated with Zapier, ENS, PostHog, and Postman/AsyncAPI-linked dependency paths; inventories vary by source |
| Golden Path | `@vietmoney/react-big-calendar@0.26.2` |
| May Mini | `@opensearch-project/opensearch` versions 3.5.3, 3.7.0, and 3.8.0; `@mistralai/mistralai` versions 2.2.2 through 2.2.4 |
| May `@antv` | `@antv/*`, `echarts-for-react`, `size-sensor`; reporting also identified GitHub Actions and `nrwl.angular-console@18.95.0` |
| August CHAINDROP | `keyv@6.0.0`, `flat-cache@6.1.24`, `file-entry-cache@11.1.6`, `cacheable@2.5.1`, `cache-manager@7.2.10`, and propagated packages |
| Trinitite | `@7nohe/openapi-react-query-codegen` versions 0.5.4, 0.5.5, 1.6.3, 1.6.4, 2.2.1, 2.2.2, 3.0.3, and 3.0.4 |

## Tools and Tradecraft

| Tool, service, or mechanism | Observed use |
| --- | --- |
| Node.js and npm lifecycle scripts | Bootstrap execution during dependency installation and package propagation |
| Bun | Execution runtime downloaded by several variants |
| TruffleHog | Local secret discovery in the September wave |
| GitHub API and repositories | Exfiltration, repository and workflow creation, propagation, and fallback transfer |
| GitHub Actions and self-hosted runners | CI execution, credential access, persistence, and downstream package publication |
| npm trusted publishing and OIDC | Publication using short-lived CI identity in Mini Shai-Hulud activity |
| Session messaging | Exfiltration channel in Mini Shai-Hulud reporting |
| Ethereum RPC and smart contract | Fallback infrastructure discovery in CHAINDROP |
| Cloud metadata and secret APIs | Discovery of AWS, Azure, and Google Cloud credentials or secrets |
| Claude Code hooks and VS Code tasks | Developer-environment persistence and later execution |
| LaunchAgents and systemd user services | Endpoint persistence for the May Python backdoor |
| SLSA provenance | Forged or abused release provenance in the `@antv` wave |

## Indicators of Compromise

Infrastructure hosted by GitHub, npm, Bun, or Ethereum RPC providers is not
independently malicious. Use shared-service indicators only with initiating
process, command line, file path, package, account, repository description, and
time-window context.

| Wave | Type | Indicator | Confidence and context |
| --- | --- | --- | --- |
| September | SHA-256 | `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09` | High; confirmed `bundle.js` |
| September | URL | `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7` | High; confirmed workflow exfiltration endpoint |
| September | File | `.github/workflows/shai-hulud-workflow.yml` | High; confirmed repository implant |
| November | Files | `setup_bun.js`, `bun_environment.js`, `.github/workflows/discussion.yaml` | High; confirmed payload and workflow names |
| November | Strings | `SHA1HULUD`; `Sha1-Hulud: The Second Coming` | High; runner name and repository description |
| Golden Path | Files | `bun_installer.js`, `environment_source.js`, `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json` | High; confirmed sample artifacts |
| Golden Path | String | `Goldox-T3chs: Only Happy Girl` | High; confirmed repository description |
| May `@antv` | SHA-256 | `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c` | High; confirmed JavaScript payload |
| May `@antv` | SHA-256 | `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142` | High; confirmed `cat.py` |
| May `@antv` | Domain and IP | `t.m-kosche.com:443`; `m-kosche.com`; `185.95.159.32` | Medium to high; reported command-and-control infrastructure |
| May `@antv` | Files and strings | `~/.local/share/kitty/cat.py`; `firedalazer`; `niagA oG eW ereH :duluH-iahS` | High; backdoor path, trigger, and reversed repository description |
| CHAINDROP | SHA-256 | `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668` | High; initial `setup.mjs` |
| CHAINDROP | SHA-256 | `fd3ca4007b225fdf8de7af4345a19179d5efa8c4bb9205f88cda806e5684b1eb` | High; propagated `setup.mjs` |
| CHAINDROP | SHA-256 | `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc` | High; `Math_Symbol.js` and `math_init.js` |
| CHAINDROP | URL | `https://npm-cache.com:443/router` | High; confirmed fallback exfiltration endpoint |
| CHAINDROP | Domains | `eth-mainnet.nodereal.io`, `go.getblock.io`, `eth.llamarpc.com`, `pypi-get.com`, `js-mirror.com` | Medium to high; RPC or reported network indicators |
| CHAINDROP | Contract | `0xE1f2395ee43e45A1556EC6438a88c31B83493103` | High; Ethereum contract used to retrieve command-and-control list |
| CHAINDROP | Files and strings | `setup.mjs`, `Math_Symbol.js`, `math_init.js`, `tmp.dpkg_14527.lock`, `Shai-Hulud: Here We Go Again`, `Bun/1.3.13` | High; confirmed artifacts |
| Trinitite | Strings and path | `Trinitite: Sponsored by Preview 2 Effects`, `n1ggatr1n`, `/var/tmp/.shit`, `IfYouRevokeThisTokenYourABadUser`, `Visit69WykenAveForFreeiPod` | High; confirmed artifacts in the limited variant |
| Trinitite | Domain | `poopy.com` | Low for detection; present but reported as unused |

## Behavioral Indicators of Attack

The following behaviors are more durable than static package names or hashes:

* An npm lifecycle process spawns Node.js or Bun to run an unfamiliar JavaScript
  file from a package directory or npm cache
* Dependency installation downloads a Bun runtime and immediately executes an
  obfuscated JavaScript payload
* A package-install process enumerates environment variables, `.npmrc`, cloud
  profiles, SSH keys, Kubernetes configuration, Vault tokens, Terraform files,
  IDE settings, AI-agent configuration, or wallet data
* Node.js or Bun reads cloud metadata endpoints or invokes cloud secret-manager
  APIs during package installation
* A build process downloads or executes TruffleHog without an approved security
  scanning step
* A CI runner process reads the memory or environment of adjacent processes
* A package-install process creates GitHub repositories, uploads JSON data,
  creates workflows, or registers a self-hosted runner
* A newly created GitHub repository uses a Shai-Hulud-related description or
  receives encrypted blobs immediately after a package installation
* A developer or CI identity publishes unexpected npm patch versions across
  several packages in a short interval
* A repository gains `.claude/settings.json`, `.vscode/tasks.json`, an unfamiliar
  workflow, or commits attributed to `claude <claude@users.noreply.github.com>`
* A package-install process contacts Session, `webhook.site`, a newly registered
  domain, or Ethereum RPC infrastructure
* A Linux or macOS package-install process creates a user systemd service,
  LaunchAgent, or `~/.local/share/kitty/cat.py`
* A GitHub Actions runner registers with the name `SHA1HULUD`
* A release workflow changes provenance or publication behavior shortly after an
  identity, workflow, or default-branch modification

## Threat Actor Profile

### Assessment

TeamPCP is the strongest named cluster for the May 2026 activity. Wiz assigned
moderate confidence based on infrastructure, malware functionality, and
operational overlap. The public availability and subsequent reuse of Mini
Shai-Hulud code reduce confidence that CHAINDROP, Trinitite, and every branded
variant were controlled by the same operator.

### Motivation

The consistent operational objective is broad credential acquisition followed
by access expansion and software supply-chain propagation. Targeted material
includes package publishing credentials, source-control tokens, cloud secrets,
CI/CD identity, Kubernetes and Vault access, SSH keys, wallets, and third-party
service credentials. This supports financially motivated credential theft and
access brokerage as plausible motives, while the destructive November fallback
also demonstrates sabotage capability. Public evidence does not establish a
single motive across all waves.

### Capability and sophistication

The campaigns show strong knowledge of npm lifecycle behavior, GitHub Actions,
trusted publishing, OIDC, cloud credential locations, package provenance, and
developer tooling. Operational improvements across waves include CI-aware
gating, source-code obfuscation, encrypted exfiltration, API-based propagation,
fallback infrastructure, and persistence through tools developers already use.

Execution quality was uneven. Public repositories exposed campaign data,
branding was conspicuous, some payload paths were apparently untested or
limited, and package counts expanded noisily. The actor or actors should be
treated as technically capable but not uniformly disciplined.

### Attribution gaps

The original September seed remains unproven. Public code reuse permits copycat
or independent operations. Shared strings, repository descriptions, filenames,
and source lineage are insufficient for actor attribution without infrastructure,
identity, temporal, or operational evidence.

## MITRE ATT&CK Mapping

Mappings reflect documented behavior, not execution-based validation or
detection coverage.

| ATT&CK technique | Confidence | Evidence |
| --- | --- | --- |
| T1195.001 Compromise Software Dependencies and Development Tools | High | Malicious versions published through compromised packages and release workflows |
| T1059.007 JavaScript/JScript | High | Node.js and Bun executed JavaScript install payloads |
| T1059.004 Unix Shell | High | Shell commands installed tooling, modified host state, and supported destructive actions |
| T1027 Obfuscated Files or Information | High | Multi-layer JavaScript obfuscation, encrypted strings, PBKDF2/AES, and XOR transformations |
| T1105 Ingress Tool Transfer | High | Bun, TruffleHog, runner archives, and secondary payloads were downloaded |
| T1082 System Information Discovery | High | Hostname, architecture, operating system, user, and CI context collection |
| T1083 File and Directory Discovery | High | Broad filesystem scanning, including 469 credential locations in CHAINDROP |
| T1552.001 Credentials In Files | High | `.npmrc`, cloud configuration, SSH keys, Vault tokens, Terraform, and IDE files targeted |
| T1552.006 Cloud Instance Metadata API | High | AWS IMDS and ECS metadata endpoints queried |
| T1528 Steal Application Access Token | High | GitHub, npm, OIDC, cloud, and service tokens collected and validated |
| T1555 Credentials from Password Stores | Medium | 1Password, browser stores, KeePass, Vault, and cloud secret stores targeted |
| T1546 Event Triggered Execution | High | GitHub workflows, Claude hooks, and VS Code tasks enabled later execution |
| T1543.001 Launch Agent | High for May | The Kitty-path monitor used a macOS LaunchAgent |
| T1543.002 Systemd Service | High for May | The Kitty-path monitor used a Linux user service |
| T1567.001 Exfiltration Over Web Service | High | GitHub repositories, `webhook.site`, Session, and HTTPS services carried exfiltration |
| T1537 Transfer Data to Cloud Account | High | Stolen information was uploaded to attacker-accessible GitHub repositories |
| T1485 Data Destruction | High for November | The Linux fallback contained home-directory shredding behavior |

## Hunting Hypotheses

These hypotheses are starting points for Microsoft Defender XDR and Microsoft
Sentinel content. They have not been executed against a tenant. Exact
`ActionType`, GitHub audit operation, cloud operation, and connector field values
must be validated against local telemetry before promotion to analytics.

### Hypothesis 1: Package installation launched a suspicious Bun payload

An exposed endpoint or CI runner executed a malicious npm lifecycle hook that
installed Bun and launched a campaign payload.

* Priority: Critical
* Primary telemetry: `DeviceProcessEvents`, supplemented by `DeviceFileEvents`
  and `DeviceNetworkEvents`
* Expected observations: npm, Node.js, a package manager, or a shell spawning Bun;
  command lines containing `setup_bun.js`, `bun_environment.js`, `setup.mjs`,
  `Math_Symbol.js`, `math_init.js`, `environment_source.js`, or `FilePII_`
* Entity pivots: device, account, parent process, package path, hash, remote URL,
  and CI job time window
* False positives: approved Bun installation or project scripts that legitimately
  invoke Bun during dependency resolution
* Detection direction: require package-manager ancestry and either an indicator,
  an unexpected package-cache path, a runtime download, or subsequent secret and
  network behaviors

### Hypothesis 2: Package execution performed broad credential discovery

A Node.js or Bun process descended from dependency installation read an unusual
concentration of credential files or queried secret services.

* Priority: Critical
* Primary telemetry: `DeviceFileEvents`, `DeviceProcessEvents`, cloud audit logs,
  and EDR file or API telemetry available in the environment
* Expected observations: access to `.npmrc`, `.aws`, `.azure`, `.config/gcloud`,
  `.kube/config`, Vault tokens, SSH keys, Terraform state, Docker configuration,
  password-store data, IDE configuration, or AI-agent settings within minutes of
  npm execution
* Entity pivots: initiating process, device, user, file path, package directory,
  cloud identity, and build identifier
* False positives: approved secret scanners, developer bootstrap scripts, or
  security tooling
* Detection direction: score diversity and volume of sensitive path families,
  then correlate with package installation and outbound traffic

### Hypothesis 3: A package-install process accessed exfiltration or control services

Node.js, Bun, or a shell process associated with npm contacted campaign
infrastructure or an unusual shared service immediately after credential access.

* Priority: Critical
* Primary telemetry: `DeviceNetworkEvents`, DNS or proxy logs, and
  `DeviceProcessEvents`
* Expected observations: connections to listed campaign domains or IPs;
  `webhook.site`; Session infrastructure; GitHub repository APIs; or Ethereum RPC
  services from package-manager descendants
* Entity pivots: remote URL, remote IP, initiating process, command line, device,
  account, package path, and preceding file access
* False positives: normal GitHub API use, blockchain development, Bun downloads,
  or approved webhook testing
* Detection direction: do not alert on GitHub or RPC domains alone. Require npm,
  Node.js, or Bun ancestry plus a rare destination, indicator, repository creation,
  or credential-discovery sequence

### Hypothesis 4: Shai-Hulud persistence artifacts were created

A malicious package changed a repository or developer profile to execute later
through GitHub Actions, Claude Code, VS Code, LaunchAgents, or systemd.

* Priority: High
* Primary telemetry: `DeviceFileEvents`, source-control audit data,
  `CloudAppEvents`, and `DeviceProcessEvents`
* Expected observations: creation or modification of
  `.github/workflows/shai-hulud-workflow.yml`,
  `.github/workflows/discussion.yaml`, `.claude/settings.json`,
  `.vscode/tasks.json`, `~/.local/share/kitty/cat.py`, LaunchAgent files, or user
  systemd units after package installation
* Entity pivots: repository, commit author, account, device, process, changed
  path, workflow trigger, and runner
* False positives: legitimate developer-tool configuration and expected workflow
  maintenance
* Detection direction: baseline file authors and repository paths; elevate changes
  from package-manager processes, CI identities, or the observed Claude commit
  identity

### Hypothesis 5: A stolen GitHub or npm identity propagated the worm

A compromised maintainer identity created repositories, workflows, runners,
tokens, releases, or multiple package versions outside its normal pattern.

* Priority: Critical
* Primary telemetry: `CloudAppEvents`, GitHub audit logs, npm audit or publication
  logs, and CI/CD logs
* Expected observations: rapid repository creation followed by JSON or encrypted
  uploads; new workflows; runner registration named `SHA1HULUD`; default-branch
  modification; package publication across several projects; or repository
  descriptions associated with the campaign
* Entity pivots: account, token, source IP, user agent, repository, package,
  workflow, runner, commit, and publication timestamp
* False positives: release automation, repository migration, or legitimate bulk
  maintenance
* Detection direction: compare behavior with the identity's historical package
  and repository set; correlate with new source networks, unusual user agents, and
  package-install telemetry

### Hypothesis 6: Compromised CI identity accessed cloud secrets

A token stolen from a developer host or CI runner accessed Azure resources or
secret material from a new context.

* Priority: High
* Primary telemetry: `SigninLogs`, `AuditLogs`, `AzureActivity`, Key Vault
  diagnostic logs, and workload identity sign-in logs
* Expected observations: service-principal or user sign-ins from unfamiliar IPs;
  secret reads; role or permission changes; credential additions; or resource
  enumeration after an affected package installation
* Entity pivots: `AppId`, `ServicePrincipalId`, user, source IP, resource ID,
  operation, affected runner, and exposed token time window
* False positives: deployment jobs, secret rotation, infrastructure automation,
  and administrator activity
* Detection direction: scope to identities present on exposed hosts or runners
  and begin the investigation window at the earliest possible package execution

### Hypothesis 7: CI runner memory or metadata was scraped

A malicious build step attempted to recover credentials from adjacent process
memory, environment state, or cloud metadata.

* Priority: High
* Primary telemetry: `DeviceProcessEvents`, Linux audit data, EDR telemetry,
  `DeviceNetworkEvents`, and CI job logs
* Expected observations: process inspection under `/proc`; reads of environment
  data from adjacent processes; cloud metadata requests from Node.js or Bun; or
  passwordless `sudo` checks during dependency installation
* Entity pivots: runner, job, process tree, target process, metadata endpoint,
  cloud identity, and package version
* False positives: diagnostics, monitoring agents, debuggers, and approved cloud
  bootstrap logic
* Detection direction: correlate process inspection or metadata access with npm
  ancestry and follow-on GitHub, npm, or cloud API use

### Hypothesis 8: Destructive fallback or self-hosted runner persistence executed

The November payload registered a persistent runner or invoked destructive Linux
commands after failing to obtain useful credentials.

* Priority: Critical
* Primary telemetry: `DeviceProcessEvents`, `DeviceFileEvents`, GitHub audit logs,
  and Linux audit data
* Expected observations: `Runner.Listener`, `config.sh`, `.dev-env`, runner
  registration using `--name SHA1HULUD`, or `shred` targeting writable paths in a
  user's home directory
* Entity pivots: device, user, process tree, repository or organization, runner
  token, affected paths, and preceding package installation
* False positives: authorized self-hosted runner deployment or legitimate secure
  deletion
* Detection direction: alert on the exact runner name or campaign paths; otherwise
  require npm ancestry, an unexpected repository owner, or high-volume home-path
  deletion

## Detection Engineering Priorities

1. Inventory exact malicious package versions across lockfiles, caches, build
   records, SBOMs, images, and developer systems.
2. Build process-tree detections for package-manager execution followed by Bun
   installation, obfuscated JavaScript execution, credential-path access, and
   external network connections.
3. Ingest and retain GitHub organization audit, npm publication, CI/CD, workload
   identity, Key Vault, cloud sign-in, DNS, proxy, and endpoint telemetry.
4. Baseline package publications, workflow changes, repository creation, runner
   registration, and developer-tool configuration by identity.
5. Use sequence-based analytics that join package installation, sensitive file
   access, API activity, and outbound transfer. Static shared-service indicators
   should remain enrichment rather than standalone alerts.
6. Validate local event names and fields before operationalizing detections. Cloud
   connectors and GitHub audit schemas vary by tenant and ingestion method.

## Investigation and Response Priorities

1. Isolate and rebuild systems that executed affected packages. Removing
   `node_modules` alone does not address stolen credentials or persistence.
2. Revoke and rotate npm, GitHub, OIDC, SSH, cloud, Kubernetes, Vault, CI/CD,
   signing, wallet, and third-party credentials reachable from exposed systems.
3. Remove unauthorized repositories, branches, workflows, self-hosted runners,
   Claude hooks, VS Code tasks, LaunchAgents, systemd services, and Python
   backdoors.
4. Audit cloud secret access and package publication from the earliest possible
   installation time.
5. Move publication to short-lived trusted identities, require phishing-resistant
   authentication, restrict workflow permissions, pin actions by commit, and
   review every use of `pull_request_target`.
6. Disable lifecycle scripts where operationally feasible and adopt package
   cooldown, provenance verification, dependency allowlisting, and controlled
   build-runner egress.

## Intelligence Gaps

* The initial seed for the September 2025 campaign remains assessed rather than
  proven.
* Public evidence does not establish one operator across all Shai-Hulud-branded
  or source-derived waves.
* Package counts differ by source date, ecosystem, and counting unit.
* Public exfiltration-repository counts do not equal unique victim counts.
* Some persistence and destructive paths were present in code but are not
  publicly confirmed as successfully exercised at scale.
* Tenant-specific Microsoft telemetry field values and analytic performance have
  not been validated as part of this research.

## Sources

* [GitHub: Our plan for a more secure npm supply chain](https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/)
* [Microsoft: Shai-Hulud 2.0 detection and investigation guidance](https://www.microsoft.com/en-us/security/blog/2025/12/09/shai-hulud-2-0-guidance-for-detecting-investigating-and-defending-against-the-supply-chain-attack/)
* [Microsoft: Mini Shai-Hulud compromised antv npm packages](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/)
* [StepSecurity: Original Shai-Hulud npm campaign](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
* [StepSecurity: Sha1-Hulud The Second Coming](https://www.stepsecurity.io/blog/sha1-hulud-the-second-coming-zapier-ens-domains-and-other-prominent-npm-packages-compromised)
* [Aikido: Shai-Hulud Golden Path](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)
* [OX Security: Shai-Hulud number three](https://www.ox.security/blog/shai-hulud-3-the-attack-continues/)
* [GitGuardian: Mini Shai-Hulud targeting the SAP ecosystem](https://blog.gitguardian.com/a-mini-shai-hulud-targeting-the-sap-ecosystem/)
* [Wiz: TeamPCP and the antv supply-chain compromise](https://www.wiz.io/blog/mini-shai-hulud-teampcp-hits-antv-supply-chain)
* [Aikido: Keyv and related package compromise](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)
* [Wiz: Keyv and Cacheable npm package hijack](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack)
* [GitGuardian: Mini Shai-Hulud Keyv wave](https://blog.gitguardian.com/keyv-mini-shai-hulud/)
* [Cyber Security Agency of Singapore: Keyv advisory](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/)
* [OX Security: Shai-Hulud Trinitite](https://www.ox.security/blog/shai-hulud-trinitite-sponsored-by-preview-2-effects/)
* [Wiz machine-readable Keyv package inventory](https://github.com/wiz-sec-public/wiz-research-iocs/blob/main/reports/keyv-packages.csv)