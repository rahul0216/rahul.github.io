---
title: "GlassWorm Campaign Threat Research and Hunting Hypotheses"
description: "Evidence-based analysis of GlassWorm supply-chain activity, affected developer artifacts, indicators, actor profile, and detection opportunities"
author: "rahul0216"
ms.date: 2026-02-08
ms.topic: reference
keywords:
  - GlassWorm
  - software supply chain
  - Visual Studio Code
  - Open VSX
  - npm
  - Microsoft Defender XDR
  - Microsoft Sentinel
estimated_reading_time: 20
---

## Executive Summary

GlassWorm is a financially motivated software supply-chain campaign that
targets developers through malicious or compromised Visual Studio Code and
Open VSX extensions, npm packages, and GitHub repositories. Public reporting
connects activity beginning in 2025 with recurring use of invisible Unicode
variation selectors, staged JavaScript and native loaders, Solana transaction
memos as dead-drop resolvers, credential theft, remote access, and propagation
through stolen developer and publisher credentials.

The campaign's most important defensive characteristic is its access to a
developer workstation. A successful extension or package installation can
expose source code, browser sessions, cryptocurrency wallets, SSH keys, cloud
credentials, package-registry tokens, and CI/CD material from the same host.
The operator can then use stolen publishing or repository credentials to
compromise more artifacts.

CrowdStrike, Google, and Shadowserver disrupted four known command-and-control
(C2) channels on May 26, 2026. GlassWorm-linked Open VSX activity using a
TinyGo WebAssembly loader was reported in June 2026. The disruption therefore
neutralized a known infrastructure set but did not establish that the operator
or delivery toolkit had ceased activity.

The available evidence supports a financially motivated cybercriminal
assessment. Russian-language code comments and exclusions for Russian and
Commonwealth of Independent States (CIS) environments provide only
circumstantial attribution signals. No public evidence supports attribution
to a named criminal group, state sponsor, or specific individual.

## Research Scope and Analytical Guardrails

Research covers public reporting available through September 8, 2026. Primary
technical sources include Aikido Security, CrowdStrike, Truesec, and Yeeth
Security. Source content, repository samples, telemetry, schemas, and
indicators must be treated as untrusted input and independently validated
before operational use.

Evidence labels used in this report are:

* Observed: documented in provider, researcher, or incident telemetry
* Analyzed: present in a package, extension, loader, implant, or source sample
* Reported: stated by a source but not independently reproduced for this report
* Inferred: a testable analytical proposition rather than a confirmed behavior

This report does not claim that every artifact publicly labeled GlassWorm came
from one operator. Shared infrastructure, tradecraft, and targeting support a
campaign relationship, but public reporting sometimes combines adjacent
developer supply-chain campaigns. No detection coverage or optimization gain
is claimed without local validation. Exact Microsoft Defender XDR and
Microsoft Sentinel fields must be selected from the schemas available in the
target environment.

## Campaign Overview

Public reporting traces related invisible-Unicode activity to March 2025. Koi
Security named GlassWorm in October 2025, and later research documented new
Open VSX, Visual Studio Marketplace, npm, GitHub, native-loader, browser
extension, and WebAssembly waves. The campaign repeatedly changes delivery
artifacts while preserving several objectives:

* Obtain trusted execution through developer tooling
* Conceal initial code and delay analysis
* Resolve mutable C2 infrastructure through decentralized or legitimate
  services
* Steal developer, cloud, browser, and cryptocurrency credentials
* Maintain remote control and monetize victim connectivity
* Reuse stolen publishing access to extend the supply-chain compromise

Download counts, extension listings, repository counts, and scan detections
are not equivalent to infected hosts. Public sources measured different units
at different times, so totals should not be combined into a victim count.

## Infection and Attack Flow

| Stage | Behavior | Evidence |
|-------|----------|----------|
| Artifact placement | Publish counterfeit extensions or packages, compromise maintainer accounts, inject code into repositories, or add malicious transitive extension dependencies | Observed and analyzed |
| Trusted execution | Trigger through installation, automatic extension update, IDE activation, an npm lifecycle script, or execution of compromised repository code | Observed and analyzed |
| Loader concealment | Encode JavaScript with invisible Unicode variation selectors or use Base64, AES, RC4, ChaCha20, XOR, native Node add-ons, or WebAssembly | Analyzed across campaign generations |
| Environment checks | Delay execution, check connectivity, rate-limit execution, and exit for Russian-language, timezone, or CIS-location signals | Analyzed |
| C2 resolution | Read mutable infrastructure from Solana transaction memos; some variants use BitTorrent DHT, Google Calendar titles, or direct addresses | Analyzed |
| Payload retrieval | Start hidden PowerShell with `Invoke-RestMethod` and `Invoke-Expression`, use `curl | bash`, or dynamically import a Base64 data URL | Analyzed |
| Discovery and collection | Enumerate host data, processes, files, environment variables, browser profiles, wallets, source code, and developer or cloud credentials | Analyzed |
| Staging and exfiltration | Copy data into temporary directories, archive or encrypt it, and send it to operator infrastructure | Analyzed |
| Persistence and control | Create Run keys or scheduled tasks, launch VBScript and PowerShell chains, install Node or Go remote-access tooling, and deploy hidden VNC | Analyzed |
| Propagation and monetization | Use stolen GitHub, Git, npm, Open VSX, and cloud credentials for new compromises; steal wallets and sessions or proxy traffic through victim hosts | Observed and inferred from analyzed capabilities |

### Initial access

Operators use names and descriptions that resemble popular developer tools,
including WakaTime, Auto Import, Flutter, React, Claude, Vim, Vue, linters,
formatters, themes, and debugging utilities. Other incidents involved
compromised legitimate publisher or repository access. The user or an
automatic update mechanism supplies the initial trust decision.

### Execution and concealment

Early loaders hid JavaScript in Unicode variation selectors from
`U+FE00` through `U+FE0F` and `U+E0100` through `U+E01EF`. The visible source
could appear benign while runtime logic decoded bytes and passed the result to
`eval()`. Later generations added encrypted JavaScript, Rust or Zig native
Node add-ons, and TinyGo WebAssembly. The changes complicate static review but
still require a decoder, an execution boundary, and follow-on network or
process activity.

Windows variants commonly launch hidden PowerShell and use an
`Invoke-RestMethod | Invoke-Expression` pattern. Linux and macOS variants use
shell download-and-execute chains. Some JavaScript loaders dynamically import
`data:text/javascript;base64,...`, which avoids writing the decoded first
stage as a normal script file.

### Command and control

Solana transaction memos act as a dead-drop resolver rather than the final C2
channel. An implant can query a stable wallet address, decode the current host
or configuration from transaction data, and then connect to infrastructure
that the operator can rotate without updating the malicious package. Other
reported channels include BitTorrent DHT and Google Calendar titles.

This design creates a durable behavioral sequence: developer tool execution,
access to an unusual public resolution service, retrieval of a second stage,
and a new outbound connection. A Solana RPC connection alone is not malicious,
especially on systems used for Web3 development.

### Credential access and collection

Analyzed payloads search broadly across developer and user data, including:

* Git, GitHub, npm, and Open VSX credentials or tokens
* SSH private keys and configuration
* AWS, Azure, and Google Cloud configuration and credentials
* Docker, Kubernetes, and Terraform material
* Visual Studio Code storage and extension data
* Browser login, cookie, session, and web-data stores
* Cryptocurrency wallet files, browser extensions, and seed phrases
* Source repositories, environment files, and other secrets

The breadth of access matters more than a single file event. IDEs and command
line tools legitimately read some of these locations. Access to several
unrelated credential stores, followed by archive creation and outbound
traffic, provides stronger evidence.

### Persistence, remote access, and impact

Reported Windows persistence includes Run keys, startup scheduled tasks, and
VBScript-to-PowerShell launch chains from user-writable directories. Payloads
include persistent Node and Go remote-access tools, Socket.IO or WebSocket
control, hidden VNC, browser surveillance, and SOCKS or WebRTC proxy
functionality. Browser-focused components can capture keystrokes, screenshots,
and clipboard data or present wallet phishing interfaces.

Stolen publishing and source-control credentials create a recursive impact:
the compromise of one developer can enable malicious releases that reach more
developers. Potential impact includes source and cloud exposure, unauthorized
package publication, repository tampering, wallet theft, session hijacking,
remote host control, and abuse of victim connectivity.

## Affected Packages, Extensions, and Repositories

The following inventory contains source-confirmed or source-reported examples.
Absence from a current marketplace does not prove that an endpoint was never
exposed. Presence of the same extension name in a different marketplace also
does not prove compromise.

### October 2025 extension wave

Open VSX artifacts and reported malicious versions included:

| Extension | Version or versions |
|-----------|---------------------|
| `codejoy.codejoy-vscode-extension` | `1.8.3`, `1.8.4` |
| `l-igh-t.vscode-theme-seti-folder` | `1.2.3` |
| `kleinesfilmroellchen.serenity-dsl-syntaxhighlight` | `0.3.2` |
| `JScearcy.rust-doc-viewer` | `4.2.1` |
| `SIRILMP.dark-theme-sm` | `3.11.4` |
| `CodeInKlingon.git-worktree-menu` | `1.0.9`, `1.0.91` |
| `ginfuru.better-nunjucks` | `0.3.2` |
| `ellacrity.recoil` | `0.7.4` |
| `grrrck.positron-plus-1-e` | `0.0.71` |
| `jeronimoekerdt.color-picker-universal` | `2.8.91` |
| `srcery-colors.srcery-colors` | `0.3.9` |
| `sissel.shopify-liquid` | `4.0.1` |
| `TretinV3.forts-api-extention` | `0.3.1` |

The Visual Studio Marketplace also hosted
`codejoy.codejoy-vscode-extension` versions `1.8.3` and `1.8.4`, and
`cline-ai-main.cline-ai-agent` version `3.1.3`. Removal or containment status
must be checked against the marketplace and the endpoint's installation
history.

### December 2025 extension wave

Reported Visual Studio Marketplace artifacts included:

* `iconkieftwo.icon-theme-materiall`
* `prisma-inc.prisma-studio-assistance`
* `prettier-vsc.vsce-prettier`
* `flutcode.flutter-extension`
* `csvmech.csvrainbow`
* `codevsce.codelldb-vscode`
* `saoudrizvsce.claude-devsce`
* `clangdcode.clangd-vsce`
* `cweijamysq.sync-settings-vscode`
* `bphpburnsus.iconesvscode`
* `klustfix.kluster-code-verify`
* `vims-vsce.vscode-vim`
* `yamlcode.yaml-vscode-extension`
* `solblanco.svetle-vsce`
* `vsceue.volar-vscode`
* `redmat.vscode-quarkus-pro`
* `msjsdreact.react-native-vsce`

Reported Open VSX artifacts included `bphpburn.icons-vscode`,
`tailwind-nuxt.tailwindcss-for-react`, `flutcode.flutter-extension`,
`yamlcode.yaml-vscode-extension`, `saoudrizvsce.claude-dev`,
`saoudrizvsce.claude-devsce`, and `vitalik.solidity`. Exact versions were not
available in the retrieved source.

### March 2026 npm, repository, and extension activity

Confirmed or reported artifacts included:

| Ecosystem | Artifact | Version or scope |
|-----------|----------|------------------|
| npm | `@aifabrix/miso-client` | `4.7.2` |
| npm | `@iflow-mcp/watercrawl-watercrawl-mcp` | `1.3.0` through `1.3.4` |
| Visual Studio Code | `quartz.quartz-markdown-editor` | `0.3.0` |
| GitHub | Compromised repositories | At least 151 repositories reported |
| Open VSX | Malicious or transitive extensions | 72 extensions reported by Socket |

Examples of affected GitHub repositories were `pedronauck/reworm`,
`pedronauck/spacefold`, `anomalyco/opencode-bench`,
`doczjs/docz-plugin-css`, `uknfire/theGreatFilter`,
`sillyva/rpg-schedule`, and `wasmer-examples/hono-wasmer-starter`.
Reported injections were dated approximately March 3 through March 9, 2026.

Examples from the reported Open VSX set included
`angular-studio.ng-angular-extension`, `crotoapp.vscode-xml-extension`,
`gvotcha.claude-code-extension`, `mswincx.antigravity-cockpit`,
`tamokill12.foundry-pdf-extension`, `turbobase.sql-turbo-tool`, and
`vce-brendan-studio-eich.js-debuger-vscode`. The complete 72-extension source
appendix was not independently retrieved, so this report does not present the
examples as an exhaustive inventory.

### April through June 2026 extension activity

| Period | Artifact | Version or behavior |
|--------|----------|---------------------|
| April 2026 | `specstudio.code-wakatime-activity-tracker` | Installed a Zig native dropper |
| April 2026 | `floktokbok.autoimport` | Force-installed second-stage `autoimport-2.7.9.vsix` |
| May 2026 | `finlay-ab.vscode-latex-runner` | `0.0.9` |
| May 2026 | `aadityanarayan.code-snap` | `1.1.2` |
| May 2026 | `AsadBinImtiaz.kiro-vscode-extension` | `0.1.3` |
| May 2026 | `superdoc-dev.superdoc-vscode-ext` | `2.7.0` |
| May 2026 | `pdragon.azure-rbs-workbench` | `1.5.0` |
| May 2026 | `bigboi.legally-blind` | `0.1.7` |
| May 2026 | `Escalion.create-react-component` | `0.5.0` |
| May 2026 | `Ansvia.ansvia-vscode` | `0.4.1` |
| June 2026 | `ExarGD.vsblack` | `0.0.1` |
| June 2026 | `noellee-doc.flint-debug` | `0.1.1` |
| June 2026 | `kmsbofoxpf.fcrhyhewjv` | `0.0.1` |
| June 2026 | `sfqkrvjrtl.prdoypxjbi` | `0.0.1` |
| June 2026 | `GoNZooo.aurora-gonz` | `0.9.4` |
| June 2026 | `istornz.koby` | `1.0.0` |
| June 2026 | `qizhao.element-vue-snippets` | `2.0.2` |

Yeeth Security associated the June set with a TinyGo WebAssembly loader and
reported upload dates from June 9 through June 12, 2026. Same-name historical
extensions in another marketplace should not be labeled malicious without a
matching publisher, marketplace, version, hash, or other supporting evidence.

## Tools, Malware, and Infrastructure

| Component | Role | Assessment |
|-----------|------|------------|
| Invisible Unicode loader | Conceals JavaScript in variation selectors and decodes it at runtime | Campaign-defining early tradecraft |
| Native Rust and Zig Node add-ons | Executes platform-specific staging and cross-IDE installation | Analyzed in later waves |
| TinyGo WebAssembly loader | Runs portable loader logic with ChaCha20 or XOR-obfuscated strings | Analyzed in June 2026 wave |
| Solana memos | Supplies mutable C2 or payload location data | Repeated dead-drop resolver |
| BitTorrent DHT and Google Calendar | Supplies alternate decentralized or legitimate-service resolution | Reported in campaign generations |
| PowerShell, shell, and Node.js | Downloads, executes, and controls payloads | Living-off-the-land and runtime tooling |
| GlassWormRAT or custom RAT components | Provides command execution, surveillance, and persistence | Public payload label, not a separate actor |
| Hidden VNC | Provides interactive remote desktop control | Analyzed capability |
| SOCKS and WebRTC proxy tooling | Relays operator traffic through victim systems | Analyzed monetization or access capability |
| Fake browser and wallet extensions | Captures browser activity, sessions, clipboard data, and seed phrases | Analyzed capability |

No evidence reviewed for this report establishes that artificial intelligence
is a core malware component. Aikido assessed that realistic, project-specific
cover commits may have been generated or adapted with AI. That remains an
inference rather than confirmed operator tooling.

## Threat Actor Profile

| Dimension | Assessment |
|-----------|------------|
| Public name | GlassWorm or GLASSWORM; payloads are sometimes called GlassWormRAT |
| Actor type | Financially motivated cybercriminal operator or collaborating operators |
| Primary targets | Developers, maintainers, and organizations using IDE extensions, npm, GitHub, cloud tooling, CI/CD systems, and cryptocurrency wallets |
| Objectives | Credential and session theft, cryptocurrency theft, supply-chain propagation, remote access, and proxy-node monetization |
| Sophistication | High adaptability across JavaScript, Rust, Zig, Go, and WebAssembly; redundant C2 resolution; account compromise; counterfeit listings; and transitive dependencies |
| Attribution | Medium confidence of Russian-speaking or Russia-aligned criminal activity based on comments and geographic exclusions; nationality and location remain unknown |
| Named-group attribution | None supported by the reviewed evidence |

GlassWorm should not be equated with TeamPCP, Shai-Hulud, PhantomRaven,
PolinRider, or other developer supply-chain clusters without artifact-level
evidence. Some secondary reporting combines campaigns that share targets or
techniques but have not been shown to share operators.

## Indicators of Compromise

Indicator matches are investigation pivots, not verdicts. Infrastructure may
be reassigned, and `164.92.88.210` was reported as a defender-controlled
sinkhole after the May 2026 disruption. A post-disruption connection to that
address can indicate a previously installed implant rather than active
attacker C2.

### Network and dead-drop indicators

| Type | Indicator | Context |
|------|-----------|---------|
| Sinkhole IP | `164.92.88.210` | CrowdStrike sinkhole after May 26, 2026 |
| IP address | `45.32.150.251` | Reported payload or C2 infrastructure |
| IP address | `217.69.3.152` | Reported payload or C2 infrastructure |
| IP address | `217.69.0.159` | Reported payload or C2 infrastructure |
| IP address | `45.150.34.158` | Reported payload or C2 infrastructure |
| IP address | `217.69.3.218` | Reported payload or C2 infrastructure |
| IP address | `140.82.52.31` | Reported campaign infrastructure |
| Domain | `dodod.lat` | May and June payload infrastructure |
| Domain | `jhggnrfnst.com` | Go implant infrastructure |
| Solana address | `28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2` | C2 dead-drop resolver |
| Solana address | `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC` | C2 dead-drop resolver |
| Solana address | `6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ` | C2 dead-drop resolver |
| Solana address | `DSRUBTziADDHSik7WQvSMjvwCHFsbsThrbbjWMoJPUiW` | C2 dead-drop resolver |
| Solana address | `6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz` | C2 dead-drop resolver |
| Solana address | `7GyHfpK8uYY9ovMuS7N2LogbEpDGePBvMkNh5AsyS9ur` | C2 dead-drop resolver |

### File hashes

All values below are SHA-256 hashes.

| Hash | Context |
|------|---------|
| `2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02` | Zig Windows native add-on |
| `112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44` | Zig macOS native add-on |
| `fc714780730a85aff02cec5370630dd275d5e09a61d912eca06ff358e47ff277` | Go `Backup.exe` implant |
| `2417df8fdc0f94e22a850892e3f6f8bc7122a079073b5ea725b3b0f2076357d8` | TinyGo WebAssembly loader |
| `06fab21dc276e3ab9b5d0a1532398979fd377b080c86d74f2c53a04603a43b1d` | Wallet-phishing component |
| `f171c383e21243ac85b5ee69821d16f10e8d718089a5c090c41efeaa42e81fca` | Browser-theft component |
| `43253a888417dfab034f781527e08fb58e929096cb4ef69456c3e13550cb4e9e` | Browser-bypass component |
| `de81eacd045a88598f16680ce01bf99837b1d8170c7fc38a18747ef10e930776` | Hidden VNC component |
| `fdba5be3da2467e642bd8710f971e6b266b30ac15f5f413982fd719d7e0bffd9` | Chrome installer component |

### Host artifacts

| Type | Artifact |
|------|----------|
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\DefenderBackup` |
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateApp` |
| Run key | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateLedger` |
| Scheduled task | `UpdateApp` |
| Path | `%LOCALAPPDATA%\Backup\Backup.exe` |
| Path | `%APPDATA%\QtCvyfVWKH\index.js` |
| Path | `%LOCALAPPDATA%\QtCvyfVWKH\AghzgY.ps1` |
| Path | `%TEMP%\hJxPxpHP\` |
| Path | `%TEMP%\EUXFUxzOVe\` |
| Path | `%LOCALAPPDATA%\Google\Chrome\jucku\` |
| URL | `https://github.com/ColossusQuailPray/oiegjqde/releases/download/12/autoimport-2.7.9.vsix` |

### Behavioral strings

* `iwueyfiugviTV2igvrfiwegvfisegf24crpwejfo`
* `vsx_installer_zig`
* `data:text/javascript;base64,`
* `/agent/poll`
* `/agent/control`

These strings require context. Generic data URLs and agent endpoint paths can
appear in legitimate software. Combine them with signer, path, process lineage,
marketplace history, network activity, or a matching file hash.

## Indicators of Attack

Behavioral indicators are more durable than individual package names or C2
addresses:

* An IDE or Node.js process starts hidden PowerShell, `cmd.exe`, `wscript.exe`,
  `curl`, or a Unix shell from an extension directory
* PowerShell or shell downloads content and immediately executes it
* An IDE extension contacts a Solana RPC endpoint and then connects to a newly
  resolved host or downloads a payload
* JavaScript contains long variation-selector runs near byte-decoding logic,
  `Buffer.from`, dynamic import, or `eval`
* An IDE command-line interface silently installs a VSIX into several editors
* A new extension loads an unsigned or rare native `.node` add-on or WebAssembly
  module from a user-writable path
* One process reads several developer, cloud, browser, and wallet credential
  stores in a short interval
* Temporary credential collections are archived or encrypted before an
  outbound HTTP POST
* Persistence is created from IDE, Node.js, PowerShell, VBScript, or an
  extension-directory process lineage
* A newly installed extension or browser component opens periodic HTTP,
  WebSocket, Socket.IO, SOCKS, or WebRTC control channels
* A publisher account releases an extension or package from a new device,
  source address, workflow, or build provenance

## MITRE ATT&CK Mapping

| ID | Technique | Rationale | Confidence |
|----|-----------|-----------|------------|
| T1195.001 | Compromise Software Dependencies and Development Tools | Trojanized packages, IDE extensions, dependencies, and repositories provide execution | High |
| T1027 | Obfuscated Files or Information | Invisible Unicode, Base64, encryption, native loaders, and WebAssembly conceal logic | High |
| T1140 | Deobfuscate/Decode Files or Information | Loaders decode or decrypt content before execution | High |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Windows stages use PowerShell download-and-execute chains | High |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Linux and macOS stages use shell execution | High |
| T1059.007 | Command and Scripting Interpreter: JavaScript/JScript | Extension and Node.js loaders execute JavaScript | High |
| T1102.001 | Web Service: Dead Drop Resolver | Solana memos and Calendar content resolve mutable infrastructure | High |
| T1105 | Ingress Tool Transfer | Loaders retrieve VSIX, native, RAT, browser, and wallet components | High |
| T1614.001 | System Location Discovery: System Language Discovery | Variants inspect locale, timezone, and region to avoid selected systems | High |
| T1082 | System Information Discovery | Payloads profile the host and installed software | High |
| T1057 | Process Discovery | Payloads enumerate running processes | High |
| T1083 | File and Directory Discovery | Payloads search source, browser, wallet, and credential locations | High |
| T1552.001 | Unsecured Credentials: Credentials In Files | Payloads collect registry, cloud, CI/CD, and configuration secrets | High |
| T1552.004 | Unsecured Credentials: Private Keys | Payloads collect SSH and other private keys | High |
| T1555.003 | Credentials from Web Browsers | Payloads extract browser login, cookie, and web-data stores | High |
| T1056.001 | Input Capture: Keylogging | A fake browser extension records keyboard input | High |
| T1113 | Screen Capture | Browser and remote-access components capture screens | High |
| T1115 | Clipboard Data | Browser components collect clipboard content | High |
| T1547.001 | Registry Run Keys / Startup Folder | Run keys launch payloads from user-writable locations | High |
| T1053.005 | Scheduled Task/Job: Scheduled Task | The `UpdateApp` task provides persistence | High |
| T1560.001 | Archive Collected Data: Archive via Utility | Collected material is staged in archives | High |
| T1041 | Exfiltration Over C2 Channel | Staged data is sent through operator-controlled channels | High |
| T1090.001 | Proxy: Internal Proxy | Victim systems provide SOCKS or WebRTC proxy capability | High |
| T1036 | Masquerading | Fake tools, browser extensions, wallet interfaces, and update names disguise activity | High |
| T1219 | Remote Access Software | Custom WebSocket RAT and hidden VNC provide remote control | Medium |
| T1071.001 | Application Layer Protocol: Web Protocols | Payloads use HTTP, HTTPS, WebSocket, and Socket.IO | High |
| T1573 | Encrypted Channel | Campaign generations encrypt payloads, configuration, or transport | Medium |

## Hunting and Detection Hypotheses

These hypotheses are starting points for query and analytic-rule development.
They intentionally name data concepts before fields. Confirm table availability,
column semantics, retention, and platform coverage before implementation.

| Priority | Hypothesis and correlation | Likely Microsoft data | False positives, tuning, and validation |
|----------|----------------------------|-----------------------|----------------------------------------|
| P0 | An IDE or Node.js process launches hidden PowerShell, `cmd.exe`, `wscript.exe`, `curl`, or a Unix shell from an extension path | Defender XDR `DeviceProcessEvents` | Builds and developer tasks spawn shells; require download-and-execute syntax, hidden-window behavior, rare paths, or nearby network activity |
| P0 | A known GlassWorm hash, path, VSIX, native add-on, or WebAssembly file appears on an endpoint | `DeviceFileEvents`, `DeviceImageLoadEvents` | Generic filenames such as `Backup.exe` need hash, path, signer, or process-lineage support |
| P0 | Persistence is created by an IDE, Node.js, PowerShell, VBScript, or extension-directory ancestor | `DeviceRegistryEvents`, `DeviceProcessEvents`, `DeviceEvents` | Updaters create legitimate Run keys and tasks; validate command, signer, author, path, prevalence, and first-seen time |
| P0 | A developer endpoint connects to a known C2 address or the post-disruption sinkhole | `DeviceNetworkEvents` and ingested DNS, proxy, or firewall data | Confirm infrastructure ownership and event time; a sinkhole beacon indicates likely prior infection, not current attacker control |
| P1 | An extension contacts Solana RPC, Calendar sharing, or DHT infrastructure and then retrieves code or connects to a rare VPS | `DeviceNetworkEvents`, `DeviceProcessEvents` | Web3 and calendar use can be legitimate; require non-Web3 extension context, a resolver sequence, or payload execution |
| P1 | A new or updated extension loads an unsigned, low-prevalence `.node` library or WebAssembly module from a user-writable directory | `DeviceImageLoadEvents`, `DeviceFileEvents`, `DeviceProcessEvents` | Native and WebAssembly extensions are legitimate; baseline publisher, hash, signer, path, and fleet prevalence |
| P1 | One process reads several unrelated developer, browser, cloud, wallet, and SSH credential stores, then creates an archive | `DeviceFileEvents`, `DeviceProcessEvents` | IDEs and CLIs read credentials; breadth, short timing, staging, and outbound transfer raise confidence |
| P1 | A browser extension appears outside approved enterprise deployment and imitates a trusted Google or wallet extension | `DeviceFileEvents`, `DeviceRegistryEvents`, available browser inventory | Compare extension ID, installation source, policy, directory creation time, and expected signer or store metadata |
| P1 | A source file contains long invisible variation-selector runs plus decoder arithmetic and an execution primitive | Repository and CI scanning; endpoint file telemetry | Emoji variation selectors are benign; require length, decoder, `Buffer.from`, dynamic import, or `eval` context |
| P1 | An IDE command-line tool installs a VSIX into multiple editors without interactive user activity | `DeviceProcessEvents`, `DeviceFileEvents` | Enterprise provisioning can match; tune for approved deployment tools, packages, publishers, and maintenance windows |
| P1 | A newly installed extension establishes periodic HTTP, WebSocket, Socket.IO, SOCKS, or WebRTC connections | `DeviceNetworkEvents`, `DeviceProcessEvents` | Collaboration extensions can use persistent channels; correlate destination rarity, process ancestry, signer, and package age |
| P1 | A publisher or source-control identity performs unusual package releases, repository pushes, or secret access after endpoint compromise | `CloudAppEvents`, `SigninLogs`, `AuditLogs`, `AzureActivity`, and ingested GitHub or registry audit data | CI jobs and maintainer travel can match; compare token identity, source device, IP, MFA, repository set, and build provenance |

### Hypothesis validation priorities

1. Confirm whether the required endpoint, identity, source-control, registry,
   DNS, proxy, and browser telemetry is retained.
2. Build an authorized lab extension that performs one benign child-process or
   network action to verify event lineage and field semantics.
3. Baseline legitimate IDE-to-shell behavior, native add-ons, WebAssembly,
   Solana use, extension deployment, and publisher automation.
4. Test exact IOC matching separately from behavior correlations because their
   expected lifetimes and false-positive modes differ.
5. Validate each correlation on representative developer systems before
   promotion to an alert.
6. Record marketplace, publisher, version, hash, signer, first-seen time, and
   parent process for every extension-related finding.

## Investigation and Response Guidance

For a credible match, isolate the developer endpoint while preserving volatile
and disk evidence. Enumerate every installed IDE and extension directory,
acquire suspect VSIX or package files, calculate hashes, and review extension
installation and update history. Inspect persistence, temporary staging,
browser extensions, active network connections, and process ancestry.

Assume developer credentials accessible from the host may be exposed. From a
known-clean system, rotate or revoke GitHub, Git, npm, Open VSX, SSH, cloud,
Kubernetes, CI/CD, and other tokens. Invalidate browser sessions and review
package publication, repository commits, workflow changes, cloud activity,
and secret access. Compare suspicious commits and released artifacts with
trusted source and reproducible build output where available.

Do not remove only the named extension and return the host to service. Later
stages can persist independently of the original delivery artifact.


## Sources

* Aikido Security, [Glassworm Is Back: A New Wave of Invisible Unicode Attacks Hits Hundreds of Repositories](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode), published March 13, 2026, updated March 17, 2026, accessed September 8, 2026
* Aikido Security, [GlassWorm Hides a RAT Inside a Malicious Chrome Extension](https://www.aikido.dev/blog/glassworm-chrome-extension-rat), published March 18, 2026, accessed September 8, 2026
* Aikido Security, [GlassWorm goes native: New Zig dropper infects every IDE on your machine](https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine), published April 8, 2026, updated April 21, 2026, accessed September 8, 2026
* CrowdStrike, [Inside CrowdStrike's Takedown of a Developer-Targeting Botnet](https://www.crowdstrike.com/en-us/blog/inside-crowdstrike-takedown-of-a-developer-targeting-botnet/), published May 2026, accessed September 8, 2026
* The Hacker News, [GlassWorm Returns with 24 Malicious Extensions Impersonating Popular Developer Tools](https://thehackernews.com/2025/12/glassworm-returns-with-24-malicious.html), published December 2, 2025, accessed September 8, 2026
* The Hacker News, [GlassWorm Supply-Chain Attack Abuses 72 Open VSX Extensions to Target Developers](https://thehackernews.com/2026/03/glassworm-supply-chain-attack-abuses-72.html), published March 14, 2026, accessed September 8, 2026
* The Hacker News, [GlassWorm Malware Takedown Disrupts Developer Supply Chain Attack Infrastructure](https://thehackernews.com/2026/05/glassworm-malware-takedown-disrupts.html), published May 27, 2026, accessed September 8, 2026
* Truesec, [GlassWorm: Self-Propagating VSCode Extension Worm](https://www.truesec.com/hub/blog/glassworm-self-propagating-vscode-extension), published October 21, 2025, accessed September 8, 2026
* Yeeth Security, [A Deeper Look at GLASSWORM's Solana Variant](https://yeethsecurity.com/blog/2026-05-25-Glassworm-Solana), published May 25, 2026, accessed September 8, 2026
* Yeeth Security, [GLASSWORM.WASM: Deconstructing the TinyGo WebAssembly Loader Hitting Open VSX](https://yeethsecurity.com/blog/2026-06-16-Glassworm-WASM), published June 16, 2026, accessed September 8, 2026
