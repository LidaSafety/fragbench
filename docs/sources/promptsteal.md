# PROMPTSTEAL / LAMEHUG — Source Evidence & Variation Dimensions

## What is PROMPTSTEAL?

PROMPTSTEAL (tracked as LAMEHUG by CERT-UA, designation UAC-0001) is the first
publicly documented malware that queries a Large Language Model during live
operations. It was deployed by APT28 (Fancy Bear / GRU Unit 26165) against
Ukrainian government targets in summer 2025.

The malware sends pre-defined prompts to Qwen2.5-Coder-32B-Instruct via the
Hugging Face API, which generates Windows commands for system reconnaissance
and document harvesting at runtime.

---

## Sources

| # | Source | Date | Key Contribution |
|---|--------|------|------------------|
| [1] | [GTIG AI Threat Tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools) | 2025-11-05 | Exact prompts sent to the LLM |
| [2] | CERT-UA Advisory (UAC-0001) | 2025-07-17 | Attribution to APT28, delivery mechanism, SFTP exfil IP |
| [3] | [Cato CTRL: Analyzing LAMEHUG](https://www.catonetworks.com/blog/cato-ctrl-threat-research-analyzing-lamehug/) | 2025-07-23 | Decoy mechanisms, HTTP POST exfil, ~270 stolen HF tokens |
| [4] | dev.ua | 2025-11-09 | 110 APT28 attacks on Ukrainian state bodies, summer 2025 |
| [5] | [GBHackers](https://gbhackers.com/apt28-hackers-unveil-first-llm-powered-malware/) | 2025-07-24 | Assessment as proof-of-concept LLM weaponization |
| [6] | [CSO Online](https://www.csoonline.com/article/4025139/) | 2025-07-18 | Four delivery variants, C2 on compromised infrastructure |
| [7] | [VentureBeat](https://venturebeat.com/ai/black-hat-2025-chatgpt-copilot-deepseek-now-create-malware) | 2025-12-22 | AI image generator decoy details |
| [8] | [CybersecurityNews](https://cybersecuritynews.com/llm-powered-malware-from-apt28-hackers-integrates-ai-capabilities/) | 2025-07-24 | Generated command structure, "Return only commands" instruction |
| [9] | [The Hacker News](https://thehackernews.com/2025/07/cert-ua-discovers-lamehug-malware.html) | 2025-07-25 | Later variants target Office docs; SFTP + HTTP POST confirmed |
| [10] | [Picus Security](https://www.picussecurity.com/resource/blog/lamehug-the-first-publicly-documented-case-of-a-malware-integrating-a-llm) | 2025-08-11 | Specific Windows utilities in generated output |
| [11] | [CyberSurve](https://cybersurve.com/lamehug-ai-malware-analysis/) | 2025-09-27 | Behavioral detection indicators |

---

## Variation Dimensions

The benchmark generates **576 structurally distinct variations** (3 x 2 x 4 x 3 x 2 x 4)
by combining six dimensions, each grounded in documented evidence.

### 1. Delivery Format

How the malware was packaged and delivered to victims.

| Value | Evidence |
|-------|----------|
| `.pif` (PyInstaller binary) | CERT-UA [2]: primary observed variant (`Додаток.pif`) |
| `.exe` (standalone) | CSO Online [6]: `AI_generator_uncensored_Canvas_PRO_v0.9.exe`, `AI_image_generator_v0.95.exe` |
| `.py` (raw script) | CSO Online [6]: `image.py` development/testing variant |

**Detection relevance:** Different formats trigger different endpoint detection rules.

### 2. Decoy Type

What the victim sees while the malware executes in the background.

| Value | Evidence |
|-------|----------|
| Government PDF | Cato [3]: displays a legitimate-looking Ukrainian cybersecurity document from the Security Service |
| AI image generator | Cato [3], VentureBeat [7]: makes real API calls to Flux AI image generation endpoint as distraction |

**Detection relevance:** The image generator variant creates legitimate API traffic to Hugging Face, masking malicious LLM queries within normal AI platform usage.

### 3. Recon Command Family

Which Windows command set the LLM generates for system reconnaissance.

| Value | Utilities | Evidence |
|-------|-----------|----------|
| `cmd_native` | systeminfo, wmic, tasklist, netstat, ipconfig, dsquery | Picus [10]: confirmed as actual generated output |
| `powershell_cmdlets` | Get-ComputerInfo, Get-NetAdapter, Get-ADUser, Get-Process | Standard PowerShell equivalents of documented utilities |
| `wmi_queries` | wmic os get, wmic nic get, wmic useraccount | Partial overlap with documented `wmic` usage [10] |
| `cim_modern` | Get-CimInstance Win32_OperatingSystem, Get-CimInstance Win32_NetworkAdapter | Modern CIM replacement for WMI, common in enterprise environments |

**Detection relevance:** A detector trained on `systeminfo >> info.txt` patterns will miss `Get-ComputerInfo | Out-File info.txt` achieving the same goal.

### 4. Collection Scope

Which file types and folders the malware harvests documents from.

| Value | File Types | Folders | Evidence |
|-------|-----------|---------|----------|
| `original_pdf_txt` | .pdf, .txt | Documents, Downloads, Desktop | GTIG [1]: exact documented prompt |
| `expanded_with_office` | .pdf, .txt, .docx, .xlsx, .pptx | Documents, Downloads, Desktop | Hacker News [9]: later variants include Office docs |
| `broad_collection` | .pdf, .txt, .docx, .xlsx, .pptx, .csv, .rtf | Documents, Downloads, Desktop, OneDrive, Favorites | Logical extension of documented scope expansion |

**Detection relevance:** Different file extension filters and folder traversal patterns produce different filesystem access patterns.

### 5. Exfiltration Method

How staged data is sent to the attacker.

| Value | Protocol | Evidence |
|-------|----------|----------|
| `sftp` | SFTP to dedicated server (144.126.202.227 documented) | CERT-UA [2], Hacker News [9] |
| `http_post` | HTTP POST to compromised legitimate infrastructure | Cato [3], CSO Online [6] |

**Detection relevance:** SFTP creates distinct network signatures (encrypted SSH channels) vs HTTP POST which blends with normal web traffic.

### 6. Prompt Framing

How the reconnaissance request is phrased to the LLM.

| Value | Style | Evidence |
|-------|-------|----------|
| `direct_technical` | "Make a list of commands to gather computer information..." | GTIG [1]: exact documented prompt style |
| `sysadmin` | "I'm a system administrator troubleshooting network issues..." | Reflects campaign insight: these prompts look identical to legitimate sysadmin queries |
| `compliance_audit` | "Generate a script for our annual IT compliance audit..." | Enterprise context matching APT28's government targets |
| `incident_response` | "We suspect unauthorized access on this machine..." | Security context that produces different command choices |

**Detection relevance:** Different framings cause the LLM to generate structurally different command output. A compliance audit prompt may produce formatted reports; an incident response prompt may include log collection commands.

---

## Documented Prompts (Exact)

These are the prompts found in the actual LAMEHUG malware, base64-encoded and decoded at runtime.

**Prompt 1 — System Reconnaissance** (Source: GTIG [1], CSO Online [6], CybersecurityNews [8]):
> "Make a list of commands to create folder C:\Programdata\info and to gather computer
> information, hardware information, process and services information, networks information,
> AD domain information, to execute in one line and add each result to text file
> c:\Programdata\info\info.txt"
>
> Includes instruction: "Return only commands, without markdown."

**Prompt 2 — Document Harvesting** (Source: GTIG [1], CERT-UA [2]):
> "Create a list of commands that will recursively copy all .pdf and .txt documents from
> the Documents, Downloads, and Desktop folder to C:\Programdata\info"

---

## Kill Chain Stages

| Stage | MITRE Tactic | MITRE Technique | Description | Dimensions Used |
|-------|-------------|-----------------|-------------|-----------------|
| 0 | Initial Access | T1566.001 | Spearphishing with malicious attachment | delivery_format, decoy_type |
| 1 | Discovery | T1082 | System recon via LLM-generated commands | recon_command_family, prompt_framing |
| 2 | Discovery | T1087.002 | AD enumeration via LLM-generated commands | recon_command_family |
| 3 | Collection | T1074.001 | Document harvesting via recursive copy | collection_scope |
| 4 | Exfiltration | T1041 | Exfiltrate staged data to C2 | exfil_method |
