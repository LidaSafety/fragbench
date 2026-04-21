# PROMPTFLUX — Source Evidence & Variation Dimensions

## What is PROMPTFLUX?

PROMPTFLUX is the first documented malware that uses an LLM during execution for
self-modification. Written in VBScript, it queries the Google Gemini API to rewrite
its own source code, producing a new obfuscated variant each time to evade
signature-based detection. Discovered in early June 2025 via suspicious VBScript
uploads on VirusTotal, it remains unattributed but is assessed as an experimental
proof-of-concept by a financially motivated actor.

---

## Sources

| # | Source | Date | Key Contribution |
|---|--------|------|------------------|
| [1] | [GTIG AI Threat Tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools) | 2025-11-05 | Primary source: module variants, prompts, persistence, LLM model used |
| [2] | [The Hacker News](https://thehackernews.com/2025/11/google-uncovers-promptflux-malware-that.html) | 2025-11-06 | "Thinking Robot" module details, hourly rewrite cadence |
| [3] | [Cybersecurity-Help](https://www.cybersecurity-help.cz/blog/5059.html) | 2025-11 | Logging path, propagation to USB/network shares, API key details |
| [4] | [The Register](https://www.theregister.com/2025/11/05/attackers_experiment_with_gemini_ai/) | 2025-11-05 | Discovery via VirusTotal uploads |
| [5] | [AI CERTs](https://www.aicerts.ai/news/promptflux-the-rise-of-ai-powered-malware/) | 2025-11-15 | Google safety layer bypass attempts, repeated micro-tuning |
| [6] | [CyberInsider](https://cyberinsider.com/promptflux-malware-uses-gemini-to-rewrite-and-hide-itself-in-real-time/) | 2025-11-05 | "Thinging" variant details, hourly full rewrite, recursive mutation |
| [7] | [GBHackers](https://gbhackers.com/promptflux-malware/) | 2025-11-06 | Assessment as PoC for AI-powered metamorphic malware |
| [8] | [CybersecurityNews](https://cybersecuritynews.com/promptflux-malware-using-gemini-api/) | 2025-11-06 | Documented filenames, social engineering lures |
| [9] | [CyberPress](https://cyberpress.org/promptflux-malware/) | 2025-11-06 | "Thinging" function replacement details |
| [10] | [PolySwarm](https://blog.polyswarm.io/rise-of-the-ai-enabled-malware) | 2025-11 | Broader context on AI-enabled malware trend |

---

## Variation Dimensions

The benchmark generates **648 structurally distinct variations** (2 x 3 x 4 x 3 x 3 x 3)
by combining six dimensions, each grounded in documented evidence.

### 1. Module Variant

Which internal module handles the LLM interaction.

| Value | Description | Evidence |
|-------|-------------|----------|
| `thinking_robot` | Original module; periodic queries; `AttemptToUpdateSelf` commented out | GTIG [1], Hacker News [2] |
| `thinging` | Later version; hourly full rewrite; recursive mutation chain | GTIG [1], CyberInsider [6] |

**Detection relevance:** Different module names appear in logs and process strings. The "Thinging" variant rewrites the entire source (more aggressive mutation), while "Thinking Robot" only requests partial changes.

### 2. Regeneration Frequency

How often the malware requests a new obfuscated version of itself.

| Value | Description | Evidence |
|-------|-------------|----------|
| `periodic` | Queries on a random timer (30–120 min) | GTIG [1]: "periodically queries the LLM" |
| `hourly` | Full rewrite every 60 minutes | GTIG [1]: "rewrite the malware's entire source code every hour" |
| `on_boot` | Regenerates only on system startup via Startup folder | Derived from documented Startup folder persistence |

**Detection relevance:** Different frequencies produce different network traffic patterns. Hourly produces regular beaconing; periodic is irregular; on-boot only triggers post-reboot.

### 3. Obfuscation Technique Requested

What specific obfuscation the LLM prompt asks for.

| Value | Description | Evidence |
|-------|-------------|----------|
| `variable_renaming` | Randomize all variable and function names | GTIG [1]: prompt requests "different variable names" |
| `string_encoding` | Change string encoding methods (Chr, hex, base64) | GTIG [1]: prompt requests "string encoding" changes |
| `control_flow` | Restructure control flow, reorder subroutines | GTIG [1]: prompt requests "control flow" changes |
| `combined_full_rewrite` | All techniques together — complete rewrite | CyberInsider [6]: "Thinging" variant does complete rewrite |

**Detection relevance:** Each technique produces different code patterns. Variable renaming changes identifiers but preserves structure; control flow changes alter the execution graph; combined rewrites change everything.

### 4. Propagation Method

How the malware spreads to other systems.

| Value | Description | Evidence |
|-------|-------------|----------|
| `usb_only` | Copies to removable USB drives (WMI DriveType=2) | GTIG [1] |
| `network_shares_only` | Copies to mapped network drives (WMI DriveType=4) | Cybersecurity-Help [3] |
| `both` | USB drives and network shares | GTIG [1] + Cybersecurity-Help [3] combined |

**Detection relevance:** USB propagation triggers removable media monitoring; network share propagation triggers file-copy alerts on shared drives. Combined produces both signatures.

### 5. Social Engineering Lure

What legitimate software the malware pretends to be.

| Value | Description | Evidence |
|-------|-------------|----------|
| `screen_recorder` | Poses as screen recording software (`crypted_ScreenRec_webinstall`) | GTIG [1]: documented filename |
| `ai_tool` | Poses as AI/productivity tool | Derived from GTIG [1]: broad, industry-agnostic targeting |
| `system_utility` | Poses as system optimizer/updater | Derived from installer-based delivery pattern |

**Detection relevance:** Different lure types target different user behavior patterns. A screen recorder appeals to content creators; an AI tool targets knowledge workers; a system utility targets less technical users.

### 6. Prompt Framing to LLM

How the obfuscation request is phrased to the Gemini API.

| Value | Style | Evidence |
|-------|-------|----------|
| `expert_obfuscator` | "You are an expert VBScript obfuscator. Rewrite the following script..." | GTIG [1]: documented prompt style |
| `code_only_directive` | Terse: "Rewrite this VBScript for AV evasion. Output only code." | GTIG [1]: "instructing the model to output only the code itself" |
| `developer_refactor` | "Refactor this VBScript with improved variable naming and string handling..." | Benign framing of same request — tests detector's ability to distinguish |

**Detection relevance:** Different framings may bypass different LLM safety filters. The "developer refactor" framing is indistinguishable from legitimate code review requests, testing whether a detector can identify malicious intent from context.

---

## Key Technical Details

### LLM Interaction
- **Model:** `gemini-1.5-flash-latest` (ensures resilience to model deprecation)
- **Access:** Hardcoded API key via HTTPS POST to Gemini endpoint
- **Auth tokens:** ~270 stolen Hugging Face tokens documented for related campaigns
- **Logging:** All Gemini responses logged to `%TEMP%\thinking_robot_log.txt`

### Persistence
- Saves obfuscated version to Windows Startup folder
- Each reboot runs a different obfuscated version
- Creates a recursive mutation chain (each version can regenerate the next)

### Skepticism
Marcus Hutchins (security researcher) noted the prompt works "under the assumption
that Gemini just instinctively knows how to evade antiviruses (it doesn't)."
Google's safety layer still flags many malicious prompts, though repeated
micro-tuning eventually yields executable output (AI CERTs [5]).

---

## Kill Chain Stages

| Stage | MITRE Tactic | MITRE Technique | Description | Dimensions Used |
|-------|-------------|-----------------|-------------|-----------------|
| 0 | Initial Access | T1566 | Social engineering lure as fake installer | social_engineering_lure |
| 1 | Execution | T1059.005 | VBScript dropper initializes LLM module | module_variant |
| 2 | Defense Evasion | T1027.005 | Queries Gemini for obfuscated self-rewrite | prompt_framing, obfuscation_technique |
| 3 | Persistence | T1547.001 | Writes to Startup folder with regen timer | regeneration_frequency |
| 4 | Lateral Movement | T1091 | Copies to USB/network shares | propagation_method |
