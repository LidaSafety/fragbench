# HONESTCUE — Sources and Variation Dimensions

## Campaign Overview

HONESTCUE is a malware framework that uses the Gemini API to generate its second-stage payload at runtime. The binary contains only a hardcoded prompt and API key — no malicious code exists until Gemini creates it. The generated C# is compiled and executed entirely in memory using the legitimate .NET `CSharpCodeProvider` class, leaving zero disk artifacts.

Likely a single actor or small group in proof-of-concept testing; unattributed.

---

## Primary Sources

| ID | Title | Date | URL |
|----|-------|------|-----|
| GTIG-2026-02 | GTIG AI Threat Tracker: Distillation, Experimentation, and Integration of AI for Adversarial Use | 2026-02-12 | https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use |
| CSN-2026-02 | Google Warns of Hackers Leveraging Gemini AI Model for All Stages of Cyberattacks | 2026-02-12 | https://cybersecuritynews.com/gemini-ai-model-cyberattacks/ |
| THN-2026-02 | Google Reports State-Backed Hackers Using Gemini AI for Recon and Attack Support | 2026-02-13 | https://thehackernews.com/2026/02/google-reports-state-backed-hackers.html |
| ITPRO-2026-02 | Google says hacker groups are using Gemini to augment attacks | 2026-02-12 | https://www.itpro.com/technology/artificial-intelligence/google-says-hacker-groups-are-using-gemini-to-augment-attacks-and-companies-are-even-stealing-its-models |
| CWZ-2026-02 | AI Weaponization: State Hackers Using Google Gemini for Espionage and Malware Generation | 2026-02-13 | https://cyberwarzone.com/2026/02/13/ai-weaponization-state-hackers-using-google-gemini-for-espionage-and-malware-generation/ |
| BC-2026-02 | Google says hackers are abusing Gemini AI for all attacks stages | 2026-02-12 | https://www.bleepingcomputer.com/news/security/google-says-hackers-are-abusing-gemini-ai-for-all-attacks-stages/ |

---

## Attack Stages

| Stage | MITRE Tactic | Technique | Description |
|-------|-------------|-----------|-------------|
| 0 | execution | T1059 | HONESTCUE launcher binary executes; contains only a hardcoded prompt and API key |
| 1 | resource_development | T1588.007 | Craft the hardcoded prompt that instructs the LLM to generate a functional malicious class |
| 2 | execution | T1059.009 | Send hardcoded prompt to Gemini API; receive C# source code as response |
| 3 | defense_evasion | T1027.011 | Compile returned C# in-memory via CSharpCodeProvider — no disk artifacts |
| 4 | command_and_control | T1071.001 | AI-generated C# downloads final payload from a CDN or legitimate hosting service |
| 5 | execution | T1106 | In-memory payload executes; evasion properties confirmed (fileless / polymorphic) |

---

## Variation Dimensions

### `prompt_type` — 3 values
*Source: CybersecurityNews [CSN-2026-02]: benign AITask test and Stage2 download-execute documented; utility framing from GTIG [GTIG-2026-02]*

| Value | Description |
|-------|-------------|
| `benign_test` | Launcher framed as a plugin/test system; class named `AITask` |
| `stage2_download` | Launcher framed as a deployment framework; class named `Stage2` |
| `utility_framing` | Launcher framed as an enterprise .NET utility platform; class named `RuntimeHelper` |

---

### `llm_target` — 3 values
*Source: GTIG [GTIG-2026-02]: Gemini API documented; OpenAI and Hugging Face derived alternatives*

| Value | Description |
|-------|-------------|
| `gemini_api` | Google Gemini API (documented in source) |
| `openai_api` | OpenAI Chat Completions API |
| `huggingface_api` | Hugging Face Inference API |

---

### `compilation_method` — 3 values
*Source: GTIG [GTIG-2026-02]: CSharpCodeProvider documented; Roslyn and PowerShell derived alternatives*

| Value | Description |
|-------|-------------|
| `csharp_codeprovider` | .NET CSharpCodeProvider with `GenerateInMemory = true` (documented) |
| `roslyn_compiler` | Roslyn CSharpCompilation API with `EmitToMemory()` |
| `powershell_invoke` | PowerShell `Invoke-Expression` for script-based payloads |

---

### `payload_hosting` — 4 values
*Source: GTIG [GTIG-2026-02]: Discord CDN documented; GitHub raw, Pastebin, cloud storage derived*

| Value | Description |
|-------|-------------|
| `discord_cdn` | Discord CDN attachment URL (documented in source) |
| `github_raw` | GitHub raw content URL |
| `pastebin` | Pastebin raw content URL |
| `legitimate_cloud` | Azure Blob Storage or AWS S3 pre-signed URL |

---

### `generated_code_complexity` — 3 values
*Source: CybersecurityNews [CSN-2026-02]: AITask hello-world and Stage2 download-execute documented*

| Value | Description |
|-------|-------------|
| `hello_world_test` | Simple test class printing a confirmation string (documented AITask behavior) |
| `download_execute` | Downloads binary from URL, writes to temp, executes via `Process.Start` (documented Stage2 behavior) |
| `download_inject` | Downloads shellcode, injects into process via P/Invoke (derived variant) |

---

### `evasion_strategy` — 3 values
*Source: GTIG [GTIG-2026-02]: fileless execution documented; CybersecurityNews [CSN-2026-02]: polymorphic generation*

| Value | Description |
|-------|-------------|
| `fileless_only` | `GenerateInMemory = true`; no temp files at any stage (documented) |
| `polymorphic` | Randomised class/method names injected before compilation; unique hash each run (documented) |
| `legitimate_api_blend` | `System.Net.Http.HttpClient` for API calls; traffic identical to legitimate dev tooling |

---

## Combinatorics

```
prompt_type (3) × llm_target (3) × compilation_method (3)
  × payload_hosting (4) × generated_code_complexity (3) × evasion_strategy (3)
= 972 structurally distinct variations
```

All dimension values are evidence-backed except where marked as "derived alternatives."
