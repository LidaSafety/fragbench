# MALTERMINAL — Sources and Variation Dimensions

## Campaign Overview

MalTerminal is the earliest known LLM-enabled malware, pre-dating the 2025 wave by over a year. It is a Python binary compiled to a Windows EXE via Python2EXE that queries OpenAI GPT-4 at runtime to generate ransomware or reverse shell code on demand. No static malicious payload exists in the binary — all malicious logic is synthesised by GPT-4 during execution. Discovered by SentinelLABS via a year-long VirusTotal retrohunt and presented at LABScon 2025.

The same developer built both the offensive MalTerminal and a defensive GPT-based scanner called FalconShield (TestMal3.py / Defe.py), demonstrating the dual-use nature of LLM-enabled security tools.

---

## Primary Sources

| ID | Title | Date | URL |
|----|-------|------|-----|
| SL-2025-09 | Prompts as Code & Embedded Keys: The Hunt for LLM-Enabled Malware | 2025-09-19 | https://www.sentinelone.com/labs/prompts-as-code-embedded-keys-the-hunt-for-llm-enabled-malware/ |
| THN-2025-09 | Researchers Uncover GPT-4-Powered MalTerminal Malware Creating Ransomware, Reverse Shell | 2025-09-21 | https://thehackernews.com/2025/09/researchers-uncover-gpt-4-powered.html |
| CP-2025-09 | MalTerminal Powered by GPT4 Generates Sophisticated Ransomware | 2025-09-22 | https://cyberpress.org/malterminal-gpt4-ransomware/ |
| DSR-2025-10 | GPT-4-Powered MalTerminal Malware Automates Ransomware Creation: Reverse Shells at Scale | 2025-10-17 | https://dailysecurityreview.com/cyber-security/data-security/gpt-4-powered-malterminal-malware-automates-ransomware-creation-reverse-shells-at-scale/ |
| ESP-2025-09 | GPT-4 Malware Generates Ransomware in Real Time | 2025-09-22 | https://www.esecurityplanet.com/news/malterminal-malware-gpt-4/ |
| CSN-2025-09 | First-ever AI-powered MalTerminal Malware uses OpenAI GPT-4 to Generate Ransomware Code | 2025-09-21 | https://cybersecuritynews.com/first-ever-ai-powered-malterminal-malware/ |
| SCM-2025-09 | Novel malware taps GPT4 for ransomware creation | 2025-09-22 | https://www.scworld.com/brief/novel-malware-taps-gpt4-for-ransomware-creation |
| GBH-2025-09 | MalTerminal: New GPT-4-Powered Malware That Writes Its Own Ransomware | 2025-09-22 | https://gbhackers.com/malterminal-new-gpt-4/ |
| CP2-2025-10 | MalTerminal Malware Powered by LLM Technology Uses OpenAI GPT-4 | 2025-10-10 | https://cyberpress.org/malterminal-malware/ |

---

## Related Samples (from SentinelLABS)

| File | Category | Description |
|------|----------|-------------|
| MalTerminal.exe | Malware | Python2EXE compiled binary; GPT-4 ransomware/reverse shell generator |
| testAPI.py (×2) | Malware | Python loaders functionally identical to EXE — choose Ransomware or Reverse Shell |
| TestMal2.py | Malware | Advanced version with more nuanced operator menu options |
| TestMal3.py | Defensive Tool | "FalconShield" — GPT-based malware scanner; benign twin of MalTerminal |
| Defe.py (×2) | Defensive Tool | Variants of FalconShield scanner |

---

## Attack Stages

| Stage | MITRE Tactic | Technique | Description |
|-------|-------------|-----------|-------------|
| 0 | execution | T1059.006 | Python binary launches; operator selects Ransomware or Reverse Shell mode from menu |
| 1 | resource_development | T1588.007 | Construct structured JSON prompt for LLM API including role definition and anti-hallucination guardrails |
| 2 | execution | T1059.009 | Send prompt to LLM API; parse response to extract generated Python source code |
| 3 | defense_evasion | T1027 | Execute LLM-returned code via `exec()` at runtime — no static payload exists in binary |
| 4 | impact | T1486 | Generated code executes: ransomware encrypts + exfiltrates, or reverse shell establishes C2 |

---

## Variation Dimensions

### `attack_mode` — 2 values
*Source: SentinelLABS [SL-2025-09]: operator selects between "Ransomware" and "Reverse Shell" modes via menu*

| Value | Description |
|-------|-------------|
| `ransomware` | AES-256 CBC file encryption + HTTP POST exfil of encrypted archive (documented) |
| `reverse_shell` | TCP reverse shell connecting to hardcoded C2 IP and port (documented) |

---

### `llm_provider` — 4 values
*Source: SentinelLABS [SL-2025-09]: OpenAI GPT-4 documented; Anthropic documented via sk-ant-api03 YARA rule from retrohunt; HuggingFace and local Ollama are derived alternatives*

| Value | Description |
|-------|-------------|
| `openai_gpt4` | OpenAI GPT-4 chat completions API — sk-... key, Base64 substring `T3BlbkFJ` (documented) |
| `anthropic_claude` | Anthropic Claude messages API — sk-ant-api03-... key (documented via YARA rule) |
| `huggingface` | Hugging Face Inference API — hf_... token (derived) |
| `local_ollama` | Ollama local API on localhost:11434 — no key required, eliminates API revocation brittleness (derived) |

---

### `prompt_role` — 3 values
*Source: SentinelLABS [SL-2025-09]: "framing tasks in the context of a cybersecurity expert" documented; system administrator and developer roles are derived alternatives*

| Value | Description |
|-------|-------------|
| `cybersecurity_expert` | "a senior cybersecurity expert who writes precise, production-quality Python tools" (documented framing) |
| `system_administrator` | "an experienced Windows system administrator who automates security operations in Python" (derived) |
| `developer` | "a Python developer building internal security testing utilities" (derived) |

---

### `code_target` — 4 values
*Source: SentinelLABS [SL-2025-09] and DSR [DSR-2025-10]: all four capabilities documented as generated code targets*

| Value | Description |
|-------|-------------|
| `aes_cbc_encryption` | AES-256 CBC file encryption with PKCS7 padding (documented) |
| `file_enumeration` | Recursive file enumeration under a directory path (documented) |
| `http_post_exfil` | Upload binary file to remote URL via HTTP POST using standard library only (documented) |
| `reverse_shell_tcp` | TCP reverse shell forwarding stdin/stdout to a socket (documented) |

---

### `delivery_format` — 3 values
*Source: SentinelLABS [SL-2025-09]: MalTerminal.exe, testAPI.py variants, and TestMal2.py all documented*

| Value | Description |
|-------|-------------|
| `compiled_exe` | Python2EXE compiled Windows EXE — MalTerminal.exe (documented) |
| `python_script` | Standalone Python script — testAPI.py style (documented) |
| `advanced_menu` | Extended operator console with more nuanced options — TestMal2.py style (documented) |

---

### `guardrails` — 4 values
*Source: SentinelLABS [SL-2025-09]: byte endianness and file mode restriction documented as explicit anti-hallucination instructions in prompts*

| Value | Description |
|-------|-------------|
| `byte_endianness` | "keep the byte endianness consistent throughout — use little-endian for all struct pack/unpack calls" (documented) |
| `file_mode_restriction` | "only open files in rb+ mode; never use w, wb, or a modes" (documented) |
| `combined_guardrails` | Both byte endianness and file mode instructions present (derived: maximally robust variant) |
| `no_guardrails` | No anti-hallucination instructions — minimal prompting (derived: brittle baseline) |

---

## Cross-Stage Inheritance

| Variable | Flows From → To | Purpose |
|----------|-----------------|---------|
| `llm_provider_name` | stage 1 → stages 2, 3 | Consistent LLM provider name across API call and execution stages |
| `code_target_description` | stage 1 → stage 3 | What the exec() wrapper knows it is executing |
| `guardrail_instruction` | stage 1 → stage 4 | Same guardrail instruction reused in the payload orchestration wrapper |

---

## Detection Notes (from SentinelLABS)

SentinelLABS documented two detection strategies in the retrohunt that found MalTerminal:

**API Key Detection:**
- YARA rules targeting provider-specific key patterns embedded in binaries
- OpenAI keys: Base64 substring `T3BlbkFJ` (decodes to "OpenAI")
- Anthropic keys: prefix `sk-ant-api03`
- Year-long retrohunt yielded 7,000+ samples containing 6,000+ unique keys

**Prompt Hunting:**
- Search binaries for JSON prompt structures and chat message formats
- Pair with lightweight LLM classifier to score malicious intent of embedded prompts
- Hardcoded anti-hallucination guardrails are themselves detectable patterns

**Brittleness as a detection opportunity:** API key revocation kills MalTerminal. This is described by SentinelLABS as making LLM-enabled malware "a curiosity: a tool that is uniquely capable, adaptable, and yet also brittle."

---

## Combinatorics

```
attack_mode (2) × llm_provider (4) × prompt_role (3)
  × code_target (4) × delivery_format (3) × guardrails (4)
= 1,152 structurally distinct variations
```

All dimension values are evidence-backed except where marked as "derived alternatives."
