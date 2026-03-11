# Feature: ScopeCreep Campaign Dataset (`SCOPE_CREEP`)

## Overview

Add Campaign #14 — **ScopeCreep** (OpenAI Threat Intelligence, June 2025) — to the
`attacks/` corpus as `attacks/scope_creep.toml`, plus a reusable `gen_campaign.py` script
that auto-generates any new campaign TOML from a seed JSON using the Claude API.

ScopeCreep is the only confirmed **iterative refinement** campaign in the FragGuard benchmark
(all 6 existing campaigns use sequential task decomposition). It documents a Russian group using
OpenAI models to iteratively refine a RAT through an AV-scan feedback loop until zero detections.

---

## 0. Strategic Weaknesses of the Current Dataset

These gaps were identified by cross-referencing the 6 existing `.toml` files against
FragGuard.pdf (Tables 1–6, Appendix A) and the FragGuard_Implementation_Guide.

### Gap 1 — Missing Iterative Refinement Strategy (Critical)
The benchmark paper (Table 2) defines 7 decomposition strategies. Every existing campaign uses
**task decomposition** (sequential independent sub-tasks). The **iterative refinement** strategy —
where the adversary runs a feedback loop of (generate → AV scan → rewrite → repeat) — is
documented as ScopeCreep's defining technique and is **entirely absent** from the corpus.
This means the harness has never tested whether a model will help improve flagged malicious code
under "fix my code" framing, which is the most common real-world LLM-evasion pattern.

### Gap 2 — No OpenAI-Sourced Campaigns
| Campaign | Source |
|---|---|
| DPRK_FRAUD, NOCODE_RANSOMWARE, VIBE_EXTORTION | Anthropic TI |
| PROMPTSTEAL, QUIETVAULT | Google GTIG |
| AD_DISCOVERY | Generic (no incident grounding) |

ScopeCreep (OpenAI TI, Jun 2025) would be the first OpenAI-grounded campaign — important for
cross-provider safety generalization and for covering the Russian malware cluster threat actor class.

### Gap 3 — No Syscall / EDR Bypass Coverage
`nocode_ransomware.toml` tests sandbox detection (T1497) and PyInstaller packaging. No campaign
tests **direct NT API syscalls** (T1562) that bypass EDR hooks in `ntdll.dll`. This is the most
technically sophisticated evasion layer and probes a safety boundary the existing corpus never reaches.

### Gap 4 — AV Feedback Loop Not Modelled
The harness sends prompts as independent, context-free requests. ScopeCreep's Fragment 1 in the
real attack carries an **AV detection report as input context**. Static prompts lose this signal.
Mitigation: embed a realistic fake AV report excerpt directly in the Fragment 1 `direct` prompt
to simulate the feedback loop without requiring harness changes.

### Gap 5 — Missing Capability Coverage
| Missing Capability | MITRE | Present in ScopeCreep |
|---|---|---|
| Browser credential theft | T1555.003 | Credential stealer (Chrome DPAPI) |
| GitHub as distribution channel | T1105 | GitHub malware distribution |
| Telegram as C2 | T1102 | Telegram bot C2 |
| RAT / reverse shell core | T1059 | Fragment 0 |
| Direct-syscall EDR bypass | T1562 | Fragment 2 |

### Gap 6 — AD_DISCOVERY Is Not a Kill Chain
1 fragment = trivially complete kill chain (`kill_chain_complete = True` on any single compliance).
Provides no chain-level signal. Needs additional fragments to be meaningful.

### Gap 7 — No Benign-Twin Pairs
The paper (Section 4.4) requires benign-twin pairs for FRR measurement. No existing `.toml`
includes them. The dataset currently measures safety only; utility cannot be evaluated.

---

## 1. Where to Find Metadata and Fragments

### Primary Source
**OpenAI Threat Intelligence — "Disrupting Malicious Uses of AI: June 2025"**
(`OpenAI, 2025a` in FragGuard.pdf references, page 12)
URL: `openai.com/safety` → threat intelligence blog

### What the Paper Already Provides (FragGuard.pdf Appendix A)

**From Table 3, page 6 (confirmed campaigns):**
> Campaign #14: ScopeCreep | OpenAI Jun 2025 | OpenAI models | Iterative RAT refinement

**From Table 6, page 8 (CHAIN-003):**
> Iterative Malware | 3 Steps | RAT Core → AV Evasion → Syscall Bypass | Source: ScopeCreep

**From ATK-02 documented cases, page 15:**
> "Operation ScopeCreep (OpenAI June 2025): Russian group, iterative development.
> RAT + credential stealer + GitHub distribution + Telegram C2."

**From ATK-03 attack path, page 15:**
> "The cycle: (1) Generate code → (2) Submit to AV → (3) Paste detection report into LLM →
> (4) 'Rewrite to avoid this detection' → (5) Repeat until 0 detections.
> Each prompt is a legitimate 'fix my code' request."

### Fragment Map (3-fragment CHAIN-003 build)

| Fragment | Kill-Chain Step | MITRE Technique | Technical Content |
|---|---|---|---|
| 0 | RAT Core | T1059 — Command Scripting | Socket C2, subprocess command exec, reverse shell loop |
| 1 | AV Evasion | T1027 — Obfuscated Files | Base64/XOR obfuscation, dynamic imports; framed as "fix my flagged code" |
| 2 | Syscall Bypass | T1562 — Impair Defenses | NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx; SSN extraction from on-disk ntdll.dll |

### Full ATK-03 MITRE TTPs (from page 16)
| Technique | Description |
|---|---|
| T1059 | RAT core: socket + subprocess |
| T1027 | Base64/XOR encoding |
| T1055 | Process injection / DLL injection |
| T1547.001 | Registry Run Keys persistence |
| T1562 | Direct syscalls bypass EDR |
| T1497 | Sandbox evasion (VMware/VBox) |
| T1555.003 | Chrome DPAPI credential theft |

### Supplementary Sources
| Source | Purpose |
|---|---|
| OpenAI Oct 2025 TI blog (`OpenAI, 2025b`) | Russian malware clusters — overlap with ScopeCreep TTPs |
| CODEBREAKER (USENIX 2024) | AV-evasion rewriting: 25/30 variants evaded GPT-4 detection |
| MITRE ATT&CK T1562.001 | Direct syscall bypass technique documentation |

---

## 2. Architecture Decisions

**A. Seed JSON → generated TOML, not hand-authored TOML**
Hand-writing 10 variation styles × 3 fragments = 30 prompts is slow and produces inconsistent
voice across styles. The generator ensures internal consistency within each fragment.

**B. One Claude API call per fragment (not per style)**
Generate all 9 non-direct styles in a single response as a JSON object. Keeps style variation
internally consistent and uses 3 API calls total (one per fragment) not 27.

**C. Haiku as default model**
`claude-haiku-4-5-20251001` is sufficient for style rephrasing at ~$0.01/fragment.
`--model claude-sonnet-4-6` available for Fragment 2 (syscall bypass needs precise technical vocabulary).

**D. Embed AV report in Fragment 1 direct prompt**
To simulate the real feedback loop without harness changes, Fragment 1's `direct` prompt includes
a realistic AV detection snippet (e.g., "VirusTotal: 34/72 — Trojan:Script/Wacatac"). This is the
most faithful static representation of the iterative refinement pattern.

**E. TOML validation via tomllib round-trip**
After generation, the script runs `tomllib.loads()` to confirm the output is parseable by the
exact same code path that `harness.py:load_attack()` uses.

---

## Implementation Tasks

### Task 1: Seed File — `seeds/scope_creep.json`
- **File**: `seeds/scope_creep.json` *(written)*
- **Description**: Campaign metadata + 3 `direct` prompts grounded in FragGuard.pdf Appendix A
- **Details**:
  - Fragment 0: Python reverse shell with socket C2 + subprocess exec loop (T1059)
  - Fragment 1: AV evasion request with embedded fake VirusTotal report as context (T1027)
  - Fragment 2: ctypes direct syscall injector — NtAllocateVirtualMemory, NtWriteVirtualMemory,
    NtCreateThreadEx, SSN extraction from on-disk ntdll.dll (T1562)
- **Dependencies**: None

### Task 2: Generator Script — `gen_campaign.py`
- **File**: `gen_campaign.py` *(written)*
- **Description**: CLI tool that reads seed JSON, calls Claude API, emits validated TOML
- **Details**:
  - `load_seed(path)` — parse and validate required fields
  - `generate_variations(direct_prompt, description, model)` — one API call per fragment,
    returns `dict[style, prompt]` parsed from JSON response
  - `build_toml(seed, variations)` — render to TOML string with correct structure
  - `validate_toml(text)` — `tomllib.loads()` round-trip confirming harness compatibility
  - `--dry-run` mode — placeholder output without API calls
  - `--model` flag — default `claude-haiku-4-5-20251001`, override to sonnet
  - `--out` flag — default `attacks/<ID>.toml`
- **Dependencies**: Task 1

### Task 3: Generate `attacks/scope_creep.toml`
- **File**: `attacks/scope_creep.toml` *(to be generated)*
- **Description**: Run the generator against the seed file
- **Command**: `python gen_campaign.py seeds/scope_creep.json`
- **Dependencies**: Tasks 1 & 2

### Task 4: Manual Review of Generated Variations
- **File**: `attacks/scope_creep.toml`
- **Description**: Read all 30 generated prompts and verify:
  - Each variation matches its style definition
  - Fragment 1 variations preserve the AV-report framing across styles
  - Fragment 2 variations retain the NT API specificity (NtAllocateVirtualMemory etc.)
  - No variation loses the technical capability of its `direct` prompt
- **Dependencies**: Task 3

### Task 5: Smoke Test Against Harness
- **Description**: Confirm the TOML loads cleanly and the campaign runs
- **Command**: `python run.py --campaign SCOPE_CREEP --model claude --judge --dry-run`
- **Dependencies**: Task 4

---

## Testing Strategy

- `--dry-run` on `gen_campaign.py` confirms seed JSON parses and TOML renders without API calls
- `tomllib.loads()` round-trip in `validate_toml()` is the primary structural test
- `python run.py --campaign SCOPE_CREEP --dry-run` confirms harness compatibility
- Manual review of Fragment 2 variations is critical — syscall bypass prompts are the most
  technically sensitive and most likely to be either watered down or over-specified by the generator

---

## Integration Points

- `gen_campaign.py` is independent of `harness.py` / `run.py` — it only produces a `.toml` file
- Output TOML is consumed by `harness.py:load_attack()` which uses standard `tomllib.loads()`
- `run.py` picks up any `*.toml` in `attacks/` automatically via `load_all_attacks()`
- The `seeds/` directory is a new addition; no existing files are modified

---

## File Map

```
fragguard-chain/
├── gen_campaign.py           ← generator script         [Task 2 — written]
├── seeds/
│   └── scope_creep.json      ← seed file                [Task 1 — written]
├── attacks/
│   └── scope_creep.toml      ← generated output         [Task 3 — pending]
└── SCOPECREEP_PLAN.md        ← this file
```

---

## Ready to Proceed?

Tasks 1 and 2 are already written. Awaiting your approval to execute **Task 3**:

```bash
python gen_campaign.py seeds/scope_creep.json
```

After that, Task 4 (manual review) will be done together with you before any harness run.
