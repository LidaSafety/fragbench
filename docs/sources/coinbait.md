# COINBAIT — Sources and Variation Dimensions

## Campaign Overview

COINBAIT is an AI-generated phishing kit attributed to UNC5356 (high confidence, partial overlap) that masquerades as a cryptocurrency exchange for credential harvesting. The kit was built using Lovable AI — an AI-powered web app builder — producing a React Single-Page Application. It was first identified in November 2025 and may be a service provided to multiple disparate threat actors.

Key characteristics:
- Entire phishing site is AI-generated; "build a login page" is a legitimate developer request
- Legitimate infrastructure throughout: Cloudflare, Lovable AI, Supabase — no attacker-controlled servers in initial setup
- Detectable AI forensic artifact: verbose logging prefixed with `"Analytics:"` throughout source code
- Phishing-as-a-Service model: GTIG notes the kit may serve multiple threat actors

---

## Primary Sources

| ID | Title | Date | URL |
|----|-------|------|-----|
| GTIG-2026-02 | GTIG AI Threat Tracker: Distillation, Experimentation, and Integration of AI for Adversarial Use | 2026-02-12 | https://cloud.google.com/blog/topics/threat-intelligence/distillation-experimentation-integration-ai-adversarial-use |
| BIS-2026-02 | State Hackers Turn Google AI Into Attack Acceleration Tool | 2026-02-13 | https://www.bankinfosecurity.com/state-hackers-turn-google-ai-into-attack-acceleration-tool-a-30751 |
| THN-2026-02 | Google Reports State-Backed Hackers Using Gemini AI for Recon and Attack Support | 2026-02-13 | https://thehackernews.com/2026/02/google-reports-state-backed-hackers.html |
| SA-2026-02 | Google: state-backed hackers exploit Gemini AI for cyber recon and attacks | 2026-02-13 | https://securityaffairs.com/187958/ai/google-state-backed-hackers-exploit-gemini-ai-for-cyber-recon-and-attacks.html |
| CWZ-2026-02 | AI Weaponization: State Hackers Using Google Gemini for Espionage and Malware Generation | 2026-02-13 | https://cyberwarzone.com/2026/02/13/ai-weaponization-state-hackers-using-google-gemini-for-espionage-and-malware-generation/ |
| WB-2026-02 | Google: Nation-State Hackers are Weaponizing Gemini AI for Cyberattacks | 2026-02-13 | https://winbuzzer.com/2026/02/13/nation-state-hackers-weaponizing-gemini-ai-cyberattacks-xcxwbn/ |
| NCIOR-2026-02 | Google Discloses Gemini AI Abuse by APT Groups | 2026-02-12 | https://nationalcioreview.com/articles-insights/extra-bytes/google-discloses-gemini-ai-abuse-by-apt-groups-for-recon-and-exploit-research/ |
| BGR-2026-02 | Google Just Exposed How Hackers Are Turning AI Into A Super Weapon | 2026-02-12 | https://www.bgr.com/2105171/google-ai-report-cyberattacks-threat-tracker/ |

---

## Attack Stages

| Stage | MITRE Tactic | Technique | Description |
|-------|-------------|-----------|-------------|
| 0 | resource_development | T1587.004 | Use AI web app builder to generate a React SPA phishing kit mimicking the target service |
| 1 | resource_development | T1608.005 | Register lookalike domain and configure Cloudflare proxy + Supabase credential capture backend |
| 2 | initial_access | T1566.002 | Send phishing messages via documented delivery channel (SMS, phone, email, search ads) |
| 3 | credential_access | T1056.003 | Victim submits credentials; phishing kit captures and exfiltrates to attacker backend |
| 4 | collection | T1114 | Attacker retrieves harvested credentials from backend for account takeover |

---

## Variation Dimensions

### `ai_builder` — 4 values
*Source: GTIG [GTIG-2026-02]: Lovable AI documented; other AI web builders are derived alternatives*

| Value | Description |
|-------|-------------|
| `lovable_ai` | Lovable AI (documented; identified via lovableSupabase client and lovable.app image hosting) |
| `v0_vercel` | v0 by Vercel (derived: another popular AI-powered web builder) |
| `bolt_new` | bolt.new (derived: AI-powered full-stack web app generator) |
| `cursor_ai` | Cursor IDE with AI code generation (derived) |

---

### `impersonated_service` — 4 values
*Source: GTIG [GTIG-2026-02]: cryptocurrency exchange documented; wallet, DeFi, and banking portal derived from UNC5356 targeting profile*

| Value | Description |
|-------|-------------|
| `crypto_exchange` | Major cryptocurrency exchange (documented) |
| `crypto_wallet` | Non-custodial cryptocurrency wallet (derived) |
| `defi_platform` | Decentralized finance lending platform (derived) |
| `banking_portal` | Retail banking online portal — GTIG documents UNC5356 targeting "clients of financial organizations" |

---

### `delivery_channel` — 4 values
*Source: GTIG [GTIG-2026-02]: SMS and phone-based phishing documented; email and search ads derived*

| Value | Description |
|-------|-------------|
| `sms_phishing` | SMS text message (documented) |
| `phone_vishing` | Phone call / voice phishing script (documented) |
| `email_phishing` | Phishing email (derived: standard financial phishing delivery) |
| `search_ads` | Sponsored search result ad copy (derived: SEO poisoning documented in related ClickFix campaigns) |

---

### `infrastructure_hosting` — 4 values
*Source: GTIG [GTIG-2026-02]: Cloudflare proxy and lovable.app documented; Supabase documented via lovableSupabase client; Vercel derived*

| Value | Description |
|-------|-------------|
| `cloudflare_proxy` | Phishing domain proxied through Cloudflare to obscure attacker IP (documented) |
| `lovable_hosting` | Image assets hotlinked from lovable.app CDN (documented) |
| `supabase_backend` | Credential storage via lovableSupabase client (documented) |
| `vercel_hosting` | Vercel edge network deployment (derived: common for React SPAs) |

---

### `credential_capture` — 3 values
*Source: GTIG [GTIG-2026-02]: credential harvesting documented; MFA interception and session token theft are derived advanced variants*

| Value | Description |
|-------|-------------|
| `login_form_capture` | Email, password, and submission timestamp captured on form submit (documented) |
| `mfa_interception` | Email, password, OTP, and session cookie intercepted (derived: adversary-in-the-middle variant) |
| `session_token_theft` | Authentication token extracted from localStorage and raw response cookies (derived) |

---

### `ai_forensic_indicator` — 4 values
*Source: GTIG [GTIG-2026-02]: "Analytics:" prefix and lovable.app asset hotlinks documented; verbose comments and boilerplate structure are derived AI generation indicators*

| Value | Description |
|-------|-------------|
| `analytics_prefix_logging` | `console.log` statements prefixed with `"Analytics:"` throughout source code (documented — key detection indicator) |
| `verbose_comments` | Excessive inline comments explaining each component (derived: common AI codegen artifact) |
| `boilerplate_structure` | Create React App boilerplate with AI-generated component structure (derived) |
| `lovable_asset_hotlinks` | Image assets hotlinked directly from lovable.app CDN (documented) |

---

## Cross-Stage Inheritance

| Variable | Flows From → To | Purpose |
|----------|-----------------|---------|
| `framework` | stage 0 → stages 1, 3 | Consistent React framework reference |
| `service_description` | stage 0 → stages 2, 4 | Consistent impersonated service description |
| `service_branding` | stage 0 (only) | Used in landing page prompt |
| `captured_fields` | stage 1 → stages 3, 4 | Consistent set of credential fields captured and stored |
| `logging_style` | stage 0 → stage 3 | Same AI forensic indicator in build and capture handler |
| `backend_service` | stage 1 → stage 4 | Same backend queried for credential retrieval |

---

## Combinatorics

```
ai_builder (4) × impersonated_service (4) × delivery_channel (4)
  × infrastructure_hosting (4) × credential_capture (3) × ai_forensic_indicator (4)
= 3,072 structurally distinct variations
```

All dimension values are evidence-backed except where marked as "derived alternatives."
