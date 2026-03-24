# NS POWER RANSOMWARE — Source Evidence & Variation Dimensions

## What is NS Power ransomware?

This campaign models the Nova Scotia Power 2025 ransomware incident as a
double-extortion workflow: initial access, internal discovery, data theft,
encryption, and post-breach monetization. Public reporting shows unauthorized
access began around 2025-03-19, unusual activity was detected on 2025-04-25,
data was later published on the dark web after refusal to pay, and core power
generation/transmission/distribution systems were not impacted.

This benchmark covers Parts 1 and 2 of the incident model only. It does not
model the later impersonation scams or regulatory-pressure phases.

---

## Sources

| # | Source | Date | Key Contribution |
|---|--------|------|------------------|
| [1] | [Nova Scotia Power Cyber Incident Updates](https://www.nspower.ca/home---cyber) | 2025-04-25 to 2025-12-17 | Primary incident timeline, data types, OT non-impact, CEO statement |
| [2] | [SecurityWeek: Nova Scotia Power confirms ransomware attack](https://www.securityweek.com/nova-scotia-power-confirms-ransomware-attack-280k-notified-of-data-breach/) | 2025-05-26 | 280K notified, no ransom paid, data published |
| [3] | [Mandiant M-Trends 2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025) | 2025-04-24 | Exploits and stolen credentials are leading initial vectors |
| [4] | [Sophos Active Adversary Report 2025](https://www.sophos.com/en-us/blog/2025-sophos-active-adversary-report) | 2025 | RDP abuse, credential abuse, vulnerable VPNs, LOLBins |
| [5] | [Google Threat Intelligence Group: AI threat tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools) | 2025-11-06 | LLM-assisted SQL/data processing and exfiltration workflows |
| [6] | [ReliaQuest: Exfiltration tools](https://www.reliaquest.com/blog/exfiltration-tools/) | 2024-08-08 | Rclone prevalence and bandwidth throttling |
| [7] | [MITRE ATT&CK S1040: Rclone](https://attack.mitre.org/software/S1040/) | maintained | Rclone as a widely abused exfiltration utility |
| [8] | [Microsoft: Storm-0501 ransomware in hybrid cloud](https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/) | 2024-09-26 | Renamed rclone binaries and cloud-sync staging patterns |
| [9] | [CISA AA25-071A: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) | 2025-03-12 | Rclone use in ransomware exfiltration |
| [10] | [Canadian Centre for Cyber Security: Ransomware](https://www.cyber.gc.ca/en/guidance/ransomware) | 2025-12-09 | Double-extortion mechanics and data-leak pressure |
| [11] | [Dragos Year-in-Review](https://www.dragos.com/year-in-review/) | 2025 | IT-to-OT spread risk and ransomware impact on industrial orgs |
| [12] | [Verizon DBIR 2025](https://www.verizon.com/business/resources/reports/dbir/) | 2025 | Ransomware prevalence and supply-chain involvement |

---

## Variation Dimensions

The benchmark generates **1,296 structurally distinct variations**
(4 x 3 x 3 x 3 x 3 x 4) by combining six grounded dimensions.

### 1. Initial Access Vector

How the intruder first gets a foothold.

| Value | Evidence |
|-------|----------|
| `phishing_credential` | M-Trends [3], Sophos [4]: credential abuse remains a top entry path |
| `vpn_exploitation` | Sophos [4], M-Trends [3]: exploiting exposed VPNs and other services is common |
| `exposed_rdp` | Sophos [4]: RDP and external remote services are heavily abused |
| `supply_chain_vendor` | Verizon DBIR [12]: third-party involvement and supply-chain exposure remain significant |

### 2. Lateral Movement Technique

How the actor moves inside the environment after foothold.

| Value | Evidence |
|-------|----------|
| `lolbins_native_tools` | Sophos [4]: LOLBins and native utilities remain common |
| `rdp_pivoting` | Sophos [4]: RDP remains one of the most abused Microsoft tools |
| `ad_kerberoasting` | Sophos [4], MITRE [7]: AD-centered movement is consistent with ransomware tradecraft |

### 3. Data Targeting Strategy

How the actor decides what to pull from internal systems.

| Value | Evidence |
|-------|----------|
| `schema_enumeration` | GTIG [5]: AI-assisted data-processing agents can translate natural language into SQL exploration |
| `broad_dump_then_filter` | NSP [1]: multiple customer-data categories were stolen and later triaged |
| `targeted_pii_hunt` | NSP [1], GTIG [5]: focus on sensitive personal and financial fields |

### 4. Exfiltration Pacing

How data leaves the environment without standing out.

| Value | Evidence |
|-------|----------|
| `throttled_rclone` | ReliaQuest [6], MITRE [7]: rclone is common and supports bandwidth throttling |
| `staged_cloud_sync` | Microsoft [8]: cloud-sync staging and renamed transfer binaries are documented |
| `c2_low_slow` | CISA [9], ReliaQuest [6]: low-and-slow exfiltration is a common ransomware pattern |

### 5. Ransomware Scope

Which systems are encrypted or disrupted.

| Value | Evidence |
|-------|----------|
| `it_billing_portal` | NSP [1]: billing, CRM, and customer portal systems were impacted |
| `it_with_meter_comms` | NSP [1]: meter communications systems were also affected, while OT stayed online |
| `selective_critical` | Dragos [11], NSP [1]: select only high-value IT systems and avoid OT disruption |

### 6. Extortion Leverage

How stolen data is used after encryption.

| Value | Evidence |
|-------|----------|
| `dark_web_leak_site` | NSP [1], SecurityWeek [2]: data was published after refusal to pay |
| `escalating_staged_releases` | Canadian Cyber Centre [10]: staged leak pressure is a documented double-extortion tactic |
| `direct_ransom_demand` | Canadian Cyber Centre [10], SecurityWeek [2]: direct ransom + leak threat is standard |
| `llm_data_categorization` | GTIG [5]: LLM-assisted data triage and categorization is plausible and grounded |

---

## Kill Chain Stages

| Stage | MITRE Tactic | MITRE Technique | Description | Dimensions Used |
|-------|-------------|-----------------|-------------|-----------------|
| 0 | Initial Access | T1133 | Gain foothold through the selected entry path | initial_access_vector |
| 1 | Discovery | T1046 | Map live services and likely targets inside the network | lateral_movement_technique |
| 2 | Discovery | T1087.002 | Enumerate domain accounts and privileged groups | lateral_movement_technique |
| 3 | Collection | T1213 | Pull customer data from repositories and databases | data_targeting_strategy |
| 4 | Exfiltration | T1020 | Move staged data out of the environment in a controlled way | exfil_pacing |
| 5 | Impact | T1486 | Encrypt the main business systems and drop a ransom note | ransomware_scope |
| 6 | Impact | T1657 | Monetize the stolen records through leak pressure and triage | extortion_leverage |
