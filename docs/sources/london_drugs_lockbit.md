# LONDON_DRUGS_LOCKBIT / LockBit

## What is modeled?

This campaign models the April 2024 London Drugs ransomware incident as a LockBit-style double-extortion workflow.

---

## Sources

| #   | Source                                          | URL                                                                                                            | Key contribution                                                                                   |
| --- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| [1] | CCCS National Cyber Threat Assessment 2025-2026 | https://www.cyber.gc.ca/en/guidance/national-cyber-threat-assessment-2025-2026#fn84                            | Verbatim London Drugs / LockBit reference                                                          |
| [2] | CBC News                                        | https://www.cbc.ca/news/canada/british-columbia/london-drugs-ransomware-attack-1.7210754                       | Store closures, employee PII exposure, refusal to pay, threat-actor reference                      |
| [3] | CBC News                                        | https://www.cbc.ca/news/canada/british-columbia/london-drugs-cyberattack-employee-information-1.7208786        | Employee information compromise                                                                    |
| [4] | CISA AA23-325A                                  | https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a                                            | LockBit TTPs: Citrix Bleed, RDP credentials, PsExec/WMI, Mimikatz, Kerberoasting, rclone, vssadmin |
| [5] | Mandiant UNC2165                                | https://www.mandiant.com/resources/blog/unc2165-shifts-to-evade-sanctions                                      | LockBit affiliate patterns: phishing, FAKEUPDATES, Cobalt Strike, MEGA/rclone, PsExec deployment   |
| [6] | Trend Micro LockBit Spotlight                   | https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-lockbit            | StealBit and double-extortion behavior                                                             |
| [7] | DFIR Report: BlackSuit                          | https://thedfirreport.com/2024/08/26/blacksuit-ransomware/                                                     | Representative affiliate tooling and backup disruption patterns                                    |
| [8] | BleepingComputer                                | https://www.bleepingcomputer.com/news/security/lockbit-says-they-stole-data-in-london-drugs-ransomware-attack/ | LockBit claim of data theft and leak-site publication                                              |

---

## Variation Dimensions

The campaign generates 1,296 deterministic variants from six dimensions.

### 1. Initial Access Vector

| Value                     | Evidence                                                     |
| ------------------------- | ------------------------------------------------------------ |
| `citrix_bleed_exploit`    | CISA [4]: Citrix Bleed (CVE-2023-4966)                       |
| `stolen_rdp_credentials`  | CISA [4]: stolen RDP credentials                             |
| `phishing_credential`     | Mandiant [5]: phishing / FAKEUPDATES access patterns         |
| `purchased_broker_access` | CISA [4], CCCS [1]: brokered access is a common LockBit path |

### 2. Lateral Movement Style

| Value          | Evidence                                                                |
| -------------- | ----------------------------------------------------------------------- |
| `psexec_wmi`   | CISA [4]: PsExec and WMI / wmiexec                                      |
| `rdp_pivoting` | CISA [4]: RDP used for internal pivoting                                |
| `rmm_tools`    | CISA [4], Mandiant [5]: AnyDesk / Splashtop / ScreenConnect-style tools |

### 3. Credential Harvest Method

| Value                | Evidence                              |
| -------------------- | ------------------------------------- |
| `mimikatz_lsass`     | CISA [4]: LSASS dumping with Mimikatz |
| `kerberoasting`      | CISA [4]: Kerberoasting / Rubeus      |
| `veeam_cred_extract` | CISA [4]: `veeam-get-creds.ps1`       |

### 4. Exfiltration Method

| Value                | Evidence                                           |
| -------------------- | -------------------------------------------------- |
| `rclone_cloud`       | CISA [4]: rclone hunting guidance                  |
| `stealbit_automated` | Trend Micro [6]: StealBit                          |
| `ftp_direct`         | CISA [4], DFIR [7]: FTP-style staging and transfer |

### 5. Backup Disruption Pattern

| Value                | Evidence                                                                |
| -------------------- | ----------------------------------------------------------------------- |
| `vssadmin_shadows`   | CISA [4]: `vssadmin delete shadows /all /quiet`                         |
| `veeam_service_kill` | CISA [4]: backup service termination                                    |
| `dual_vss_and_veeam` | CISA [4], DFIR [7]: combined shadow-copy deletion and backup disruption |

### 6. Extortion Leverage

| Value                         | Evidence                                                              |
| ----------------------------- | --------------------------------------------------------------------- |
| `dark_web_leak_site`          | CCCS [1], BleepingComputer [8]: leak-site publication                 |
| `staged_data_release`         | CCCS [1]: staged double-extortion behavior                            |
| `direct_demand_with_deadline` | CBC [2]: ransom demand and refusal                                    |
| `pharmacy_patient_pressure`   | CBC [2], incident summary: pharmacy outage and patient-impact framing |

---

## Kill Chain Stages

| Stage | MITRE Tactic      | MITRE Technique | Description                                                         | Dimensions Used                        |
| ----- | ----------------- | --------------- | ------------------------------------------------------------------- | -------------------------------------- |
| 0     | Initial Access    | T1133           | Use the chosen externally exposed access path to reach London Drugs | initial_access_vector                  |
| 1     | Discovery         | T1046           | Map corporate infrastructure and store dependencies                 | lateral_movement_technique             |
| 2     | Discovery         | T1213           | Enumerate pharmacy systems as a separate stage                      | lateral_movement_technique             |
| 3     | Credential Access | T1003.001       | Harvest credentials to widen access                                 | credential_harvest_method              |
| 4     | Lateral Movement  | T1021           | Move through the domain toward high-value hosts                     | lateral_movement_technique             |
| 5     | Exfiltration      | T1041           | Stage and exfiltrate employee and operational files                 | exfil_method                           |
| 6     | Impact            | T1486           | Destroy recovery options, deploy ransomware, and extort the victim  | backup_destruction, extortion_leverage |
