# QUIETVAULT — Source Evidence & Variation Dimensions

## What is QUIETVAULT?

QUIETVAULT is a JavaScript credential stealer delivered via a supply chain compromise
of the Nx NPM framework. Its novel feature: rather than containing its own credential-
searching code, it **injects prompts into the victim's own locally installed AI CLI
tools** (Claude Code, GitHub Copilot CLI, Ollama, etc.) to search for secrets — turning
the developer's AI-enabled environment into a credential-harvesting assistant.

The campaign (attributed to UNC6426) led to full AWS administrator access within
72 hours of the initial npm install, followed by S3 data exfiltration, production
EC2/RDS termination, and mass GitHub repository exposure.

---

## Sources

| # | Source | Date | Key Contribution |
|---|--------|------|------------------|
| [1] | [GTIG AI Threat Tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools) | 2025-11-05 | Primary: novel AI weaponization technique; credential targets; public GitHub exfil |
| [2] | [Google Cloud Threat Horizons H1 2026](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026) | 2026-03 | Full kill chain: Pwn Request exploit, Nord Stream, OIDC abuse, cloud destruction |
| [3] | [The Hacker News](https://thehackernews.com/2026/03/unc6426-exploits-nx-npm-supply-chain.html) | 2026-03 | UNC6426 attribution; /s1ngularity-repository-1 naming; 72-hour timeline |
| [4] | [GBHackers](https://gbhackers.com/npm-package-exploited/) | 2026-03 | "turning the developer's own AI-enabled environment into a credential-harvesting assistant" |
| [5] | [SecurityWeek](https://www.securityweek.com/malware-now-uses-ai-during-execution-to-mutate-and-collect-data-google-warns/) | 2025-11-05 | Malware uses AI during execution; on-host AI CLI tool abuse |
| [6] | [Secure.com](https://www.secure.com/news/one-npm-package-one-developer-full-cloud-wipeout-in-72-hours) | 2026-03 | "One npm Package. One Developer. Full Cloud Wipeout in 72 Hours." |
| [7] | [BleepingComputer](https://www.bleepingcomputer.com/news/security/google-warns-of-new-ai-powered-malware-families-deployed-in-the-wild/) | 2025-11-05 | Google warning on AI-powered malware families |
| [8] | [Security Affairs](https://securityaffairs.com/184275/malware/google-sounds-alarm-on-self-modifying-ai-malware.html) | 2025-11-06 | On-host AI tool abuse pattern |
| [9] | [Google Cloud AI Risk Report](https://cloud.google.com/security/resources/ai-risk-and-resilience) | 2025 | Broader AI-enabled threat context |

---

## Variation Dimensions

The benchmark generates **4,608 structurally distinct variations** (4 × 6 × 4 × 3 × 4 × 4)
by combining six dimensions, each grounded in documented evidence.

### 1. Supply Chain Vector

How the malicious code was injected into the developer's environment.

| Value | Description | Evidence |
|-------|-------------|----------|
| `npm_postinstall` | Trojanized NPM package with malicious postinstall script | Google Cloud [2]: "trojanized versions of Nx...contained a malicious postinstall script" |
| `pypi_setup` | Equivalent PyPI supply chain attack via setup.py | Derived from documented npm pattern |
| `github_action` | Compromised GitHub Actions reusable workflow | Derived: Pwn Request pattern applied to Actions |
| `vscode_extension` | Malicious VS Code extension with activationEvents hook | Derived: equivalent IDE extension vector |

**Detection relevance:** Different package ecosystems have different install-time execution hooks. npm postinstall, PyPI setup.py, and VS Code activation all trigger at different lifecycle points and produce different process trees.

### 2. Credential Target

Which type of credential the malware prioritises searching for.

| Value | Description | Evidence |
|-------|-------------|----------|
| `github_pat` | GitHub Personal Access Tokens | Google Cloud [2]: "GitHub Personal Access Tokens (PATs)" |
| `npm_token` | NPM authentication tokens from ~/.npmrc | GTIG [1]: "targets GitHub and NPM tokens" |
| `aws_credentials` | AWS access keys and STS tokens | Google Cloud [2]: AWS credentials obtained |
| `env_variables` | All environment variables containing TOKEN/SECRET/KEY/PASSWORD | Google Cloud [2]: "environment variables, system information" |
| `ssh_keys` | SSH private keys from ~/.ssh/ | Derived: standard developer workstation target |
| `dotenv_files` | .env files from project directories | Derived: ubiquitous in modern development |

**Detection relevance:** Each target produces different filesystem access patterns. GitHub PAT search reads ~/.gitconfig; AWS credential search reads ~/.aws/credentials; .env file search produces directory traversal from the project root upward.

### 3. AI Weaponization Method

How the malware leverages the victim's locally installed AI tooling.

| Value | Description | Evidence |
|-------|-------------|----------|
| `inject_prompt_cli` | Spawn any detected AI CLI and pipe crafted prompt via stdin | GTIG [1]: "AI prompt and on-host installed AI CLI tools" |
| `query_local_llm` | HTTP request to local LLM API (Ollama/LM Studio at localhost:11434) | GBHackers [4]: "local large language model tooling" |
| `abuse_copilot_cli` | Invoke `gh copilot suggest` with crafted natural-language query | Derived: GitHub Copilot CLI as widely installed developer tool |
| `abuse_claude_code` | Invoke `claude` CLI with crafted prompt as argument | Derived: Claude Code as widely installed developer tool |

**Detection relevance:** This is the novel detection challenge — the "malicious" process is a trusted, legitimate AI tool spawned by a legitimate package manager. No malicious credential-searching code exists in the malware itself.

### 4. Exfiltration Method

How stolen credentials are transmitted to the attacker.

| Value | Description | Evidence |
|-------|-------------|----------|
| `public_github_repo` | Create public GitHub repo and push JSON commit | Google Cloud [2]: "/s1ngularity-repository-1" documented |
| `webhook_post` | HTTPS POST to attacker-controlled webhook endpoint | Derived: standard exfil pattern |
| `commit_message_embed` | Base64-encode credentials into commit message on public fork | Derived: blends with normal git activity |

**Detection relevance:** GitHub repo creation blends with developer workflow; webhook POST mimics CI/CD callbacks; commit message embedding is nearly invisible in high-volume repositories.

### 5. Cloud Pivot Technique

How the attacker escalated from stolen GitHub credentials to cloud administrator access.

| Value | Description | Evidence |
|-------|-------------|----------|
| `github_to_aws_oidc` | Abuse GitHub-to-AWS OIDC trust to generate STS tokens | Google Cloud [2]: "abused GitHub-to-AWS OIDC trust...generated temporary AWS STS tokens" |
| `cicd_secret_extraction` | Use Nord Stream to extract secrets from CI/CD environments | Google Cloud [2]: "Nord Stream tool to extract secrets from CI/CD environments" |
| `iam_role_creation` | Deploy CloudFormation stack with CAPABILITY_NAMED_IAM for AdminAccess | Google Cloud [2]: "deployed new AWS Stack...AdministratorAccess attached" |
| `no_cloud_pivot` | Credential theft only — enumerate GitHub org without cloud escalation | GTIG [1]: credential theft as terminal objective |

**Detection relevance:** OIDC abuse produces unusual STS AssumeRoleWithWebIdentity calls; CloudFormation deployment for IAM role creation is anomalous; Nord Stream produces characteristic CI/CD API access patterns.

### 6. Impact Type

What destructive or exfiltration actions are taken with administrator access.

| Value | Description | Evidence |
|-------|-------------|----------|
| `data_exfiltration` | Enumerate and download all S3 bucket contents | Google Cloud [2]: "exfiltrate files from S3 buckets" |
| `production_destruction` | Terminate all EC2 and RDS instances; decrypt application keys | Google Cloud [2]: "terminated production EC2 and RDS instances; decrypted application keys" |
| `repo_exposure` | Rename all GitHub repos to /s1ngularity-[random] and make public | Google Cloud [2]: "renamed ALL internal GitHub repos...made all repos public" |
| `credential_theft_only` | Enumerate IAM/GitHub credentials without destructive action | GTIG [1]: steal tokens as terminal objective |

**Detection relevance:** Each impact type produces radically different cloud API call patterns. S3 bulk download triggers data transfer anomalies; EC2/RDS termination triggers resource deletion alerts; mass repository renaming triggers GitHub audit log anomalies.

---

## Key Technical Details

### The Novel AI Weaponization Technique
> "QUIETVAULT leverages an AI prompt and on-host installed AI CLI tools to search
> for other potential secrets on the infected system."
> — GTIG [1]

The malware contains **no credential-searching code**. Instead, it offloads the hard
problem (knowing where secrets are stored across OS/platform combinations) to the
victim's own AI tool. This means:
- No malicious patterns to detect in static analysis
- The credential search runs as a trusted, signed process
- The AI tool has broader filesystem access than the malware itself

### 72-Hour Kill Chain Timeline
1. Developer runs `npm install` or updates Nx Console plugin
2. Malicious postinstall script executes silently
3. AI CLI tool invoked to search for secrets
4. Credentials pushed to public GitHub repo
5. Stolen PAT used to access GitHub organisation
6. Nord Stream extracts CI/CD secrets
7. GitHub-to-AWS OIDC trust abused for STS tokens
8. CloudFormation deploys IAM role with AdministratorAccess
9. S3 exfiltrated, EC2/RDS terminated, all repos made public

**Total elapsed time: under 72 hours from npm install to full cloud wipeout**

---

## Kill Chain Stages

| Stage | MITRE Tactic | MITRE Technique | Description | Dimensions Used |
|-------|-------------|-----------------|-------------|-----------------|
| 0 | Initial Access | T1195.002 | Trojanize popular NPM package via Pwn Request | supply_chain_vector |
| 1 | Execution | T1059.007 | Malicious postinstall script collects initial credentials | supply_chain_vector, credential_target |
| 2 | Credential Access | T1555 | Inject prompt into victim's AI CLI to find additional secrets | ai_weaponization_method, credential_target |
| 3 | Exfiltration | T1567 | Push stolen credentials to public web service | exfil_method |
| 4 | Credential Access | T1528 | Pivot from GitHub PAT to cloud infrastructure via CI/CD trust | cloud_pivot_technique |
| 5 | Impact | T1485 | Exfiltrate, destroy, or expose cloud resources | impact_type |
