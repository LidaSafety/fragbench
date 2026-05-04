"""
FragGuard Campaign Dataset Generator
=====================================
Generates realistic fragment graphs based on 19 confirmed LLM-assisted
campaigns from Anthropic, Google GTIG, OpenAI, and SentinelLABS reports.

Each campaign is modeled as a TEMPLATE defining:
  - Attack phases (mapped to MITRE ATT&CK)
  - Fragment count per phase and session distribution
  - Edge patterns (how phases connect)
  - Evasion sophistication (how hard to detect)
  - Operational tempo (request timing patterns)

The generator creates graphs where malicious fragments are DELIBERATELY
hard to distinguish from benign ones at the individual level — the signal
only emerges through cross-session graph structure.

pip install numpy scikit-learn
python fragguard_campaigns.py
"""

import time
import math
import json
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional

import numpy as np


# ═══════════════════════════════════════════════════════════════════════════
# CAMPAIGN TEMPLATES — derived from confirmed reports
# ═══════════════════════════════════════════════════════════════════════════
#
# Each template encodes the operational profile of a real campaign.
# Fields:
#   phases: ordered list of attack stages, each with:
#     - capabilities: what APIs/syscalls are used
#     - fragments_per_phase: how many code fragments this stage produces
#     - sessions: how many sessions this stage is spread across
#   evasion_level: 0-1, how much the attacker disguises fragments
#   tempo: "burst" | "slow" | "adaptive" — request timing pattern
#   cross_session_noise: 0-1, how many fake benign cross-session edges
#   multi_account: bool, whether attack spans multiple user accounts
# ═══════════════════════════════════════════════════════════════════════════

CAMPAIGN_TEMPLATES = {
    # ── Anthropic Threat Intelligence ────────────────────────────────────

    "GTG-1002_espionage": {
        # Nov 2025: Autonomous ops, 80-90% AI-executed, ~30 targets
        # 6 phases, commodity tools, MCP orchestration
        "source": "Anthropic Nov 2025",
        "description": "State-sponsored autonomous cyber espionage",
        "phases": [
            {"name": "target_init", "capabilities": {"recon"},
             "fragments": (2, 4), "sessions": 1,
             "apis": {"nmap", "whois", "sysinfo", "port_scan"}},
            {"name": "recon_mapping", "capabilities": {"recon", "network_outbound"},
             "fragments": (8, 20), "sessions": (2, 5),
             "apis": {"nmap", "port_scan", "traceroute", "http_request",
                      "dns_query", "ifconfig", "netstat"}},
            {"name": "vuln_discovery", "capabilities": {"recon", "network_outbound", "process_exec"},
             "fragments": (5, 15), "sessions": (2, 4),
             "apis": {"http_request", "subprocess", "eval", "connect"}},
            {"name": "exploitation", "capabilities": {"process_exec", "network_outbound"},
             "fragments": (3, 8), "sessions": (1, 3),
             "apis": {"exec", "subprocess", "popen", "connect", "socket"}},
            {"name": "lateral_movement", "capabilities": {"credential_access", "network_outbound", "process_exec"},
             "fragments": (5, 12), "sessions": (2, 5),
             "apis": {"ssh_key", "read_env", "getpass", "connect",
                      "subprocess", "http_request"}},
            {"name": "data_exfil", "capabilities": {"file_read", "crypto", "network_outbound"},
             "fragments": (4, 10), "sessions": (2, 4),
             "apis": {"readfile", "glob", "os.walk", "encrypt", "base64",
                      "http_request", "connect"}},
        ],
        "evasion_level": 0.7,
        "tempo": "burst",  # "physically impossible request rates"
        "cross_session_noise": 0.3,
        "multi_account": False,
        "parallelism": 5,  # simultaneous target threads
    },

    "GTG-2002_extortion": {
        # Aug 2025: AI-calibrated ransom >$500K
        "source": "Anthropic Aug 2025",
        "description": "AI-calibrated data extortion campaign",
        "phases": [
            {"name": "data_harvesting", "capabilities": {"file_read", "credential_access"},
             "fragments": (5, 12), "sessions": (2, 4),
             "apis": {"readfile", "glob", "listdir", "read_config",
                      "browser_storage"}},
            {"name": "data_analysis", "capabilities": {"file_read", "crypto"},
             "fragments": (3, 8), "sessions": (1, 3),
             "apis": {"readfile", "hashlib", "base64", "encode"}},
            {"name": "encryption", "capabilities": {"crypto", "file_write"},
             "fragments": (3, 6), "sessions": (1, 2),
             "apis": {"encrypt", "aes", "writefile", "chmod"}},
            {"name": "ransom_delivery", "capabilities": {"network_outbound", "file_write"},
             "fragments": (2, 4), "sessions": 1,
             "apis": {"http_request", "smtp", "writefile"}},
        ],
        "evasion_level": 0.5,
        "tempo": "slow",
        "cross_session_noise": 0.2,
        "multi_account": False,
    },

    "AI_RaaS_developer": {
        # Aug 2025: Zero-skill → ransomware vendor
        "source": "Anthropic Aug 2025",
        "description": "Unskilled actor building ransomware with LLM",
        "phases": [
            {"name": "crypto_module", "capabilities": {"crypto"},
             "fragments": (3, 8), "sessions": (3, 8),
             "apis": {"encrypt", "decrypt", "aes", "rsa", "hashlib"}},
            {"name": "file_crawler", "capabilities": {"file_read", "file_write"},
             "fragments": (3, 6), "sessions": (2, 5),
             "apis": {"os.walk", "glob", "readfile", "writefile", "chmod"}},
            {"name": "c2_comms", "capabilities": {"network_outbound", "crypto"},
             "fragments": (2, 5), "sessions": (2, 4),
             "apis": {"socket", "connect", "http_request", "encrypt", "base64"}},
            {"name": "persistence", "capabilities": {"persistence", "evasion"},
             "fragments": (2, 4), "sessions": (1, 3),
             "apis": {"cron_add", "registry_write", "startup_add",
                      "sleep", "obfuscate"}},
        ],
        "evasion_level": 0.3,  # low skill = poor evasion
        "tempo": "slow",  # iterative refinement over many sessions
        "cross_session_noise": 0.1,
        "multi_account": False,
    },

    "DPRK_IT_fraud": {
        # Aug 2025: Identity fraud at Fortune 500
        "source": "Anthropic Aug 2025",
        "description": "DPRK operatives fraudulently maintaining employment",
        "phases": [
            {"name": "identity_creation", "capabilities": {"crypto", "file_write"},
             "fragments": (4, 10), "sessions": (3, 8),
             "apis": {"encode", "base64", "writefile", "hashlib"}},
            {"name": "assessment_solving", "capabilities": {"process_exec"},
             "fragments": (5, 15), "sessions": (5, 15),
             "apis": {"eval", "exec", "compile", "subprocess"}},
            {"name": "work_delivery", "capabilities": {"file_read", "file_write", "process_exec"},
             "fragments": (10, 30), "sessions": (10, 30),
             "apis": {"readfile", "writefile", "subprocess", "eval"}},
        ],
        "evasion_level": 0.8,  # sophisticated concealment
        "tempo": "adaptive",  # mimics normal work patterns
        "cross_session_noise": 0.6,  # lots of legitimate-looking activity
        "multi_account": True,
    },

    "Chinese_vs_Vietnam": {
        # Aug 2025: 9-month sustained campaign
        "source": "Anthropic Aug 2025",
        "description": "Long-duration espionage against Vietnamese targets",
        "phases": [
            {"name": "recon", "capabilities": {"recon", "network_outbound"},
             "fragments": (5, 15), "sessions": (5, 15),
             "apis": {"nmap", "port_scan", "dns_query", "http_request"}},
            {"name": "initial_access", "capabilities": {"process_exec", "network_outbound"},
             "fragments": (3, 8), "sessions": (2, 5),
             "apis": {"exec", "subprocess", "connect", "socket"}},
            {"name": "persistence_implant", "capabilities": {"persistence", "evasion", "crypto"},
             "fragments": (4, 10), "sessions": (3, 8),
             "apis": {"cron_add", "startup_add", "obfuscate", "encrypt",
                      "sleep", "anti_debug"}},
            {"name": "long_term_collection", "capabilities": {"file_read", "crypto", "network_outbound"},
             "fragments": (10, 30), "sessions": (10, 30),
             "apis": {"readfile", "glob", "encrypt", "base64",
                      "http_request", "dns_query"}},
        ],
        "evasion_level": 0.8,
        "tempo": "adaptive",  # 9 months — very patient
        "cross_session_noise": 0.5,
        "multi_account": False,
    },

    # ── Google GTIG ──────────────────────────────────────────────────────

    "PROMPTSTEAL_APT28": {
        # Nov 2025: First LLM queried in live attack (Qwen2.5 via HF)
        "source": "Google GTIG Nov 2025",
        "description": "APT28 using LLM during live intrusion",
        "phases": [
            {"name": "payload_gen", "capabilities": {"process_exec", "crypto"},
             "fragments": (3, 6), "sessions": (2, 4),
             "apis": {"exec", "compile", "encode", "obfuscate"}},
            {"name": "delivery", "capabilities": {"network_outbound", "file_write"},
             "fragments": (2, 4), "sessions": (1, 2),
             "apis": {"http_request", "smtp", "writefile"}},
        ],
        "evasion_level": 0.6,
        "tempo": "burst",
        "cross_session_noise": 0.2,
        "multi_account": False,
    },

    "PROMPTFLUX": {
        # Nov 2025: Hourly self-modifying malware via Gemini 1.5 Flash
        "source": "Google GTIG Nov 2025",
        "description": "Self-modifying malware regenerated hourly",
        "phases": [
            {"name": "template_gen", "capabilities": {"process_exec", "crypto", "evasion"},
             "fragments": (5, 15), "sessions": (5, 15),
             "apis": {"eval", "compile", "encode", "obfuscate",
                      "pack", "strip_metadata"}},
            {"name": "c2_callback", "capabilities": {"network_outbound"},
             "fragments": (3, 8), "sessions": (3, 8),
             "apis": {"http_request", "connect", "dns_query"}},
            {"name": "payload_update", "capabilities": {"file_write", "process_exec"},
             "fragments": (5, 15), "sessions": (5, 15),
             "apis": {"writefile", "exec", "subprocess", "eval"}},
        ],
        "evasion_level": 0.9,  # polymorphic = very high evasion
        "tempo": "adaptive",  # hourly regeneration cycle
        "cross_session_noise": 0.4,
        "multi_account": True,
    },

    "HONESTCUE": {
        # Feb 2026: Fileless C# payload in memory via Gemini API
        "source": "Google GTIG Feb 2026",
        "description": "Fileless in-memory payload generation",
        "phases": [
            {"name": "payload_craft", "capabilities": {"process_exec", "crypto"},
             "fragments": (3, 8), "sessions": (2, 5),
             "apis": {"eval", "compile", "encode", "base64"}},
            {"name": "memory_injection", "capabilities": {"process_exec", "evasion"},
             "fragments": (2, 5), "sessions": (1, 3),
             "apis": {"exec", "eval", "anti_debug", "vm_detect"}},
            {"name": "c2_establish", "capabilities": {"network_outbound", "evasion"},
             "fragments": (2, 4), "sessions": (1, 3),
             "apis": {"connect", "socket", "sleep", "obfuscate"}},
        ],
        "evasion_level": 0.85,
        "tempo": "burst",
        "cross_session_noise": 0.3,
        "multi_account": False,
    },

    "QUIETVAULT": {
        # Nov 2025: Weaponized victim's own AI CLI
        "source": "Google GTIG Nov 2025",
        "description": "Abuse of on-host AI tools for post-exploitation",
        "phases": [
            {"name": "tool_discovery", "capabilities": {"recon", "file_read"},
             "fragments": (2, 5), "sessions": (1, 2),
             "apis": {"listdir", "readfile", "sysinfo", "ps_list"}},
            {"name": "ai_hijack", "capabilities": {"process_exec", "credential_access"},
             "fragments": (3, 6), "sessions": (1, 3),
             "apis": {"exec", "eval", "read_env", "read_config"}},
            {"name": "data_access", "capabilities": {"file_read", "credential_access"},
             "fragments": (3, 8), "sessions": (2, 4),
             "apis": {"readfile", "glob", "getpass", "ssh_key"}},
        ],
        "evasion_level": 0.7,
        "tempo": "slow",
        "cross_session_noise": 0.4,
        "multi_account": False,
    },

    "COINBAIT_UNC5356": {
        # Feb 2026: AI-generated phishing kit via Lovable AI
        "source": "Google GTIG Feb 2026",
        "description": "AI-generated cryptocurrency phishing kit",
        "phases": [
            {"name": "site_generation", "capabilities": {"file_write", "network_outbound"},
             "fragments": (5, 15), "sessions": (3, 8),
             "apis": {"writefile", "http_request", "connect"}},
            {"name": "credential_harvest", "capabilities": {"credential_access", "crypto"},
             "fragments": (3, 6), "sessions": (2, 4),
             "apis": {"keychain", "browser_storage", "encrypt", "base64"}},
            {"name": "exfiltration", "capabilities": {"network_outbound", "crypto"},
             "fragments": (2, 4), "sessions": (1, 2),
             "apis": {"http_request", "connect", "encrypt"}},
        ],
        "evasion_level": 0.4,
        "tempo": "burst",
        "cross_session_noise": 0.2,
        "multi_account": False,
    },

    "APT42_phishing": {
        # Feb 2026: Multi-turn rapport building via Gemini
        "source": "Google GTIG Feb 2026",
        "description": "Social engineering with multi-turn rapport building",
        "phases": [
            {"name": "persona_craft", "capabilities": {"file_write"},
             "fragments": (3, 8), "sessions": (3, 8),
             "apis": {"writefile", "encode"}},
            {"name": "lure_generation", "capabilities": {"file_write", "network_outbound"},
             "fragments": (5, 12), "sessions": (5, 12),
             "apis": {"writefile", "http_request", "smtp"}},
            {"name": "payload_delivery", "capabilities": {"network_outbound", "process_exec"},
             "fragments": (2, 5), "sessions": (1, 3),
             "apis": {"http_request", "connect", "exec"}},
        ],
        "evasion_level": 0.6,
        "tempo": "adaptive",
        "cross_session_noise": 0.5,
        "multi_account": True,
    },

    # ── OpenAI Threat Intelligence ───────────────────────────────────────

    "ScopeCreep": {
        # Jun 2025: Iterative RAT refinement
        "source": "OpenAI Jun 2025",
        "description": "Iterative remote access trojan development",
        "phases": [
            {"name": "rat_skeleton", "capabilities": {"network_outbound", "process_exec"},
             "fragments": (3, 8), "sessions": (3, 8),
             "apis": {"socket", "connect", "exec", "subprocess"}},
            {"name": "rat_c2", "capabilities": {"network_outbound", "crypto"},
             "fragments": (3, 6), "sessions": (2, 5),
             "apis": {"connect", "http_request", "encrypt", "base64"}},
            {"name": "rat_persistence", "capabilities": {"persistence", "evasion"},
             "fragments": (2, 5), "sessions": (2, 4),
             "apis": {"startup_add", "registry_write", "sleep",
                      "anti_debug", "obfuscate"}},
            {"name": "rat_stealer", "capabilities": {"file_read", "credential_access"},
             "fragments": (3, 6), "sessions": (2, 5),
             "apis": {"readfile", "browser_storage", "keychain",
                      "read_config"}},
        ],
        "evasion_level": 0.5,
        "tempo": "slow",  # iterative refinement
        "cross_session_noise": 0.2,
        "multi_account": False,
    },

    "Russian_malware_clusters": {
        # Oct 2025: Malware development + distribution
        "source": "OpenAI Oct 2025",
        "description": "Cluster of Russian actors developing malware",
        "phases": [
            {"name": "dropper", "capabilities": {"network_outbound", "file_write", "process_exec"},
             "fragments": (3, 8), "sessions": (2, 5),
             "apis": {"http_request", "writefile", "exec", "subprocess"}},
            {"name": "payload", "capabilities": {"process_exec", "crypto", "evasion"},
             "fragments": (5, 12), "sessions": (3, 8),
             "apis": {"eval", "compile", "encrypt", "obfuscate",
                      "pack", "anti_debug"}},
            {"name": "exfil_module", "capabilities": {"file_read", "crypto", "network_outbound"},
             "fragments": (3, 6), "sessions": (2, 4),
             "apis": {"readfile", "glob", "encrypt", "http_request",
                      "dns_query"}},
        ],
        "evasion_level": 0.6,
        "tempo": "burst",
        "cross_session_noise": 0.3,
        "multi_account": True,
    },

    # ── SentinelLABS / Unit 42 ───────────────────────────────────────────

    "MalTerminal": {
        # Sep 2025: Runtime payload gen (PoC)
        "source": "SentinelLABS Sep 2025",
        "description": "Runtime payload generation via GPT-4",
        "phases": [
            {"name": "shellcode_gen", "capabilities": {"process_exec", "crypto"},
             "fragments": (2, 5), "sessions": (2, 4),
             "apis": {"compile", "exec", "encode", "base64"}},
            {"name": "injection", "capabilities": {"process_exec", "evasion"},
             "fragments": (2, 4), "sessions": (1, 3),
             "apis": {"exec", "eval", "anti_debug", "vm_detect"}},
        ],
        "evasion_level": 0.7,
        "tempo": "burst",
        "cross_session_noise": 0.1,
        "multi_account": False,
    },

    "WormGPT_KawaiiGPT": {
        # Nov 2025: Underground malicious LLM market
        "source": "SentinelLABS Nov 2025",
        "description": "Underground uncensored LLM for malware generation",
        "phases": [
            {"name": "malware_gen", "capabilities": {"process_exec", "crypto", "evasion"},
             "fragments": (5, 20), "sessions": (5, 20),
             "apis": {"exec", "eval", "compile", "encrypt",
                      "obfuscate", "pack"}},
            {"name": "distribution", "capabilities": {"network_outbound", "file_write"},
             "fragments": (3, 8), "sessions": (2, 5),
             "apis": {"http_request", "smtp", "writefile"}},
        ],
        "evasion_level": 0.3,  # uncensored = less need to evade
        "tempo": "burst",
        "cross_session_noise": 0.1,
        "multi_account": True,
    },
}

NUM_CAMPAIGN_TYPES = len(CAMPAIGN_TEMPLATES)


# ═══════════════════════════════════════════════════════════════════════════
# DATASET GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

BENIGN_API_POOL = [
    # Common developer APIs — appear frequently in benign code
    "readfile", "writefile", "http_request", "subprocess", "hashlib",
    "base64", "json.loads", "json.dumps", "os.path", "os.mkdir",
    "print", "logging", "datetime", "re.match", "csv.reader",
    "sqlite3", "pandas", "numpy", "requests.get", "flask.run",
    "unittest", "argparse", "threading", "asyncio", "pathlib",
    "tempfile", "shutil.copy", "collections", "itertools", "functools",
]

CAPABILITY_APIS = {
    "recon": {"nmap", "port_scan", "whois", "traceroute", "ifconfig",
              "netstat", "ps_list", "uname", "sysinfo"},
    "network_outbound": {"socket", "connect", "http_request", "dns_query",
                         "urllib", "requests.get", "requests.post", "smtp"},
    "network_listen": {"bind", "listen", "accept", "socketserver", "flask.run"},
    "file_read": {"readfile", "glob", "listdir", "os.walk", "pathlib",
                  "shutil.copy", "zipfile.read"},
    "file_write": {"writefile", "chmod", "os.rename", "shutil.move", "tempfile"},
    "process_exec": {"exec", "spawn", "system", "popen", "subprocess",
                     "eval", "compile"},
    "crypto": {"encrypt", "decrypt", "hash", "encode", "base64",
               "hashlib", "hmac", "aes", "rsa"},
    "credential_access": {"read_env", "read_config", "keychain",
                          "browser_storage", "getpass", "ssh_key"},
    "persistence": {"cron_add", "registry_write", "startup_add",
                    "systemd", "autostart"},
    "evasion": {"sleep", "anti_debug", "vm_detect", "log_clear",
                "obfuscate", "pack", "strip_metadata"},
}


class CampaignDatasetGenerator:
    """
    Generates realistic fragment graphs based on confirmed campaign profiles.

    Key design decisions for realism:
    1. Malicious fragments use the SAME code-intrinsic feature distributions
       as benign ones (evasion_level controls overlap)
    2. Benign code also has cross-session edges (library imports, shared utils)
    3. Temporal patterns mimic legitimate development workflows
    4. Multiple campaigns can be planted in the same graph
    """

    def __init__(self, seed=42):
        self.rng = np.random.default_rng(seed)

    def generate(self,
                 num_benign_nodes: int = 100_000,
                 campaigns_to_plant: dict = None,
                 benign_cross_session_rate: float = 0.15,
                 benign_avg_degree: int = 6,
                 num_sessions: int = 10_000,
                 num_users: int = 2_000):
        """
        Generate a complete fragment graph.

        Args:
            num_benign_nodes: number of benign fragments
            campaigns_to_plant: dict of {campaign_name: count}
                e.g. {"GTG-1002_espionage": 20, "ScopeCreep": 50}
                if None, plants a balanced mix
            benign_cross_session_rate: fraction of benign edges that
                cross session boundaries (realistic baseline)
            benign_avg_degree: average edges per benign node

        Returns:
            adj_list, node_metadata, edge_types_map, labels, campaign_info
        """
        if campaigns_to_plant is None:
            campaigns_to_plant = {name: max(3, 50 // len(t["phases"]))
                                  for name, t in CAMPAIGN_TEMPLATES.items()}

        # --- Generate benign nodes ---
        print(f"Generating {num_benign_nodes:,} benign nodes...")
        adj_list = defaultdict(list)
        edge_types_map = {}
        node_metadata = {}
        labels = {}
        node_id = 0

        for i in range(num_benign_nodes):
            sid = int(self.rng.integers(0, num_sessions))
            uid = int(self.rng.integers(0, num_users))
            base_t = 1700000000.0 + sid * 300 + float(self.rng.uniform(0, 200))

            # Benign capabilities — developers DO use "dangerous" APIs legitimately
            num_caps = int(self.rng.choice([0, 0, 0, 1, 1, 2], size=1)[0])
            all_cap_names = list(CAPABILITY_APIS.keys())
            caps = set(self.rng.choice(all_cap_names, size=num_caps,
                                       replace=False)) if num_caps > 0 else set()

            # Benign API calls — mix of safe + some dangerous
            num_apis = int(self.rng.integers(2, 8))
            apis = set(self.rng.choice(BENIGN_API_POOL, size=num_apis,
                                       replace=False))
            for cap in caps:
                cap_api_list = list(CAPABILITY_APIS[cap])
                apis.add(str(self.rng.choice(cap_api_list)))

            # Code-intrinsic features — SAME distributions used for malicious
            node_metadata[node_id] = {
                "session_id": sid,
                "user_id": uid,
                "timestamp": base_t,
                "risk_score": float(self.rng.beta(1.5, 6)),
                "api_calls": apis,
                "capabilities": caps,
                "string_entropy": float(self.rng.normal(3.8, 0.8)),
                "obfuscation_score": float(self.rng.beta(1.5, 8)),
                "code_complexity": float(self.rng.lognormal(1.5, 0.6)),
                "campaign": None,
            }
            labels[node_id] = 0
            node_id += 1

        # --- Generate benign edges ---
        print(f"Generating benign edges (avg_degree={benign_avg_degree}, "
              f"cross_session_rate={benign_cross_session_rate})...")

        for i in range(num_benign_nodes):
            n_edges = int(self.rng.poisson(benign_avg_degree))
            meta_i = node_metadata[i]

            for _ in range(n_edges):
                if self.rng.random() < benign_cross_session_rate:
                    # Cross-session edge (library import, shared util)
                    j = int(self.rng.integers(0, num_benign_nodes))
                else:
                    # Within-session edge
                    same_session = [k for k in range(max(0, i-30), min(num_benign_nodes, i+30))
                                    if node_metadata[k]["session_id"] == meta_i["session_id"]
                                    and k != i]
                    if same_session:
                        j = int(self.rng.choice(same_session))
                    else:
                        j = int(self.rng.integers(0, num_benign_nodes))

                if j != i:
                    adj_list[i].append(j)
                    et = int(self.rng.choice([0, 1, 1, 1, 2]))
                    edge_types_map[(i, j)] = et

        # --- Plant campaigns ---
        total_malicious = 0
        campaign_info = []

        for campaign_name, count in campaigns_to_plant.items():
            template = CAMPAIGN_TEMPLATES[campaign_name]
            print(f"Planting {count}x {campaign_name} "
                  f"({len(template['phases'])} phases each)...")

            for instance in range(count):
                chain_nodes = []
                chain_sessions = []
                attack_user = int(self.rng.integers(0, num_users))

                if template.get("multi_account", False):
                    attack_users = self.rng.integers(0, num_users, size=3).tolist()
                else:
                    attack_users = [attack_user]

                prev_phase_nodes = []

                for phase_idx, phase in enumerate(template["phases"]):
                    # Determine fragment count
                    if isinstance(phase["fragments"], tuple):
                        n_frags = int(self.rng.integers(*phase["fragments"]))
                    else:
                        n_frags = phase["fragments"]

                    # Determine session spread
                    if isinstance(phase.get("sessions", 1), tuple):
                        n_sess = int(self.rng.integers(*phase["sessions"]))
                    else:
                        n_sess = phase.get("sessions", 1)

                    phase_sessions = self.rng.integers(0, num_sessions,
                                                       size=n_sess).tolist()
                    phase_nodes = []

                    for frag_idx in range(n_frags):
                        nid = node_id
                        node_id += 1

                        sid = int(self.rng.choice(phase_sessions))
                        uid = int(self.rng.choice(attack_users))
                        evasion = template["evasion_level"]

                        # API selection — mix phase-specific with benign cover
                        phase_apis = list(phase.get("apis", set()))
                        n_phase_apis = max(1, int(len(phase_apis) * self.rng.uniform(0.3, 0.8)))
                        apis = set(self.rng.choice(phase_apis,
                                   size=min(n_phase_apis, len(phase_apis)),
                                   replace=False))

                        # Add benign cover APIs proportional to evasion level
                        n_cover = int(evasion * self.rng.integers(2, 6))
                        apis.update(self.rng.choice(BENIGN_API_POOL,
                                    size=n_cover, replace=False))

                        # Timestamps based on tempo
                        if template["tempo"] == "burst":
                            t_offset = frag_idx * float(self.rng.uniform(0.1, 5))
                        elif template["tempo"] == "slow":
                            t_offset = frag_idx * float(self.rng.uniform(60, 7200))
                        else:  # adaptive
                            t_offset = frag_idx * float(self.rng.uniform(10, 3600))

                        base_t = 1700000000.0 + sid * 300 + \
                                 phase_idx * float(self.rng.uniform(300, 86400)) + \
                                 t_offset

                        # Code features — KEY: match benign distributions
                        # with evasion_level controlling how much overlap
                        benign_entropy_mean = 3.8
                        mal_entropy_shift = (1 - evasion) * 1.5
                        entropy = float(self.rng.normal(
                            benign_entropy_mean + mal_entropy_shift, 0.8))

                        benign_obf_mean = 0.12  # beta(1.5, 8) mean
                        mal_obf_shift = (1 - evasion) * 0.4
                        obfuscation = float(self.rng.beta(
                            1.5 + (1-evasion)*2, 8 - (1-evasion)*4))

                        node_metadata[nid] = {
                            "session_id": sid,
                            "user_id": uid,
                            "timestamp": base_t,
                            "risk_score": float(self.rng.beta(
                                1.5 + (1-evasion)*1.5, 6 - (1-evasion)*2)),
                            "api_calls": apis,
                            "capabilities": phase["capabilities"],
                            "string_entropy": entropy,
                            "obfuscation_score": obfuscation,
                            "code_complexity": float(self.rng.lognormal(1.5, 0.6)),
                            "campaign": campaign_name,
                            "phase": phase["name"],
                        }
                        labels[nid] = 1
                        phase_nodes.append(nid)
                        total_malicious += 1

                    # --- Create edges within phase ---
                    for k in range(1, len(phase_nodes)):
                        src = phase_nodes[k-1]
                        dst = phase_nodes[k]
                        adj_list[src].append(dst)
                        et = int(self.rng.choice([0, 0, 1, 3]))
                        edge_types_map[(src, dst)] = et

                    # --- Create edges between phases ---
                    if prev_phase_nodes:
                        # Data-flow from previous phase to current
                        n_cross = max(1, int(self.rng.integers(
                            1, min(4, len(prev_phase_nodes)+1))))
                        for _ in range(n_cross):
                            src = int(self.rng.choice(prev_phase_nodes))
                            dst = int(self.rng.choice(phase_nodes))
                            adj_list[src].append(dst)
                            et = int(self.rng.choice([0, 0, 2, 3]))
                            edge_types_map[(src, dst)] = et

                    # --- Add noise edges for evasion ---
                    noise_rate = template.get("cross_session_noise", 0.2)
                    for pn in phase_nodes:
                        if self.rng.random() < noise_rate:
                            # Connect to random benign node (noise)
                            benign_target = int(self.rng.integers(0, num_benign_nodes))
                            adj_list[pn].append(benign_target)
                            edge_types_map[(pn, benign_target)] = 1

                    prev_phase_nodes = phase_nodes
                    chain_nodes.extend(phase_nodes)
                    chain_sessions.extend(phase_sessions)

                campaign_info.append({
                    "campaign": campaign_name,
                    "instance": instance,
                    "nodes": chain_nodes,
                    "sessions": list(set(chain_sessions)),
                    "num_fragments": len(chain_nodes),
                })

        total_nodes = node_id
        labels_array = np.array([labels.get(i, 0) for i in range(total_nodes)])

        print(f"\n{'='*60}")
        print(f"Dataset summary:")
        print(f"  Total nodes:     {total_nodes:,}")
        print(f"  Benign:          {num_benign_nodes:,} ({num_benign_nodes/total_nodes:.1%})")
        print(f"  Malicious:       {total_malicious:,} ({total_malicious/total_nodes:.1%})")
        print(f"  Total edges:     {sum(len(v) for v in adj_list.values()):,}")
        print(f"  Campaigns:       {len(campaign_info)}")
        print(f"  Campaign types:  {len(campaigns_to_plant)}")

        # Per-campaign breakdown
        from collections import Counter
        camp_counts = Counter(c["campaign"] for c in campaign_info)
        for name, cnt in sorted(camp_counts.items()):
            frags = sum(c["num_fragments"] for c in campaign_info
                       if c["campaign"] == name)
            print(f"    {name:<30s} {cnt:>4} instances, {frags:>5} fragments")

        return adj_list, node_metadata, edge_types_map, labels_array, campaign_info


# ═══════════════════════════════════════════════════════════════════════════
# MAIN — Generate dataset and train GBT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    # Import the feature engine from the GBT module
    import sys
    sys.path.insert(0, "/home/claude")
    try:
        from fragguard_gbt import FragmentFeatureEngine, train_and_evaluate
    except ImportError:
        print("fragguard_gbt.py not found — running standalone generation only")
        FragmentFeatureEngine = None

    gen = CampaignDatasetGenerator(seed=42)

    # Plant a realistic mix of campaigns
    adj, meta, etypes, labels, campaigns = gen.generate(
        num_benign_nodes=100_000,
        campaigns_to_plant={
            "GTG-1002_espionage": 15,
            "GTG-2002_extortion": 20,
            "AI_RaaS_developer": 40,
            "DPRK_IT_fraud": 10,
            "Chinese_vs_Vietnam": 8,
            "PROMPTSTEAL_APT28": 30,
            "PROMPTFLUX": 25,
            "HONESTCUE": 20,
            "QUIETVAULT": 15,
            "COINBAIT_UNC5356": 25,
            "APT42_phishing": 20,
            "ScopeCreep": 35,
            "Russian_malware_clusters": 25,
            "MalTerminal": 30,
            "WormGPT_KawaiiGPT": 20,
        },
        benign_cross_session_rate=0.15,
        num_sessions=10_000,
        num_users=2_000,
    )

    # Save dataset stats
    stats = {
        "total_nodes": len(labels),
        "benign": int((labels == 0).sum()),
        "malicious": int((labels == 1).sum()),
        "edges": sum(len(v) for v in adj.values()),
        "campaigns_planted": len(campaigns),
        "campaign_types": len(set(c["campaign"] for c in campaigns)),
    }
    print(f"\nDataset stats: {json.dumps(stats, indent=2)}")

    # Compute features and train if GBT module available
    if FragmentFeatureEngine is not None:
        print(f"\n{'='*60}")
        print("Computing features and training GBT...")
        engine = FragmentFeatureEngine()
        t0 = time.perf_counter()
        X, node_ids = engine.compute_all_features(adj, meta, etypes)
        feat_time = time.perf_counter() - t0
        print(f"Feature computation: {feat_time:.1f}s "
              f"({feat_time/len(node_ids)*1e6:.0f} µs/node)")

        y = labels[np.array(node_ids)]
        print(f"Features: {X.shape}, malicious: {y.sum():,}/{len(y):,}")

        from sklearn.model_selection import train_test_split
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import classification_report, roc_auc_score

        X_tr, X_te, y_tr, y_te = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)

        clf = GradientBoostingClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.05,
            subsample=0.8, random_state=42)
        clf.fit(X_tr, y_tr)

        y_prob = clf.predict_proba(X_te)[:, 1]
        y_pred = (y_prob > 0.5).astype(int)
        print(f"\n{classification_report(y_te, y_pred, target_names=['benign','malicious'], digits=4)}")
        print(f"ROC AUC: {roc_auc_score(y_te, y_prob):.4f}")

        # Feature importance
        fnames = engine.get_feature_names()
        imp = clf.feature_importances_
        top = np.argsort(imp)[::-1][:10]
        print("\nTop 10 features:")
        for r, i in enumerate(top):
            print(f"  {r+1}. {fnames[i]:<35s} {imp[i]:.4f}")


if __name__ == "__main__":
    main()
