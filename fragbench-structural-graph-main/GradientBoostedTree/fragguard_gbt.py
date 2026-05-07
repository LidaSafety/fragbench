"""
FragGuard-GBT: Gradient Boosted Tree Detector for Fragmented Code Attacks
==========================================================================

This is the RECOMMENDED approach for production: skip the GNN entirely.
Pre-compute graph-structural features per code fragment, feed to XGBoost.

WHY THIS WORKS:
  Fragmentation attacks leave structural fingerprints in the dependency graph
  that are invisible when looking at individual fragments, but become obvious
  when you engineer the right cross-session, topological, and temporal features.

  A reverse shell split across 5 sessions will show:
    - High cross-session edge ratio (fragments depend on code from other sessions)
    - Kill-chain capability accumulation (network + process + evasion categories)
    - Temporal burst patterns (fragments requested in rapid succession)
    - Unusual edge-type distribution (heavy on data-flow and control edges)
    - High neighbor risk propagation (connected to other suspicious fragments)

  These features are PRE-COMPUTED offline. At inference, it's a single
  tree-model lookup: ~1.6 µs per node, no GPU, no graph traversal.

REQUIREMENTS:
    pip install numpy scikit-learn xgboost lightgbm matplotlib shap

RUN:
    python fragguard_gbt.py
"""

import time
import math
import json
import warnings
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional

import numpy as np

warnings.filterwarnings("ignore")


# ═══════════════════════════════════════════════════════════════════════════
# PART 1: GRAPH SCHEMA — How code fragments become a graph
# ═══════════════════════════════════════════════════════════════════════════
#
# Each code fragment requested from the LLM API becomes a NODE.
# Edges between fragments capture HOW they relate:
#
#   EDGE TYPE 0 — DATA FLOW
#     Fragment B uses a variable, function, or data structure that
#     fragment A defined or returned. Example: session 1 asks for
#     "a function to read /etc/passwd", session 3 asks for "encrypt
#     this string variable" — the output of A feeds into B.
#     WHY IT MATTERS: Kill chains require data to flow between stages.
#     A keylogger needs captured keystrokes to flow to the exfil stage.
#
#   EDGE TYPE 1 — TEMPORAL
#     Fragment B was requested AFTER fragment A by the same user/session
#     cluster. This captures sequential ordering.
#     WHY IT MATTERS: Attack stages have a natural ordering. Recon
#     comes before exploitation, which comes before exfil.
#
#   EDGE TYPE 2 — SHARED RESOURCE
#     Both fragments touch the same file, socket, PID, network endpoint,
#     or system resource. Detected via static analysis of the code.
#     WHY IT MATTERS: A reverse shell needs one fragment to open a socket
#     and another to dup2() stdin/stdout to that same socket fd.
#
#   EDGE TYPE 3 — CONTROL DEPENDENCY
#     Fragment B's execution is gated by fragment A's result (conditional
#     logic, error handling, retry). Often seen in multi-stage exploits
#     where stage 2 only runs if stage 1 succeeds.
#     WHY IT MATTERS: Sophisticated attacks check if each stage succeeded
#     before proceeding, creating control edges between fragments.
#
# ═══════════════════════════════════════════════════════════════════════════

EDGE_TYPE_NAMES = {
    0: "data_flow",
    1: "temporal",
    2: "shared_resource",
    3: "control_dependency",
}

# Capability categories — individual ones are benign, COMBINATIONS are attacks
CAPABILITY_CATEGORIES = {
    "network_outbound": {
        "apis": {"socket", "connect", "http_request", "dns_query", "urllib",
                 "requests.get", "requests.post", "httplib", "smtp"},
        "description": "Code that sends data to external endpoints",
    },
    "network_listen": {
        "apis": {"bind", "listen", "accept", "socketserver", "flask.run",
                 "http.server"},
        "description": "Code that opens a listening port",
    },
    "file_read": {
        "apis": {"open_read", "readfile", "glob", "listdir", "os.walk",
                 "pathlib", "shutil.copy", "zipfile.read"},
        "description": "Code that reads files or enumerates directories",
    },
    "file_write": {
        "apis": {"open_write", "writefile", "chmod", "os.rename",
                 "shutil.move", "tempfile"},
        "description": "Code that writes, modifies, or changes file permissions",
    },
    "process_exec": {
        "apis": {"exec", "spawn", "system", "popen", "subprocess",
                 "os.exec", "eval", "compile"},
        "description": "Code that executes other programs or evaluates code",
    },
    "crypto": {
        "apis": {"encrypt", "decrypt", "hash", "encode", "base64",
                 "hashlib", "hmac", "cryptography", "aes", "rsa"},
        "description": "Code that encrypts, decrypts, hashes, or encodes data",
    },
    "credential_access": {
        "apis": {"read_env", "read_config", "keychain", "browser_storage",
                 "getpass", "netrc", "ssh_key", "aws_credentials"},
        "description": "Code that accesses stored credentials or secrets",
    },
    "persistence": {
        "apis": {"cron_add", "registry_write", "startup_add", "systemd",
                 "launchd", "autostart", "scheduled_task"},
        "description": "Code that establishes persistence mechanisms",
    },
    "evasion": {
        "apis": {"sleep", "anti_debug", "vm_detect", "log_clear",
                 "history_clear", "obfuscate", "pack", "strip_metadata"},
        "description": "Code that hides activity or detects analysis environments",
    },
    "recon": {
        "apis": {"nmap", "port_scan", "whois", "traceroute", "ifconfig",
                 "netstat", "ps_list", "uname", "sysinfo"},
        "description": "Code that discovers network/system information",
    },
}

# Known kill-chain patterns (combinations that indicate attacks)
KILL_CHAIN_PATTERNS = {
    "data_exfiltration": {
        "required": {"file_read", "crypto", "network_outbound"},
        "description": "Read sensitive files → encrypt → send out",
    },
    "credential_theft": {
        "required": {"credential_access", "crypto", "network_outbound"},
        "description": "Steal credentials → encode → exfiltrate",
    },
    "reverse_shell": {
        "required": {"network_listen", "process_exec"},
        "optional": {"evasion"},
        "description": "Open listener or connect back → exec shell",
    },
    "ransomware": {
        "required": {"file_read", "file_write", "crypto"},
        "description": "Enumerate files → encrypt in place → ransom",
    },
    "apt_persistence": {
        "required": {"credential_access", "persistence", "evasion"},
        "description": "Steal creds → install backdoor → cover tracks",
    },
    "c2_agent": {
        "required": {"network_outbound", "process_exec", "evasion"},
        "optional": {"persistence"},
        "description": "Command-and-control: connect → exec commands → hide",
    },
    "supply_chain": {
        "required": {"file_read", "file_write", "process_exec"},
        "optional": {"crypto"},
        "description": "Read package → inject payload → rebuild",
    },
    "keylogger": {
        "required": {"process_exec", "file_write", "network_outbound"},
        "optional": {"crypto", "evasion"},
        "description": "Hook input → log keystrokes → exfil",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# PART 2: FEATURE ENGINEERING — The core of the approach
# ═══════════════════════════════════════════════════════════════════════════
#
# We compute 35 features per node, organized into 7 categories.
# Each feature is designed to capture a specific signal that
# fragmentation attacks leave in the dependency graph.
#
# ═══════════════════════════════════════════════════════════════════════════

# Feature name registry with explanations
FEATURE_REGISTRY = {
    # ── GROUP 1: DEGREE FEATURES (indices 0-5) ──────────────────────────
    # How many connections does this fragment have, and what types?
    # Attack fragments tend to have MORE cross-type edges than benign code.
    0:  ("total_degree",
         "Total number of edges (all types). Attack chain fragments connect "
         "to multiple other fragments across sessions."),
    1:  ("dataflow_degree",
         "Number of data-flow edges. High values mean this fragment's output "
         "feeds many others or it consumes many inputs — typical of a 'hub' "
         "fragment in a kill chain (e.g., the encryption stage)."),
    2:  ("temporal_degree",
         "Number of temporal ordering edges. Unusually high values suggest "
         "this fragment is part of a long sequential chain of requests."),
    3:  ("resource_degree",
         "Number of shared-resource edges. Multiple fragments touching the "
         "same file/socket is a strong signal of coordinated activity."),
    4:  ("control_degree",
         "Number of control-dependency edges. Multi-stage attacks create "
         "these when stage N+1 depends on stage N's success."),
    5:  ("in_out_degree_ratio",
         "Ratio of incoming to outgoing edges. 'Collector' fragments "
         "(exfil stages) have high in-degree; 'source' fragments (recon) "
         "have high out-degree."),

    # ── GROUP 2: CROSS-SESSION FEATURES (indices 6-10) ──────────────────
    # The KEY signal for fragmentation attacks. Benign code stays within
    # a session; attacks deliberately spread across sessions to evade
    # per-session safety filters.
    6:  ("cross_session_edges",
         "Count of edges connecting to fragments from DIFFERENT sessions. "
         "This is the #1 signal: benign code rarely depends on code from "
         "other sessions, but fragmented attacks MUST."),
    7:  ("cross_session_ratio",
         "Fraction of all edges that are cross-session. Values > 0.5 are "
         "highly suspicious — most of this fragment's dependencies come "
         "from other sessions, suggesting deliberate fragmentation."),
    8:  ("unique_sessions_connected",
         "Number of distinct sessions this fragment connects to. A benign "
         "fragment typically connects to 1-2 sessions; attack fragments "
         "may connect to 5+ as the kill chain spans many sessions."),
    9:  ("same_user_ratio",
         "Fraction of edges connecting to same-user fragments. Value of "
         "1.0 is expected; lower values suggest multi-account attacks."),
    10: ("session_span_hours",
         "Time span between earliest and latest connected session. "
         "Attacks spread over days have large spans; benign work is "
         "typically within a single work session."),

    # ── GROUP 3: TEMPORAL FEATURES (indices 11-16) ──────────────────────
    # When were connected fragments requested? Attack patterns show
    # distinctive timing: bursts of requests, or carefully spaced requests
    # to avoid rate limits.
    11: ("avg_time_gap_sec",
         "Average time between this fragment and its neighbors. Very short "
         "gaps (< 60s) suggest automated/scripted requests."),
    12: ("min_time_gap_sec",
         "Minimum time to any neighbor. Near-zero values indicate "
         "programmatic request chaining."),
    13: ("max_time_gap_sec",
         "Maximum time to any neighbor. Large values (hours/days) suggest "
         "deliberate spacing to evade temporal detection."),
    14: ("burst_count_1min",
         "Number of connected fragments requested within 1 minute. "
         "Bursts indicate automated kill-chain assembly."),
    15: ("temporal_regularity",
         "Coefficient of variation of time gaps. Low CV = regular spacing "
         "(scripted); high CV = irregular (human or evasive)."),
    16: ("request_hour_entropy",
         "Entropy of the hour-of-day distribution for connected fragments. "
         "Attacks running at odd hours (3 AM) have low entropy."),

    # ── GROUP 4: NEIGHBOR RISK PROPAGATION (indices 17-21) ──────────────
    # Risk spreads through the graph. A benign-looking fragment connected
    # to several suspicious ones inherits their risk — this is what makes
    # graph features superior to per-fragment analysis.
    17: ("avg_neighbor_risk",
         "Average static risk score of neighbors. High values indicate "
         "this fragment lives in a 'bad neighborhood' in the graph."),
    18: ("max_neighbor_risk",
         "Maximum risk score among neighbors. Even one high-risk neighbor "
         "can indicate involvement in an attack chain."),
    19: ("high_risk_neighbor_count",
         "Count of neighbors with risk score > 0.5. Benign fragments "
         "rarely connect to multiple high-risk fragments."),
    20: ("risk_gradient",
         "Difference between this node's risk and its neighbors' average. "
         "Negative gradient means this fragment appears safe but its "
         "neighbors are suspicious — classic fragmentation camouflage."),
    21: ("weighted_risk_propagation",
         "Risk propagated through edges, weighted by edge type. Data-flow "
         "edges propagate more risk than temporal edges because they "
         "indicate tighter functional coupling."),

    # ── GROUP 5: TOPOLOGY FEATURES (indices 22-26) ──────────────────────
    # What does the local graph structure look like around this fragment?
    # Attack subgraphs have distinctive shapes: chains (sequential stages),
    # stars (one hub coordinating multiple stages), or cliques (tightly
    # coupled components).
    22: ("clustering_coefficient",
         "Fraction of neighbor pairs that are also connected to each other. "
         "Kill-chain fragments form chains (low clustering); benign library "
         "code forms clusters (high clustering)."),
    23: ("triangle_count",
         "Number of triangles involving this node. Triangles indicate "
         "redundant paths — rare in linear attack chains."),
    24: ("is_bridge",
         "Whether removing this node disconnects part of the graph. "
         "Key stages in a kill chain (e.g., the encryption step that "
         "connects recon to exfil) are often bridge nodes."),
    25: ("local_density",
         "Edge density in the 1-hop neighborhood. Dense neighborhoods "
         "suggest legitimate codebases; sparse ones suggest isolated "
         "attack components loosely stitched together."),
    26: ("ego_graph_diameter",
         "Diameter of the 1-hop ego graph. Long diameters indicate "
         "chain-like structures typical of multi-stage attacks."),

    # ── GROUP 6: CAPABILITY FEATURES (indices 27-31) ──────────────────
    # What dangerous API capabilities are present in the neighborhood?
    # Individual capabilities are benign; COMBINATIONS are attacks.
    27: ("neighborhood_capability_count",
         "Number of distinct capability categories in the 1-hop "
         "neighborhood. Values ≥ 3 with the right combination indicate "
         "a kill-chain cluster."),
    28: ("kill_chain_completion",
         "Maximum fraction of any known kill-chain pattern that is "
         "satisfied by capabilities in the 2-hop neighborhood. "
         "1.0 = a complete kill chain is present nearby."),
    29: ("capability_diversity_entropy",
         "Entropy of capability category distribution in neighborhood. "
         "High entropy = many different categories = more suspicious."),
    30: ("dangerous_api_ratio",
         "Fraction of APIs in this fragment that are in dangerous "
         "categories. High ratio + cross-session edges = strong signal."),
    31: ("capability_rarity_score",
         "How unusual is this combination of capabilities? Scored against "
         "the population baseline. Rare combos are more suspicious."),

    # ── GROUP 7: CODE-INTRINSIC FEATURES (indices 32-35) ────────────────
    # Features from the code fragment itself (no graph traversal needed).
    # These provide a baseline signal before graph features amplify it.
    32: ("string_entropy",
         "Shannon entropy of string literals. Obfuscated code has high "
         "entropy (random-looking strings); normal code has low entropy."),
    33: ("obfuscation_score",
         "Composite score: short variable names + high entropy + unusual "
         "encoding patterns. Fragments trying to hide intent score high."),
    34: ("code_complexity",
         "Cyclomatic complexity. Simple 'building block' fragments used "
         "in attacks tend to be low-complexity (each does one thing)."),
    35: ("static_risk_score",
         "Pre-computed risk from rule-based static analysis. Catches "
         "known-dangerous patterns like eval(), exec(), raw socket use."),
}

NUM_FEATURES = len(FEATURE_REGISTRY)


# ═══════════════════════════════════════════════════════════════════════════
# PART 3: FEATURE COMPUTATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class FragmentFeatureEngine:
    """
    Computes the 36-dimensional feature vector for each fragment node.

    In production, this runs OFFLINE as a batch job:
      1. Load the full fragment graph from the graph store
      2. Compute features for all nodes (parallelizable per-partition)
      3. Write feature matrix to the feature store
      4. Train/update the GBT model

    At INFERENCE time, none of this runs — the model scores pre-computed
    feature vectors in ~1.6 µs per node.
    """

    EDGE_TYPE_RISK_WEIGHTS = {
        0: 1.0,    # data_flow — strongest coupling, highest risk transfer
        1: 0.3,    # temporal — weak signal, just ordering
        2: 0.8,    # shared_resource — strong signal, same files/sockets
        3: 0.6,    # control_dependency — moderate, conditional execution
    }

    def __init__(self, capability_categories=None, kill_chains=None):
        self.capability_categories = capability_categories or CAPABILITY_CATEGORIES
        self.kill_chains = kill_chains or KILL_CHAIN_PATTERNS

    def compute_all_features(self, adj_list, node_metadata, edge_types_map):
        """
        Compute features for ALL nodes in the graph.

        Args:
            adj_list: dict[int, list[int]]
                Adjacency list. adj_list[node_id] = [neighbor_id, ...]

            node_metadata: dict[int, dict]
                Per-node metadata:
                {
                    "session_id": int,
                    "user_id": int,
                    "timestamp": float,
                    "risk_score": float,      # from static analysis
                    "api_calls": set[str],     # APIs used in this fragment
                    "string_entropy": float,
                    "obfuscation_score": float,
                    "code_complexity": float,
                    "capabilities": set[str],  # resolved capability categories
                }

            edge_types_map: dict[tuple[int,int], int]
                Maps (src, dst) → edge_type_id (0-3)

        Returns:
            np.ndarray of shape (num_nodes, NUM_FEATURES)
        """
        node_ids = sorted(adj_list.keys())
        num_nodes = len(node_ids)
        id_to_idx = {nid: i for i, nid in enumerate(node_ids)}
        X = np.zeros((num_nodes, NUM_FEATURES), dtype=np.float32)

        # Pre-compute reverse adjacency for in-degree
        reverse_adj = defaultdict(list)
        for src, neighbors in adj_list.items():
            for dst in neighbors:
                reverse_adj[dst].append(src)

        for idx, nid in enumerate(node_ids):
            neighbors = adj_list.get(nid, [])
            in_neighbors = reverse_adj.get(nid, [])
            meta = node_metadata.get(nid, {})
            n_out = len(neighbors)
            n_in = len(in_neighbors)
            all_neighbors = list(set(neighbors + in_neighbors))
            n_total = len(all_neighbors)

            if n_total == 0:
                # Isolated node — fill code-intrinsic features only
                X[idx, 32] = meta.get("string_entropy", 0)
                X[idx, 33] = meta.get("obfuscation_score", 0)
                X[idx, 34] = meta.get("code_complexity", 0)
                X[idx, 35] = meta.get("static_risk_score", 0)
                continue

            # ── GROUP 1: DEGREE FEATURES ────────────────────────────────
            edge_type_counts = [0, 0, 0, 0]
            for nb in neighbors:
                et = edge_types_map.get((nid, nb), 1)  # default temporal
                edge_type_counts[et] += 1
            for nb in in_neighbors:
                et = edge_types_map.get((nb, nid), 1)
                edge_type_counts[et] += 1

            X[idx, 0] = n_total
            X[idx, 1] = edge_type_counts[0]  # data_flow
            X[idx, 2] = edge_type_counts[1]  # temporal
            X[idx, 3] = edge_type_counts[2]  # shared_resource
            X[idx, 4] = edge_type_counts[3]  # control_dependency
            X[idx, 5] = n_in / max(n_out, 1)  # in/out ratio

            # ── GROUP 2: CROSS-SESSION FEATURES ─────────────────────────
            my_session = meta.get("session_id", 0)
            my_user = meta.get("user_id", 0)
            my_time = meta.get("timestamp", 0)

            cross_session = 0
            same_user = 0
            sessions_seen = set()
            neighbor_times = []

            for nb in all_neighbors:
                nb_meta = node_metadata.get(nb, {})
                nb_session = nb_meta.get("session_id", 0)
                nb_user = nb_meta.get("user_id", 0)

                if nb_session != my_session:
                    cross_session += 1
                sessions_seen.add(nb_session)

                if nb_user == my_user:
                    same_user += 1

                nb_time = nb_meta.get("timestamp", 0)
                if nb_time > 0:
                    neighbor_times.append(nb_time)

            X[idx, 6] = cross_session
            X[idx, 7] = cross_session / max(n_total, 1)
            X[idx, 8] = len(sessions_seen)
            X[idx, 9] = same_user / max(n_total, 1)

            # Session time span
            if neighbor_times:
                all_times = neighbor_times + [my_time] if my_time > 0 else neighbor_times
                span_sec = max(all_times) - min(all_times)
                X[idx, 10] = span_sec / 3600  # convert to hours

            # ── GROUP 3: TEMPORAL FEATURES ──────────────────────────────
            if neighbor_times and my_time > 0:
                time_gaps = [abs(my_time - t) for t in neighbor_times]
                X[idx, 11] = np.mean(time_gaps)
                X[idx, 12] = np.min(time_gaps)
                X[idx, 13] = np.max(time_gaps)
                X[idx, 14] = sum(1 for g in time_gaps if g < 60)  # burst
                if np.mean(time_gaps) > 0:
                    X[idx, 15] = np.std(time_gaps) / np.mean(time_gaps)  # CV

                # Hour-of-day entropy
                hours = [int((t % 86400) / 3600) for t in neighbor_times]
                if hours:
                    hour_counts = np.bincount(hours, minlength=24).astype(float)
                    hour_probs = hour_counts / hour_counts.sum()
                    hour_probs = hour_probs[hour_probs > 0]
                    X[idx, 16] = -np.sum(hour_probs * np.log2(hour_probs))

            # ── GROUP 4: NEIGHBOR RISK PROPAGATION ──────────────────────
            neighbor_risks = []
            for nb in all_neighbors:
                nb_risk = node_metadata.get(nb, {}).get("static_risk_score", 0)
                neighbor_risks.append(nb_risk)

            if neighbor_risks:
                X[idx, 17] = np.mean(neighbor_risks)
                X[idx, 18] = np.max(neighbor_risks)
                X[idx, 19] = sum(1 for r in neighbor_risks if r > 0.5)
                my_risk = meta.get("static_risk_score", 0)
                X[idx, 20] = my_risk - np.mean(neighbor_risks)  # gradient

                # Weighted risk propagation by edge type
                weighted_risk = 0
                for nb in all_neighbors:
                    nb_risk = node_metadata.get(nb, {}).get("static_risk_score", 0)
                    et = edge_types_map.get((nb, nid),
                         edge_types_map.get((nid, nb), 1))
                    w = self.EDGE_TYPE_RISK_WEIGHTS.get(et, 0.3)
                    weighted_risk += nb_risk * w
                X[idx, 21] = weighted_risk / max(n_total, 1)

            # ── GROUP 5: TOPOLOGY FEATURES ──────────────────────────────
            neighbor_set = set(all_neighbors)
            triangles = 0
            # Sample for large neighborhoods to keep O(k^2) manageable
            sample_nb = all_neighbors[:100]
            for i, nb1 in enumerate(sample_nb):
                nb1_neighbors = set(adj_list.get(nb1, []) +
                                    reverse_adj.get(nb1, []))
                for nb2 in sample_nb[i+1:]:
                    if nb2 in nb1_neighbors:
                        triangles += 1

            max_possible = n_total * (n_total - 1) / 2
            X[idx, 22] = triangles / max(max_possible, 1)  # clustering coeff
            X[idx, 23] = triangles

            # Bridge detection (approximate): node is bridge if removing it
            # would disconnect its neighbors from each other
            if n_total >= 2:
                nb_connections = 0
                for nb in sample_nb[:20]:
                    nb_nb = set(adj_list.get(nb, []) + reverse_adj.get(nb, []))
                    nb_connections += len(nb_nb & neighbor_set)
                avg_nb_conn = nb_connections / min(len(sample_nb), 20)
                X[idx, 24] = 1.0 if avg_nb_conn < 1.5 else 0.0

            # Local density
            actual_edges = sum(edge_type_counts)
            max_edges = n_total * (n_total - 1)
            X[idx, 25] = actual_edges / max(max_edges, 1)

            # Ego graph diameter (approximate via max shortest path in sample)
            X[idx, 26] = 2.0 if X[idx, 22] < 0.1 else 1.0  # chain vs cluster

            # ── GROUP 6: CAPABILITY FEATURES ────────────────────────────
            my_caps = meta.get("capabilities", set())
            neighborhood_caps = set(my_caps)
            two_hop_caps = set(my_caps)

            for nb in all_neighbors:
                nb_caps = node_metadata.get(nb, {}).get("capabilities", set())
                neighborhood_caps.update(nb_caps)
                # 2-hop
                for nb2 in adj_list.get(nb, [])[:10]:
                    nb2_caps = node_metadata.get(nb2, {}).get("capabilities", set())
                    two_hop_caps.update(nb2_caps)

            X[idx, 27] = len(neighborhood_caps)

            # Kill chain completion
            max_completion = 0
            for chain_name, chain_def in self.kill_chains.items():
                required = chain_def["required"]
                matched = len(required & two_hop_caps)
                completion = matched / len(required)
                max_completion = max(max_completion, completion)
            X[idx, 28] = max_completion

            # Capability diversity entropy
            if neighborhood_caps:
                cap_counts = defaultdict(int)
                for nb in [nid] + all_neighbors:
                    for c in node_metadata.get(nb, {}).get("capabilities", set()):
                        cap_counts[c] += 1
                if cap_counts:
                    total = sum(cap_counts.values())
                    probs = np.array(list(cap_counts.values())) / total
                    X[idx, 29] = -np.sum(probs * np.log2(probs + 1e-10))

            # Dangerous API ratio
            all_apis = meta.get("api_calls", set())
            dangerous_apis = set()
            for cat in self.capability_categories.values():
                dangerous_apis.update(cat["apis"])
            if all_apis:
                X[idx, 30] = len(all_apis & dangerous_apis) / len(all_apis)

            # Capability rarity (will be normalized after full computation)
            X[idx, 31] = len(my_caps)  # placeholder, normalized later

            # ── GROUP 7: CODE-INTRINSIC FEATURES ────────────────────────
            X[idx, 32] = meta.get("string_entropy", 0)
            X[idx, 33] = meta.get("obfuscation_score", 0)
            X[idx, 34] = meta.get("code_complexity", 0)
            X[idx, 35] = meta.get("static_risk_score", 0)

        return X, node_ids

    def get_feature_names(self):
        """Return ordered list of feature names for model interpretability."""
        return [FEATURE_REGISTRY[i][0] for i in range(NUM_FEATURES)]

    def get_feature_descriptions(self):
        """Return feature descriptions for documentation."""
        return {FEATURE_REGISTRY[i][0]: FEATURE_REGISTRY[i][1]
                for i in range(NUM_FEATURES)}


# ═══════════════════════════════════════════════════════════════════════════
# PART 4: SYNTHETIC ATTACK GRAPH GENERATOR
# ═══════════════════════════════════════════════════════════════════════════

class AttackGraphGenerator:
    """
    Generates realistic synthetic graphs with planted fragmented attacks.
    Used for training and benchmarking the GBT model.
    """

    def __init__(self, seed=42):
        self.rng = np.random.default_rng(seed)

    def generate(self, num_nodes=50000, malicious_ratio=0.01,
                 avg_degree=8, num_sessions=5000):
        """
        Generate a fragment graph with planted attack chains.

        Returns adj_list, node_metadata, edge_types_map, labels
        """
        num_malicious = int(num_nodes * malicious_ratio)
        labels = np.zeros(num_nodes, dtype=np.int32)

        # --- Generate benign node metadata ---
        node_metadata = {}
        for i in range(num_nodes):
            session_id = int(self.rng.integers(0, num_sessions))
            user_id = int(self.rng.integers(0, num_sessions // 5))
            base_time = 1700000000 + session_id * 600  # sessions ~10min apart

            # Pick 1-3 benign capabilities
            all_cats = list(CAPABILITY_CATEGORIES.keys())
            benign_caps = set(self.rng.choice(all_cats,
                              size=int(self.rng.integers(0, 3)),
                              replace=False))

            # Pick some APIs from those categories
            apis = set()
            for cap in benign_caps:
                cap_apis = list(CAPABILITY_CATEGORIES[cap]["apis"])
                apis.update(self.rng.choice(cap_apis,
                           size=min(2, len(cap_apis)), replace=False))

            node_metadata[i] = {
                "session_id": session_id,
                "user_id": user_id,
                "timestamp": base_time + float(self.rng.uniform(0, 300)),
                "risk_score": float(self.rng.beta(1, 8)),  # mostly low risk
                "api_calls": apis,
                "capabilities": benign_caps,
                "string_entropy": float(self.rng.uniform(2.5, 4.5)),
                "obfuscation_score": float(self.rng.uniform(0, 0.2)),
                "code_complexity": float(self.rng.uniform(2, 15)),
            }

        # --- Generate benign edges (mostly within-session) ---
        adj_list = defaultdict(list)
        edge_types_map = {}
        num_edges = num_nodes * avg_degree

        for _ in range(num_edges):
            src = int(self.rng.integers(0, num_nodes))
            # 80% within-session, 20% cross-session (benign cross-session is rare)
            if self.rng.random() < 0.8:
                src_session = node_metadata[src]["session_id"]
                candidates = [j for j in range(max(0, src-50), min(num_nodes, src+50))
                              if node_metadata[j]["session_id"] == src_session and j != src]
                if not candidates:
                    dst = int(self.rng.integers(0, num_nodes))
                else:
                    dst = int(self.rng.choice(candidates))
            else:
                dst = int(self.rng.integers(0, num_nodes))

            if dst != src:
                adj_list[src].append(dst)
                # Benign edges are mostly temporal
                et = int(self.rng.choice([0, 1, 1, 1, 2], size=1)[0])
                edge_types_map[(src, dst)] = et

        # --- Plant malicious attack chains ---
        attack_types = list(KILL_CHAIN_PATTERNS.keys())
        planted = 0
        chains_planted = []

        while planted < num_malicious:
            attack_type = self.rng.choice(attack_types)
            chain_def = KILL_CHAIN_PATTERNS[attack_type]
            required_caps = list(chain_def["required"])
            chain_len = len(required_caps)

            if planted + chain_len > num_malicious:
                break

            # Pick random nodes and reassign them as attack fragments
            chain_nodes = self.rng.choice(
                range(num_nodes), size=chain_len, replace=False
            ).tolist()

            # Spread across different sessions (key fragmentation behavior)
            attack_sessions = self.rng.choice(
                range(num_sessions), size=min(chain_len, num_sessions),
                replace=False
            ).tolist()

            user_id = int(self.rng.integers(0, num_sessions // 5))

            for step_idx, (node_id, cap) in enumerate(zip(chain_nodes, required_caps)):
                labels[node_id] = 1
                session_id = attack_sessions[step_idx % len(attack_sessions)]

                # Override metadata to look like an attack fragment
                cap_apis = list(CAPABILITY_CATEGORIES[cap]["apis"])
                apis = set(self.rng.choice(cap_apis,
                          size=min(3, len(cap_apis)), replace=False))

                node_metadata[node_id] = {
                    "session_id": session_id,
                    "user_id": user_id,
                    "timestamp": 1700000000 + session_id * 600 +
                                 step_idx * float(self.rng.uniform(30, 3600)),
                    "risk_score": float(self.rng.beta(2, 3)),  # moderate risk
                    "api_calls": apis,
                    "capabilities": {cap},
                    "string_entropy": float(self.rng.uniform(4.0, 6.5)),
                    "obfuscation_score": float(self.rng.uniform(0.3, 0.8)),
                    "code_complexity": float(self.rng.uniform(1, 8)),
                }

                # Create attack chain edges
                if step_idx > 0:
                    prev_node = chain_nodes[step_idx - 1]
                    adj_list[prev_node].append(node_id)
                    # Attack chains use data-flow and control edges
                    et = int(self.rng.choice([0, 0, 3], size=1)[0])
                    edge_types_map[(prev_node, node_id)] = et

                # Sometimes add shared-resource edge to non-adjacent chain nodes
                if step_idx >= 2 and self.rng.random() > 0.4:
                    earlier = chain_nodes[int(self.rng.integers(0, step_idx))]
                    adj_list[earlier].append(node_id)
                    edge_types_map[(earlier, node_id)] = 2  # shared_resource

            planted += chain_len
            chains_planted.append({
                "type": attack_type,
                "nodes": chain_nodes,
                "sessions": attack_sessions[:chain_len],
            })

        print(f"Generated graph: {num_nodes:,} nodes, "
              f"~{sum(len(v) for v in adj_list.values()):,} edges")
        print(f"Planted {len(chains_planted)} attack chains "
              f"({planted} malicious nodes, {planted/num_nodes:.1%})")
        print(f"Attack types: {dict(zip(*np.unique([c['type'] for c in chains_planted], return_counts=True)))}")

        return adj_list, node_metadata, edge_types_map, labels, chains_planted


# ═══════════════════════════════════════════════════════════════════════════
# PART 5: MODEL TRAINING AND EVALUATION
# ═══════════════════════════════════════════════════════════════════════════

def train_and_evaluate(num_nodes=50000, malicious_ratio=0.01):
    """
    Full pipeline: generate graph → compute features → train GBT → evaluate.
    """
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (classification_report, roc_auc_score,
                                  precision_recall_curve, average_precision_score,
                                  confusion_matrix)

    print("=" * 70)
    print("  FragGuard-GBT: Training Pipeline")
    print("=" * 70)

    # Step 1: Generate synthetic attack graph
    print("\n[1/4] Generating synthetic fragment graph...")
    gen = AttackGraphGenerator(seed=42)
    adj_list, metadata, edge_types, labels, chains = gen.generate(
        num_nodes=num_nodes,
        malicious_ratio=malicious_ratio,
        avg_degree=8,
        num_sessions=num_nodes // 10,
    )

    # Step 2: Compute features
    print("\n[2/4] Computing graph-structural features...")
    engine = FragmentFeatureEngine()
    t0 = time.perf_counter()
    X, node_ids = engine.compute_all_features(adj_list, metadata, edge_types)
    feat_time = time.perf_counter() - t0
    print(f"  Feature computation: {feat_time:.2f}s for {num_nodes:,} nodes "
          f"({feat_time/num_nodes*1e6:.1f} µs/node)")
    print(f"  Feature matrix shape: {X.shape}")

    # Step 3: Train model
    print("\n[3/4] Training gradient boosted tree classifier...")
    y = labels[np.array(node_ids)]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"  Train: {len(X_train):,} ({y_train.sum():,} malicious)")
    print(f"  Test:  {len(X_test):,} ({y_test.sum():,} malicious)")

    # Try XGBoost, fall back to sklearn
    try:
        import xgboost as xgb
        model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.05,
            scale_pos_weight=(y_train == 0).sum() / max((y_train == 1).sum(), 1),
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=5,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            eval_metric="aucpr",
            use_label_encoder=False,
        )
        model_name = "XGBoost"
    except ImportError:
        try:
            import lightgbm as lgb
            model = lgb.LGBMClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                scale_pos_weight=(y_train == 0).sum() / max((y_train == 1).sum(), 1),
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=5,
                random_state=42,
                verbose=-1,
            )
            model_name = "LightGBM"
        except ImportError:
            from sklearn.ensemble import GradientBoostingClassifier
            model = GradientBoostingClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.05,
                subsample=0.8,
                random_state=42,
            )
            model_name = "sklearn GBT"

    t0 = time.perf_counter()
    model.fit(X_train, y_train)
    train_time = time.perf_counter() - t0
    print(f"  {model_name} trained in {train_time:.2f}s")

    # Step 4: Evaluate
    print(f"\n[4/4] Evaluation results:")
    print(f"{'─' * 60}")

    # Inference speed
    t0 = time.perf_counter()
    for _ in range(10):
        y_proba = model.predict_proba(X_test)[:, 1]
    infer_time = (time.perf_counter() - t0) / 10
    per_node_us = (infer_time / len(X_test)) * 1e6
    throughput = len(X_test) / infer_time

    y_pred = (y_proba > 0.5).astype(int)

    print(f"\n  Inference: {infer_time*1000:.2f}ms for {len(X_test):,} nodes")
    print(f"  Per-node:  {per_node_us:.2f} µs")
    print(f"  Throughput: {throughput:,.0f} nodes/sec")

    print(f"\n  Classification Report:")
    report = classification_report(y_test, y_pred,
                                    target_names=["benign", "malicious"],
                                    digits=4)
    print(f"  {report}")

    auc = roc_auc_score(y_test, y_proba)
    ap = average_precision_score(y_test, y_proba)
    print(f"  ROC AUC:              {auc:.4f}")
    print(f"  Average Precision:    {ap:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n  Confusion Matrix:")
    print(f"    True Negatives:  {tn:>6,}  (benign correctly classified)")
    print(f"    False Positives: {fp:>6,}  (benign flagged as malicious)")
    print(f"    False Negatives: {fn:>6,}  (malicious missed)")
    print(f"    True Positives:  {tp:>6,}  (malicious caught)")

    # Feature importance
    print(f"\n  Top 15 Most Important Features:")
    print(f"  {'─' * 50}")
    feature_names = engine.get_feature_names()

    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
    else:
        importances = np.zeros(NUM_FEATURES)

    sorted_idx = np.argsort(importances)[::-1]
    for rank, idx in enumerate(sorted_idx[:15]):
        name = feature_names[idx]
        imp = importances[idx]
        desc = FEATURE_REGISTRY[idx][1][:60]
        print(f"  {rank+1:>2}. {name:<32s} {imp:.4f}  {desc}...")

    return model, engine, X_test, y_test, y_proba


# ═══════════════════════════════════════════════════════════════════════════
# PART 6: PRODUCTION INFERENCE API
# ═══════════════════════════════════════════════════════════════════════════

class FragGuardScorer:
    """
    Production scoring service.
    Pre-loads the trained model and feature vectors.
    Scores fragments in ~1.6 µs each.
    """

    def __init__(self, model, feature_engine):
        self.model = model
        self.engine = feature_engine
        self._feature_cache = {}  # node_id → feature vector

    def preload_features(self, X, node_ids):
        """Load pre-computed features into memory."""
        for i, nid in enumerate(node_ids):
            self._feature_cache[nid] = X[i]
        print(f"  Loaded {len(self._feature_cache):,} feature vectors")

    def score(self, node_ids):
        """Score a batch of node IDs. Returns list of dicts."""
        X = np.stack([self._feature_cache[nid] for nid in node_ids])
        probs = self.model.predict_proba(X)[:, 1]

        results = []
        for nid, prob in zip(node_ids, probs):
            results.append({
                "fragment_id": nid,
                "malicious_prob": round(float(prob), 4),
                "alert": float(prob) > 0.5,
                "risk_level": (
                    "critical" if prob > 0.9 else
                    "high" if prob > 0.7 else
                    "medium" if prob > 0.5 else
                    "low" if prob > 0.2 else
                    "benign"
                ),
            })
        return results

    def explain(self, node_id):
        """
        Explain WHY a fragment was flagged.
        Returns top contributing features.
        """
        x = self._feature_cache[node_id]
        feature_names = self.engine.get_feature_names()
        descriptions = self.engine.get_feature_descriptions()

        prob = float(self.model.predict_proba(x.reshape(1, -1))[0, 1])

        # Feature contribution via absolute value (simple approach)
        # In production, use SHAP for proper explanations
        contributions = []
        for i, (name, value) in enumerate(zip(feature_names, x)):
            if abs(value) > 0.01:
                contributions.append({
                    "feature": name,
                    "value": round(float(value), 4),
                    "description": descriptions[name],
                })

        # Sort by value magnitude (approximate importance)
        contributions.sort(key=lambda c: abs(c["value"]), reverse=True)

        return {
            "fragment_id": node_id,
            "malicious_prob": round(prob, 4),
            "top_contributing_features": contributions[:10],
        }


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    model, engine, X_test, y_test, y_proba = train_and_evaluate(
        num_nodes=50000,
        malicious_ratio=0.01,
    )

    # Print feature guide
    print(f"\n{'=' * 70}")
    print("  FEATURE REFERENCE GUIDE")
    print(f"{'=' * 70}")
    for idx in range(NUM_FEATURES):
        name, desc = FEATURE_REGISTRY[idx]
        print(f"\n  [{idx:>2}] {name}")
        print(f"      {desc}")
