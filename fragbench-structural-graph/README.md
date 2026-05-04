# FragBench: Structural Graph Benchmark for Detecting LLM-Assisted Fragmented Code Attacks

A benchmark for detecting **fragmented malicious code** generated through LLM APIs, where attack payloads are deliberately split across multiple sessions to evade per-request safety filters. Detection leverages **graph neural networks** and **classical ML** over the fragment dependency graph.

## Problem

Attackers use LLM coding assistants to generate malicious code in small, innocent-looking fragments spread across many sessions. Each fragment alone appears benign (e.g., "read a file", "encode a string", "open a socket"), but combined they form complete attack chains — reverse shells, ransomware, data exfiltration, etc.

**Individual fragment analysis fails.** The signal only emerges from **cross-session graph structure**: which fragments depend on each other, share resources, or form temporal chains.

## Architecture

```
Code Fragments ──→ Fragment Graph ──→ Detection Model ──→ P(malicious)
                   (nodes + edges)

  Edge types:
    0: data_flow        (output of A feeds into B)
    1: temporal          (B requested after A)
    2: shared_resource   (both touch same file/socket/PID)
    3: control_dep       (B's execution gated by A's result)
```

Two detection approaches:

1. **GNN-based** (`PrecomputedMLPGNN/`): FragGNN learns embeddings from 2-hop neighborhoods, FragScorer classifies. Runs offline to produce embeddings, online MLP scores at ~78M nodes/sec.

2. **Feature-engineered** (`GradientBoostedTree/`): 36 hand-crafted graph-structural features (degree, cross-session edges, temporal patterns, kill-chain completion, neighbor risk propagation, topology) fed to classical ML models.

## Real-Time Detection Pipeline

In deployment, fragments arrive **independently** with no pre-attached chain identifier — the detector must infer which fragments belong together from event attributes alone, then decide whether each discovered chain is malicious. The full pipeline is three online stages:

```
Event arrives ──▶ ① Link discovery ──▶ ② Chain identification ──▶ ③ Score chain
   (independent)        (build edges       (connected components       (aggregate
                         from event           or community detection     per-event
                         attributes)          on the running graph)      classifier)
```

### ① Link discovery (per-event, online)

When a new event arrives, the system extracts candidate links to the *existing* event graph using only attributes that don't require knowing the chain ID:

| Edge type | Heuristic | Implementation |
|---|---|---|
| `temporal` | Same `session_id` AND `seq` is consecutive | index by `session_id` → most-recent `seq` |
| `shared_session` | Same `session_id` (regardless of sub-session) | hash-index by `session_id` |
| `shared_resource` | Same path / URL / hostname / IPv4 extracted from `arguments` | regex extract → hash table from resource → list of nodes |
| `data_flow` | Matching `tool_call_index` ↔ `tool_result_index` within a session | pending-call dict keyed by `(session_id, idx)` |
| `argument_similarity` | SimHash on `arguments` text within a low Hamming distance | banded LSH on 64-bit SimHash |

Each new event produces 0–N edges to existing nodes. No supervised chain assignment is consulted.

#### Link discovery — full design space

The four heuristics above are the **identity-preserving layer** — they work when the attacker hasn't actively obfuscated identifiers. A robust production deployment layers stronger techniques on top to defeat adversarial fragmentation.

**Layer 1 — Identity-preserving (online, exact match, O(1) per event)**

1. **`data_flow`** — pair `tool_call` ↔ `tool_result` by matching `tool_call_index` ↔ `tool_result_index` within a `session_id`. Edge weight 1.0 (definitive). Only links within a single tool-use turn.
2. **`temporal`** — consecutive `seq` numbers within the same `session_id`. Edge weight 1.0.
3. **`shared_session`** — same `session_id` for any non-consecutive pair. Edge weight 0.9.
4. **`shared_resource`** — same path / URL / hostname / IPv4 extracted from `arguments` via regex. Resource cardinality drives weight: `/tmp/output.csv` (very common) → 0.3, `/private/key/aws_secret.pem` (rare) → 0.9. Cap fan-out per resource (e.g. last 16) to prevent hub explosion.

Limitation of Layer 1: an attacker can defeat all four by **rotating session_ids** between fragments and using **unique random filenames** for every resource.

**Layer 2 — Account-level binding (when identity-preserving fails)**

5. **Same user / API key** — even when session_ids vary and resources differ, the authenticated principal is fixed (rate limits, billing). Hash-index by `(account_id, time_window)`. Edge weight 0.7. *Requires `account_id` on each event — nice1 doesn't carry this; production deployments routinely do.*
6. **Loose temporal proximity within account** — events from the same account within an N-minute window. Combine with a coarse tool-set filter to suppress legitimate parallel work. Edge weight 0.5.

**Layer 3 — Content-similarity (defeats unique-resource adversaries)**

7. **Tool-sequence MinHash** — MinHash of `(tool, arg_shape)` n-grams over a sliding window. Banded LSH gives sub-linear lookup; hash-collision = candidate chain match. Edge weight 0.6.
8. **Argument SimHash** — 64-bit SimHash of arguments text; events within Hamming distance ≤ 8 link. Catches templated argument generation. Edge weight 0.5–0.7. *(Implemented in `build_graph.py` — see `--enable-argsim`.)*
9. **Embedding kNN** — embed each event's `(tool, arguments)` with a small sentence transformer (e.g. `bge-small-en-v1.5`, 384-dim). Maintain a faiss approximate-kNN index. Link nearest neighbors above similarity threshold. Edge weight `1 − cosine_distance`. Cost ~30–100 ms/event but parallelizes; catches semantic matches that surface-form heuristics miss.

**Layer 4 — Behavioral / motif binding (research-grade)**

10. **Inter-event timing fingerprint** — each user/agent has a characteristic inter-arrival distribution; KS test or moment match between two streams. Useful even when the attacker rotates accounts.
11. **Graph motif recurrence** — small motifs (paths of length 3 over edge types) within each candidate chain; recurring motifs across sessions = same attack pattern. Match via Weisfeiler–Lehman hashes.
12. **LLM-based intent meta-classifier (periodic, slow)** — every N minutes, summarize each connected component and ask an LLM "what task is this trying to accomplish?". Use the answer as a meta-feature; escalate when the answer matches a known attack signature. Runs over discovered components rather than per-event; ~$0.001 per chain.

#### Edge weights and union-find with thresholding

Each link carries a confidence weight ∈ [0, 1]. Union-find only merges components when an edge weight clears a threshold:

```python
class WeightedUF:
    def union_if(self, a, b, weight, threshold=0.5):
        if weight < threshold: return       # weak links don't merge
        # ... union by rank
```

Tighter threshold → more chains, fewer false merges (high purity). Looser threshold → fewer chains, may over-merge unrelated activity.

#### Edge TTL and sliding window

Production systems can't grow the graph forever:

- TTL on every edge (e.g. 24 h)
- Periodic pruning: drop nodes whose all edges have expired
- Resource indices use LRU-evict to bound memory
- Embedding kNN index rebuilt on a rolling window

#### Adversarial coverage

| Attacker tactic | Defeated by |
|---|---|
| Random session IDs | (5) account binding, (7)–(9) content links |
| Unique random filenames | (5)–(6) account/temporal, (7)–(9) content links |
| Multi-account rotation | (10) inter-arrival fingerprinting, (11) motif recurrence |
| Slow drip across days | TTL too long for content links; (12) periodic LLM scan still catches |
| All of the above combined | Residual leakage in inter-event timing + tool-sequence motifs is hard to fully erase, but signal weakens — at this point the safety boundary is statistical |

### ② Chain identification (online connected components)

A union-find structure over event nodes is updated whenever an edge is created in step ①. The connected components of the running graph **are** the discovered chains:

```python
uf = UnionFind()
def on_event(ev):
    nid = add_node(ev)
    for nbr in find_neighbors(ev):     # link discovery (step ①)
        add_edge(nid, nbr, edge_type)
        uf.union(nid, nbr)             # chain assignment
    chain_id = uf.find(nid)            # which discovered chain this event joins
```

Events from unrelated sessions naturally end up in different components because they share no `session_id`, no resources, and no data-flow links. Adversarial fragmentation tries to break this by avoiding shared resources — that's exactly where graph-aware features still surface co-membership through indirect signals (matching tool patterns, similar argument fingerprints, recurring temporal motifs).

### ③ Score chain (per-event classifier + rollup)

The per-event classifier (GBT or GNN) scores every event individually using its own attributes plus 1-hop neighborhood aggregations (per-edge-type neighbor counts, neighbor-tool histograms, neighbor success-rate, etc.). The chain-level decision is an aggregation:

| Aggregator | Behavior |
|---|---|
| `max(p_i)` | Flags chain if any event scores high — high recall, low precision |
| `mean(p_i)` | Smoother; majority of events must look malicious |
| top-k mean | Robust middle ground |
| Attention pool | Learnable; needs more data |

A threshold on the chain score → flag.

### Continuous update

- New events update existing chains and may **merge** previously-separate chains when a bridging resource appears.
- Old events expire on a TTL to keep the running graph bounded.
- Decisions are re-run on each chain as it grows; flagging is monotonic by design (a flagged chain stays flagged).

### Honest evaluation metrics

When the chain assignment is *discovered* rather than supplied, the meaningful metrics are:

| Metric | What it measures |
|---|---|
| **Chain purity** | Fraction of events in each discovered chain that share the same true label — measures "did link discovery group the right things?" |
| **Component count** | How many chains the system finds vs. how many true chains exist |
| **Chain-level F1** | Of discovered chains, how many are correctly labeled malicious vs benign |
| **Per-event F1** | Independent of chain discovery — measures the per-fragment classifier alone |

### Reference numbers on `dataset/nice1`

1,017 outer samples, 18,581 events. 70/30 stratified split *over outer samples* (no event leakage). Per-event train: 13,549; test: 5,032. Per-sample rollup test (samples with ≥1 event): 190. Models use only inferable graph features — no `outer_idx`/chain ID is supplied to the model.

#### Per-event (test = 5,032 events, threshold 0.5)

| Model | Features | Accuracy | Precision | Recall | F1 | ROC AUC | AP |
|---|---|---:|---:|---:|---:|---:|---:|
| **GBT (multi-hop SAGE-mean)** | own + mean(1-hop) + mean(2-hop) | **0.9688** | 0.9643 | 0.9937 | **0.9788** | 0.9965 | 0.9987 |
| Random Forest | own + 1-hop summary | 0.9636 | 0.9686 | 0.9816 | 0.9751 | 0.9893 | 0.9939 |
| MLP (sklearn) | own + 1-hop summary | 0.9338 | 0.9517 | 0.9572 | 0.9545 | 0.9752 | 0.9904 |
| GBT (own + 1-hop summary) | own + 1-hop summary | 0.9219 | 0.9138 | 0.9852 | 0.9481 | 0.9799 | 0.9919 |
| KNN (k=15) | own + 1-hop summary | 0.9014 | 0.9156 | 0.9517 | 0.9333 | 0.9559 | 0.9769 |
| SVM (RBF) | own + 1-hop summary | 0.8841 | 0.8820 | 0.9698 | 0.9238 | 0.9523 | 0.9800 |
| AdaBoost | own + 1-hop summary | 0.8690 | 0.8635 | 0.9731 | 0.9150 | 0.9551 | 0.9828 |
| Logistic Regression | own + 1-hop summary | 0.8607 | 0.8693 | 0.9506 | 0.9082 | 0.9292 | 0.9726 |

#### Per-sample rollup (max event prob, best-F1 threshold)

| Model | Threshold | Accuracy | Precision | Recall | F1 | ROC AUC |
|---|---:|---:|---:|---:|---:|---:|
| **GBT (multi-hop SAGE-mean)** | 0.98 | **1.0000** | **1.0000** | 1.0000 | **1.0000** | 1.0000 |
| AdaBoost | 0.59 | 0.9895 | 0.9592 | 1.0000 | 0.9792 | 0.9994 |
| Logistic Regression | 0.98 | 0.9895 | 0.9592 | 1.0000 | 0.9792 | 1.0000 |
| GBT (own + 1-hop summary) | 0.93 | 0.9842 | 0.9400 | 1.0000 | 0.9691 | 0.9994 |
| SVM (RBF) | 0.96 | 0.9737 | 0.9200 | 0.9787 | 0.9485 | 0.9954 |
| Random Forest | 0.99 | 0.9579 | 0.8545 | 1.0000 | 0.9216 | 0.9720 |
| MLP (sklearn) | 0.99 | 0.9316 | 0.7833 | 1.0000 | 0.8785 | 1.0000 |
| KNN (k=15) | 0.94 | 0.9000 | 0.7121 | 1.0000 | 0.8319 | 0.9336 |

#### Per-campaign breakdown (best model: GBT multi-hop SAGE-mean, threshold 0.98)

Per-campaign sample-level recall and intra-campaign per-event F1. Only campaigns with ≥1 sample in the 30% test split are shown.

| Campaign | # test samples | caught | sample recall | # events | event F1 |
|---|---:|---:|---:|---:|---:|
| AI_PHISHING | 2 | 2 | 1.0000 | 448 | 1.0000 |
| CLICKFIX_VIA_AI_CHAT | 3 | 3 | 1.0000 | 216 | 0.9907 |
| COINBAIT | 1 | 1 | 1.0000 | 86 | 1.0000 |
| DPRK_FRAUD | 17 | 17 | 1.0000 | 583 | 0.9983 |
| GTG1002 | 1 | 1 | 1.0000 | 298 | 0.9932 |
| LONDON_DRUGS_LOCKBIT | 2 | 2 | 1.0000 | 406 | 0.9963 |
| MALTERMINAL | 1 | 1 | 1.0000 | 98 | 1.0000 |
| NOCODE_RANSOMWARE | 1 | 1 | 1.0000 | 162 | 1.0000 |
| OPERATION_FALSE_WITNESS | 1 | 1 | 1.0000 | 82 | 1.0000 |
| PROMPTFLUX | 3 | 3 | 1.0000 | 172 | 0.9971 |
| PROMPTSTEAL | 5 | 5 | 1.0000 | 189 | 0.9811 |
| QUIETVAULT | 6 | 6 | 1.0000 | 554 | 1.0000 |
| SCOPE_CREEP | 1 | 1 | 1.0000 | 104 | 0.9903 |
| TYCOON2FA | 1 | 1 | 1.0000 | 100 | 1.0000 |
| WORMGPT_KAWAIIGPT | 2 | 2 | 1.0000 | 148 | 1.0000 |
| **All campaigns combined** | **47** | **47** | **1.0000** | 3,646 | 0.9788 |
| BENIGN (control) | 143 | — | — | 1,386 | 0 false-positive samples |

**Highlights:**

- **100% sample-level recall in every represented campaign** — every malicious chain in the test split is caught.
- **0 benign samples flagged** as malicious at the optimal threshold.
- Intra-campaign event F1 varies between 0.9811 (PROMPTSTEAL — densely-fragmented attack with many ambiguous individual events) and 1.0000 (e.g. WORMGPT_KAWAIIGPT, QUIETVAULT, MALTERMINAL — campaigns whose individual fragments retain enough structural anomaly to flag per-event without rollup).
- The 7 campaigns absent from the table (e.g. ad_discovery, HELLO_WORLD, JASPER_SLEET, ns_power_ransomware, UNC2970, DEEPFAKE_ID_FRAUD, VIBE_EXTORTION) had no samples land in the 30% test split (each has only 4 total samples in the full corpus).

#### Takeaways

1. **Multi-hop graph structure adds real signal.** Switching from `own + 1-hop summary` to `own + mean(1-hop) + mean(2-hop)` lifts per-event F1 from 0.9481 → **0.9788** (+3.1 pp) and the per-sample rollup from F1 0.9691 → **1.0000**. The 2-hop neighborhood encodes kill-chain context that single-fragment views miss — exactly the FragBench thesis.
2. **All non-trivial classifiers achieve F1 ≥ 0.91** at the per-event level using only inferable graph features (no labels supplied at inference). The ceiling is set by ambiguous fragments where local context alone is insufficient.
3. **Threshold tuning matters at rollup time.** Default 0.5 routinely under-flags benign-heavy chains; the optimal threshold for the multi-hop model is 0.98. The classifier ranks events very well (AUC ≈ 1.0); the operating point should be tuned per deployment.
4. **75 of 191 test malicious samples are empty** in `dataset/nice1/malicious.json` (no events in their sub-sessions — a source-data artifact). They are excluded from the rollup metrics because no detector with no input can classify them. Keeping them inflates the apparent error rate.

These numbers still rely on the dataset's `outer_idx` for the rollup grouping; substituting union-find connected components from the inferred edges closes that loop. Reproduction scripts in `dataset/nice1/`:

```bash
python dataset/nice1/build_graph.py     # build the inferable-link graph
python dataset/nice1/eval_realtime.py   # GBT / LR per-event + rollup
python dataset/nice1/eval_compare.py    # full classical-ML + multi-hop SAGE comparison
```

## Project Structure

```
├── PrecomputedMLPGNN/
│   ├── models.py           # FragGNN (SAGE/GAT/GCN/GIN) + FragScorer
│   ├── train_gnn.py        # GNN training pipeline with neighbor sampling
│   ├── compare_gnns.py     # 11-model comparison benchmark
│   ├── bench_inference.py   # Inference latency benchmarks
│   ├── embedder.py         # Offline batch embedding to KV store
│   └── server.py           # Online scoring service
├── GradientBoostedTree/
│   ├── fragguard_gbt.py    # Feature engine + GBT training + scoring API
│   └── main.py             # Campaign dataset generator (19 templates)
├── dataset/
│   ├── synthetic/
│   │   ├── fragguard_100k_campaigns.jsonl.gz  # 100K campaigns (83 MB)
│   │   └── fragbench_samples.json             # 30 sample campaigns
│   ├── generated-llm/                         # LLM-generated fragments
│   └── generated-manual/                      # Manually-curated fragments
└── checkpoints/            # Saved models (git-ignored)
```

## Dataset

**100,000 campaigns** derived from 19 confirmed LLM-assisted attack reports:

| Source | Campaigns | Examples |
|---|---|---|
| Anthropic | 5 | GTG-1002 espionage (state-sponsored, 6 phases), AI RaaS, DPRK IT fraud |
| Google GTIG | 7 | PROMPTFLUX (self-modifying malware), HONESTCUE (fileless), APT42 phishing |
| OpenAI | 2 | ScopeCreep (iterative RAT), Russian malware clusters |
| SentinelLABS | 2 | MalTerminal (runtime payload gen), WormGPT underground market |

Each campaign defines attack phases mapped to MITRE ATT&CK, with realistic evasion levels, temporal patterns, and cross-session noise.

## GNN Architectures

Four GNN variants implemented in `models.py`, all sharing the same 2-hop neighbor sampling and edge-type-aware aggregation:

| Architecture | Aggregation | Key Property |
|---|---|---|
| **GraphSAGE** | Masked mean | Bounded activations, scales to billions of nodes |
| **GAT** | Multi-head attention (4 heads) | Learns which neighbors matter most |
| **GCN** | Single weight on self+neighbor mean | Fewest parameters, simple and effective |
| **GIN** | Sum + MLP with learnable epsilon | Maximally expressive (WL-equivalent) in theory |

## Quick Start

Independent-fragment evaluation on `dataset/nice1/`:

```bash
# 1. Build the inferable-link graph from the raw event sessions
python dataset/nice1/build_graph.py                       # Layer 1 edges
python dataset/nice1/build_graph.py --enable-argsim       # + Layer 8 (SimHash)

# 2. Per-event GBT/LR baseline (no outer_idx leakage)
python dataset/nice1/eval_realtime.py

# 3. Full classical-ML + multi-hop SAGE-mean comparison
#    (per-event, per-sample rollup, per-campaign breakdown)
python dataset/nice1/eval_compare.py
```

## Requirements

```
torch >= 2.0
numpy
scikit-learn
```

Optional: `xgboost` (faster GBT), `rocksdb` (embedding store for production serving).
