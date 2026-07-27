# Executed-benign control set — updated execution plan

Status as of 2026-07-25. Supersedes the sequencing in `history.txt` (that file is the
original brief and is not edited). Reviewer ask being answered: *"train the same
detectors on MCP executions of benign objectives and report the F1"*.

Decisions taken: full 24 × 21 = 504-chain scope; detector-eval code resolved after
data generation; within-session edge ablation out of scope for this work item.

---

## A. Completed (verified in-repo)

| Item | Evidence |
|---|---|
| Profiler for all three corpora | `scripts/profile_sessions.py` (687 lines) |
| Measured profiles | `docs/profiles/{benign_synthetic,malicious_executed}.json` |
| Distributional target spec | `docs/profiles/benign_targets.md` (§1–§8) |
| `BenignVariation` driver | `variations/benign.py`, registered in `generator.py` |
| Benign style wrappers | `_BENIGN_STYLE_TEMPLATES` in `generator.py`, keyed on `metadata.benign` |
| Two campaign seeds | `seeds/benign_sysadmin_capacity.json` (10 frags), `seeds/benign_it_onboarding.json` (7 frags) |
| Generated fragment files | `results/benign_*_manual.json`, 21 variations each, `base_seed=0` |
| Seed numbering aligned | `DATASET_BASE_SEED 1000 → 0` (Makefile) |
| Pilot execution | 11 runs in `results/runs/`; the 6 most recent are **all-PASS** (7/7, 10/10) |

### Pilot tell measurement (6 most recent chains vs `malicious_executed`)

```
                          executed-benign      malicious      verdict
placeholder session_ids          0.0%             0.0%        fixed
tool_call_index == 1/1          84.4%            77.1%        fixed
failure rate                     3.2%             3.7%        fixed
absolute path share             31.0%            42.6%        fixed
events/fragment (mean)          12.11            11.97        matched
arguments_bytes p99            17,238           26,301        close
result_bytes p99               26,412           45,238        close
```

All four hard tells from `benign_targets.md` §1 are closed. The two byte-tail rows
are within a factor of ~1.7 and will be re-measured on the full run, where the
sample is large enough to judge. Earlier notes claiming two tells overshoot in the
opposite direction are stale — the seed trims fixed them.

---

## B. Open blockers

### B1. Artifact filenames are identical across variations *(must fix before authoring the remaining seeds)*

```
benign    seed 0/1/2 → server_inventory.csv  server_inventory.csv  server_inventory.csv
malicious seed 0/1/2 → invite.txt            (varies)              email.txt
```

Two consequences:

1. **Correctness.** The detector's `shared_resource` edge is built by extracting
   paths from `arguments`. Identical filenames across all 21 variations of a
   campaign would fuse them into one connected component under union-find — a new,
   inverted generation artifact on precisely the edge type the paper's claim rests
   on. The malicious side does not have this property.
2. **Throughput.** All variations of a run share one `/workspace`
   (`docker-attack-graph-run` restarts `server-filesystem` once, at run start), so
   parallel variations would read each other's files. Until fixed, execution must
   stay at `MAX_PARALLEL_VARIATIONS=1`.

**Fix.** Use the existing `filename` variable type (`variations/base.py:114`), the
same mechanism the malicious seeds use. Declare a discriminator in stage 0 and
`inherit` it downstream, embedding it in the artifact base names — bare relative
filenames are preserved, satisfying `benign_targets.md` §4.1:

```jsonc
// stage 0
"variables": {
  "tag": { "type": "filename", "name_pool": ["q3", "q4", "emea", "apac", "fy26", ...] }
}
// fragment prompt
"Save it as server_inventory_{tag}.csv."
"produces": ["server_inventory_{tag}.csv"]
```

Name pool must be large enough that 21 seeds rarely collide (≥ 40 entries, or
compose two variables).

**Required code change:** `run.py:318-319` copies `produces` / `consumes` raw while
prompts go through `_safe_format`. Both lists must be formatted with the resolved
variables too, or the dependency wiring in `attack_runner.py` will try to match a
literal `{tag}`.

### B1a. The sandbox has two filesystem roots, and only one is reset *(accepted as-is by decision)*

Discovered while verifying Step 1. The MCP filesystem server exposes two distinct
directories, and the actor writes to both:

| root | reachable via | reset by `restart server-filesystem` | contents |
|---|---|---|---|
| `/app` (server process cwd) | **relative** paths — the default | **no**, it is the container writable layer | 325 entries accumulated across every run ever, including malicious campaign artifacts (`C:\ProgramData\cache\credentials\…`, `lateral_movement_plan.txt`, `EDUCATIONAL_DEMO_EVASION_TECHNIQUE.md`) |
| `/workspace` | absolute `/workspace/...` | yes, it is a tmpfs re-seeded from the 44 KB `/workspace-seed` | clean per run |

`attack_sysprompt1.txt:19` ("file paths you return MUST be absolute") pushes the
actor toward absolute paths, but tool calls mix both freely — the pilot's measured
absolute-path share is 31%. A chain breaks wherever a fragment writes to one root
and the next fragment reads from the other.

Three consequences, all of which the paper should state rather than hide:

1. **The documented per-run reset does not do what the compose comment claims.**
   Only `/workspace` is reset; the default (relative) root is never cleared.
2. **The earlier all-PASS pilots were partly reading stale data.** With untagged,
   generic filenames (`server_inventory.csv`), a relative read that missed was
   silently satisfied by a leftover from a *previous run*. The self-seeding
   property was partly illusory. Step 1's discriminator removes the leftovers that
   were masking this, which is why failures became visible, not why they exist.
3. **The released malicious corpus was generated in the same contaminated root** —
   42% of its `list_directory` results (348 of 820) contain cross-run clutter.

**Decision: leave the harness unchanged.** Pinning the server cwd to `/workspace`
is a one-line Dockerfile change and would make relative/absolute mixing harmless,
but benign chains would then see a clean filesystem while the released malicious
chains show 42% clutter — a fresh class-separating tell in `list_directory` results,
which is the same category of problem this whole work item exists to remove. Exact
parity with the environment that produced the malicious data is worth more than a
tidy sandbox.

**Consequences to manage instead:**

- Fragment failures from root-mixing are handled the way the paper already
  documents for the malicious side (§4, four failure modes — `session_missing` and
  `no_tool_results` are this exact case): re-run or patch the seed, do not change
  the pipeline.
- The failure rate must be tracked. Malicious sits at 3.7%; the first tagged pilot
  chain came in at 14.7% tool-level (2 of 10 fragments FAIL). If that persists,
  it becomes a tell in its own right and needs a prompt-level mitigation (see
  Step 1a), **not** a harness change.
- `docs/profiles/benign_targets.md` §7 should record that the filesystem state is
  shared and cumulative across both classes, so the environment is a constant
  rather than a class marker.

### B2. No detector evaluation code for real data *(deferred by decision; resolve before Step 6)*

`fragbench-structural-graph-main/` contains `PrecomputedMLPGNN/`,
`GradientBoostedTree/` and `dataset/normalize_dataset.py`, but every `main()` there
builds a **synthetic** graph via `CampaignDatasetGenerator`. Nothing in the checkout
reads a `{is_malicious, sessions}` JSON into a graph. The `build_graph.py` /
`eval_realtime.py` / `eval_compare.py` scripts referenced in the original brief are
absent.

Consequence: the paper's Table 3 F1 cannot currently be reproduced, on either the
synthetic or the executed benign set. Data generation (Steps 1–5) is unaffected and
proceeds; this must be resolved — recovered or rebuilt from §5 and the structural
README's edge-type table — before Step 6 can produce the number the reviewer wants.

---

## C. Remaining steps

Each step is run by hand. Commands are given verbatim; run from the repo root with
`.env` sourced.

### Step 1 — Filename discriminator (blocker B1) — **applied, pending Docker check**

1. ✅ `run.py` now `_safe_format`s each entry of `produces` / `consumes` with the
   variation's resolved variables.
2. ✅ Both seeds carry a two-part discriminator declared in stage 0 as the
   `filename` variable type and `inherit`ed downstream:
   - `benign_sysadmin_capacity`: `{site}` (24 values) × `{cycle}` (20) = 480
   - `benign_it_onboarding`: `{office}` (24) × `{intake}` (20) = 480

   480 combinations puts the expected number of colliding pairs across 21
   variations at ≈0.44, so parallel execution is safe in practice.
3. ✅ Regenerated and verified: 21/21 distinct artifact names per campaign, zero
   collisions, zero unresolved placeholders, zero absolute paths, validator clean
   (210 and 147 fragments), and `attack_runner --dry-run` resolves the full
   dependency ordering.

   Canonical regeneration command (`--output-json` is **required**; `make -f
   Makefrag` wraps it and rebuilds every seed whose result file is stale):
   ```bash
   python run.py --generate --seed-file seeds/<name>.json \
       --seed 0 --num-variations 21 --output-json results/<name>_manual.json
   python scripts/validate_fragments.py results/<name>_manual.json
   ```
4. ⬜ Re-run one chain to confirm the harness still resolves the dependency
   ordering under real execution:
   ```bash
   make docker-attack-graph-run FRAGMENTS=results/benign_sysadmin_capacity_manual.json \
       STYLE=direct SEEDS=0 JUDGE=0 \
       MCP_MODEL_BACKEND=openrouter MCP_MODEL=qwen/qwen3.5-122b-a10b \
       MAX_PARALLEL_VARIATIONS=1 MAX_PARALLEL_FRAGMENTS=1
   ```
   Expect all fragments `PASS` and distinct filenames in `tools_executed`.

**Exit criterion:** two seeds of the same campaign write disjoint artifact sets.
The generation half is met. First execution check: seed 0 of
`BENIGN_SYSADMIN_CAPACITY` ran 8/10 PASS, with fragments 3 and 4 failing to
root-mixing (blocker B1a), not to the discriminator.

### Step 1a — Establish the root-mixing failure rate, then mitigate by prompt

Because the harness stays unchanged (B1a), the only remaining levers are in the
seed prompts. Before pulling one, measure — a single chain is not a rate.

1. Re-run seed 0 and run seed 12 to get four chains' worth of signal:
   ```bash
   make docker-attack-graph-run FRAGMENTS=results/benign_sysadmin_capacity_manual.json \
       STYLE=direct SEEDS=0,12 JUDGE=0 \
       MCP_MODEL_BACKEND=openrouter MCP_MODEL=qwen/qwen3.5-122b-a10b \
       MAX_PARALLEL_VARIATIONS=1 MAX_PARALLEL_FRAGMENTS=1
   ```
2. If the fragment failure rate holds near 20%, the cheapest symmetric mitigation
   is to anchor the root in the *first* fragment's prompt only — "save it in the
   current working directory as `<name>`" — so the chain seeds `/app`, where every
   later relative read already looks. This changes authored prompt text, which is
   ours to write, and leaves the pipeline, sandbox and system prompt untouched.
3. Re-measure. Target: fragment failure rate in the same band as the malicious
   side (3.7%), and no worse than ~2x it.

**Exit criterion:** a full 10-fragment chain completes without root-mixing
failures on two consecutive seeds.

### Step 2 — Author the remaining 22 campaign seeds

Allocation is fixed by `docs/profiles/benign_targets.md` §3 and reproduces the
malicious length histogram (§2) exactly:

| theme | campaigns | fragment counts | authored |
|---|---:|---|---|
| system_administration | 5 | 10, 10, 12, 14, 16 | 1 of 5 (capacity, 10) |
| it_support | 4 | 7, 10, 10, 12 | 1 of 4 (onboarding, 7) |
| compliance_auditing | 3 | 10, 12, 14 | 0 |
| course_preparation | 3 | 10, 10, 12 | 0 |
| project_lifecycle | 3 | 10, 11, 12 | 0 |
| personal_organisation | 2 | 4, 10 | 0 |
| data_wrangling | 2 | 8, 10 | 0 |
| documentation | 2 | 10, 10 | 0 |

Per-seed requirements (`benign_targets.md` §4, plus §7a which the pilot added):

- bare relative filenames, now carrying the `tag` discriminator (Step 1)
- ~16 distinct files per chain; 8–12 tool calls per fragment
- 1–4 fragments per chain carry a multi-KB payload, to hold the `result_bytes`
  p90/p99 tail
- ~5 cross-fragment shared resources via `produces` / `consumes`
- self-seeding: an early fragment writes what later fragments read
- **bulk tabular artifacts must be produced by a short script the agent runs, not
  typed row by row** — wall-clock tracks model *output* bytes (§7a). Reserve
  literal long-form writing for the one or two narrative deliverables and bound
  their length explicitly.
- seed-authoring model: `claude-sonnet-4.5` (§8), matching the released benign corpus
- benign-only toolkits; no `scan_subnet` / `summarize_exposure` / `upload_archive`
- **a per-variation filename discriminator, per Step 1** — two `filename`
  variables in stage 0, `inherit`ed by every later stage, embedded in every
  artifact name in the prompts *and* in `produces` / `consumes`. Aim for ≥400
  combinations. Pick campaign-appropriate axes (site/cycle, office/intake,
  course/term, client/sprint …) rather than reusing one pair everywhere.

Validate each as authored:
```bash
python run.py --generate --seed-file seeds/<name>.json \
    --seed 0 --num-variations 21 --output-json results/<name>_manual.json
python scripts/validate_fragments.py results/<name>_manual.json
```

**Exit criterion:** 24 seeds, 24 `results/*_manual.json`, zero validator errors,
zero absolute paths, length histogram matches §2.

### Step 3 — Smoke-test each new campaign

One chain per campaign (`SEEDS=0`) before committing to the full run — a campaign
whose fragment 4 reliably fails wastes 21 chains' worth of execution.

```bash
make docker-attack-graph-run FRAGMENTS=results/<name>_manual.json \
    STYLE=direct SEEDS=0 JUDGE=0 \
    MCP_MODEL_BACKEND=openrouter MCP_MODEL=qwen/qwen3.5-122b-a10b \
    MAX_PARALLEL_VARIATIONS=1 MAX_PARALLEL_FRAGMENTS=1
```

Patch any campaign with a repeatable fragment failure using the four failure modes
in §4 of the paper (`no_tool_calls` → restore the imperative verb, etc.).

**Exit criterion:** 24/24 campaigns complete a full chain with no `FAIL`.

### Step 4 — Full execution (~504 chains)

Cost model, measured from the pilot: **~6 min per 10-fragment chain**, ~100% actor
generation latency. Serial ≈ 50 h. With `MAX_PARALLEL_VARIATIONS=4` (safe only once
Step 1 lands) ≈ 13 h.

Run **one campaign at a time** — the `server-filesystem` restart at the top of
`docker-attack-graph-run` resets `/workspace`, so concurrent campaigns clobber each
other. `.pilot_onboarding.sh` is the no-restart variant if campaigns must overlap;
cross-campaign filename collisions are unlikely but `/workspace` accumulates.

```bash
for f in results/benign_*_manual.json; do
  make docker-attack-graph-run FRAGMENTS="$f" \
      STYLE=direct SEEDS=0-20 JUDGE=0 \
      MCP_MODEL_BACKEND=openrouter MCP_MODEL=qwen/qwen3.5-122b-a10b \
      MAX_PARALLEL_VARIATIONS=4 MAX_PARALLEL_FRAGMENTS=2
done
```

Harvest: chain records and graphs in `results/runs/`, session JSONLs flat in `logs/`.

**Exit criterion:** ~504 `attack_graph_*BENIGN*` files, fragment pass rate ≥ 95%.

### Step 5 — Re-profile and confirm parity

```bash
mkdir -p /tmp/benign_graphs && cp results/runs/attack_graph_*BENIGN*.json /tmp/benign_graphs/
python scripts/profile_sessions.py --malicious-dir /tmp/benign_graphs --logs-dir logs \
    --label executed_benign --out docs/profiles/executed_benign.json
python scripts/profile_sessions.py --compare \
    docs/profiles/executed_benign.json docs/profiles/malicious_executed.json
```

Check all four tells at parity, byte tails within tolerance, chain-length histogram
matching §2, and theme mix matching §3. This is the table that goes in the rebuttal
whether or not Step 6 lands.

### Step 6 — Normalize and evaluate *(gated on blocker B2)*

1. Fix the benign glob/path in `fragbench-structural-graph-main/dataset/normalize_dataset.py`
   and emit `executed_benign.json` in the `{is_malicious: false, sessions: [[[event]]]}`
   triple-nested schema.
2. Resolve B2 — recover or rebuild the graph-construction and evaluation scripts.
3. Establish the **baseline first**: reproduce the paper's F1 on malicious vs
   *synthetic* benign. A number that doesn't reproduce invalidates the comparison
   before the new data is even involved.
4. Retrain/evaluate GCN, GraphSAGE, GAT, GIN, SVM, MLP, GBT on malicious vs
   executed-benign; report event-level F1 side by side.
5. **Length-stratified comparison on length-10 chains only** (207 synthetic vs 252
   executed) — isolates provenance with chain length held fixed, and comes free
   from this design.

### Step 7 — Write-up

- Parity table from Step 5 (the four tells, before and after).
- F1 side-by-side plus the length-10 stratified cut from Step 6.
- Model-provenance paragraph from `benign_targets.md` §8: benign seeds authored by
  Sonnet 4.5, expanded through the same deterministic generator, executed through
  the same harness with the same actor (`qwen/qwen3.5-122b-a10b`). Sonnet no longer
  fabricates any trace.
