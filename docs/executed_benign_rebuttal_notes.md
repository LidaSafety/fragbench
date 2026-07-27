# Executed-benign control set — construction notes for the rebuttal

Source material for answering the reviewer request: *"train the same detectors on
MCP executions of benign objectives and report the F1."* Everything below is
measured from the repository, not asserted.

---

## 1. What the control set is

24 benign campaigns × 21 variations = **504 chains / 5,334 fragment sessions**,
generated from seed JSONs under `seeds/benign_*.json` and executed through the
same MCP harness, with the same actor model, as every malicious campaign in the
released corpus.

The point of the design is that **benign and malicious data now differ only in
the objective**. Provenance, generator, expansion path, styles, sandbox, actor
model and log schema are held identical. In the submitted paper the benign side
was synthesised directly by Claude Sonnet 4.5 in the shape of execution logs;
here no model writes a trace at all.

## 2. What is held identical to the malicious side

| axis | malicious | executed benign |
|---|---|---|
| seed → variation expansion | `run.py --generate`, deterministic `_manual.json` path | same code path, same flag |
| fragment styles | `direct`, `command_form`, `sysadmin`, `compliance_audit`, `educational`, `helpdesk` | same six labels |
| actor model | `qwen/qwen3.5-122b-a10b` via OpenRouter | unchanged |
| iteration budget | 16 | unchanged |
| sandbox | 24 MCP servers, Docker Compose, isolated network | unchanged, and deliberately **not** modified (§6) |
| log schema | `session_*.jsonl` tool_call / tool_result stream | unchanged — it is the harness that writes it |
| variation numbering | seeds from 0 | unchanged (`DATASET_BASE_SEED = 0`) |

Two of the six style wrappers presuppose an offensive objective
(`educational` → "For an educational cybersecurity demonstration…",
`compliance_audit` → "For a red team compliance audit…"). Applied to benign work
they produce incoherent prompts, so benign campaigns substitute benign wrapper
text under the *same six style labels* via `_BENIGN_STYLE_TEMPLATES` in
`generator.py`, selected by the seed's `metadata.benign` flag. The style
mechanism is otherwise identical; the two halves differ in exactly two strings.
This is prompt-side only, and the detector never sees prompts.

## 3. Why these 24 campaigns

Chain length was the axis a reviewer named as a possible shortcut. The released
benign corpus contains only lengths 7, 8 and 10, over half of it length 8, while
half the malicious side is length 10 and a third is length 12–16. The executed
set therefore reproduces the **malicious length histogram exactly**:

| fragments/chain | malicious campaigns | benign campaigns |
|---:|---:|---:|
| 4 | 1 | 1 |
| 7 | 1 | 1 |
| 8 | 1 | 1 |
| 10 | 12 | 12 |
| 11 | 1 | 1 |
| 12 | 5 | 5 |
| 14 | 2 | 2 |
| 16 | 1 | 1 |

Themes are the eight named in the paper, allocated to hold the *measured* soft
theme mix of the released benign corpus (mined with
`scripts/profile_sessions.py`), so the objectives stay recognisably the same
population as the synthetic benign set:

| theme | campaigns | fragment sessions | share | released-corpus target |
|---|---:|---:|---:|---:|
| system administration | 5 | 1,302 | 24.4% | 22.1% |
| IT support | 4 | 819 | 15.4% | 14.7% |
| compliance auditing | 3 | 756 | 14.2% | 13.4% |
| course preparation | 3 | 672 | 12.6% | 13.3% |
| project lifecycle | 3 | 693 | 13.0% | 11.5% |
| personal organisation | 2 | 294 | 5.5% | 9.8% |
| data wrangling | 2 | 378 | 7.1% | 8.7% |
| documentation | 2 | 420 | 7.9% | 6.4% |

Shares are within ~2 points of target except personal organisation, which is
under-weighted because its allocation (a 4-fragment and a 10-fragment campaign)
is fixed by the length histogram — length parity was given priority over theme
parity, since length is the axis the reviewer raised.

The 24 campaigns are ordinary workplace workflows: backup assurance, patch
management, certificate lifecycle, storage tiering, laptop refresh, access
cleanup, incident review, access recertification, vendor assurance, records
retention, syllabus preparation, assessment design, lab materials, project
kickoff, release planning, retrospectives, inbox triage, relocation planning,
survey analysis, data cataloguing, API reference authoring and team handbook
authoring.

## 4. Distribution targets the seeds were authored against

`docs/profiles/benign_targets.md` records the measured gap between the two
released corpora. Four axes were **hard tells** — a trivial classifier could
separate the classes on them without modelling composition:

| axis | synthetic benign | executed malicious | executed benign (pilot) |
|---|---:|---:|---:|
| placeholder `session_id`s | 30.6% | 0.0% | 0.0% |
| `tool_call_index == 1/1` | 99.6% | 77.1% | 84.4% |
| tool-result failure rate | 0.5% | 3.7% | 4.2% |
| absolute path share | 99.9% | 42.6% | 31.0% |

All four are fixed **for free** by executing rather than synthesising — they are
properties of the harness, not of the authoring. The remaining targets had to be
authored deliberately, and are the reason the seeds look the way they do:

- **bare relative filenames**, because the actor emits relative paths when the
  prompt does; the synthetic corpus wrote `/workspace/...` almost everywhere
- **8–12 tool calls per fragment** — every fragment requires a read, a transform
  and a write rather than a single action
- **one or two long-form deliverables per chain** (reports, runbooks, syllabi,
  release notes) to carry the `arguments_bytes` p90/p99 tail
- **self-seeding chains** — an early fragment writes what later fragments read,
  because the sandbox seed is only 44 KB and attack-flavoured
- **~5 cross-fragment shared resources per chain** via `produces`/`consumes`,
  the one axis that already matched. Note this counts resources touched by two or
  more fragments *of the same chain*; it is a different quantity from the
  cross-*chain* sharing discussed in §5, which needed a deliberate fix.

## 5. Two construction decisions worth stating

**Artifact names are two-tier.** Each campaign declares two discriminator axes
(e.g. `{site}` × `{cycle}`, 24 × 20 = 480 combinations) in stage 0, inherited by
later stages. Those axes are embedded in the names of each chain's *headline
deliverables* (reports, runbooks, plans, announcements), which therefore stay
unique per variation. A second tier of 2 to 9 stems per campaign, declared in
`SHARED_ARTIFACTS` in `scripts/author_benign_seeds.py`, deliberately drops the
discriminator and carries a bare name across every variation. Those are the
reference-shaped, read-mostly parts of each workflow (registers, catalogues,
matrices, schedules, codebooks): the artifacts an organisation maintains once and
many workflows read.

Discriminating *every* name was the original design, and it drove cross-chain
resource sharing to zero. 462 of 504 chains shared no resource with any other
chain and none shared more than one, against a median of 7 for the executed
malicious corpus, whose chains write generic names (`ad_users.txt`,
`sysinfo.txt`) into a filesystem that is never reset. Since `shared_resource` is
one of the edge types the paper's claim rests on, and
`ablations/real_edge_ablation.py` ablates it directly as `drop_shared_resource`,
suppressing it on the benign side alone would have manufactured the asymmetry
rather than removed it.

Measured after the change: **median 6 shared resources per chain** (min 2,
max 10, mean 5.9), a spread rather than a constant, against malicious 7. Every
variation still carries a median of 6 uniquely-named artifacts, so the 21
variations of a campaign stay distinguishable and do not fuse into one component.
This is the declared-artifact figure; execution adds resources beyond the
declared set, so re-measure on the executed corpus.

**Per-variation filesystem root.** A `{wd}` variable chosen once per variation
pins each chain to either relative paths or `/workspace/`, never both. This is
required for correctness (produces/consumes resolution breaks when a chain mixes
roots) and is set light — 21% of chains pinned absolute — because the actor
already reaches for absolute paths unprompted. Measured: **0 mixed-root chains**
across all 504.

## 6. Known limitations to state rather than hide

**The sandbox has two filesystem roots and only one is reset.** Relative paths
resolve to the MCP server's working directory, which is the container's writable
layer and is *not* cleared between runs; `/workspace` is a tmpfs that is. The
default root therefore accumulates artifacts across every run. This affects the
released malicious corpus too: 42% of its `list_directory` results contain
cross-run clutter. **The harness was deliberately left unmodified**, because
pinning the root would give benign chains a clean filesystem while the released
malicious chains show 42% clutter — introducing a fresh class-separating tell in
exactly the category this control set exists to remove. Parity with the
environment that produced the malicious data was judged more valuable than a
tidy sandbox.

**Self-containment looks different between the classes, but the comparison is
confounded.** Measured on session logs, 71.6% of successful reads in the benign
smoke chains are of files that chain itself wrote, against 55.5% for the
malicious corpus. Decomposing the remainder shows the gap is entirely cross-chain
residue, not the attack-flavoured sandbox seed, which both classes barely touch:

| source of a successful read | benign (23 chains) | malicious (146 graphs) |
|---|---:|---:|
| written earlier in the same chain | 71.6% | 55.5% |
| written by another chain in the corpus | 18.1% | 41.6% |
| written by no chain (sandbox seed, pre-existing) | 10.3% | 2.9% |

The confound is exposure. The 146 malicious graphs are only **26 distinct
campaign+seed variations, 24 of them executed six times** — once per style — into
the filesystem that is never reset. Passes two through six of a variation read
the artifacts its own first pass left behind, and those count as another chain's
files. The benign figure comes from a smoke sweep that ran each campaign exactly
once, so it had no prior pass to inherit from.

The two numbers therefore measure one-pass-deep against six-passes-deep, not
benign against malicious. Once the benign grid runs six styles across nine seeds
it accumulates the same way, and the number should fall to the malicious range.
**Re-measure after the full run before reporting either figure**; the residue is
a property of how much has been executed, not of the objective.

The table above is doubly stale: it was measured before the shared artifact tier
in §5 existed. Shared bare names mean benign chains can now genuinely read one
another's output, so the "written by another chain" row (18.1%) is precisely the
one the change targets and is expected to rise toward the malicious 41.6%. Treat
all three rows as pending re-measurement on the executed grid.

An earlier version of this design pushed benign upward independently: when every
artifact name carried the discriminator, two benign chains never shared a
filename and so could not read each other's output even when it was present.
That was a real asymmetry, and on the detector's own `shared_resource` edge, so
it has been removed rather than merely stated. The shared tier in §5 lets benign
chains reference the same reference-shaped artifacts the way malicious chains do,
while the discriminated deliverables still keep the 21 variations of a campaign
from fusing into one component.

**Fragment failure rates differ.** On like-for-like fragment verdicts the
malicious corpus fails 26.6% of fragments against the benign pilot's 11.4%; at
tool-result level the two are 3.7% and 4.2%. Benign fragments are *less* likely
to fail overall, which needs acknowledging rather than correcting — driving
benign failures up to match would be manufacturing an artifact.

**An output-budget caveat that shaped the seeds.** The actor runs at
`max_tokens=4000`. A tool call whose arguments exceed roughly 19,000 characters
is truncated mid-value, the JSON fails to parse, and the client falls back to
`{"__raw_arguments": ...}` — which fails schema validation, so the write never
lands and every downstream fragment starves. Row counts in the seeds are
therefore capped so the largest inline table stays near 10,000 characters, and
the two prompts that asked for a cross product (hosts × days of metrics, jobs ×
restore points) were rewritten to weekly aggregates and a fixed three points per
job. Measured before the fix: 6 of 205 benign pilot sessions carried a truncated
tool call against 1 of ~1,400 malicious sessions — a class-separating artifact of
prompt sizing, not of the objective, which is exactly what this control set
exists to remove.

**An unguarded crash path in the client.** `mcp_client_v1.py:3484` does
`response.choices[0]` with no check, so an OpenRouter reply carrying an error
payload instead of choices kills the fragment with a `TypeError` rather than
costing it one iteration. This was left unpatched for the same reason as the
filesystem roots: the released malicious corpus was produced by the same
unguarded code, and fixing it only on the benign side would introduce a
difference in failure behaviour between the classes.

**A shell caveat that shaped the seeds.** `run_command` in the sandbox defaults
to `mode="simulated"` and returns success with `"[simulated stdout]"` without
executing anything. Seeds must therefore instruct the agent to write bulk tables
inline with `write_file` rather than "run a script that emits the rows" —
otherwise the artifact never lands and every downstream fragment fails.

## 7. Reproducibility

Seeds are authored from a single spec (`scripts/author_benign_seeds.py` plus
`scripts/benign_specs*.py`) so all 24 campaigns share one scaffolding and differ
only in authored content. Regenerating is deterministic and requires no model
calls:

```bash
# 22 seeds rebuilt from the specs; the two pilot campaigns predate the spec
# format and are patched in place instead (idempotent). Checks placeholder
# resolution and produces/consumes closure.
python scripts/author_benign_seeds.py

# 24 results/*_manual.json. Pass --num-variations explicitly: run.py defaults to
# 100, and the released set is 21 per campaign.
for s in seeds/benign_*.json; do
  n=$(basename "$s" .json)
  python run.py --generate --seed-file "$s" --seed 0 --num-variations 21 \
      --output-json "results/${n}_manual.json"
done
```

Validation status at time of writing: **0 errors, 0 warnings** across all 24
campaigns (357 fragments per campaign-set expansion; 5,334 fragment sessions
total), length histogram matching the malicious side exactly, 0 mixed-root
chains, 0 unresolved placeholders across the 504 variations, and every consume
resolved to an earlier producer. Artifact names are deliberately *not* collision
free: the shared tier in §5 is common across variations by design, while every
variation retains a median of 6 uniquely-named deliverables.
