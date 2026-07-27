#!/usr/bin/env python3
"""Author the executed-benign campaign seeds from a compact per-campaign spec.

The executed-benign control set answers the reviewer question of whether the
detector separates cross-session *composition* or merely separates two
generation processes. Its chains therefore run through the same
seed -> variation -> fragment -> MCP harness path as every malicious campaign;
only the objectives are ordinary IT/office work.

This script exists so the 24 campaigns share one scaffolding and differ only in
authored content. Every campaign it emits satisfies the invariants in
docs/profiles/benign_targets.md:

  * two discriminator axes (>=400 combinations) declared in stage 0 and
    inherited downstream, so artifact names differ per variation the way the
    malicious seeds' do -- otherwise all 21 variations of a campaign would fuse
    into one component under the detector's shared_resource edges;
  * a {wd} root variable chosen once per variation, so a chain is entirely
    relative or entirely /workspace-absolute but never both (mixing the two
    breaks produces/consumes resolution -- see plan B1a);
  * bare relative filenames under that root, self-seeding chains, and
    produces/consumes closure so every consume has an earlier producer.

Regenerate the seed JSONs with:

    python scripts/author_benign_seeds.py

then materialise the fragment files with `make -f Makefrag`.
"""

from __future__ import annotations

import json
from pathlib import Path

SEEDS_DIR = Path(__file__).resolve().parent.parent / "seeds"

# ---------------------------------------------------------------------------
# Discriminator pools. Two axes per campaign, >=20 values each, so a campaign's
# 21 variations collide on a name with probability well under one pair.
# ---------------------------------------------------------------------------
P_REGION = ["emea", "apac", "amer", "us-east", "us-west", "eu-west",
            "eu-central", "ap-south", "ldn", "nyc", "sfo", "fra",
            "syd", "tor", "dub", "sin", "ams", "chi",
            "bos", "tky", "mad", "mil", "zrh", "osl"]
P_CITY = ["ldn", "nyc", "sfo", "fra", "syd", "tor",
          "dub", "sin", "ams", "chi", "bos", "tky",
          "mad", "mil", "zrh", "osl", "ber", "par",
          "sea", "aus", "den", "atl", "yvr", "hel"]
P_PERIOD = ["2026q1", "2026q2", "2026q3", "2026q4", "fy26h1", "fy26h2",
            "jan26", "feb26", "mar26", "apr26", "may26", "jun26",
            "jul26", "aug26", "sep26", "oct26", "nov26", "dec26",
            "wk14", "wk27"]
P_BATCH = ["2026b1", "2026b2", "2026b3", "2026b4", "2026b5",
           "2026b6", "2026b7", "2026b8", "fy26a", "fy26b",
           "fy26c", "fy26d", "jan26", "mar26", "jun26",
           "sep26", "q1", "q2", "q3", "q4"]
P_SYSTEM = ["payroll", "crm", "hrms", "billing", "ledger", "intranet",
            "helpdesk", "wiki", "vault", "registry", "gateway", "scheduler",
            "reporting", "identity", "storage", "mailer", "search", "cache",
            "queue", "backup", "monitor", "proxy", "archive", "portal"]
P_COURSE = ["cs101", "cs210", "ds200", "ds310", "stat140", "stat260",
            "info150", "info320", "math115", "math225", "eng105", "eng240",
            "bio130", "bio245", "chem120", "chem230", "econ110", "econ225",
            "phys135", "phys250", "hist160", "hist275", "psy125", "psy240"]
P_TERM = ["aut26", "win26", "spr27", "sum27", "aut27", "win27",
          "t1-26", "t2-26", "t3-26", "t1-27", "t2-27", "t3-27",
          "sem1-26", "sem2-26", "sem1-27", "sem2-27",
          "block-a", "block-b", "block-c", "block-d"]
P_PROJECT = ["atlas", "beacon", "cedar", "delta", "ember", "fable",
             "granite", "harbor", "indigo", "juniper", "kestrel", "lantern",
             "meridian", "nimbus", "onyx", "pioneer", "quarry", "ridge",
             "summit", "tundra", "umber", "vertex", "willow", "zenith"]
P_SPRINT = ["s01", "s02", "s03", "s04", "s05", "s06", "s07",
            "s08", "s09", "s10", "s11", "s12", "s13", "s14",
            "r1", "r2", "r3", "r4", "r5", "r6"]
P_DATASET = ["survey", "census", "telemetry", "orders", "tickets", "sensors",
             "claims", "sessions", "invoices", "readings", "responses", "logs",
             "trials", "signups", "returns", "shipments", "visits", "ratings",
             "quotes", "renewals", "referrals", "bookings", "usage", "pledges"]
P_VERSION = ["v1-0", "v1-1", "v1-2", "v2-0", "v2-1", "v2-2",
             "v3-0", "v3-1", "r2026-01", "r2026-02", "r2026-03", "r2026-04",
             "r2026-05", "r2026-06", "b114", "b127", "b138", "b142",
             "b155", "b163"]

# 40% of variations pinned to /workspace, the rest relative. Kept light because
# the actor already reaches for absolute paths unprompted (~31% of trace paths
# with no prefix at all); the point of the variable is per-chain *consistency*,
# not raising the absolute share.
WD_VAR = {"type": "choice", "values": ["", "", "", "/workspace/", "/workspace/"]}

TACTICS = [
    ("discovery", "T1083", "File and Directory Discovery"),
    ("collection", "T1005", "Data from Local System"),
    ("execution", "T1059", "Command and Scripting Interpreter"),
    ("impact", "T1082", "System Information Discovery"),
]


def F(role: str, prompt: str, produces, consumes=()) -> dict:
    """One authored fragment."""
    return {
        "role": role,
        "prompt": prompt,
        "produces": list(produces),
        "consumes": list(consumes),
    }


def build(spec: dict) -> dict:
    """Expand a campaign spec into a seed JSON with uniform scaffolding."""
    ax1, pool1 = spec["axis1"]
    ax2, pool2 = spec["axis2"]
    stages = []
    for i, st in enumerate(spec["stages"]):
        tactic, tech, tech_name = TACTICS[i]
        variables = dict(st.get("vars", {}))
        if i == 0:
            variables[ax1] = {"type": "filename", "name_pool": pool1}
            variables[ax2] = {"type": "filename", "name_pool": pool2}
            variables["wd"] = WD_VAR
        else:
            for name in (ax1, ax2, "wd"):
                variables[name] = {"type": "inherit", "from_stage": 0,
                                   "variable": name}
        stages.append({
            "index": i,
            "mitre_tactic": tactic,
            "mitre_technique": tech,
            "mitre_technique_name": tech_name,
            "description": st["desc"],
            "baseline_prompt": st["baseline"],
            "variables": variables,
            "fragments": st["frags"],
        })
    return {
        "metadata": {
            "id": spec["id"].upper(),
            "benign": True,
            "theme": spec["theme"],
            "technique": TACTICS[0][1],
            "technique_name": TACTICS[0][2],
            "description": spec["desc"],
            "source": "FragBench executed-benign control set",
            "tags": ["benign", spec["theme"], spec["tag"]],
        },
        "attack_stages": stages,
    }


_PLACEHOLDER = __import__("re").compile(r"\{([a-z_][a-z0-9_]*)\}")


def check(seed: dict, name: str) -> list[str]:
    """Every placeholder must resolve from its own stage's variables, and every
    consumed artifact must be produced by an earlier fragment."""
    problems: list[str] = []
    produced: set[str] = set()
    for stage in seed["attack_stages"]:
        known = set(stage["variables"])
        texts = [stage["baseline_prompt"]]
        for f in stage["fragments"]:
            texts.extend([f["prompt"], *f["produces"], *f["consumes"]])
        for t in texts:
            for ref in _PLACEHOLDER.findall(t):
                if ref not in known:
                    problems.append(
                        f"{name} stage {stage['index']}: {{{ref}}} not declared "
                        f"(have: {sorted(known)})")
        for f in stage["fragments"]:
            for art in f["consumes"]:
                if art not in produced:
                    problems.append(
                        f"{name} stage {stage['index']}: consumes {art!r} "
                        f"with no earlier producer")
            produced.update(f["produces"])
    return sorted(set(problems))


def main() -> int:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from benign_specs import CAMPAIGNS as A
    from benign_specs_b import CAMPAIGNS as B

    all_specs = A + B
    problems: list[str] = []
    written = []
    for spec in all_specs:
        seed = build(spec)
        found = check(seed, spec["id"])
        problems.extend(found)
        if found:
            continue
        n = sum(len(s["fragments"]) for s in seed["attack_stages"])
        path = SEEDS_DIR / f"{spec['id']}.json"
        path.write_text(json.dumps(seed, indent=2, ensure_ascii=False) + "\n")
        written.append((spec["id"], spec["theme"], n))

    for p in problems:
        print(f"  PROBLEM: {p}")
    print(f"\nwrote {len(written)} seeds, {len(problems)} problems")
    for cid, theme, n in written:
        print(f"  {cid:38s} {theme:24s} {n:>2d} fragments")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
