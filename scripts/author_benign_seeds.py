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

  * two-tier artifact names. Two discriminator axes (>=400 combinations) declared
    in stage 0 and inherited downstream keep each chain's *deliverables* unique
    per variation, so the 21 variations of a campaign do not fuse into one
    component under the detector's shared_resource edges. A second tier of 2-9
    reference-shaped stems per campaign (SHARED_ARTIFACTS below) deliberately
    drops the discriminator, so chains share resources the way the malicious
    corpus does; discriminating everything drove cross-chain sharing to zero;
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
# 21 variations collide on a *deliverable* name with probability well under one
# pair. The shared tier (SHARED_ARTIFACTS) bypasses these pools entirely.
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

# ---------------------------------------------------------------------------
# Shared (undiscriminated) artifacts.
#
# Discriminating *every* artifact name drives cross-chain resource sharing to
# zero: measured over the 504 generated chains, 462 shared no resource with any
# other chain and none shared more than one. The executed malicious corpus sits
# at a median of 7 shared resources per chain, because its chains write generic
# names (ad_users.txt, sysinfo.txt) into a filesystem that is never reset. A
# detector whose shared_resource edges are the claim under test would separate
# the two classes on that gap alone.
#
# The stems below therefore keep a bare name across every variation, so all
# chains of a campaign -- and, where a stem recurs, of several campaigns --
# reference the same resource. They are chosen to be the reference-shaped,
# read-mostly parts of each workflow (registers, catalogues, matrices,
# schedules, policies), the artifacts an organisation genuinely maintains once
# and many workflows read. Each chain's headline deliverables (reports,
# runbooks, announcements) stay discriminated: they are cycle-specific, and
# keeping them unique preserves the per-variation identity that stops all 21
# variations of a campaign fusing into a single component.
#
# Counts vary per campaign (2-9) so the resulting shared-resource distribution
# has a spread rather than a constant, which would be a tell in its own right.
SHARED_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "benign_compliance_access_review": (
        "entitlement_extract", "privileged_accounts", "dormant_accounts",
        "reviewer_assignments", "evidence_index", "sampling_method"),
    "benign_compliance_retention": (
        "record_inventory", "retention_schedule", "storage_locations",
        "legal_holds", "age_analysis", "owner_map", "evidence_pack",
        "approval_checklist"),
    "benign_compliance_vendor": (
        "vendor_register", "contract_index", "data_flows", "questionnaire",
        "evidence_matrix", "exception_register"),
    "benign_course_assessment": (
        "outcome_map", "question_bank", "exam_blueprint", "rubric_matrix",
        "moderation_checklist"),
    "benign_course_lab": (
        "lab_topics", "dataset_index", "environment_spec", "starter_files",
        "grading_criteria", "feedback_form"),
    "benign_course_syllabus": (
        "learning_outcomes", "topic_inventory", "reading_list",
        "resource_index", "course_policies"),
    "benign_data_catalog": (
        "table_inventory", "column_profiles", "quality_metrics",
        "owner_register", "validation_checklist"),
    "benign_data_survey": (
        "raw_responses", "codebook", "cleaning_notes", "chart_spec"),
    "benign_docs_api": (
        "endpoint_inventory", "schema_extract", "error_catalog", "changelog",
        "review_checklist"),
    "benign_docs_handbook": (
        "topic_inventory", "existing_docs", "tool_list", "glossary",
        "review_log"),
    "benign_it_onboarding": (
        "new_hires", "ticket_backlog", "validated_users",
        "onboarding_checklist"),
    "benign_itsupport_access": (
        "entitlements", "role_catalog", "review_flags", "reviewer_map",
        "review_worksheet", "unclaimed_accounts", "change_checklist"),
    "benign_itsupport_asset": (
        "asset_register", "warranty_status", "spec_assignments",
        "purchase_schedule", "rollout_schedule", "imaging_checklist"),
    "benign_itsupport_incident": (
        "incident_timeline", "affected_services", "ticket_extract",
        "impact_metrics", "contributing_factors", "prevention_checklist"),
    "benign_personal_inbox": (
        "inbox_export", "triage_sheet"),
    "benign_personal_relocation": (
        "move_inventory", "address_list", "move_checklist", "packing_list"),
    "benign_project_kickoff": (
        "stakeholder_register", "scope_items", "constraints", "raid_log",
        "comms_plan"),
    "benign_project_release": (
        "change_inventory", "ticket_extract", "dependency_map",
        "risk_register", "test_matrix", "go_live_checklist"),
    "benign_project_retro": (
        "sprint_metrics", "ticket_flow", "incident_extract",
        "survey_responses", "action_items", "owner_assignments"),
    "benign_sysadmin_backup": (
        "backup_jobs", "backup_targets", "job_coverage", "restore_points",
        "restore_points_verified", "retention_matrix", "drill_results"),
    "benign_sysadmin_capacity": (
        "server_inventory", "server_roles", "raw_metrics", "metrics_clean",
        "headroom", "top_constrained_hosts", "rollback_checklist"),
    "benign_sysadmin_certs": (
        "cert_inventory", "endpoint_map", "expiry_calendar", "owner_matrix",
        "chain_validation", "renewal_candidates", "cost_estimate",
        "exception_register"),
    "benign_sysadmin_patching": (
        "host_inventory", "package_versions", "patch_baseline", "advisories",
        "applicable_patches", "risk_ranking", "verification_checklist"),
    "benign_sysadmin_storage": (
        "volume_inventory", "mount_map", "growth_history", "quota_register",
        "growth_forecast", "access_classification", "tiering_candidates",
        "cost_model", "validation_checklist"),
}

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


def _demote(text: str, ax1: str, ax2: str, stems: tuple[str, ...]) -> str:
    """Strip the per-variation discriminator from the shared artifact stems.

    Artifact names are uniformly ``{wd}<stem>_{ax1}_{ax2}.<ext>``, so dropping
    the ``_{ax1}_{ax2}`` infix is an unambiguous substitution: a longer stem
    that merely starts with a shorter one (``restore_points_verified`` vs
    ``restore_points``) does not contain the shorter one's discriminator and is
    left alone.
    """
    for stem in stems:
        text = text.replace(f"{stem}_{{{ax1}}}_{{{ax2}}}", stem)
    return text


def _demote_fragment(frag: dict, ax1: str, ax2: str,
                     stems: tuple[str, ...]) -> dict:
    return {
        "role": frag["role"],
        "prompt": _demote(frag["prompt"], ax1, ax2, stems),
        "produces": [_demote(p, ax1, ax2, stems) for p in frag["produces"]],
        "consumes": [_demote(c, ax1, ax2, stems) for c in frag["consumes"]],
    }


def build(spec: dict) -> dict:
    """Expand a campaign spec into a seed JSON with uniform scaffolding."""
    ax1, pool1 = spec["axis1"]
    ax2, pool2 = spec["axis2"]
    shared = SHARED_ARTIFACTS.get(spec["id"], ())
    # A stem that matches nothing is a typo, not a no-op: fail loudly rather
    # than silently leaving the artifact discriminated.
    spec_text = " ".join(
        [f["prompt"] for st in spec["stages"] for f in st["frags"]]
        + [a for st in spec["stages"] for f in st["frags"]
           for a in f["produces"] + f["consumes"]])
    for stem in shared:
        if f"{stem}_{{{ax1}}}_{{{ax2}}}" not in spec_text:
            raise ValueError(
                f"{spec['id']}: shared stem {stem!r} matches no artifact")
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
            "baseline_prompt": _demote(st["baseline"], ax1, ax2, shared),
            "variables": variables,
            "fragments": [_demote_fragment(f, ax1, ax2, shared)
                          for f in st["frags"]],
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


def demote_authored_seed(path: Path) -> int:
    """Apply the shared-artifact demotion to a seed JSON authored by hand.

    The two pilot campaigns predate the spec format and have no entry in
    benign_specs*, so they are edited in place instead of rebuilt. `_demote` is
    idempotent -- once the discriminator infix is gone a second pass matches
    nothing -- so re-running this is safe.
    """
    stems = SHARED_ARTIFACTS.get(path.stem, ())
    if not stems:
        return 0
    seed = json.loads(path.read_text())
    ax = [k for k, v in seed["attack_stages"][0]["variables"].items()
          if v.get("type") == "filename"]
    if len(ax) != 2:
        raise ValueError(f"{path.stem}: expected two discriminator axes, got {ax}")
    ax1, ax2 = ax
    before = json.dumps(seed, sort_keys=True)
    for stage in seed["attack_stages"]:
        stage["baseline_prompt"] = _demote(stage["baseline_prompt"], ax1, ax2, stems)
        stage["fragments"] = [
            _demote_fragment(f, ax1, ax2, stems) for f in stage["fragments"]
        ]
    if json.dumps(seed, sort_keys=True) == before:
        return 0
    path.write_text(json.dumps(seed, indent=2, ensure_ascii=False) + "\n")
    return 1


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

    spec_ids = {s["id"] for s in all_specs}
    patched = [
        p.stem for p in sorted(SEEDS_DIR.glob("benign_*.json"))
        if p.stem not in spec_ids and demote_authored_seed(p)
    ]

    for p in problems:
        print(f"  PROBLEM: {p}")
    print(f"\nwrote {len(written)} seeds, {len(problems)} problems")
    if patched:
        print(f"demoted shared artifacts in {len(patched)} hand-authored seeds: "
              f"{', '.join(patched)}")
    for cid, theme, n in written:
        print(f"  {cid:38s} {theme:24s} {n:>2d} fragments")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
