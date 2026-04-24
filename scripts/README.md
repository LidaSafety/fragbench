# scripts — dataset generation helpers

This directory contains branch-specific helper scripts for contributors generating fragbench datasets.

## End-to-end flow (this branch)

1. `seeds/<campaign>.json` defines campaign metadata and stages.
2. `variations/<campaign>.py` deterministically resolves a seed into concrete stage prompts.
3. `run.py --generate` uses `generator.py` (`VARIATION_REGISTRY`, TOML serialization, optional LLM transforms) to produce attack files.
4. Output TOMLs are written as `generated_<campaign>_<seed>.toml` (often under `attacks/batches/...`).
5. `scripts/batch_to_fragbench_samples.py` can optionally convert a generated TOML batch into a `fragbench_samples`-style JSON array.

## `generate_all_seeds.sh` (main batch dataset-generation script)

Batch-generates TOMLs for all seed JSON files.

- Scans `seeds/*.json` by default (override with `--seeds-dir`).
- Creates a fresh output directory under `attacks/batches/` by default (`generated_<utc_timestamp>_<rand>`).
- Runs `uv run run.py --generate ... --attacks-dir <batch_dir>` for each seed.
- Uses plain generation mode only (no `--fragment`, `--stylize`, or `--legitimize`).
- Continues on per-seed failures, then exits non-zero if any seed failed.

Example:

```bash
./scripts/generate_all_seeds.sh --num-variations 200
```

## `batch_to_fragbench_samples.py` (post-processing conversion step)

Converts a generated batch directory of TOMLs into JSON samples.

- Reads `*.toml` from a batch directory.
- Loads TOMLs via harness parsing (with a TOML quote-repair fallback).
- Re-attaches campaign metadata from `seeds/*.json` when possible.
- Emits one sample per TOML, with deterministic synthetic `time_offset_sec` values in 15-minute increments.
- Treats all fragments as attack fragments (`is_cover: false`).

Example:

```bash
python3 scripts/batch_to_fragbench_samples.py \
  attacks/batches/generated_20260424_010203_abcd12 \
  output/fragbench_samples.json \
  --indent 2
```

## Practical caveats

- In `generate_all_seeds.sh`, help text says default `--num-variations` is `100`, but the script variable default is `500`.
- Prefer setting `--num-variations` explicitly.
- If you need fragmented/stylized/legitimized generation, run `run.py --generate` directly with those flags (the batch script intentionally does plain generation).
