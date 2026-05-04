#!/bin/bash
for dataset in promptsteal dprk_fraud quietvault; do
    time python fragbench_dataset_generator/fragbench_pack/fragbench_generated_rl.py \
        --mode rl --variation-style direct \
        --judge-backend anthropic --judge-model claude-sonnet-4-6 \
        --rewriter-backend anthropic --rewriter-model claude-opus-4-6 \
        --input dataset/generated-manual/${dataset}_manual.json
done
