#!/bin/bash

STYLES="command_form compliance_audit direct educational helpdesk sysadmin"

for rewriter in openai/gpt-5.4-mini; do
    for judge in meta-llama/llama-guard-4-12b anthropic/claude-sonnet-4.6 anthropic/claude-opus-4.7 openai/gpt-5.4-mini; do
        for dataset in promptsteal dprk_fraud quietvault; do
            for style in $STYLES; do
                time python fragbench_dataset_generator/fragbench_pack/fragbench_generated_rl.py \
                    --mode rl --variation-style $style \
                    --judge-backend anthropic --judge-model claude-sonnet-4-6 \
                    --rewriter-backend anthropic --rewriter-model claude-opus-4-6 \
                    --input dataset/generated-manual/${dataset}_manual.json
            done
        done
    done
done
