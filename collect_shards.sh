#!/bin/bash
#
# Pull executed-benign output back from the EC2 shards into this repo.
#
# Session logs and graph files carry a timestamp plus a random run-id suffix, so
# the four shards merge into one corpus without collisions. Rsync is resumable --
# re-run it as often as you like, including while a shard is still running.
#
# Usage:  ./collect_shards.sh host1 host2 host3 host4
#         KEY=~/neurips-1.pem ./collect_shards.sh host1

set -uo pipefail

KEY="${KEY:-neurips-1.pem}"
USER="${USER_REMOTE:-ec2-user}"
REMOTE_DIR="${REMOTE_DIR:-~/fragbench}"

if [ $# -eq 0 ]; then
    echo "usage: $0 <host> [host ...]"
    echo "  e.g. $0 ec2-54-91-33-218.compute-1.amazonaws.com"
    exit 2
fi

if [ ! -f "$KEY" ]; then
    echo "key not found: $KEY  (set KEY=/path/to/key.pem)"
    exit 2
fi

mkdir -p logs results/runs

for host in "$@"; do
    echo
    echo "########## $host"
    for sub in logs results/runs; do
        echo "  <- $sub"
        # --progress, not --info=progress2: macOS ships openrsync (rsync
        # 2.6.9-compatible), which does not have the newer --info flag.
        rsync -az --progress --partial \
            -e "ssh -i $KEY -o StrictHostKeyChecking=accept-new" \
            "$USER@$host:$REMOTE_DIR/$sub/" "./$sub/"
        [ $? -ne 0 ] && echo "  WARNING: $sub failed for $host"
    done
done

echo
echo "=== merged corpus ==="
echo "  session logs : $(find logs -name 'session_*.jsonl' | wc -l | tr -d ' ')"
echo "  benign graphs: $(find results/runs -name 'attack_graph_*BENIGN*.json' | wc -l | tr -d ' ')"
echo
python3 scripts/summarize_benign_run.py 2>/dev/null | tail -6
