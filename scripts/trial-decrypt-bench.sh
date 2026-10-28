#!/usr/bin/env bash
#
# Measure compact-block trial decryption at 1 core, half the machine, and every core.
#
# Prints one table. Each row is the median of three timed passes (after a warmup)
# from `zcash_client_backend`'s `trial_decrypt` benchmark. `notes/sec` counts every
# Sapling output, Orchard action, and Ironwood action in the fixed fixture.
# `decrypt share` is trial-decryption time divided by `scan_block` wall time.
#
# Usage:
#   scripts/trial-decrypt-bench.sh
#   THREADS="1 4" scripts/trial-decrypt-bench.sh

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

cores=$(nproc)
half=$((cores / 2))
if [ "$half" -lt 1 ]; then
    half=1
fi

if [ -n "${THREADS:-}" ]; then
    # shellcheck disable=SC2206
    counts=($THREADS)
else
    counts=(1 "$half" "$cores")
    # Drop duplicates when the machine has one or two cores.
    declare -A seen=()
    unique=()
    for n in "${counts[@]}"; do
        if [ -z "${seen[$n]:-}" ]; then
            seen[$n]=1
            unique+=("$n")
        fi
    done
    counts=("${unique[@]}")
fi

echo "host_cores=$cores measured_counts=${counts[*]}"
printf '%-28s %8s %12s %10s %12s %14s\n' \
    "range" "threads" "notes" "notes/sec" "scan_sec" "decrypt_share"

for n in "${counts[@]}"; do
    log=$(mktemp)
    RAYON_NUM_THREADS="$n" cargo bench -p zcash_client_backend --bench trial_decrypt -- --quiet \
        >"$log" 2>&1 || {
        cat "$log" >&2
        rm -f "$log"
        exit 1
    }
    # cargo bench may wrap our stdout. Keep only the machine-readable lines.
    while IFS= read -r line; do
        case "$line" in
        TRIAL_DECRYPT\ *)
            range=$(printf '%s\n' "$line" | sed -n 's/.* range=\([^ ]*\).*/\1/p')
            notes=$(printf '%s\n' "$line" | sed -n 's/.* notes=\([^ ]*\).*/\1/p')
            rate=$(printf '%s\n' "$line" | sed -n 's/.* notes_per_sec=\([^ ]*\).*/\1/p')
            scan_ns=$(printf '%s\n' "$line" | sed -n 's/.* scan_ns=\([^ ]*\).*/\1/p')
            share=$(printf '%s\n' "$line" | sed -n 's/.* decrypt_share=\([^ ]*\).*/\1/p')
            scan_sec=$(awk -v ns="$scan_ns" 'BEGIN { printf "%.3f", ns / 1000000000 }')
            printf '%-28s %8s %12s %10s %12s %14s\n' \
                "$range" "$n" "$notes" "$rate" "$scan_sec" "$share"
            ;;
        esac
    done <"$log"
    rm -f "$log"
done
