#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for messages in 100000 1000000; do
    printf '\n==> opaque store scale gate: %s messages\n' "$messages"
    (
        cd "$root"
        KOMMS_STORE_BENCH_MESSAGES="$messages" \
            cargo test --release -p kult-store \
            scale_bench::opaque_store_scale_budget -- \
            --exact --ignored --nocapture --test-threads=1
    )
done
