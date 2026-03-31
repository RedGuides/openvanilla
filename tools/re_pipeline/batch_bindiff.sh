#!/usr/bin/env bash
#
# batch_bindiff.sh - Queue and run all needed BinDiff pairs
#
# Runs pairs 2 at a time. Each takes ~25 min.
# Results auto-ingested into the DB.
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILDS_DIR="$BASE_DIR/eq-builds/live"
PIPELINE="$SCRIPT_DIR/patch_day_pipeline.sh"
PIPELINE_RUNS="$BASE_DIR/data/pipeline_runs"
LOG_DIR="$BASE_DIR/data/batch_bindiff_logs"

mkdir -p "$LOG_DIR"

run_pair() {
    local old_date="$1"
    local new_date="$2"
    local work_dir="$PIPELINE_RUNS/patch_day_${old_date}_to_${new_date}"

    if [ -f "$work_dir/output/old_vs_new.BinDiff" ]; then
        echo "[SKIP] $old_date → $new_date (already complete)"
        return 0
    fi

    local old_exe="$BUILDS_DIR/$old_date/eqgame.exe"
    local new_exe="$BUILDS_DIR/$new_date/eqgame.exe"
    local old_h="$BUILDS_DIR/$old_date/eqgame.h"

    if [ ! -f "$old_exe" ] || [ ! -f "$new_exe" ] || [ ! -f "$old_h" ]; then
        echo "[ERROR] Missing files for $old_date → $new_date"
        return 1
    fi

    local answer_args=""
    local new_h="$BUILDS_DIR/$new_date/eqgame.h"
    if [ -f "$new_h" ]; then
        answer_args="--answer-key $new_h"
    fi

    echo "[START] $old_date → $new_date ($(date '+%H:%M:%S'))"

    if bash "$PIPELINE" \
        --old-binary "$old_exe" \
        --new-binary "$new_exe" \
        --old-header "$old_h" \
        --work-dir "$work_dir" \
        $answer_args \
        > "$LOG_DIR/${old_date}_to_${new_date}.log" 2>&1; then

        echo "[DONE] $old_date → $new_date ($(date '+%H:%M:%S'))"
        python3 -c "
from tools.re_pipeline.eq_xref_db import EQXrefDB
db = EQXrefDB()
old_id = db.get_binary_id('$old_date')
new_id = db.get_binary_id('$new_date')
if old_id and new_id:
    count = db.ingest_bindiff(old_id, new_id, '$work_dir/output/old_vs_new.BinDiff')
    print(f'  Ingested {count} matches')
db.close()
" 2>&1
    else
        echo "[FAIL] $old_date → $new_date (see log)"
    fi
}

# All pairs to process
PAIRS=(
    "2024-01-17:2024-02-01"
    "2024-02-01:2024-02-20"
    "2024-02-20:2024-02-21"
    "2024-02-21:2024-02-22"
    "2024-02-22:2024-03-29"
    "2024-03-29:2024-04-01"
    "2024-04-01:2024-04-02"
    "2024-04-02:2024-04-16"
    "2024-04-16:2024-05-14"
    "2024-05-14:2024-05-22"
    "2024-05-22:2024-06-18"
    "2024-06-18:2024-06-24"
    "2024-06-24:2024-07-16"
    "2024-07-16:2024-07-18"
    "2024-07-18:2024-07-22"
    "2024-07-22:2024-08-15"
    "2024-08-15:2024-10-15"
    "2024-10-15:2024-10-16"
    "2024-10-16:2024-11-08"
    "2024-11-08:2024-11-19"
    "2024-11-19:2024-11-30"
    "2024-11-30:2024-12-03"
    "2024-12-03:2024-12-05"
    "2024-12-05:2024-12-10"
    "2024-12-10:2025-01-14"
    "2025-03-11:2025-03-18"
    "2025-03-18:2025-04-15"
    "2025-04-15:2025-04-17"
    "2025-04-17:2025-05-20"
    "2025-05-20:2025-06-17"
    "2025-06-17:2025-07-15"
    "2025-07-15:2025-07-18"
    "2025-07-18:2025-08-19"
    "2025-08-26:2025-09-03"
    "2025-09-03:2025-09-07"
    "2025-09-07:2025-09-16"
    "2025-10-14:2025-11-12"
    "2025-11-12:2025-11-13"
    "2025-11-13:2025-11-17"
    "2025-11-17:2025-12-01"
    "2025-12-01:2025-12-04"
    "2025-12-04:2025-12-08"
)

echo "=========================================="
echo "Batch BinDiff: ${#PAIRS[@]} pairs, 2 concurrent"
echo "=========================================="

# Process pairs 2 at a time
i=0
completed=0
failed=0
while [ $i -lt ${#PAIRS[@]} ]; do
    # Launch up to 2 pairs
    pids=()
    for j in 0 1; do
        idx=$((i + j))
        if [ $idx -ge ${#PAIRS[@]} ]; then break; fi

        pair="${PAIRS[$idx]}"
        old_date="${pair%%:*}"
        new_date="${pair##*:}"

        run_pair "$old_date" "$new_date" &
        pids+=($!)
    done

    # Wait for this batch of 2
    for pid in "${pids[@]}"; do
        if wait "$pid"; then
            ((completed++))
        else
            ((failed++))
        fi
    done

    i=$((i + 2))
    echo "--- Progress: $((completed + failed))/${#PAIRS[@]} done ($completed ok, $failed fail) ---"
done

echo ""
echo "=========================================="
echo "Complete: $completed succeeded, $failed failed"
echo "=========================================="
