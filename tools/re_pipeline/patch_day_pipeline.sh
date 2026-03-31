#!/usr/bin/env bash
#
# patch_day_pipeline.sh -- Automated eqgame.h generation for EQ patch day
#
# Takes old and new eqgame.exe binaries + old eqgame.h (known baseline)
# and produces new eqgame.h with updated addresses.
#
# Requirements:
#   - Ghidra 12.x with BinExport extension at /opt/ghidra/
#   - BinDiff 8 (bindiff command)
#   - rizin with rz-ghidra
#   - Python 3.10+
#   - JDK 21 (for BinExport compilation)
#
# Usage:
#   ./patch_day_pipeline.sh \
#     --old-binary /path/to/old/eqgame.exe \
#     --new-binary /path/to/new/eqgame.exe \
#     --old-header /path/to/old/eqgame.h \
#     [--answer-key /path/to/new/eqgame.h] \
#     [--work-dir /tmp/patch_day] \
#     [--workers 60] \
#     [--ghidra-heap 16G]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Defaults
WORK_DIR="/tmp/patch_day_$(date +%Y%m%d_%H%M%S)"
WORKERS=60
GHIDRA_HEAP="16G"
GHIDRA_DIR="/opt/ghidra"
ANSWER_KEY=""

usage() {
    echo "Usage: $0 --old-binary OLD --new-binary NEW --old-header HEADER [options]"
    echo ""
    echo "Required:"
    echo "  --old-binary    Path to old eqgame.exe"
    echo "  --new-binary    Path to new eqgame.exe"
    echo "  --old-header    Path to old eqgame.h (known baseline)"
    echo ""
    echo "Optional:"
    echo "  --answer-key    Path to new eqgame.h for scoring (validation only)"
    echo "  --work-dir      Working directory (default: /tmp/patch_day_TIMESTAMP)"
    echo "  --workers       Parallel workers for sub-function matching (default: 60)"
    echo "  --ghidra-heap   Ghidra JVM heap size (default: 16G)"
    echo "  --ghidra-dir    Ghidra installation directory (default: /opt/ghidra)"
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --old-binary)   OLD_BINARY="$2"; shift 2 ;;
        --new-binary)   NEW_BINARY="$2"; shift 2 ;;
        --old-header)   OLD_HEADER="$2"; shift 2 ;;
        --answer-key)   ANSWER_KEY="$2"; shift 2 ;;
        --work-dir)     WORK_DIR="$2"; shift 2 ;;
        --workers)      WORKERS="$2"; shift 2 ;;
        --ghidra-heap)  GHIDRA_HEAP="$2"; shift 2 ;;
        --ghidra-dir)   GHIDRA_DIR="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1"; usage ;;
    esac
done

# Validate required args
[[ -z "${OLD_BINARY:-}" ]] && { echo "ERROR: --old-binary required"; usage; }
[[ -z "${NEW_BINARY:-}" ]] && { echo "ERROR: --new-binary required"; usage; }
[[ -z "${OLD_HEADER:-}" ]] && { echo "ERROR: --old-header required"; usage; }
[[ -f "$OLD_BINARY" ]] || { echo "ERROR: old binary not found: $OLD_BINARY"; exit 1; }
[[ -f "$NEW_BINARY" ]] || { echo "ERROR: new binary not found: $NEW_BINARY"; exit 1; }
[[ -f "$OLD_HEADER" ]] || { echo "ERROR: old header not found: $OLD_HEADER"; exit 1; }

# Validate tools
command -v bindiff >/dev/null || { echo "ERROR: bindiff not found. Install: yay -S bindiff"; exit 1; }
command -v rizin >/dev/null || { echo "ERROR: rizin not found"; exit 1; }
[[ -d "$GHIDRA_DIR" ]] || { echo "ERROR: Ghidra not found at $GHIDRA_DIR"; exit 1; }
[[ -f "$GHIDRA_DIR/Extensions/Ghidra/BinExport/lib/BinExport.jar" ]] || {
    echo "ERROR: BinExport extension not installed in Ghidra"
    echo "Build from source: see tools/re_pipeline/README.md"
    exit 1
}

# Setup
mkdir -p "$WORK_DIR"/{old_project,new_project,output}
BINEXPORT_SCRIPT="$SCRIPT_DIR/ghidra/ExportViaReflection.java"
MATCHER_SCRIPT="$SCRIPT_DIR/eqgame_h_generator.py"

echo "============================================================"
echo "EQ Patch Day Pipeline"
echo "============================================================"
echo "Old binary:  $OLD_BINARY"
echo "New binary:  $NEW_BINARY"
echo "Old header:  $OLD_HEADER"
echo "Work dir:    $WORK_DIR"
echo "Workers:     $WORKERS"
echo "Ghidra heap: $GHIDRA_HEAP"
[[ -n "$ANSWER_KEY" ]] && echo "Answer key:  $ANSWER_KEY (scoring only)"
echo "============================================================"
echo ""

# Create modified analyzeHeadless with increased heap
HEADLESS="$WORK_DIR/analyzeHeadless"
cp "$GHIDRA_DIR/support/analyzeHeadless" "$HEADLESS"
sed -i "s/MAXMEM=2G/MAXMEM=$GHIDRA_HEAP/" "$HEADLESS"
sed -i "s|\"\${SCRIPT_DIR}\"|\"$GHIDRA_DIR/support\"|" "$HEADLESS"
chmod +x "$HEADLESS"

# ── Step 1: Ghidra Headless Analysis + BinExport ─────────────────────
echo "[Step 1/4] Ghidra analysis + BinExport (parallel, ~20 min)..."
START_TIME=$SECONDS

# Launch both in parallel
"$HEADLESS" "$WORK_DIR/old_project" OldEQ \
    -import "$OLD_BINARY" \
    -postScript "$BINEXPORT_SCRIPT" "$WORK_DIR/output/old.BinExport" \
    -scriptPath "$(dirname "$BINEXPORT_SCRIPT")" \
    > "$WORK_DIR/old_ghidra.log" 2>&1 &
OLD_PID=$!

"$HEADLESS" "$WORK_DIR/new_project" NewEQ \
    -import "$NEW_BINARY" \
    -postScript "$BINEXPORT_SCRIPT" "$WORK_DIR/output/new.BinExport" \
    -scriptPath "$(dirname "$BINEXPORT_SCRIPT")" \
    > "$WORK_DIR/new_ghidra.log" 2>&1 &
NEW_PID=$!

echo "  Old binary analysis PID: $OLD_PID"
echo "  New binary analysis PID: $NEW_PID"
echo "  Waiting for both to complete..."

# Monitor progress
FAILED=0
wait $OLD_PID || FAILED=1
if [[ $FAILED -eq 1 ]]; then
    echo "  ERROR: Old binary analysis failed. Check $WORK_DIR/old_ghidra.log"
    exit 1
fi
echo "  Old binary: done ($(( SECONDS - START_TIME ))s)"

wait $NEW_PID || FAILED=1
if [[ $FAILED -eq 1 ]]; then
    echo "  ERROR: New binary analysis failed. Check $WORK_DIR/new_ghidra.log"
    exit 1
fi
echo "  New binary: done ($(( SECONDS - START_TIME ))s)"

# Verify exports exist
[[ -f "$WORK_DIR/output/old.BinExport" ]] || { echo "ERROR: old BinExport not created"; exit 1; }
[[ -f "$WORK_DIR/output/new.BinExport" ]] || { echo "ERROR: new BinExport not created"; exit 1; }

OLD_SIZE=$(stat -c%s "$WORK_DIR/output/old.BinExport")
NEW_SIZE=$(stat -c%s "$WORK_DIR/output/new.BinExport")
echo "  Exports: old=${OLD_SIZE} bytes, new=${NEW_SIZE} bytes"

# ── Step 2: BinDiff ──────────────────────────────────────────────────
echo ""
echo "[Step 2/4] BinDiff function matching..."
DIFF_START=$SECONDS

bindiff "$WORK_DIR/output/old.BinExport" "$WORK_DIR/output/new.BinExport" \
    --output_dir="$WORK_DIR/output/" \
    > "$WORK_DIR/bindiff.log" 2>&1

BINDIFF_DB=$(find "$WORK_DIR/output/" -name "*.BinDiff" -type f | head -1)
[[ -f "$BINDIFF_DB" ]] || { echo "ERROR: BinDiff output not found"; exit 1; }

# Extract summary from log
MATCHED=$(grep "^matched:" "$WORK_DIR/bindiff.log" 2>/dev/null || echo "unknown")
SIMILARITY=$(grep "^Similarity:" "$WORK_DIR/bindiff.log" 2>/dev/null || echo "unknown")
echo "  $MATCHED"
echo "  $SIMILARITY"
echo "  Completed in $(( SECONDS - DIFF_START ))s"

# ── Step 3: Extract Cross-References ─────────────────────────────────
echo ""
echo "[Step 3/5] Extracting cross-references from old binary..."
XREF_START=$SECONDS
XREF_SCRIPT="$SCRIPT_DIR/ghidra/ExtractReferences.java"

# Generate target address list
python3 -c "
import re
with open('$OLD_HEADER') as f:
    with open('$WORK_DIR/xref_targets.txt', 'w') as out:
        for line in f:
            m = re.match(r'#define\s+(\w+)_x\s+(0x[0-9a-fA-F]+)', line.strip())
            if m:
                out.write(f'{m.group(1)} {m.group(2)}\n')
"

"$HEADLESS" "$WORK_DIR/old_project" OldEQ \
    -process eqgame.exe -noanalysis \
    -scriptPath "$(dirname "$XREF_SCRIPT")" \
    -postScript ExtractReferences.java "$WORK_DIR/xref_targets.txt" "$WORK_DIR/old_xrefs.json" \
    > "$WORK_DIR/old_xref.log" 2>&1

[[ -f "$WORK_DIR/old_xrefs.json" ]] || { echo "ERROR: xref extraction failed. Check $WORK_DIR/old_xref.log"; exit 1; }
echo "  Xrefs extracted in $(( SECONDS - XREF_START ))s"

# ── Step 4: Address Translation ──────────────────────────────────────
echo ""
echo "[Step 4/5] Translating eqgame.h addresses..."

MATCHER_ARGS=(
    --old-binary "$OLD_BINARY"
    --new-binary "$NEW_BINARY"
    --old-header "$OLD_HEADER"
    --bindiff-db "$BINDIFF_DB"
    --old-xrefs "$WORK_DIR/old_xrefs.json"
    --workers "$WORKERS"
    --output "$WORK_DIR/results.json"
    --generate "$WORK_DIR/eqgame_new.h"
)
[[ -n "$ANSWER_KEY" ]] && MATCHER_ARGS+=(--new-header "$ANSWER_KEY")

python3 "$MATCHER_SCRIPT" "${MATCHER_ARGS[@]}"

# ── Step 5: Output ───────────────────────────────────────────────────
echo ""
echo "[Step 4/4] Results"
echo "============================================================"
echo "Generated header:  $WORK_DIR/eqgame_new.h"
echo "Full results:      $WORK_DIR/results.json"
echo "BinDiff database:  $BINDIFF_DB"
echo "Total time:        $(( SECONDS - START_TIME ))s"
echo "============================================================"

if [[ -f "$WORK_DIR/eqgame_new.h" ]]; then
    ENTRY_COUNT=$(grep -c "#define.*_x.*0x" "$WORK_DIR/eqgame_new.h")
    echo "Entries in generated header: $ENTRY_COUNT"
fi
