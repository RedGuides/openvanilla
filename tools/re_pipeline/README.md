# EQ Reverse Engineering Pipeline

Tools for automating EverQuest struct offset updates on patch day. When Daybreak patches EQ, all struct member offsets shuffle (MSVC struct randomization) and all function addresses change. This pipeline uses BinDiff to map old addresses to new ones, then uses disassembly analysis to identify which struct fields live at which offsets in each build.

The core idea: track accessor functions (getters/setters) that touch a single struct offset. Those functions are stable identifiers for a field across builds, even when the offset itself moves. BinDiff maps the function from old binary to new binary, then you read what offset the new version accesses.

## Architecture

```
patch_day_pipeline.sh          Main entry point for patch day
  |
  +-- Ghidra headless analysis (parallel, 2 binaries)
  |     +-- ghidra/ExportViaReflection.java   BinExport output
  |     +-- ghidra/ExtractReferences.java     Cross-reference extraction
  |
  +-- BinDiff (old.BinExport vs new.BinExport)
  |
  +-- eqgame_h_generator.py    Three-layer address translator
  |     Layer 1: BinDiff direct match (function-start entries)
  |     Layer 2: Xref following (data refs inside matched functions)
  |     Layer 3: Sub-function signature matching (zero-xref entries)
  |
  +-- Output: new eqgame.h with translated addresses

eq_xref_db.py                  Persistent SQLite database API
  |                             Tracks members, offsets, evidence across builds
  |
  +-- disasm_accessor_scanner.py   rizin-based accessor identification
  +-- gap_analysis.py              Size/alignment constraint solving
  +-- scan_unlisted_all_builds.py  Find accessors outside eqgame.h
  +-- wide_scan_sequential.py      Full-binary accessor sweep
  +-- populate_xref_db.py          Historical data backfill
  +-- extract_2024_headers.py      Pull old eqgame.h from eqlib git

batch_bindiff.sh               Run BinDiff on all consecutive build pairs
distributed_scan_sequential.sh Distribute rizin scans across multiple hosts
```

## Prerequisites

- **Ghidra 12.x** with BinExport extension installed at `/opt/ghidra/`
- **BinDiff 8** (`bindiff` in PATH)
- **rizin** with rz-ghidra plugin (for disassembly scanning)
- **Python 3.10+** (stdlib only, no pip packages needed)
- **JDK 21** (for Ghidra headless analysis)
- **EQ build archive** at `../../eq-builds/live/` with subdirs like `2025-03-18/` containing `eqgame.exe` and `eqgame.h`

## Quick Start: Patch Day

When a new EQ patch drops:

```bash
# 1. Run the full pipeline (Ghidra analysis + BinDiff + address translation)
./patch_day_pipeline.sh \
    --old-binary /path/to/old/eqgame.exe \
    --new-binary /path/to/new/eqgame.exe \
    --old-header /path/to/old/eqgame.h \
    --answer-key /path/to/new/eqgame.h   # optional, for scoring only

# 2. Output lands in /tmp/patch_day_TIMESTAMP/eqgame_new.h
```

The pipeline takes about 45 minutes total: ~20 min for Ghidra analysis (two binaries in parallel), ~5 min for BinDiff, ~20 min for address translation with sub-function matching.

## Script Reference

### patch_day_pipeline.sh

The main pipeline. Runs Ghidra headless analysis on both binaries (parallel), runs BinDiff, extracts cross-references, then translates all eqgame.h addresses.

```bash
./patch_day_pipeline.sh \
    --old-binary OLD_EXE \
    --new-binary NEW_EXE \
    --old-header OLD_EQGAME_H \
    [--answer-key NEW_EQGAME_H]     # validation only, not used for placement
    [--work-dir /tmp/patch_day]      # default: /tmp/patch_day_TIMESTAMP
    [--workers 60]                   # parallel workers for sub-function matching
    [--ghidra-heap 16G]              # JVM heap for Ghidra
    [--ghidra-dir /opt/ghidra]       # Ghidra installation path
```

Steps:
1. Ghidra headless analysis + BinExport on both binaries (parallel)
2. BinDiff function matching
3. Cross-reference extraction from old binary
4. Three-layer address translation via `eqgame_h_generator.py`

### eq_xref_db.py

SQLite database API for tracking struct members across builds. All other Python scripts import from this. The database stores:

- **binaries** - Build dates, paths, server (live/test)
- **struct_members** - Field catalog (class, name, type, size)
- **member_offsets** - Where each field sits in each build (offset + confidence)
- **function_identities** - Named functions and their addresses per build
- **evidence_records** - Which functions access which fields (setter/getter/access)
- **bindiff_matches** - Function address mappings between build pairs

```python
from eq_xref_db import EQXrefDB

db = EQXrefDB()                              # opens/creates default DB
db = EQXrefDB('/path/to/custom.db')          # custom path

bid = db.add_binary('2025-03-18', '/path/to/eqgame.exe', '/path/to/eqgame.h')
db.ingest_eqgame_h(bid, '/path/to/eqgame.h')
db.ingest_struct_header(bid, '/path/to/CXWnd.h', 'CXWnd')

offset = db.get_offset(bid, 'CXWnd', 'pController')   # returns int or None
history = db.get_member_history('CXWnd', 'pController') # all builds

# CLI: print database stats
python3 eq_xref_db.py stats
```

Confidence levels: `GROUND_TRUTH` (from headers), `HIGH` (single-offset accessor), `MED` (multi-offset function), `LOW` (complex function access).

### disasm_accessor_scanner.py

Scans functions using rizin disassembly to find struct member accesses. For each function in eqgame.h, disassembles it and finds all `[this + offset]` patterns. Functions that only touch one offset are HIGH confidence identifiers for that field.

```bash
# Scan a single binary
python3 disasm_accessor_scanner.py \
    --binary /path/to/eqgame.exe \
    --offsets /path/to/eqgame.h \
    --struct-range 0x030:0x268

# Scan a registered build (reads paths from DB)
python3 disasm_accessor_scanner.py --build 2025-03-18

# Scan all registered builds
python3 disasm_accessor_scanner.py --all

# Dry run (no DB writes)
python3 disasm_accessor_scanner.py --all --no-db
```

Options:
- `--workers N` - Parallel rizin processes (default: 32)
- `--struct-range LO:HI` - Hex offset range to scan (default: CXWnd 0x030:0x268)

### gap_analysis.py

Places struct fields that don't have accessor evidence by using size and alignment constraints. If a field is the only one that fits in a gap between two already-identified fields (due to its size/alignment), it gets placed automatically.

Also runs cascade resolution: if a field is identified in build A and there's a BinDiff link to build B, the identifying function's address gets translated and the field gets propagated.

```bash
python3 gap_analysis.py
```

No arguments. Runs on all builds in the database, then cascades iteratively until no more fields can be placed.

### batch_bindiff.sh

Runs BinDiff on all consecutive build pairs. Processes 2 pairs concurrently (each pair takes ~25 min). Results are auto-ingested into the xref database.

```bash
./batch_bindiff.sh
```

Edit the `PAIRS` array at the top of the script to add new build pairs. Each pair is `"OLD_DATE:NEW_DATE"`. Already-completed pairs are skipped.

Expects build files at `../../eq-builds/live/DATE/eqgame.exe` and `.../eqgame.h`.

### distributed_scan_sequential.sh

Distributes rizin disassembly scanning across multiple hosts (default: pvehost1-4). Copies binaries to each host, runs scans with 48 workers per host, then you collect results back.

```bash
./distributed_scan_sequential.sh
```

Edit `HOSTS` and `BUILDS_DIR` at the top. After completion, collect results:

```bash
for h in pvehost{1..4}; do
    for d in $(ssh $h 'ls -d /tmp/eq_scan/20*/disasm 2>/dev/null'); do
        date=$(basename $(dirname $d))
        mkdir -p data/disasm_cache/$date
        rsync -a $h:$d/ data/disasm_cache/$date/
    done
done
```

### extract_2024_headers.py

Extracts historical eqgame.h files from eqlib git history by matching `__ClientDate` values to build dates. Also extracts CXWnd.h when available. Registers everything in the xref database.

```bash
python3 extract_2024_headers.py
```

Expects:
- eqlib git repo at `../../eqlib-history/` with a `live` branch
- Build directories at `../../eq-builds/live/2024-*/`

### populate_xref_db.py

Backfills the cross-reference database from all available historical data:

1. Registers all live/test builds
2. Ingests eqgame.h function addresses
3. Ingests CXWnd member offsets from eqlib git commits
4. Imports BinDiff results from pipeline run directories

```bash
python3 populate_xref_db.py
```

Edit `EQLIB_COMMITS` dict to map build dates to eqlib git commits that have CXWnd.h for that patch.

### scan_unlisted_all_builds.py

Finds CXWnd accessor functions that are NOT in eqgame.h. These are functions in the CXWnd code range (0x1405B0000-0x14060FFFF) that BinDiff knows about but eqgame.h doesn't list. If an unlisted function is a pure accessor (touches only one CXWnd-range offset), and it shows up consistently across 5+ builds, it gets added as HIGH evidence.

```bash
python3 scan_unlisted_all_builds.py
```

Uses 48 parallel workers per build. Caches results in `../../data/unlisted_disasm_cache/`.

### wide_scan_sequential.py

Like `scan_unlisted_all_builds.py` but scans the entire binary (not just CXWnd code range) for any function that accesses remaining unidentified CXWnd fields. Used as a last resort to fill gaps that the other scanners miss.

```bash
python3 wide_scan_sequential.py
```

Targets only fields that don't already have HIGH confidence evidence in 5+ builds.

## Database Schema

The `eq_xref_db.py` module manages a SQLite database with these tables:

| Table | Purpose |
|-------|---------|
| `binaries` | One row per EQ build. Keyed by build_date. Stores paths, server type, image base. |
| `struct_members` | Field catalog. Unique on (class_name, field_name). Stores type and size. |
| `member_offsets` | Where each field sits in each build. Confidence: GROUND_TRUTH/HIGH/MED/LOW. |
| `function_identities` | Named functions per build. Address changes each patch. |
| `evidence_records` | Links functions to fields they access. Type: setter/getter/ini_key/destructor/xref/access. |
| `bindiff_matches` | Old->new function address pairs from BinDiff, with similarity scores. |

Key relationships:
- `member_offsets` references both `binaries` and `struct_members`
- `evidence_records` references `binaries`, `struct_members`, and `function_identities`
- `bindiff_matches` references `binaries` (old and new)

## Supporting Scripts

These are used internally or for specific analysis tasks:

- `eqgame_h_generator.py` - Three-layer address translator called by the main pipeline
- `xref_translator.py` - Xref-following address translator (alternative approach)
- `auto_field_mapper.py` - Automated field mapping using vtable decompilation
- `vtable_accessor_scanner.py` - Parse Ghidra decompilation output for accessor patterns
- `parse_vtable_decompilations.py` - Batch parse vtable decompilation dumps
- `walk_vtable.py` - Walk CXWnd vtable entries and classify them
- `scan_full_binary.py` - Full binary scan variant
- `scan_unlisted_accessors.py` - Single-build unlisted accessor scanner
- `populate_evidence.py` - Populate evidence records from decompilation data

### Ghidra Scripts (ghidra/)

- `ExportViaReflection.java` - BinExport via reflection (works around Ghidra extension API quirks)
- `ExtractReferences.java` - Extract code/data cross-references for target addresses
- `ExtractXrefs.java` - Simpler xref extraction variant

## Data Layout

The pipeline expects this directory structure relative to the repo root:

```
../../eq-builds/live/
    2025-03-18/
        eqgame.exe
        eqgame.h
        CXWnd.h          (optional)
    2025-04-15/
        ...
../../data/
    eq_xref.db            Cross-reference database
    disasm_cache/          Cached rizin disassembly per build
    pipeline_runs/         BinDiff pipeline output per pair
    unlisted_disasm_cache/ Cache for unlisted function scans
    full_scan_cache/       Cache for wide binary scans
    batch_bindiff_logs/    Logs from batch processing
```
