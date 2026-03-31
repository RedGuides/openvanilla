#!/usr/bin/env python3
"""
populate_evidence.py - Run accessor scanning against historical builds
and populate evidence_records in the cross-reference database.

For each build:
1. Decompile CXWnd/CSidlScreenWnd accessor functions via rizin
2. Parse setter/getter patterns to identify which function accesses which offset
3. Cross-reference with ground truth to name the offset
4. Store as evidence records in eq_xref.db

Usage:
    python3 populate_evidence.py [--build 2025-08-26] [--workers 32]

    Without --build, runs against all builds in the database.
"""

import re
import os
import sys
import json
import subprocess
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB
from vtable_accessor_scanner import parse_decompilation

BASE_DIR = os.path.join(os.path.dirname(__file__), '..', '..')
CACHE_DIR = os.path.join(BASE_DIR, 'data', 'evidence_cache')


def decompile_function(binary_path, addr_hex, func_name):
    """Decompile a single function via rz-ghidra."""
    try:
        result = subprocess.run(
            ["rizin", "-a", "x86", "-b", "64", "-q",
             "-c", f"af @ {addr_hex}; pdg @ {addr_hex}",
             binary_path],
            capture_output=True, text=True, timeout=30
        )
        code = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
        if len(code) > 20 and "ERROR" not in code:
            return (func_name, addr_hex, code)
    except (subprocess.TimeoutExpired, Exception) as e:
        pass
    return (func_name, addr_hex, None)


def scan_build(db, binary_id, build_date, binary_path, workers=32):
    """Scan one build for accessor evidence."""

    print(f"\n{'='*60}")
    print(f"Scanning {build_date}: {binary_path}")
    print(f"{'='*60}")

    # Get all CXWnd/CSidlScreenWnd function addresses for this build
    funcs = {}
    for row in db.conn.execute("""
        SELECT func_name, func_addr FROM function_identities
        WHERE binary_id = ? AND (
            func_name LIKE 'CXWnd__%' OR
            func_name LIKE 'CSidlScreenWnd__%' OR
            func_name LIKE 'CXWndManager__%'
        )
    """, (binary_id,)).fetchall():
        funcs[row['func_name']] = f"0x{row['func_addr']:x}"

    if not funcs:
        print(f"  No CXWnd functions found for {build_date}")
        return 0

    print(f"  {len(funcs)} functions to scan")

    # Check cache
    cache_dir = Path(CACHE_DIR) / build_date
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Decompile (with caching)
    decompilations = {}
    to_decompile = {}

    for func_name, addr in funcs.items():
        cache_file = cache_dir / f"{func_name}.txt"
        if cache_file.exists():
            code = cache_file.read_text()
            if len(code) > 20:
                decompilations[func_name] = code
                continue
        to_decompile[func_name] = addr

    if decompilations:
        print(f"  {len(decompilations)} cached, {len(to_decompile)} to decompile")

    if to_decompile:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(decompile_function, binary_path, addr, name): name
                for name, addr in to_decompile.items()
            }
            done = 0
            for future in as_completed(futures):
                name, addr, code = future.result()
                done += 1
                if code:
                    decompilations[name] = code
                    (cache_dir / f"{name}.txt").write_text(code)
                if done % 20 == 0:
                    print(f"  Decompiled {done}/{len(to_decompile)}...")

    print(f"  Total decompiled: {len(decompilations)}")

    # Get ground truth offsets for this build
    ground_truth = {}  # offset -> field_name
    for row in db.conn.execute("""
        SELECT sm.field_name, sm.class_name, mo.offset_val
        FROM member_offsets mo
        JOIN struct_members sm ON mo.member_id = sm.id
        WHERE mo.binary_id = ? AND mo.confidence = 'GROUND_TRUTH'
    """, (binary_id,)).fetchall():
        ground_truth[row['offset_val']] = (row['class_name'], row['field_name'])

    # Parse decompilations for accessor patterns
    evidence_count = 0

    for func_name, code in decompilations.items():
        findings = parse_decompilation(code, func_name)

        for finding in findings:
            offset = finding['offset']
            ftype = finding['type']  # 'setter', 'getter', etc

            if offset not in ground_truth:
                continue

            class_name, field_name = ground_truth[offset]
            func_addr = int(funcs.get(func_name, '0'), 16)

            # Map finding type to evidence type
            evidence_type = ftype if ftype in ('setter', 'getter') else 'access'

            # Get a representative line from the decompilation
            decompile_line = None
            offset_hex = f"0x{offset:x}"
            for line in code.split('\n'):
                if offset_hex in line.lower() or f"+{offset}" in line:
                    decompile_line = line.strip()[:200]
                    break

            db.add_evidence(
                binary_id=binary_id,
                class_name=class_name,
                field_name=field_name,
                func_name=func_name,
                func_addr=func_addr,
                evidence_type=evidence_type,
                decompile_line=decompile_line,
                confidence='HIGH' if ftype in ('setter', 'getter') else 'MED'
            )
            evidence_count += 1

    print(f"  Evidence records added: {evidence_count}")
    return evidence_count


def main():
    parser = argparse.ArgumentParser(description="Populate evidence records")
    parser.add_argument("--build", help="Specific build date (default: all)")
    parser.add_argument("--workers", type=int, default=32, help="Parallel decompile workers")
    args = parser.parse_args()

    db = EQXrefDB()

    if args.build:
        builds = [args.build]
    else:
        builds = [r['build_date'] for r in db.list_binaries() if r['server'] == 'live']

    total_evidence = 0

    for build_date in sorted(builds):
        bid = db.get_binary_id(build_date)
        if not bid:
            print(f"Build {build_date} not in database, skipping")
            continue

        row = db.conn.execute(
            "SELECT binary_path FROM binaries WHERE id = ?", (bid,)).fetchone()
        binary_path = row['binary_path']

        if not os.path.exists(binary_path):
            print(f"Binary not found: {binary_path}, skipping")
            continue

        # Check if evidence already exists for this build
        existing = db.conn.execute(
            "SELECT COUNT(*) FROM evidence_records WHERE binary_id = ?", (bid,)).fetchone()[0]
        if existing > 0:
            print(f"  {build_date}: {existing} evidence records already exist, skipping")
            continue

        count = scan_build(db, bid, build_date, binary_path, args.workers)
        total_evidence += count

    # Summary
    print(f"\n{'='*60}")
    print(f"Total evidence records added: {total_evidence}")

    stats = db.stats()
    print(f"\nDatabase stats:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # Show top identifying functions
    print(f"\nTop identifying functions for CXWnd (appear in most builds):")
    rows = db.conn.execute("""
        SELECT fi.func_name, sm.field_name, er.evidence_type,
               COUNT(DISTINCT b.id) as build_count
        FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        JOIN function_identities fi ON er.func_id = fi.id
        JOIN binaries b ON er.binary_id = b.id
        WHERE sm.class_name = 'CXWnd' AND er.confidence = 'HIGH'
        GROUP BY fi.func_name, sm.field_name, er.evidence_type
        HAVING build_count >= 5
        ORDER BY build_count DESC, fi.func_name
        LIMIT 30
    """).fetchall()

    for row in rows:
        print(f"  {row['func_name']:45s} -> {row['field_name']:25s} "
              f"({row['evidence_type']}) {row['build_count']}/7 builds")

    db.close()


if __name__ == '__main__':
    main()
