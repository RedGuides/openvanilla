#!/usr/bin/env python3
"""
populate_xref_db.py - Backfill the cross-reference database from historical builds.

Ingests:
1. All live builds from eq-builds/live/ (binary + eqgame.h ground truth)
2. CXWnd.h member offsets from eqlib git history for each build
3. BinDiff results from pipeline runs
"""

import os
import sys
import re
import subprocess
import sqlite3

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

BASE_DIR = os.path.join(os.path.dirname(__file__), '..', '..')
BUILDS_DIR = os.path.join(BASE_DIR, 'eq-builds')
EQLIB_DIR = os.path.join(BASE_DIR, 'eqlib-history')
PIPELINE_RUNS = os.path.join(BASE_DIR, 'data', 'pipeline_runs')


# Map build dates to eqlib commits that have the matching CXWnd.h
# These are the commits where brainiac updated for each live patch
EQLIB_COMMITS = {
    '2025-08-26': '3c352ecc',
    '2025-09-16': 'e0a59681',
    '2025-10-14': '9cce0eb7',
    '2025-11-17': '28d686cf',
    '2025-12-08': '19cbcefe',
    '2026-01-22': 'bd4a4ab2',
    '2026-02-10': '90403708',
}

# Old eqlib had CXWnd.h at root, newer ones at include/eqlib/game/
CXWND_PATHS = [
    'include/eqlib/game/CXWnd.h',
    'CXWnd.h',
]


def find_cxwnd_at_commit(commit):
    """Extract CXWnd.h content from an eqlib git commit."""
    for path in CXWND_PATHS:
        result = subprocess.run(
            ['git', '-C', EQLIB_DIR, 'show', f'{commit}:{path}'],
            capture_output=True, text=True)
        if result.returncode == 0 and 'CXWnd' in result.stdout:
            return result.stdout
    return None


def ingest_cxwnd_members(db, binary_id, header_content):
    """Parse CXWnd member offsets from header content string."""
    # find the member block between @start and @end markers
    start = header_content.find('@start: CXWnd Members')
    end = header_content.find('@end: CXWnd Members')

    if start < 0 or end < 0:
        # older format might not have markers, search for the member block
        start = header_content.find('// CXWnd Members')
        if start < 0:
            start = 0
        end = len(header_content)

    section = header_content[start:end]

    member_re = re.compile(
        r'/\*0x([0-9a-fA-F]+)\*/\s+(\S+(?:\s*\*)?)\s+(\w+)\s*;')

    count = 0
    for m in member_re.finditer(section):
        offset = int(m.group(1), 16)
        field_type = m.group(2).strip()
        field_name = m.group(3)

        if field_name.startswith('Pad') or field_name.startswith('__'):
            continue

        member_id = db.ensure_member('CXWnd', field_name, field_type)
        db.conn.execute(
            """INSERT OR REPLACE INTO member_offsets
               (binary_id, member_id, offset_val, confidence, source)
               VALUES (?, ?, ?, 'GROUND_TRUTH', 'eqlib_git')""",
            (binary_id, member_id, offset))
        count += 1

    # Also grab CSidlScreenWnd members
    sidl_start = header_content.find('CSidlScreenWnd')
    if sidl_start > 0:
        sidl_section = header_content[sidl_start:]
        for m in member_re.finditer(sidl_section):
            offset = int(m.group(1), 16)
            field_type = m.group(2).strip()
            field_name = m.group(3)
            if field_name.startswith('Pad'):
                continue
            member_id = db.ensure_member('CSidlScreenWnd', field_name, field_type)
            db.conn.execute(
                """INSERT OR REPLACE INTO member_offsets
                   (binary_id, member_id, offset_val, confidence, source)
                   VALUES (?, ?, ?, 'GROUND_TRUTH', 'eqlib_git')""",
                (binary_id, member_id, offset))
            count += 1

    db.conn.commit()
    return count


def ingest_bindiff_results(db):
    """Import BinDiff results from preserved pipeline runs."""
    if not os.path.exists(PIPELINE_RUNS):
        print("  No pipeline runs directory found, skipping BinDiff ingestion")
        return

    for dirname in sorted(os.listdir(PIPELINE_RUNS)):
        # parse dates from dirname like "patch_day_2025-09-16_to_2025-10-14"
        date_match = re.search(r'(\d{4}-\d{2}-\d{2})_to_(\d{4}-\d{2}-\d{2})', dirname)
        if not date_match:
            # try the old format "patch_day_20260330_104236"
            continue

        old_date = date_match.group(1)
        new_date = date_match.group(2)

        old_id = db.get_binary_id(old_date)
        new_id = db.get_binary_id(new_date)
        if not old_id or not new_id:
            continue

        # find BinDiff DB
        output_dir = os.path.join(PIPELINE_RUNS, dirname, 'output')
        bindiff_files = [f for f in os.listdir(output_dir)
                        if f.endswith('.BinDiff')] if os.path.exists(output_dir) else []

        if bindiff_files:
            bd_path = os.path.join(output_dir, bindiff_files[0])
            count = db.ingest_bindiff(old_id, new_id, bd_path)
            print(f"  BinDiff {old_date} -> {new_date}: {count} function matches")


def main():
    db = EQXrefDB()
    print(f"Database: {db.db_path}\n")

    # Step 1: Register all live builds and ingest eqgame.h
    print("=== Registering builds and ingesting eqgame.h ===")
    live_dir = os.path.join(BUILDS_DIR, 'live')
    for build_date in sorted(os.listdir(live_dir)):
        build_path = os.path.join(live_dir, build_date)
        if not os.path.isdir(build_path):
            continue

        exe_path = os.path.join(build_path, 'eqgame.exe')
        h_path = os.path.join(build_path, 'eqgame.h')

        if not os.path.exists(exe_path):
            continue

        bid = db.add_binary(build_date, exe_path,
                           h_path if os.path.exists(h_path) else None,
                           server='live')

        if os.path.exists(h_path):
            func_count = db.ingest_eqgame_h(bid, h_path)
            print(f"  {build_date}: {func_count} functions from eqgame.h")

    # Also register test builds
    test_dir = os.path.join(BUILDS_DIR, 'test')
    if os.path.exists(test_dir):
        for build_date in sorted(os.listdir(test_dir)):
            build_path = os.path.join(test_dir, build_date)
            if not os.path.isdir(build_path):
                continue
            exe_path = os.path.join(build_path, 'eqgame.exe')
            if os.path.exists(exe_path):
                db.add_binary(build_date, exe_path, server='test')
                print(f"  {build_date} (test): registered")

    # Step 2: Ingest CXWnd member offsets from eqlib git history
    print("\n=== Ingesting CXWnd member offsets from eqlib git ===")
    for build_date, commit in sorted(EQLIB_COMMITS.items()):
        bid = db.get_binary_id(build_date)
        if not bid:
            print(f"  {build_date}: no binary registered, skipping")
            continue

        content = find_cxwnd_at_commit(commit)
        if content:
            count = ingest_cxwnd_members(db, bid, content)
            print(f"  {build_date} (commit {commit[:8]}): {count} struct members")
        else:
            print(f"  {build_date}: CXWnd.h not found at commit {commit[:8]}")

    # Step 3: Ingest BinDiff results
    print("\n=== Ingesting BinDiff results ===")
    ingest_bindiff_results(db)

    # Summary
    print("\n=== Database stats ===")
    stats = db.stats()
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # Show member offset history for a sample field
    print("\n=== Sample: CXWnd::pController history ===")
    history = db.get_member_history('CXWnd', 'pController')
    for h in history:
        print(f"  {h['build_date']}  0x{h['offset_val']:03x}  {h['confidence']}")

    db.close()


if __name__ == '__main__':
    main()
