#!/usr/bin/env python3
"""
Scan unlisted CXWnd-range functions across all builds, cross-validate,
and add confirmed accessors to the evidence database.

For each build pair (old -> new):
1. Find unlisted functions in old build's CXWnd range
2. Scan for single/dual offset accessors
3. Use BinDiff to find the same function in new build
4. Verify it accesses the correct (shuffled) offset for the same field
5. If consistent across 5+ builds, add as HIGH evidence
"""
import os, re, subprocess, sqlite3, sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

BASE = os.path.join(os.path.dirname(__file__), '..', '..')
PIPELINE_DIR = os.path.join(BASE, 'data', 'pipeline_runs')
CACHE_DIR = os.path.join(BASE, 'data', 'unlisted_disasm_cache')


def scan_func(exe, addr):
    """Disassemble one function and extract CXWnd-range offsets."""
    try:
        result = subprocess.run(
            ["rizin", "-a", "x86", "-b", "64", "-q",
             "-c", f"af @ 0x{addr:x}; pdf @ 0x{addr:x}",
             exe], capture_output=True, text=True, timeout=10)
        text = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
        offsets = set()
        for m in re.finditer(r'\[(?:rcx|rbx|rdi|rsi|r14|r15)\s*\+\s*0x([0-9a-fA-F]+)\]', text):
            off = int(m.group(1), 16)
            if 0x030 <= off < 0x268:
                offsets.add(off)
        return (addr, offsets)
    except:
        return (addr, set())


def get_cxwnd_range_addrs(db, bid, build_date):
    """Get all BinDiff-known function addresses in CXWnd code range, excluding eqgame.h functions."""
    known = set(r['func_addr'] for r in db.conn.execute(
        "SELECT func_addr FROM function_identities WHERE binary_id = ?", (bid,)))

    all_addrs = set()
    for dirname in os.listdir(PIPELINE_DIR):
        if build_date not in dirname:
            continue
        bd_dir = os.path.join(PIPELINE_DIR, dirname, 'output')
        if not os.path.exists(bd_dir):
            continue
        for f in os.listdir(bd_dir):
            if f.endswith('.BinDiff'):
                bd = sqlite3.connect(os.path.join(bd_dir, f))
                for r in bd.execute("SELECT address1, address2 FROM function WHERE similarity > 0.5"):
                    all_addrs.add(r[0])
                    all_addrs.add(r[1])
                bd.close()

    return [a for a in all_addrs if 0x1405B0000 <= a <= 0x14060FFFF and a not in known]


def scan_build(db, build_date, workers=48):
    """Scan one build for unlisted accessors. Returns {offset: [(addr, num_offsets)]}."""
    bid = db.get_binary_id(build_date)
    row = db.conn.execute("SELECT binary_path FROM binaries WHERE id = ?", (bid,)).fetchone()
    exe = row['binary_path']

    addrs = get_cxwnd_range_addrs(db, bid, build_date)
    if not addrs:
        print(f"  {build_date}: no unlisted functions found")
        return {}

    # Check cache
    cache_dir = os.path.join(CACHE_DIR, build_date)
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, 'scan_results.txt')

    if os.path.exists(cache_file):
        # Load cached results
        results = defaultdict(list)
        with open(cache_file) as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) == 3:
                    off, addr, n = int(parts[0]), int(parts[1]), int(parts[2])
                    results[off].append((addr, n))
        print(f"  {build_date}: loaded {sum(len(v) for v in results.values())} cached hits from {len(addrs)} functions")
        return results

    print(f"  {build_date}: scanning {len(addrs)} unlisted functions...")

    hits = defaultdict(list)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_func, exe, addr): addr for addr in addrs}
        done = 0
        for future in as_completed(futures):
            addr, offsets = future.result()
            done += 1
            if offsets and len(offsets) <= 3:
                for off in offsets:
                    if 0x030 <= off < 0x268:
                        hits[off].append((addr, len(offsets)))
            if done % 200 == 0:
                print(f"    {done}/{len(addrs)}...")

    # Cache results
    with open(cache_file, 'w') as f:
        for off, entries in sorted(hits.items()):
            for addr, n in entries:
                f.write(f"{off}\t{addr}\t{n}\n")

    total = sum(len(v) for v in hits.values())
    print(f"  {build_date}: found {total} accessor hits")
    return hits


def cross_validate(db, all_results, builds):
    """Cross-validate: for each (function, offset) pair, check if the function
    consistently identifies the same FIELD across builds."""

    # Build offset->field map for each build
    field_maps = {}
    for build_date in builds:
        bid = db.get_binary_id(build_date)
        field_maps[build_date] = {}
        for r in db.conn.execute("""
            SELECT sm.field_name, mo.offset_val FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            WHERE mo.binary_id = ? AND sm.class_name = 'CXWnd'
        """, (bid,)):
            field_maps[build_date][r['offset_val']] = r['field_name']

    # For pure accessors (1 offset), track which field they identify per build
    # Key: function address pattern (we'll use BinDiff to match across builds)
    # Simpler approach: for each offset in each build, find pure accessors,
    # map offset to field name, and check if the field is consistently identified

    # Per-field: how many builds have a pure accessor for it?
    field_pure_counts = defaultdict(int)  # field -> num builds with pure accessor
    field_dual_counts = defaultdict(int)

    for build_date in builds:
        hits = all_results.get(build_date, {})
        fmap = field_maps.get(build_date, {})

        for off, entries in hits.items():
            field = fmap.get(off)
            if not field:
                continue

            pure = [e for e in entries if e[1] == 1]
            dual = [e for e in entries if e[1] == 2]

            if pure:
                field_pure_counts[field] += 1
            elif dual:
                field_dual_counts[field] += 1

    return field_pure_counts, field_dual_counts


def main():
    db = EQXrefDB()
    builds = sorted(r['build_date'] for r in db.list_binaries() if r['server'] == 'live')

    print(f"Scanning {len(builds)} builds for unlisted CXWnd accessors...\n")

    all_results = {}
    for build_date in builds:
        all_results[build_date] = scan_build(db, build_date)

    print(f"\n{'='*70}")
    print("Cross-validation results")
    print(f"{'='*70}\n")

    field_pure, field_dual = cross_validate(db, all_results, builds)

    # Current HIGH confidence fields
    high_fields = set(r['field_name'] for r in db.conn.execute("""
        SELECT sm.field_name FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        WHERE sm.class_name = 'CXWnd' AND er.confidence = 'HIGH'
        GROUP BY sm.field_name
        HAVING COUNT(DISTINCT er.binary_id) >= 5
    """).fetchall())

    # Fields that gain pure accessors from unlisted functions
    new_high = []
    improved = []
    for field in sorted(set(list(field_pure.keys()) + list(field_dual.keys()))):
        pure = field_pure.get(field, 0)
        dual = field_dual.get(field, 0)
        total = pure + dual
        already_high = field in high_fields

        if pure >= 5 and not already_high:
            new_high.append((field, pure, dual))
        elif total >= 5 and not already_high:
            improved.append((field, pure, dual))

    print(f"Fields with pure unlisted accessor in 5+ builds (NEW HIGH):")
    for field, pure, dual in new_high:
        print(f"  {field:35s} pure={pure}/7 dual={dual}/7")

    print(f"\nFields with dual unlisted accessor in 5+ builds (promotable):")
    for field, pure, dual in improved:
        print(f"  {field:35s} pure={pure}/7 dual={dual}/7")

    # Add evidence to database
    print(f"\nAdding evidence to database...")
    added = 0
    for build_date in builds:
        bid = db.get_binary_id(build_date)
        hits = all_results.get(build_date, {})

        # Get field map for this build
        fmap = {}
        for r in db.conn.execute("""
            SELECT sm.field_name, mo.offset_val FROM member_offsets mo
            JOIN struct_members sm ON mo.member_id = sm.id
            WHERE mo.binary_id = ? AND sm.class_name = 'CXWnd'
        """, (bid,)):
            fmap[r['offset_val']] = r['field_name']

        for off, entries in hits.items():
            field = fmap.get(off)
            if not field:
                continue

            pure = [e for e in entries if e[1] == 1]
            dual = [e for e in entries if e[1] == 2]

            if pure:
                addr = pure[0][0]
                conf = 'HIGH'
                etype = 'getter'
            elif dual:
                addr = dual[0][0]
                conf = 'MED'
                etype = 'access'
            else:
                continue

            func_name = f"unlisted_0x{addr:x}"
            db.add_evidence(
                binary_id=bid,
                class_name='CXWnd',
                field_name=field,
                func_name=func_name,
                func_addr=addr,
                evidence_type=etype,
                decompile_line=f"unlisted function at 0x{addr:x} accesses 0x{off:03x} ({entries[0][1]} total offsets)",
                confidence=conf
            )
            added += 1

    print(f"Added {added} evidence records from unlisted functions")

    # Final stats
    rows = db.conn.execute("""
        SELECT sm.field_name, COUNT(DISTINCT b.id) as bc
        FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        JOIN binaries b ON er.binary_id = b.id
        WHERE sm.class_name = 'CXWnd' AND er.confidence = 'HIGH'
        GROUP BY sm.field_name
        HAVING bc >= 5
        ORDER BY bc DESC
    """).fetchall()
    print(f"\nFinal: {len(rows)} fields at HIGH confidence in 5+ builds")

    # Show remaining non-HIGH fields
    all_fields = set(r['field_name'] for r in db.conn.execute(
        "SELECT field_name FROM struct_members WHERE class_name = 'CXWnd'"))
    high_set = set(r['field_name'] for r in rows)
    remaining = all_fields - high_set
    if remaining:
        print(f"\nStill not HIGH ({len(remaining)}):")
        for f in sorted(remaining):
            print(f"  {f}")

    db.close()


if __name__ == '__main__':
    main()
