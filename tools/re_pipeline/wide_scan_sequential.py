#!/usr/bin/env python3
"""Scan full binary for CXWnd accessors, one build at a time."""
import os, re, subprocess, sqlite3, sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

PIPELINE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'pipeline_runs')
CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'full_scan_cache')


def scan_func(exe, addr):
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


def main():
    db = EQXrefDB()

    # Get remaining non-HIGH fields
    all_high = set(r['field_name'] for r in db.conn.execute("""
        SELECT sm.field_name FROM evidence_records er
        JOIN struct_members sm ON er.member_id = sm.id
        WHERE sm.class_name = 'CXWnd' AND er.confidence = 'HIGH'
        GROUP BY sm.field_name
        HAVING COUNT(DISTINCT er.binary_id) >= 5
    """))
    all_fields = set(r['field_name'] for r in db.conn.execute(
        "SELECT field_name FROM struct_members WHERE class_name = 'CXWnd'"))
    remaining = all_fields - all_high
    print(f"Targeting {len(remaining)} remaining fields\n")

    # Build pairs: (build_date, pair_dir, address_column)
    scans = [
        ('2025-09-16', 'patch_day_2025-09-16_to_2025-10-14', 'address1'),
        ('2025-10-14', 'patch_day_2025-10-14_to_2025-11-17', 'address1'),
        ('2025-11-17', 'patch_day_2025-11-17_to_2025-12-08', 'address1'),
        ('2025-12-08', 'patch_day_2025-12-08_to_2026-01-22', 'address1'),
        ('2026-01-22', 'patch_day_2026-01-22_to_2026-02-10', 'address1'),
        ('2026-02-10', 'patch_day_2026-01-22_to_2026-02-10', 'address2'),
    ]

    for build_date, pair_dir, addr_col in scans:
        bid = db.get_binary_id(build_date)
        if not bid:
            print(f"{build_date}: not in database, skipping")
            continue

        row = db.conn.execute("SELECT binary_path FROM binaries WHERE id = ?", (bid,)).fetchone()
        exe = row['binary_path']

        # Target offsets for remaining fields
        target_offsets = set()
        offset_to_field = {}
        for field in remaining:
            off = db.get_offset(bid, 'CXWnd', field)
            if off is not None:
                target_offsets.add(off)
                offset_to_field[off] = field

        # Get function addresses
        bd_dir = os.path.join(PIPELINE_DIR, pair_dir, 'output')
        bd_files = [f for f in os.listdir(bd_dir) if f.endswith('.BinDiff')]
        bd_conn = sqlite3.connect(os.path.join(bd_dir, bd_files[0]))
        func_addrs = [r[0] for r in bd_conn.execute(
            f"SELECT {addr_col} FROM function WHERE similarity > 0.5")]
        bd_conn.close()

        # Filter
        known = set(r['func_addr'] for r in db.conn.execute(
            "SELECT func_addr FROM function_identities WHERE binary_id = ?", (bid,)))
        to_scan = [a for a in func_addrs
                   if 0x140001000 <= a <= 0x14083D000
                   and not (0x1405B0000 <= a <= 0x14060FFFF)
                   and a not in known]

        # Check cache
        cache_dir = os.path.join(CACHE_DIR, build_date)
        os.makedirs(cache_dir, exist_ok=True)
        cache_file = os.path.join(cache_dir, 'wide_scan.txt')

        if os.path.exists(cache_file):
            hits = defaultdict(list)
            with open(cache_file) as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) == 3:
                        hits[int(parts[0])].append((int(parts[1]), int(parts[2])))
            print(f"{build_date}: loaded {sum(len(v) for v in hits.values())} cached")
        else:
            print(f"{build_date}: scanning {len(to_scan)} functions...")
            hits = defaultdict(list)

            with ProcessPoolExecutor(max_workers=48) as executor:
                futures = {executor.submit(scan_func, exe, addr): addr for addr in to_scan}
                done = 0
                for future in as_completed(futures):
                    addr, offsets = future.result()
                    done += 1
                    if offsets and len(offsets) <= 3:
                        for off in offsets:
                            if off in target_offsets:
                                hits[off].append((addr, len(offsets)))
                    if done % 1000 == 0:
                        print(f"  {done}/{len(to_scan)}...")

            with open(cache_file, 'w') as f:
                for off, entries in sorted(hits.items()):
                    for addr, n in entries:
                        f.write(f"{off}\t{addr}\t{n}\n")

            total = sum(len(v) for v in hits.values())
            print(f"{build_date}: {total} hits for remaining fields")

        # Add evidence
        for off, entries in hits.items():
            field = offset_to_field.get(off)
            if not field:
                continue
            pure = [e for e in entries if e[1] == 1]
            dual = [e for e in entries if e[1] == 2]
            if pure:
                addr, n = pure[0]
                conf = 'HIGH'
            elif dual:
                addr, n = dual[0]
                conf = 'MED'
            else:
                continue

            db.add_evidence(
                binary_id=bid, class_name='CXWnd', field_name=field,
                func_name=f"wide_0x{addr:x}", func_addr=addr,
                evidence_type='getter' if n == 1 else 'access',
                decompile_line=f"wide scan: 0x{addr:x} touches {n} offset(s)",
                confidence=conf)

    # Final count
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
    high_set = set(r['field_name'] for r in rows)
    still_left = all_fields - high_set

    print(f"\n{'='*60}")
    print(f"HIGH confidence fields (5+ builds): {len(rows)}")
    print(f"Still not HIGH: {len(still_left)}")
    for f in sorted(still_left):
        print(f"  {f}")

    db.close()


if __name__ == '__main__':
    main()
