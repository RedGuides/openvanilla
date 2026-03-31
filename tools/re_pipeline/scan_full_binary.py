#!/usr/bin/env python3
"""
Scan ALL BinDiff-matched functions (not just CXWnd range) for CXWnd member accessors.
Filters to small functions first (< 50 bytes) to find pure getters/setters efficiently.
"""
import os, re, subprocess, sqlite3, sys, struct
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

BASE = os.path.join(os.path.dirname(__file__), '..', '..')
PIPELINE_DIR = os.path.join(BASE, 'data', 'pipeline_runs')
CACHE_DIR = os.path.join(BASE, 'data', 'full_scan_cache')


def get_small_functions(exe_path, addrs, max_size=64):
    """Filter to functions that are small (likely pure accessors).
    Uses rizin to get function size, batched for efficiency."""
    small = []
    # Batch: analyze and get size for each function
    # This is faster than individual calls
    for addr in addrs:
        try:
            result = subprocess.run(
                ["rizin", "-a", "x86", "-b", "64", "-q",
                 "-c", f"af @ 0x{addr:x}; afi @ 0x{addr:x} ~size",
                 exe_path], capture_output=True, text=True, timeout=5)
            text = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)
            m = re.search(r'size:\s*(\d+)', text)
            if m and int(m.group(1)) <= max_size:
                small.append((addr, int(m.group(1))))
        except:
            pass
    return small


def scan_func(exe, addr):
    """Disassemble one function, extract CXWnd-range offsets."""
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
    build_date = sys.argv[1] if len(sys.argv) > 1 else '2026-02-10'
    bid = db.get_binary_id(build_date)
    row = db.conn.execute("SELECT binary_path FROM binaries WHERE id = ?", (bid,)).fetchone()
    exe = row['binary_path']

    # Get all BinDiff addresses for this build
    known_addrs = set(r['func_addr'] for r in db.conn.execute(
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

    # EXCLUDE CXWnd range (already scanned) and known eqgame.h functions
    outside_cxwnd = [a for a in all_addrs
                     if not (0x1405B0000 <= a <= 0x14060FFFF)
                     and a not in known_addrs
                     and 0x140001000 <= a <= 0x140900000]  # .text range only

    print(f"Build {build_date}: {len(outside_cxwnd)} functions outside CXWnd range")

    # Check cache
    cache_dir = os.path.join(CACHE_DIR, build_date)
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, 'full_scan_results.txt')

    if os.path.exists(cache_file):
        hits = defaultdict(list)
        with open(cache_file) as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) == 3:
                    hits[int(parts[0])].append((int(parts[1]), int(parts[2])))
        print(f"Loaded {sum(len(v) for v in hits.values())} cached results")
    else:
        # Scan all with parallel workers -- rizin is fast for small functions
        print(f"Scanning {len(outside_cxwnd)} functions with 48 workers...")
        hits = defaultdict(list)

        with ProcessPoolExecutor(max_workers=48) as executor:
            futures = {executor.submit(scan_func, exe, addr): addr for addr in outside_cxwnd}
            done = 0
            for future in as_completed(futures):
                addr, offsets = future.result()
                done += 1
                if offsets and len(offsets) <= 3:
                    for off in offsets:
                        hits[off].append((addr, len(offsets)))
                if done % 500 == 0:
                    print(f"  {done}/{len(outside_cxwnd)}...")

        # Cache
        with open(cache_file, 'w') as f:
            for off, entries in sorted(hits.items()):
                for addr, n in entries:
                    f.write(f"{off}\t{addr}\t{n}\n")

        print(f"Found {sum(len(v) for v in hits.values())} accessor hits")

    # Map offsets to fields
    offset_to_field = {}
    for r in db.conn.execute("""
        SELECT sm.field_name, mo.offset_val FROM member_offsets mo
        JOIN struct_members sm ON mo.member_id = sm.id
        WHERE mo.binary_id = ? AND sm.class_name = 'CXWnd'
    """, (bid,)):
        offset_to_field[r['offset_val']] = r['field_name']

    # Report and add to database
    print(f"\nAccessors from outside CXWnd code range:")
    added = 0
    for off in sorted(hits.keys()):
        field = offset_to_field.get(off)
        if not field:
            continue
        entries = hits[off]
        pure = [e for e in entries if e[1] == 1]
        dual = [e for e in entries if e[1] == 2]
        triple = [e for e in entries if e[1] == 3]

        parts = []
        if pure: parts.append(f"{len(pure)} pure")
        if dual: parts.append(f"{len(dual)} dual")
        if triple: parts.append(f"{len(triple)} triple")

        if pure or dual:
            print(f"  0x{off:03x} {field:30s}: {', '.join(parts)}")

        # Add best evidence
        if pure:
            addr, n = pure[0]
            conf = 'HIGH'
        elif dual:
            addr, n = dual[0]
            conf = 'MED'
        else:
            continue

        db.add_evidence(
            binary_id=bid,
            class_name='CXWnd',
            field_name=field,
            func_name=f"unlisted_wide_0x{addr:x}",
            func_addr=addr,
            evidence_type='getter' if n == 1 else 'access',
            decompile_line=f"non-CXWnd-range function at 0x{addr:x}, {n} offset(s)",
            confidence=conf
        )
        added += 1

    print(f"\nAdded {added} evidence records")

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
    print(f"\nHIGH confidence fields (5+ builds): {len(rows)}")

    remaining = set(offset_to_field.values()) - set(r['field_name'] for r in rows)
    if remaining:
        print(f"Still not HIGH ({len(remaining)}): {', '.join(sorted(remaining))}")

    db.close()


if __name__ == '__main__':
    main()
