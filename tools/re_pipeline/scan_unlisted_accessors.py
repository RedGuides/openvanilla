#!/usr/bin/env python3
"""Scan non-eqgame.h functions in the CXWnd code range for focused accessors."""
import os, re, subprocess, sqlite3, sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(__file__))
from eq_xref_db import EQXrefDB

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
    build_date = sys.argv[1] if len(sys.argv) > 1 else '2026-02-10'
    bid = db.get_binary_id(build_date)

    build_row = db.conn.execute("SELECT binary_path FROM binaries WHERE id = ?", (bid,)).fetchone()
    EXE = build_row['binary_path']

    known_addrs = set(r['func_addr'] for r in db.conn.execute(
        "SELECT func_addr FROM function_identities WHERE binary_id = ?", (bid,)))

    # Get all function addresses from BinDiff for this build
    pipeline_dir = "/mnt/DEV/reverse-engineering/MQ-RE/data/pipeline_runs"
    # Find a BinDiff DB where this build is the "new" binary
    all_addrs = set()
    for dirname in os.listdir(pipeline_dir):
        if build_date not in dirname:
            continue
        bd_dir = os.path.join(pipeline_dir, dirname, 'output')
        if not os.path.exists(bd_dir):
            continue
        for f in os.listdir(bd_dir):
            if f.endswith('.BinDiff'):
                bd_conn = sqlite3.connect(os.path.join(bd_dir, f))
                for r in bd_conn.execute("SELECT address1, address2 FROM function WHERE similarity > 0.5"):
                    all_addrs.add(r[0])
                    all_addrs.add(r[1])
                bd_conn.close()

    cxwnd_range = [a for a in all_addrs if 0x1405B0000 <= a <= 0x14060FFFF and a not in known_addrs]
    print(f"Scanning {len(cxwnd_range)} non-eqgame.h CXWnd-range functions for {build_date}...")

    all_offsets = {}
    for r in db.conn.execute("""
        SELECT sm.field_name, mo.offset_val FROM member_offsets mo
        JOIN struct_members sm ON mo.member_id = sm.id
        WHERE mo.binary_id = ? AND sm.class_name = 'CXWnd'
    """, (bid,)):
        all_offsets[r['offset_val']] = r['field_name']

    accessor_hits = defaultdict(list)
    with ProcessPoolExecutor(max_workers=48) as executor:
        futures = {executor.submit(scan_func, EXE, addr): addr for addr in cxwnd_range}
        done = 0
        for future in as_completed(futures):
            addr, offsets = future.result()
            done += 1
            if offsets and len(offsets) <= 3:
                for off in offsets:
                    if off in all_offsets:
                        accessor_hits[off].append((addr, len(offsets)))
            if done % 200 == 0:
                print(f"  {done}/{len(cxwnd_range)}...")

    print(f"\nFocused accessor functions (1-3 offsets) for CXWnd fields:")
    for off in sorted(accessor_hits.keys()):
        field = all_offsets.get(off, '???')
        single = [(a,n) for a, n in accessor_hits[off] if n == 1]
        dual = [(a,n) for a, n in accessor_hits[off] if n == 2]
        triple = [(a,n) for a, n in accessor_hits[off] if n == 3]
        parts = []
        if single: parts.append(f"{len(single)} pure({','.join(f'0x{a:x}' for a,_ in single[:3])})")
        if dual: parts.append(f"{len(dual)} dual")
        if triple: parts.append(f"{len(triple)} triple")
        print(f"  0x{off:03x} {field:30s}: {', '.join(parts)}")

    db.close()

if __name__ == '__main__':
    main()
